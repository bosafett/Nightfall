"""Background worker: claims queued operations and runs passive collectors.

    nightfall-worker            (NIGHTFALL_WORKER_DATABASE_URL, role nightfall_worker)

Safety properties:
  * Scope is re-checked at execution time against the *current* active scope. If the
    scope was replaced after the request, the job is denied, not run on stale authority.
  * Only collectors registered for the operation's tool run; the worker never executes
    anything derived from user or model input.
  * Collector output is stored as evidence before anything is derived from it.
  * Jobs left "running" by a crashed worker are retried (max 3 attempts), and re-runs
    never duplicate evidence, assets or relationships.
"""

from __future__ import annotations

import functools
import ipaddress
import logging
import os
import signal
import socket
import sys
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import create_engine, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, sessionmaker

from nightfall.agents import runner as agent_runner
from nightfall.agents.providers import Provider, get_provider
from nightfall.blackice.ingest import apply_finding_rules, ingest
from nightfall.config import get_settings
from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    ActorType,
    Approval,
    ApprovalDecision,
    Operation,
    OperationStatus,
    Project,
    RiskClass,
    Scope,
    ScopeEntryKind,
    ScopeExclusion,
    ScopeTarget,
    WorkerHeartbeat,
)
from nightfall.core.db.session import set_workspace_context
from nightfall.core.evidence_store import BlobStore, EvidenceStore, PostgresEvidenceStore
from nightfall.recon.collectors import (
    Collector,
    NucleiScan,
    RunContext,
    collectors,
    lab_collectors,
)
from nightfall.recon.safe_http import Refused
from nightfall.scope.engine import evaluate
from nightfall.scope.lab import LAB_APPROVAL_TTL_HOURS
from nightfall.scope.repository import active_scope, snapshot
from nightfall.tools.runner import Sandbox

log = logging.getLogger("nightfall.worker")


# Constants are inlined (not formatted) so these stay static SQL. The lab worker and the
# normal worker take disjoint queues (also enforced by RLS, migration 0010).
_CLAIM = """
UPDATE operations SET status = 'running', started_at = now(), attempts = attempts + 1
WHERE id = (
  SELECT id FROM operations
  WHERE ((status = 'queued')
     OR (status = 'running' AND started_at < now() - interval '10 minutes' AND attempts < 3))
    AND {lab}
  ORDER BY queued_at
  FOR UPDATE SKIP LOCKED
  LIMIT 1)
RETURNING id, workspace_id
"""
_EXPIRE = """
UPDATE operations SET status = 'failed', finished_at = now(),
  error = 'Gave up after 3 attempts (worker stopped responding).'
WHERE status = 'running' AND started_at < now() - interval '10 minutes' AND attempts >= 3
  AND {lab}
"""
CLAIM = text(_CLAIM.format(lab="NOT is_lab"))
EXPIRE = text(_EXPIRE.format(lab="NOT is_lab"))
CLAIM_LAB = text(_CLAIM.format(lab="is_lab"))
EXPIRE_LAB = text(_EXPIRE.format(lab="is_lab"))


def _excluded_networks(
    db: Session, scope_id: uuid.UUID
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    rows = db.execute(
        select(ScopeExclusion.kind, ScopeExclusion.value).where(
            ScopeExclusion.scope_id == scope_id,
            ScopeExclusion.kind.in_([ScopeEntryKind.IP, ScopeEntryKind.CIDR]),
        )
    ).all()
    return tuple(ipaddress.ip_network(v) for _, v in rows)


def _probe_bounds(db: Session, op: Operation) -> dict[str, object] | None:
    """Probe bounds from the operation's pinned scope version (not the request's copy)."""
    from nightfall.blacksite.probes import target_bounds

    entries = db.scalars(select(ScopeTarget).where(ScopeTarget.scope_id == op.scope_id)).all()
    try:
        b = target_bounds(entries, op.target_value)
    except ValueError:
        return None
    return b.model_dump() if b else None


def _get_op(db: Session, op_id: uuid.UUID) -> Operation:
    op = db.get(Operation, op_id)
    if op is None:
        raise RuntimeError(f"operation {op_id} not visible to the worker")
    return op


@dataclass
class Worker:
    sessions: sessionmaker[Session]
    store: BlobStore
    tools: dict[str, Collector]
    worker_id: str = f"{socket.gethostname()}:{os.getpid()}"
    clock: Callable[[], object] = utcnow
    # Agents (Phase 5): None means AI is off; queued agent tasks then fail with that reason.
    provider_factory: Callable[[], Provider | None] = lambda: None
    # Isolated lab worker (Phase 6b): only lab operations, never agent tasks.
    lab: bool = False

    def heartbeat(self) -> None:
        with self.sessions() as db:
            db.execute(
                insert(WorkerHeartbeat)
                .values(
                    worker_id=self.worker_id, version=get_settings().version, last_seen_at=utcnow()
                )
                .on_conflict_do_update(
                    index_elements=["worker_id"], set_={"last_seen_at": utcnow()}
                )
            )
            db.commit()

    def run_once(self) -> bool:
        """Processes at most one operation, or else one agent task. Returns False when both
        queues are empty."""
        with self.sessions() as db:
            db.execute(EXPIRE_LAB if self.lab else EXPIRE)
            claimed = db.execute(CLAIM_LAB if self.lab else CLAIM).first()
            db.commit()
        if claimed is None:
            if self.lab:
                return False
            return agent_runner.run_once(self.sessions, self.store, self.provider_factory)
        self.process(claimed.id, claimed.workspace_id)
        return True

    def _finish(
        self,
        op_id: uuid.UUID,
        ws: uuid.UUID,
        status: OperationStatus,
        action: str,
        **fields: object,
    ) -> None:
        with self.sessions() as db:
            set_workspace_context(db, ws)
            op = _get_op(db, op_id)
            op.status = status
            op.finished_at = utcnow()
            for k, v in fields.items():
                setattr(op, k, v)
            record(
                db,
                action,
                actor_type=ActorType.SYSTEM,
                workspace_id=ws,
                entity_type="operation",
                entity_id=op_id,
                data={
                    "tool": op.tool,
                    "target": op.target_value,
                    **{k: v for k, v in fields.items() if k in ("denial_reason", "error")},
                },
            )
            db.commit()

    def process(self, op_id: uuid.UUID, ws: uuid.UUID) -> None:
        now = utcnow()
        with self.sessions() as db:
            set_workspace_context(db, ws)
            op = _get_op(db, op_id)
            current = active_scope(db, op.project_id)
            if current is None or current.id != op.scope_id:
                reason = "The scope changed after this was requested. Request it again."
                decision_ok = False
            else:
                decision = evaluate(snapshot(db, current), op.target_value, now)
                decision_ok, reason = decision.allowed, decision.reason
            if decision_ok and op.risk_class is not RiskClass.PASSIVE:
                approval = db.scalar(
                    select(Approval).where(
                        Approval.operation_id == op.id,
                        Approval.decision == ApprovalDecision.APPROVED,
                        Approval.scope_id_at_decision == op.scope_id,
                    )
                )
                if approval is None:
                    decision_ok, reason = False, "No valid approval for this operation."
                elif op.is_lab and approval.decided_at < now - timedelta(
                    hours=LAB_APPROVAL_TTL_HOURS
                ):
                    decision_ok, reason = (
                        False,
                        f"The approval is more than {LAB_APPROVAL_TTL_HOURS} hours old "
                        "(lab approvals expire). Request it again.",
                    )
            pinned = db.get(Scope, op.scope_id)
            if decision_ok and (
                pinned is None or pinned.is_lab != op.is_lab or op.is_lab != self.lab
            ):
                decision_ok = False
                reason = "Lab and non-lab work are kept apart; this worker can't run it."
            run_ctx = RunContext(
                excluded_networks=_excluded_networks(db, op.scope_id),
                scope=snapshot(db, pinned) if decision_ok and pinned is not None else None,
                params=dict(op.params),
                bounds=_probe_bounds(db, op) if op.tool == "probe" else None,
            )
            tool = self.tools.get(op.tool)
            target, tool_key = op.target_value, op.tool
        if not decision_ok:
            self._finish(
                op_id, ws, OperationStatus.DENIED, "operation.denied", denial_reason=reason
            )
            return
        if tool is None:
            self._finish(
                op_id,
                ws,
                OperationStatus.FAILED,
                "operation.failed",
                error=f"Unknown tool {tool_key!r}.",
            )
            return

        try:
            result = tool.run(target, run_ctx)
            digest = self.store.put(result.raw)
        except Refused as exc:  # safety check refused to send anything
            self._finish(
                op_id, ws, OperationStatus.DENIED, "operation.denied", denial_reason=str(exc)
            )
            return
        except Exception as exc:  # collector/network failure: recorded, not raised
            log.warning("operation %s failed: %s", op_id, exc)
            self._finish(
                op_id,
                ws,
                OperationStatus.FAILED,
                "operation.failed",
                error=f"{type(exc).__name__}: {str(exc)[:300]}",
            )
            return

        with self.sessions() as db:
            set_workspace_context(db, ws)
            op = _get_op(db, op_id)
            org_id = db.scalar(select(Project.organization_id).where(Project.id == op.project_id))
            scope = db.get(Scope, op.scope_id)
            if org_id is None or scope is None:
                raise RuntimeError(f"operation {op_id}: project or scope missing")
            now = utcnow()
            summary = ingest(db, op, org_id, snapshot(db, scope), result, digest, now)
            findings = apply_finding_rules(
                db, op, summary.target_asset_id, summary.evidence_id, result, now
            )
            op.status = OperationStatus.SUCCEEDED
            op.finished_at = utcnow()
            op.result_summary = {**summary.as_dict(), "findings": findings}
            if op.tool == "nuclei":
                op.result_summary["checks"] = result.matches
                op.result_summary["egress"] = result.egress
            record(
                db,
                "operation.completed",
                actor_type=ActorType.SYSTEM,
                workspace_id=ws,
                entity_type="operation",
                entity_id=op_id,
                data=op.result_summary,
            )
            db.commit()


def build_worker() -> Worker:
    s = get_settings()
    if not s.worker_database_url:
        raise SystemExit("NIGHTFALL_WORKER_DATABASE_URL is not set")
    engine = create_engine(s.worker_database_url, pool_pre_ping=True, pool_size=2)
    if s.collector_mode == "fixture":
        log.warning("COLLECTOR MODE IS 'fixture': canned results only, for tests.")
    scan = NucleiScan(
        s.nuclei_bin,
        Sandbox(mode=s.tool_sandbox, user=s.tool_user if s.tool_sandbox == "uid" else None),
        egress_port=s.egress_port,
    )
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    store: BlobStore = (
        PostgresEvidenceStore(sessions)
        if s.evidence_backend == "postgres"
        else EvidenceStore(s.evidence_dir)
    )
    if s.worker_mode == "lab":
        if s.collector_mode != "live":
            raise SystemExit("The lab worker runs live tools only.")
        if problem := _lab_network_problem():
            raise SystemExit(f"LAB WORKER REFUSED TO START: {problem}")
        log.info("LAB WORKER: lab operations only, addresses in %s only", s.lab_networks)
        return Worker(sessions, store, lab_collectors(s.lab_networks, nuclei_scan=scan), lab=True)
    return Worker(
        sessions,
        store,
        collectors(s.collector_mode, nuclei_scan=scan),
        provider_factory=functools.cache(get_provider),
    )


def _lab_network_problem() -> str | None:
    from nightfall.scope.lab import lab_network_problem

    try:
        with open("/proc/net/route") as f:
            table = f.read()
    except OSError as exc:
        return f"can't read the routing table ({exc})"
    return lab_network_problem(get_settings().lab_networks, table)


def run_loop(worker: Worker, stopping: Callable[[], bool]) -> None:
    log.info("worker %s started", worker.worker_id)
    if get_settings().collector_mode == "live":
        for name, ok, detail in self_check():
            (log.info if ok else log.warning)("tool check %s: %s", name, detail)
    last_beat = 0.0
    while not stopping():
        if time.monotonic() - last_beat > 10:
            try:
                worker.heartbeat()
            except Exception:
                log.exception("worker heartbeat failed")
            last_beat = time.monotonic()
        try:
            busy = worker.run_once()
        except Exception:
            log.exception("worker loop error")
            busy = False
        if not busy:
            time.sleep(1.0)
    log.info("worker %s stopped", worker.worker_id)


def start_embedded() -> tuple[threading.Thread, threading.Event]:
    """Runs the worker loop on a daemon thread inside the API process (single-container
    hosting). It still connects as nightfall_worker, never with the API's credentials."""
    stop = threading.Event()
    thread = threading.Thread(
        target=run_loop, args=(build_worker(), stop.is_set), name="nightfall-worker", daemon=True
    )
    thread.start()
    return thread, stop


def self_check() -> list[tuple[str, bool, str]]:
    """Tool readiness, without touching the database or the network:
    sandbox lock, Nuclei binary and version, pinned templates."""
    from nightfall.tools import nuclei
    from nightfall.tools.runner import run as run_tool

    s = get_settings()
    sandbox = Sandbox(mode=s.tool_sandbox, user=s.tool_user if s.tool_sandbox == "uid" else None)
    checks: list[tuple[str, bool, str]] = []
    try:
        sandbox.verify_lock()
        checks.append(("sandbox lock", True, f"tools run as {s.tool_user}, proxy port only"))
    except Refused as exc:
        checks.append(("sandbox lock", False, str(exc)))
    try:
        nuclei.template_paths()
        checks.append(("templates", True, f"{len(nuclei.CATALOG)} pinned, hashes match"))
    except (nuclei.TemplateTampered, OSError) as exc:
        checks.append(("templates", False, str(exc)))
    if s.worker_mode == "lab":
        problem = _lab_network_problem()
        nets = ", ".join(str(n) for n in s.lab_networks)
        checks.append(
            ("lab network", problem is None, problem or f"{nets} is the attached lab-net")
        )
    if not s.nuclei_bin:
        checks.append(("nuclei", False, "NIGHTFALL_NUCLEI_BIN is not set"))
    else:
        try:
            res = run_tool([s.nuclei_bin, "-version", "-duc"], sandbox=sandbox, timeout=30)
            ver = nuclei.engine_version(res.stderr)
            checks.append(("nuclei", ver != "unknown", f"{s.nuclei_bin} {ver}"))
        except (OSError, ValueError) as exc:
            checks.append(("nuclei", False, f"{type(exc).__name__}: {exc}"))
    return checks


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # Evidence and temporary files are private to the worker user: the tool user must not
    # be able to read other runs' evidence.
    os.umask(0o077)
    if "--check" in sys.argv[1:]:
        results = self_check()
        for name, ok, detail in results:
            print(f"{'ok  ' if ok else 'FAIL'} {name}: {detail}")
        raise SystemExit(0 if all(ok for _, ok, _ in results) else 1)
    worker = build_worker()
    stopping = False

    def stop(*_: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    run_loop(worker, lambda: stopping)


if __name__ == "__main__":
    main()
