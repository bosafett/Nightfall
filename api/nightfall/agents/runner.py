"""Runs queued agent tasks (called by the worker after collections).

  1. Claim one task (FOR UPDATE SKIP LOCKED; stale running tasks retried, max 3 attempts).
  2. In the task's workspace context, build what the agent is shown (context.py).
  3. Call the model outside any database transaction.
  4. In a new transaction, apply the answer through the gateway and record the task's
     model, prompt version, tokens and latency.
The worker connects as nightfall_worker, never with the API's role.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from nightfall.agents import context as ctx
from nightfall.agents import gateway
from nightfall.agents.providers import (
    GenerationRequest,
    Provider,
    ProviderError,
)
from nightfall.agents.registry import (
    AGENTS,
    PROMPT_VERSION,
    GuardianOutput,
    HunterOutput,
    ScoutOutput,
)
from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import ActorType, AgentTask, AgentTaskStatus
from nightfall.core.db.session import set_workspace_context
from nightfall.core.evidence_store import BlobStore

log = logging.getLogger("nightfall.agents")

CLAIM = text("""
UPDATE agent_tasks SET status = 'running', started_at = now(), attempts = attempts + 1
WHERE id = (
  SELECT id FROM agent_tasks
  WHERE (status = 'queued')
     OR (status = 'running' AND started_at < now() - interval '10 minutes' AND attempts < 3)
  ORDER BY queued_at
  FOR UPDATE SKIP LOCKED
  LIMIT 1)
RETURNING id, workspace_id
""")
EXPIRE = text("""
UPDATE agent_tasks SET status = 'failed', finished_at = now(),
  error = 'Gave up after 3 attempts (worker stopped responding).'
WHERE status = 'running' AND started_at < now() - interval '10 minutes' AND attempts >= 3
""")


def run_once(
    sessions: sessionmaker[Session],
    store: BlobStore,
    provider_factory: Callable[[], Provider | None],
) -> bool:
    """Processes at most one agent task. Returns False when there is none."""
    with sessions() as db:
        db.execute(EXPIRE)
        claimed = db.execute(CLAIM).first()
        db.commit()
    if claimed is None:
        return False
    _process(sessions, store, provider_factory, claimed.id, claimed.workspace_id)
    return True


def _finish(
    sessions: sessionmaker[Session],
    task_id: uuid.UUID,
    ws: uuid.UUID,
    status: AgentTaskStatus,
    error: str | None = None,
) -> None:
    with sessions() as db:
        set_workspace_context(db, ws)
        task = db.get(AgentTask, task_id)
        if task is None:
            return
        task.status = status
        task.error = error
        task.finished_at = utcnow()
        record(
            db,
            f"agent_task.{status.value}",
            actor_type=ActorType.AGENT,
            workspace_id=ws,
            entity_type="agent_task",
            entity_id=task_id,
            data={"agent": task.agent, **({"error": error} if error else {})},
        )
        db.commit()


def _process(
    sessions: sessionmaker[Session],
    store: BlobStore,
    provider_factory: Callable[[], Provider | None],
    task_id: uuid.UUID,
    ws: uuid.UUID,
) -> None:
    provider = provider_factory()
    if provider is None:
        _finish(
            sessions, task_id, ws, AgentTaskStatus.FAILED, "AI is turned off on this deployment."
        )
        return
    with sessions() as db:
        set_workspace_context(db, ws)
        task = db.get(AgentTask, task_id)
        if task is None:
            return
        spec = AGENTS.get(task.agent)
        if spec is None:
            agent = task.agent
            db.rollback()
            _finish(
                sessions,
                task_id,
                ws,
                AgentTaskStatus.FAILED,
                f"Agent {agent!r} isn't available yet.",
            )
            return
        try:
            if task.agent == "scout":
                prepared = ctx.scout(db, task)
            elif task.agent == "hunter":
                prepared = ctx.hunter(db, task)
            else:
                prepared = ctx.guardian(db, task, store)
        except LookupError as exc:
            db.rollback()
            _finish(sessions, task_id, ws, AgentTaskStatus.FAILED, str(exc))
            return
        db.commit()

    try:
        result = provider.generate(
            GenerationRequest(
                system=spec.system,
                user=prepared.user,
                output_model=spec.output_model,
                effort=spec.effort,
            )
        )
    except ProviderError as exc:
        _finish(sessions, task_id, ws, AgentTaskStatus.FAILED, str(exc))
        return
    except Exception as exc:  # unexpected: recorded, not raised
        log.exception("agent task %s failed", task_id)
        _finish(sessions, task_id, ws, AgentTaskStatus.FAILED, f"{type(exc).__name__}")
        return

    with sessions() as db:
        set_workspace_context(db, ws)
        task = db.get(AgentTask, task_id)
        if task is None or task.status is not AgentTaskStatus.RUNNING:
            return  # cancelled meanwhile: nothing is applied
        parsed = result.parsed
        if isinstance(parsed, ScoutOutput):
            applied = gateway.apply_scout(db, task, parsed)
            notes = parsed.notes
        elif isinstance(parsed, HunterOutput):
            applied = gateway.apply_hunter(db, task, parsed, prepared.shown_evidence)
            notes = parsed.notes
        elif isinstance(parsed, GuardianOutput):
            applied = gateway.apply_guardian(db, task, parsed, result.model)
            notes = parsed.rationale
        else:  # pragma: no cover - registry and runner are in step
            raise RuntimeError("unexpected output type")
        task.status = AgentTaskStatus.SUCCEEDED
        task.finished_at = utcnow()
        task.result = {**applied.as_dict(), "notes": " ".join(notes.split())[:3000]}
        task.provider = result.provider
        task.model = result.model
        task.prompt_version = PROMPT_VERSION
        task.input_tokens = result.input_tokens
        task.output_tokens = result.output_tokens
        task.latency_ms = result.latency_ms
        record(
            db,
            "agent_task.succeeded",
            actor_type=ActorType.AGENT,
            workspace_id=ws,
            entity_type="agent_task",
            entity_id=task_id,
            data={
                "agent": task.agent,
                "model": result.model,
                "accepted": len(applied.accepted),
                "refused": len(applied.refused),
            },
        )
        db.commit()
