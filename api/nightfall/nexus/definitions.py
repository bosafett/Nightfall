"""NEXUS workflow definitions: reviewed code, versioned and fingerprinted like playbooks.

Nothing in a definition comes from a user or a model. At start a run takes only the
project, a target from the active scope (for workflows that need one) or a finding (for
reassessment), and pins the definition's version and fingerprint.

Step kinds (v1):
  playbook    launch a BLACK OPS playbook through its normal preflight and launch path
  rerun       re-run whatever produced the run's remediated findings (their playbook, or
              the collector), through the same paths, so each new operation is checked and
              approved as usual
  review      a task for a person; done when they mark it done
  checkpoint  waits for "continue" or "stop" from someone allowed to approve operations
  wait        waits for a condition (a fixed predicate); sends nothing

SHIELD, AEGIS and integration steps don't exist yet: a definition can't use them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal

Kind = Literal["playbook", "rerun", "review", "checkpoint", "wait"]
KINDS: tuple[str, ...] = ("playbook", "rerun", "review", "checkpoint", "wait")
EXECUTING: tuple[str, ...] = ("playbook", "rerun")  # a person starts these (owner decision D3)
UNAVAILABLE: tuple[str, ...] = ("shield.evaluate", "aegis.recommend", "integration.execute")

# Fixed predicates. Each name is implemented in engine.PREDICATES; nothing else is allowed.
Predicate = Literal[
    "always",
    "tracked_open",  # at least one tracked finding is open
    "continue",  # the checkpoint this step depends on was answered "continue"
    "tracked_closed",  # no tracked finding is open any more (wait steps)
    "any_remediated",  # at least one tracked finding was marked remediated
]
PREDICATES: tuple[str, ...] = (
    "always",
    "tracked_open",
    "continue",
    "tracked_closed",
    "any_remediated",
)

DEFAULT_TIMEOUT: dict[str, timedelta] = {
    "playbook": timedelta(hours=24),  # includes waiting for operation approvals
    "rerun": timedelta(hours=24),
    "review": timedelta(days=7),
    "checkpoint": timedelta(days=7),
    "wait": timedelta(days=30),
}
MAX_RETRIES = 2  # owner decision D4


class DefinitionError(ValueError):
    pass


@dataclass(frozen=True)
class StepDef:
    key: str
    label: str
    kind: Kind
    description: str
    depends_on: tuple[str, ...] = ()
    when: Predicate = "always"
    retries: int = 0
    timeout: timedelta | None = None
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def deadline(self) -> timedelta:
        return self.timeout or DEFAULT_TIMEOUT[self.kind]


@dataclass(frozen=True)
class WorkflowDef:
    id: str
    name: str
    version: str
    summary: str
    starts_from: Literal["target", "finding"]
    steps: tuple[StepDef, ...]
    deadline: timedelta
    tests: tuple[str, ...]

    def step(self, key: str) -> StepDef:
        for s in self.steps:
            if s.key == key:
                return s
        raise KeyError(key)

    def definition(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "starts_from": self.starts_from,
            "deadline_s": int(self.deadline.total_seconds()),
            "steps": [
                {
                    "key": s.key,
                    "kind": s.kind,
                    "depends_on": list(s.depends_on),
                    "when": s.when,
                    "retries": s.retries,
                    "timeout_s": int(s.deadline.total_seconds()),
                    "params": s.params,
                }
                for s in self.steps
            ],
        }

    @property
    def sha256(self) -> str:
        canonical = json.dumps(self.definition(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


def validate(w: WorkflowDef) -> None:
    """Refuses unknown kinds and predicates, bad retries, unknown or later dependencies
    (steps are listed in an order where every dependency comes first, so there are no
    cycles), and checkpoints answered by nothing."""
    seen: set[str] = set()
    for s in w.steps:
        if s.key in seen:
            raise DefinitionError(f"{w.id}: duplicate step {s.key}")
        if s.kind not in KINDS:
            raise DefinitionError(f"{w.id}.{s.key}: step kind {s.kind} isn't available")
        if s.when not in PREDICATES:
            raise DefinitionError(f"{w.id}.{s.key}: unknown predicate {s.when}")
        if not 0 <= s.retries <= MAX_RETRIES:
            raise DefinitionError(f"{w.id}.{s.key}: retries must be 0 to {MAX_RETRIES}")
        if s.retries and s.kind not in EXECUTING:
            raise DefinitionError(f"{w.id}.{s.key}: only executing steps may retry")
        for d in s.depends_on:
            if d not in seen:
                raise DefinitionError(f"{w.id}.{s.key}: depends on {d}, which isn't earlier")
        if s.when == "continue" and not any(w.step(d).kind == "checkpoint" for d in s.depends_on):
            raise DefinitionError(f"{w.id}.{s.key}: 'continue' needs a checkpoint dependency")
        if s.kind == "wait" and s.params.get("until") not in PREDICATES:
            raise DefinitionError(f"{w.id}.{s.key}: a wait step needs a known params.until")
        if s.kind == "playbook" and not s.params.get("playbook_id"):
            raise DefinitionError(f"{w.id}.{s.key}: a playbook step needs params.playbook_id")
        seen.add(s.key)
    if not w.steps:
        raise DefinitionError(f"{w.id}: no steps")


_TRIAGE = (
    "Review the open findings this run tracks: validate the real ones, mark false positives. "
    "Findings stay unverified until a person decides."
)
_VERIFY = (
    "Look at the reassessment: findings still present are reopened by BLACK ICE, and "
    "contradiction flags show where newer evidence disagrees. Confirm each one."
)

WORKFLOWS: dict[str, WorkflowDef] = {
    w.id: w
    for w in (
        WorkflowDef(
            id="exposure-review",
            name="Exposure review",
            version="1.0.0",
            summary="Assess a host's HTTP security, triage what's found, and reassess once "
            "it's fixed.",
            starts_from="target",
            deadline=timedelta(days=60),
            steps=(
                StepDef(
                    "assess",
                    "Assess HTTP security",
                    "playbook",
                    "Runs the HTTP Security Assessment playbook on the target. Its operation "
                    "needs approval as usual.",
                    retries=1,
                    params={"playbook_id": "http-security-assessment"},
                ),
                StepDef(
                    "triage",
                    "Triage findings",
                    "review",
                    _TRIAGE,
                    depends_on=("assess",),
                    when="tracked_open",
                ),
                StepDef(
                    "decide",
                    "Reassess after remediation?",
                    "checkpoint",
                    "Continue to wait for fixes and reassess them, or stop here.",
                    depends_on=("triage",),
                ),
                StepDef(
                    "fixed",
                    "Wait for fixes",
                    "wait",
                    "Waits until no tracked finding is open (each one marked remediated or a "
                    "false positive).",
                    depends_on=("decide",),
                    when="continue",
                    params={"until": "tracked_closed"},
                ),
                StepDef(
                    "reassess",
                    "Reassess",
                    "rerun",
                    "Re-runs what produced the remediated findings. Each operation needs "
                    "approval as usual.",
                    depends_on=("fixed",),
                    when="any_remediated",
                    retries=1,
                ),
                StepDef("verify", "Check the result", "review", _VERIFY, depends_on=("reassess",)),
            ),
            tests=("tests/test_nexus.py::test_exposure_review_end_to_end",),
        ),
        WorkflowDef(
            id="remediation-reassessment",
            name="Remediation reassessment",
            version="1.0.0",
            summary="Re-run what found a finding that was marked remediated, then check the "
            "result.",
            starts_from="finding",
            deadline=timedelta(days=14),
            steps=(
                StepDef(
                    "reassess",
                    "Reassess",
                    "rerun",
                    "Re-runs what produced the finding. Each operation needs approval as usual.",
                    when="any_remediated",
                    retries=1,
                ),
                StepDef("verify", "Check the result", "review", _VERIFY, depends_on=("reassess",)),
            ),
            tests=("tests/test_nexus.py::test_remediation_reassessment",),
        ),
    )
}

for _w in WORKFLOWS.values():
    validate(_w)
