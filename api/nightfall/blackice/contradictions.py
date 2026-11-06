"""BLACK ICE contradiction flags: a finding's status disagrees with newer evidence.

Read-only. Flags are computed when asked for and never change a finding: only a person
can mark one validated, a false positive or remediated, so a flag is a prompt to review.

Two kinds:
  * not_reproduced: an open rule-made finding (unverified or validated) whose asset was
    checked again by the same tool, after the evidence behind the finding, and the current
    rules don't find the condition in that newer evidence.
  * seen_after_false_positive: a finding marked a false positive that the rules have
    observed again since it was marked (ingest keeps the false-positive status).

Remediated findings aren't flagged: ingest reopens them as unverified when seen again.

Comparison rules, so that an incomparable check isn't read as a contradiction:
  * Only the latest evidence from the same tool, on the same asset and project, with the
    same simulation flag (lab results never contradict real ones, nor the reverse).
  * The evidence behind the finding must itself still produce the check under the
    current rules; otherwise the two records can't be compared (e.g. the rules changed or
    the finding came from a probe the rules don't read) and nothing is flagged.
  * Header checks only count when the newer audit got an HTTPS response, and cookie checks
    only when the newer response set that cookie.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.orm import Session

from nightfall.blackice.finding_rules import _slug
from nightfall.blackice.replay import drafts_for
from nightfall.core.db.models import (
    Evidence,
    Finding,
    FindingEvidence,
    FindingOrigin,
    ValidationStatus,
)

Kind = Literal["not_reproduced", "seen_after_false_positive"]
FLAGGED_STATUSES = (
    ValidationStatus.UNVERIFIED,
    ValidationStatus.VALIDATED,
    ValidationStatus.FALSE_POSITIVE,
)
SCAN_LIMIT = 1000

_HEADER_CHECKS = (
    "http.missing-hsts",
    "http.hsts-short-max-age",
    "http.missing-csp",
    "http.no-framing-protection",
    "http.cookie-",
)


@dataclass(frozen=True)
class Contradiction:
    finding_id: uuid.UUID
    kind: Kind
    explanation: str
    evidence_id: uuid.UUID
    evidence_collected_at: datetime
    tool_name: str


def _https_ok(headers: dict[str, Any]) -> dict[str, Any] | None:
    https = headers.get("https")
    if isinstance(https, dict) and 200 <= int(https.get("status") or 0) < 400:
        return https
    return None


def retests(check_id: str, summary: dict[str, Any]) -> bool:
    """Whether newer evidence from the finding's tool could have shown this check."""
    if not check_id.startswith(_HEADER_CHECKS) and check_id != "http.no-https-redirect":
        return True
    headers = (summary.get("posture") or {}).get("headers")
    if not isinstance(headers, dict):
        return False
    if check_id == "http.no-https-redirect":
        return isinstance(headers.get("https"), dict) and isinstance(headers.get("http"), dict)
    https = _https_ok(headers)
    if https is None:
        return False
    if check_id.startswith("http.cookie-"):
        name = check_id.split(".", 2)[2] if check_id.count(".") >= 2 else ""
        return any(
            isinstance(c, dict) and _slug(str(c.get("name") or "")) == name
            for c in https.get("cookies") or []
        )
    return True


def _produces(ev: Evidence, check_id: str) -> bool:
    return any(d.check_id == check_id for d in drafts_for(ev.summary or {}, ev.collected_at))


def find(
    db: Session,
    workspace_id: uuid.UUID,
    *,
    project_id: uuid.UUID | None = None,
    finding_id: uuid.UUID | None = None,
) -> list[Contradiction]:
    q = select(Finding).where(
        Finding.workspace_id == workspace_id,
        Finding.origin == FindingOrigin.DETERMINISTIC_CHECK,
        Finding.check_id.is_not(None),
        Finding.asset_id.is_not(None),
        Finding.validation_status.in_(FLAGGED_STATUSES),
    )
    if project_id:
        q = q.where(Finding.project_id == project_id)
    if finding_id:
        q = q.where(Finding.id == finding_id)
    findings = list(db.scalars(q.order_by(Finding.last_observed_at.desc()).limit(SCAN_LIMIT)))
    if not findings:
        return []

    # The latest rule-linked evidence behind each finding.
    source: dict[uuid.UUID, Evidence] = {}
    for fid, ev in db.execute(
        select(FindingEvidence.finding_id, Evidence)
        .join(Evidence, Evidence.id == FindingEvidence.evidence_id)
        .where(
            FindingEvidence.finding_id.in_([f.id for f in findings]),
            FindingEvidence.linked_by.like("rule:%"),
        )
        .ext(distinct_on(FindingEvidence.finding_id))
        .order_by(FindingEvidence.finding_id, Evidence.collected_at.desc(), Evidence.id)
    ).all():
        source[fid] = ev

    # The latest evidence per (project, asset, tool, simulation flag).
    group = (Evidence.project_id, Evidence.asset_id, Evidence.tool_name, Evidence.is_simulation)
    latest: dict[tuple[Any, ...], Evidence] = {}
    for ev in db.scalars(
        select(Evidence)
        .where(
            Evidence.workspace_id == workspace_id,
            Evidence.asset_id.in_({f.asset_id for f in findings}),
            Evidence.project_id.in_({f.project_id for f in findings}),
        )
        .ext(distinct_on(*group))
        .order_by(*group, Evidence.collected_at.desc(), Evidence.id)
    ):
        latest[(ev.project_id, ev.asset_id, ev.tool_name, ev.is_simulation)] = ev

    out: list[Contradiction] = []
    for f in findings:
        src = source.get(f.id)
        check = f.check_id or ""
        if src is None:
            continue
        if f.validation_status is ValidationStatus.FALSE_POSITIVE:
            if f.validated_at is not None and f.last_observed_at > f.validated_at:
                out.append(
                    Contradiction(
                        f.id,
                        "seen_after_false_positive",
                        f"Marked a false positive on {f.validated_at.date().isoformat()}, "
                        f"but {src.tool_name} observed it again on "
                        f"{f.last_observed_at.date().isoformat()}.",
                        src.id,
                        src.collected_at,
                        src.tool_name,
                    )
                )
            continue
        newer = latest.get((f.project_id, f.asset_id, src.tool_name, src.is_simulation))
        if (
            newer is None
            or newer.id == src.id
            or newer.collected_at <= max(src.collected_at, f.last_observed_at)
            or not retests(check, newer.summary or {})
            or not _produces(src, check)
            or _produces(newer, check)
        ):
            continue
        out.append(
            Contradiction(
                f.id,
                "not_reproduced",
                f"{newer.tool_name} checked this asset again on "
                f"{newer.collected_at.date().isoformat()} and the current rules don't find "
                "this condition. It may have been fixed; a person should re-check it and "
                "update the status.",
                newer.id,
                newer.collected_at,
                newer.tool_name,
            )
        )
    return out
