"""BLACK ICE replay (review §14): re-run the finding rules over a report's evidence and
show what would change. Read-only: the snapshot and the findings are never modified.

  * Evidence "as of the snapshot": every evidence record of the project collected at or
    before the snapshot was taken (evidence is insert-only, so this set can't have changed).
  * The rules read the observations stored on each evidence record (the same inputs they
    had at collection time), with the clock set to the snapshot's time, so time-based rules
    (certificate expiry) judge as they would have then.
  * The comparison is against the snapshot's rule-made findings, matched by asset + check id
    (snapshots taken before check ids were recorded are matched by asset + rule + title).
  * Only the current ruleset can be replayed: older rule versions aren't kept in the code.
    The snapshot's ruleset version is shown next to the current one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nightfall.blackice.finding_rules import RULESET, Draft, from_http, from_nuclei, from_posture
from nightfall.core.db.models import AssessmentSnapshot, Asset, Evidence


@dataclass(frozen=True)
class Item:
    asset: str | None
    check_id: str | None
    rule_id: str
    title: str
    severity: str


@dataclass
class Diff:
    snapshot_ruleset: str
    current_ruleset: str
    as_of: datetime
    evidence_considered: int
    unchanged: list[Item] = field(default_factory=list)
    changed: list[tuple[Item, Item]] = field(default_factory=list)  # (snapshot, now)
    new: list[Item] = field(default_factory=list)
    gone: list[Item] = field(default_factory=list)


def drafts_for(summary: dict[str, Any], now: datetime) -> list[Draft]:
    """The rules' output for one evidence record's stored observations."""
    return (
        from_http(summary.get("http") or [], summary.get("technologies") or [], now)
        + from_nuclei(summary.get("checks") or [])
        + from_posture(summary.get("posture"), now)
    )


def _key(it: Item, by_check: bool) -> tuple[Any, ...]:
    return (it.asset, it.check_id) if by_check else (it.asset, it.rule_id, it.title)


def replay(db: Session, snap: AssessmentSnapshot) -> Diff:
    as_of = snap.taken_at
    rows = db.execute(
        select(Evidence, Asset.value)
        .outerjoin(Asset, Asset.id == Evidence.asset_id)
        .where(Evidence.project_id == snap.project_id, Evidence.collected_at <= as_of)
        .order_by(Evidence.collected_at)
    ).all()
    produced: dict[tuple[str | None, str], Item] = {}
    for ev, asset in rows:
        for d in drafts_for(ev.summary or {}, as_of):
            produced[(asset, d.check_id)] = Item(
                asset, d.check_id, d.rule_id, d.title, d.severity.value
            )

    recorded = [
        Item(
            f.get("asset"),
            f.get("check_id"),
            str(f.get("rule_id") or "").split("@")[0],  # stored as "<rule>@<ruleset>"
            str(f.get("title") or ""),
            str(f.get("severity") or ""),
        )
        for f in snap.content.get("findings", [])
        if f.get("origin") == "deterministic_check"
    ]
    by_check = all(r.check_id for r in recorded)
    now_items = {_key(it, by_check): it for it in produced.values()}
    then_items = {_key(it, by_check): it for it in recorded}

    diff = Diff(
        snapshot_ruleset=snap.ruleset_version,
        current_ruleset=RULESET,
        as_of=as_of,
        evidence_considered=len(rows),
    )
    for k, then in then_items.items():
        now = now_items.get(k)
        if now is None:
            diff.gone.append(then)
        elif (now.severity, now.title) != (then.severity, then.title):
            diff.changed.append((then, now))
        else:
            diff.unchanged.append(then)
    diff.new = [it for k, it in now_items.items() if k not in then_items]
    for lst in (diff.unchanged, diff.new, diff.gone):
        lst.sort(key=lambda i: (i.asset or "", i.check_id or i.title))
    return diff
