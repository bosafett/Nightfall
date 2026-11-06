"""How long an approval stays valid before the work it approved must start.

An approval is a decision about a target, a scope version and a moment. Work that waits too
long (the worker was down, the lab machine was off) is refused by the worker and has to be
approved again. Lab approvals are shorter-lived (authorization review finding F5).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from nightfall.scope.lab import LAB_APPROVAL_TTL_HOURS

LIVE_APPROVAL_TTL_HOURS = 72


def approval_ttl(is_lab: bool) -> timedelta:
    return timedelta(hours=LAB_APPROVAL_TTL_HOURS if is_lab else LIVE_APPROVAL_TTL_HOURS)


def approval_expired(decided_at: datetime, is_lab: bool, now: datetime) -> str | None:
    """The refusal reason when an approval is too old to act on, else None."""
    if decided_at >= now - approval_ttl(is_lab):
        return None
    hours = LAB_APPROVAL_TTL_HOURS if is_lab else LIVE_APPROVAL_TTL_HOURS
    kind = "lab approvals" if is_lab else "approvals"
    return f"The approval is more than {hours} hours old ({kind} expire). Request it again."
