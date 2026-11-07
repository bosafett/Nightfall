"""How long an approval stays valid before the work it approved must start.

An approval is a decision about a target, a scope version and a moment. Work that waits too
long (the worker was down, the lab machine was off) is refused by the worker and has to be
approved again. Lab approvals are shorter-lived (authorization review finding F5).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from nightfall.scope.lab import LAB_APPROVAL_TTL_HOURS

LIVE_APPROVAL_TTL_HOURS = 72
PROFILE_B_APPROVAL_TTL_HOURS = 24  # design G4


def _hours(is_lab: bool, profile_b: bool) -> int:
    if profile_b:
        return PROFILE_B_APPROVAL_TTL_HOURS
    return LAB_APPROVAL_TTL_HOURS if is_lab else LIVE_APPROVAL_TTL_HOURS


def approval_ttl(is_lab: bool, profile_b: bool = False) -> timedelta:
    return timedelta(hours=_hours(is_lab, profile_b))


def approval_expired(
    decided_at: datetime, is_lab: bool, now: datetime, profile_b: bool = False
) -> str | None:
    """The refusal reason when an approval is too old to act on, else None."""
    if decided_at >= now - approval_ttl(is_lab, profile_b):
        return None
    hours = _hours(is_lab, profile_b)
    kind = "Profile B approvals" if profile_b else "lab approvals" if is_lab else "approvals"
    return f"The approval is more than {hours} hours old ({kind} expire). Request it again."
