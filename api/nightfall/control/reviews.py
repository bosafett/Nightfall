"""CONTROL: what a recorded review reference means (one rule for every review switch).

The owner's original rule: restricted capabilities (BLACKSITE, lab tool pack 1, Profile B)
stay off until an *independent* review is recorded; self-review isn't independent sign-off.

Owner decision, 2026-11-08 (single person on the project): a temporary self-review mode.
  * A reference starting with "SELF:" is a self-review by the owner.
  * It unlocks a feature only while NIGHTFALL_SELF_REVIEW_UNTIL is set to a date that hasn't
    passed (at most 90 days ahead, checked at start-up). After that date it unlocks nothing,
    with no further action needed.
  * It is never presented as independent: every place that reports the review says
    "self-review, not independent", and runs record which kind they ran under.
  * Any other non-empty reference is an independent review, exactly as before.
Every other gate (owner only, fresh two-factor, lab network, proof of control, sealed
credentials, approvals, worker re-checks) is unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from nightfall.config import Settings

SELF_PREFIX = "SELF:"
MAX_SELF_REVIEW_DAYS = 90


@dataclass(frozen=True)
class Review:
    kind: Literal["independent", "self", "none"]
    ok: bool  # does it unlock the feature right now?
    reference: str | None
    label: str  # for people: what kind of review this is
    problem: str | None  # why it doesn't unlock, when it doesn't


def review(ref: str | None, s: Settings, now: datetime, name: str) -> Review:
    ref = (ref or "").strip() or None
    if ref is None:
        return Review("none", False, None, "No review recorded",
                      f"{name} has no recorded review.")  # fmt: skip
    if not ref.upper().startswith(SELF_PREFIX):
        return Review("independent", True, ref, f"Independent review {ref}", None)
    until = s.self_review_until
    if until is None:
        return Review(
            "self", False, ref, f"Self-review {ref} (not independent)",
            f"{name} has only a self-review, and self-review mode is off "
            "(NIGHTFALL_SELF_REVIEW_UNTIL isn't set).",
        )  # fmt: skip
    if now >= until:
        return Review(
            "self", False, ref, f"Self-review {ref} (not independent)",
            f"{name} has only a self-review, and self-review mode ended on "
            f"{until:%Y-%m-%d %H:%M} UTC. Record an independent review to switch it on.",
        )  # fmt: skip
    return Review(
        "self", True, ref,
        f"Self-review {ref}: NOT independent, accepted until {until:%Y-%m-%d} (owner decision)",
        None,
    )  # fmt: skip
