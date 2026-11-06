"""The lab boundary (owner decision D3) and the review gate (D4), shared by the routes.

* Lab work is created, approved and cancelled only through BLACKSITE, the host-only
  listener on the lab machine. The hosted app can read lab records but not act on them
  (also enforced in the database, migration 0013).
* BLACKSITE acts only on lab work.
* BLACKSITE refuses to create or approve lab execution until an independent review is
  recorded (NIGHTFALL_BLACKSITE_REVIEW_REF). That value is the operator's attestation; it
  is not proof that a review happened.
"""

from __future__ import annotations

from fastapi import Request

from nightfall.config import get_settings
from nightfall.core.audit.writer import record_detached
from nightfall.core.errors import api_error
from nightfall.core.tenancy.deps import WorkspaceContext, is_blacksite


def lab_boundary(
    request: Request, ctx: WorkspaceContext, is_lab: bool, action: str, *, executes: bool = False
) -> None:
    """Raises (and audits) unless this app may do `action` on lab / non-lab work."""
    blacksite = is_blacksite(request)
    if is_lab and not blacksite:
        reason, code = "lab_outside_blacksite", "lab_from_blacksite"
        message = "Lab work is requested and approved from BLACKSITE on the lab machine."
    elif blacksite and not is_lab:
        reason, code = "blacksite_not_lab", "blacksite_lab_only"
        message = "BLACKSITE acts on lab work only."
    elif blacksite and executes and not get_settings().blacksite_review_ref:
        reason, code = "review_not_recorded", "review_required"
        message = (
            "Lab execution stays off until the independent review is recorded "
            "(NIGHTFALL_BLACKSITE_REVIEW_REF)."
        )
    else:
        return
    record_detached("authz.denied", data={"reason": reason, "action": action}, **ctx.audit_kwargs())
    raise api_error(403, code, message)
