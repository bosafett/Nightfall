"""SHIELD detection rules (alerts/2026.11-1): compare a scheduled check with the previous
one of the same project, target and check, and say what changed or crossed a threshold.

Deterministic and pure: they read the two snapshots (what a check observed, reduced to the
facts the rules use) and return alert drafts. The first run of a check is a baseline: only
threshold rules (certificate expiry) can fire on it. Nothing here touches the network, the
database or a finding.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from nightfall.core.db.models import Severity

RULES = "alerts/2026.11-1"
EXPIRY_DAYS = ((7, Severity.CRITICAL), (14, Severity.HIGH), (21, Severity.MEDIUM))  # decision 3
OLD_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS")  # TXT is too noisy to alert on

RECOMMEND: dict[str, str] = {
    "cert.expiring": "Renew the certificate now and automate renewal (e.g. ACME).",
    "cert.changed": "Confirm the new certificate was issued on purpose and by the expected CA.",
    "tls.weakened": "Disable the old protocol versions and weak ciphers again; check what "
    "configuration change re-enabled them.",
    "headers.regressed": "Restore the missing or weakened security headers; check the last "
    "deployment of the web server or CDN configuration.",
    "ct.new_names": "Check that each new name was issued on purpose. Names outside the scope "
    "may be look-alike or shadow domains: investigate them first.",
    "dns.changed": "Confirm the record change was intended and made by your team.",
    "finding.reopened": "The problem marked fixed is back: re-apply the fix and find what "
    "undid it.",
    "monitor.failed": "Open the operation to see why the check didn't run, then fix the cause "
    "or renew the authorization.",
    "monitor.expiring": "Renew the authorization if this monitoring should continue.",
    "monitor.ended": "Monitoring stopped. Authorize again (for the new scope version, if it "
    "changed) to resume it.",
}


@dataclass(frozen=True)
class AlertDraft:
    kind: str
    severity: Severity
    title: str
    detail: str
    key: str  # de-duplication key: one open alert per condition


def _h(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:12]


def snapshot(tool: str, result: Any, header_failures: list[str]) -> dict[str, Any] | None:
    """The facts the rules compare, from a collector result. None for unknown tools."""
    if tool == "tls":
        tls = (result.posture or {}).get("tls") or {}
        cert = tls.get("certificate") or {}
        return {
            "cert_sha256": cert.get("sha256"),
            "not_after": cert.get("not_after"),
            "accepted": sorted(tls.get("accepted") or []),
            "trusted": bool((tls.get("validation") or {}).get("trusted")),
        }
    if tool == "headers":
        return {"failing": sorted(set(header_failures))}
    if tool == "ct":
        return {"names": sorted(set(result.names or []))}
    if tool == "dns":
        records = result.records or {}
        return {t: sorted(records.get(t) or []) for t in DNS_TYPES}
    return None


def compare(
    tool: str,
    target: str,
    prev: dict[str, Any] | None,
    cur: dict[str, Any],
    now: datetime,
    in_scope: Any = lambda name: True,
) -> list[AlertDraft]:
    out: list[AlertDraft] = []
    if tool == "tls":
        if cur.get("not_after"):
            left = (datetime.fromisoformat(cur["not_after"]) - now).days
            for days, sev in EXPIRY_DAYS:
                if left <= days:
                    out.append(
                        AlertDraft(
                            "cert.expiring",
                            sev,
                            f"Certificate for {target} expires in {left} days",
                            f"The certificate served by {target} expires on {cur['not_after']}.",
                            f"cert.expiring:{target}",
                        )  # fmt: skip
                    )
                    break
        if prev is None:
            return out
        if prev.get("cert_sha256") and cur.get("cert_sha256") != prev.get("cert_sha256"):
            out.append(
                AlertDraft(
                    "cert.changed",
                    Severity.INFO,
                    f"{target} serves a different certificate",
                    f"SHA-256 {str(prev['cert_sha256'])[:16]}… → "
                    f"{str(cur.get('cert_sha256'))[:16]}….",
                    f"cert.changed:{target}:{cur.get('cert_sha256')}",
                )  # fmt: skip
            )
        new_old = sorted(set(cur["accepted"]) - set(prev.get("accepted") or []))
        new_old = [p for p in new_old if p in OLD_PROTOCOLS]
        lost_trust = prev.get("trusted") and not cur.get("trusted")
        if new_old or lost_trust:
            why = []
            if new_old:
                why.append(f"now accepts {', '.join(new_old)}")
            if lost_trust:
                why.append("its certificate no longer validates")
            out.append(
                AlertDraft(
                    "tls.weakened",
                    Severity.HIGH,
                    f"TLS on {target} got weaker",
                    f"{target} {' and '.join(why)} (it didn't at the previous check).",
                    f"tls.weakened:{target}:{_h(cur)}",
                )  # fmt: skip
            )
    elif tool == "headers" and prev is not None:
        worse = sorted(set(cur["failing"]) - set(prev.get("failing") or []))
        if worse:
            out.append(
                AlertDraft(
                    "headers.regressed",
                    Severity.MEDIUM,
                    f"Security headers on {target} got worse",
                    "Checks that passed at the previous run now fail: " + ", ".join(worse) + ".",
                    f"headers.regressed:{target}:{_h(worse)}",
                )  # fmt: skip
            )
    elif tool == "ct" and prev is not None:
        new = sorted(set(cur["names"]) - set(prev.get("names") or []))
        if new:
            outside = [n for n in new if not in_scope(n)]
            sev = Severity.HIGH if outside else Severity.INFO  # decision 4
            detail = f"New names in certificate logs under {target}: {', '.join(new[:50])}."
            if outside:
                detail += f" Outside the authorized scope: {', '.join(outside[:50])}."
            out.append(
                AlertDraft(
                    "ct.new_names",
                    sev,
                    f"{len(new)} new name(s) in certificate logs for {target}",
                    detail,
                    f"ct.new_names:{target}:{_h(new)}",
                )  # fmt: skip
            )
    elif tool == "dns" and prev is not None:
        changed = [t for t in DNS_TYPES if cur.get(t) != prev.get(t)]
        if changed:
            parts = [
                f"{t}: {', '.join(prev.get(t) or []) or '—'} → {', '.join(cur.get(t) or []) or '—'}"
                for t in changed
            ]
            out.append(
                AlertDraft(
                    "dns.changed",
                    Severity.LOW,
                    f"DNS records of {target} changed",
                    "; ".join(parts)[:3000],
                    f"dns.changed:{target}:{_h(cur)}",
                )  # fmt: skip
            )
    return out
