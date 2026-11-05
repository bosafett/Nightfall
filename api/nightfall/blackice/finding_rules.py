"""BLACK ICE finding rules: deterministic, versioned, explainable (review §14).

Rules turn stored evidence into findings. A rule-made finding always starts as
"unverified": the evidence shows the condition, but only a person can mark it validated,
a false positive or remediated (enforced by a database CHECK).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from nightfall.core.db.models import Confidence, Severity

RULESET = "findings/2026.11-1"


@dataclass(frozen=True)
class Draft:
    check_id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    impact: str
    remediation: str


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _parse(ts: object) -> datetime | None:
    if not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def from_http(
    http: list[dict[str, Any]], technologies: list[dict[str, Any]], now: datetime
) -> list[Draft]:
    drafts: list[Draft] = []
    summary = http[0] if http else {}
    attempts = summary.get("attempts") or []

    # R1: a server states its software version in a response header.
    for t in technologies:
        if t.get("confidence") == "high" and t.get("version"):
            drafts.append(
                Draft(
                    check_id=f"http.version-disclosure.{_slug(str(t['name']))}",
                    rule_id="R1-version-disclosure",
                    title=f"{t['name']} version disclosed in HTTP headers",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=f"The response header states the version: {t.get('evidence')}",
                    impact="Lets an attacker match the exact version to published vulnerabilities "
                    "without probing further.",
                    remediation="Remove the version (or the whole header) in the server or "
                    "framework configuration.",
                )
            )

    https_ok = [a for a in attempts if str(a.get("url", "")).startswith("https") and "status" in a]
    https_verified_failed = any(
        str(a.get("url", "")).startswith("https") and a.get("verified_tls") and "error" in a
        for a in attempts
    )
    http_ok = [a for a in attempts if str(a.get("url", "")).startswith("http:") and "status" in a]

    # R2: HTTPS only answered once certificate validation was switched off.
    if https_verified_failed and any(not a.get("verified_tls") for a in https_ok):
        drafts.append(
            Draft(
                check_id="tls.certificate-not-trusted",
                rule_id="R2-certificate-not-trusted",
                title="TLS certificate failed validation",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="The HTTPS service answered, but its certificate did not validate "
                "against the system trust store for this hostname.",
                impact="Users are trained to click through warnings, and connections can be "
                "intercepted without detection.",
                remediation="Install a certificate from a trusted CA that covers this hostname, "
                "with the full chain.",
            )
        )

    # R3: plain HTTP answered and HTTPS did not.
    if http_ok and not https_ok:
        drafts.append(
            Draft(
                check_id="http.no-https",
                rule_id="R3-no-https",
                title="Site served without HTTPS",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="Port 80 answered; HTTPS on port 443 did not.",
                impact="Traffic, including credentials or session cookies, travels unencrypted.",
                remediation="Serve the site over HTTPS and redirect HTTP to HTTPS.",
            )
        )

    # R4/R5: certificate expired or expiring within 30 days.
    tls = summary.get("tls") or {}
    not_after = _parse(tls.get("not_after"))
    if not_after is not None:
        if not_after <= now:
            drafts.append(
                Draft(
                    check_id="tls.certificate-expired",
                    rule_id="R4-certificate-expired",
                    title="TLS certificate has expired",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"The certificate expired on {not_after.isoformat()}.",
                    impact="Browsers block or warn on the site; users may bypass warnings.",
                    remediation="Renew the certificate and automate renewal.",
                )
            )
        elif not_after - now <= timedelta(days=30):
            drafts.append(
                Draft(
                    check_id="tls.certificate-expiring",
                    rule_id="R5-certificate-expiring",
                    title="TLS certificate expires within 30 days",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=f"The certificate expires on {not_after.isoformat()}.",
                    impact="The site will become unavailable or show warnings if it isn't renewed.",
                    remediation="Renew the certificate and automate renewal.",
                )
            )
    return drafts
