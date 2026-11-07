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

RULESET = "findings/2026.11-4"


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
    drafts.extend(_certificate_expiry(tls.get("not_after"), now))
    return drafts


def _certificate_expiry(value: object, now: datetime) -> list[Draft]:
    not_after = _parse(value)
    if not_after is None:
        return []
    if not_after <= now:
        return [
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
        ]
    if not_after - now <= timedelta(days=30):
        return [
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
        ]
    return []


def from_nuclei(matches: list[dict[str, str]]) -> list[Draft]:
    """R6: a curated Nuclei check matched. Wording and severity come from the reviewed
    catalog, never from the tool's output."""
    from nightfall.tools.nuclei import CATALOG

    drafts: list[Draft] = []
    seen: set[str] = set()
    for m in matches:
        check = CATALOG.get(m.get("template_id", ""))
        if check is None:
            pack = _from_pack1(m, seen)
            drafts += [pack] if pack else []
            continue
        if check.template_id in seen:
            continue
        seen.add(check.template_id)
        drafts.append(
            Draft(
                check_id=check.check_id,
                rule_id=f"R6-curated-check:{check.template_id}",
                title=check.title,
                severity=check.severity,
                confidence=Confidence.HIGH,
                description=f"{check.description} Matched at {m.get('matched_at', '?')}.",
                impact=check.impact,
                remediation=check.remediation,
            )
        )
    return drafts


def _from_pack1(m: dict[str, str], seen: set[str]) -> Draft | None:
    """R17: a lab tool pack 1 template matched (lab only). The template's own name and
    severity come from the reviewed manifest; the wording says what was and wasn't done."""
    from nightfall.tools.nuclei import pack1

    t = pack1.templates().get(m.get("template_id", ""))
    if t is None or t.id in seen:
        return None
    seen.add(t.id)
    cves = f" ({', '.join(t.cves)})" if t.cves else ""
    return Draft(
        check_id=f"lab-pack1.{t.id}",
        rule_id=f"R17-lab-pack1:{t.id}",
        title=t.name[:200],
        severity=t.severity,
        confidence=Confidence.MEDIUM,
        description=f"Nuclei template {t.id}{cves} from lab tool pack 1 ({pack1.version()}) "
        f"matched at {m.get('matched_at', '?')}. Detected by the template's checks, not "
        "exploited. Lab result.",
        impact="Depends on the weakness: see the template's references and any CVE advisory.",
        remediation="Confirm the finding by hand, then apply the vendor's fix or "
        "configuration change.",
    )


HSTS_MIN_AGE = 15_552_000  # 180 days
MAX_COOKIE_FINDINGS = 10


def from_posture(posture: dict[str, Any] | None, now: datetime) -> list[Draft]:
    """R2, R4, R5 and R7-R16: TLS configuration and HTTP security-header audits."""
    posture = posture or {}
    tls = posture.get("tls")
    headers = posture.get("headers")
    return (_from_tls(tls, now) if isinstance(tls, dict) else []) + (
        _from_headers(headers) if isinstance(headers, dict) else []
    )


def _from_tls(audit: dict[str, Any], now: datetime) -> list[Draft]:
    drafts: list[Draft] = []
    cert = audit.get("certificate") or {}
    validation = audit.get("validation") or {}
    accepted = [p for p in audit.get("accepted") or [] if isinstance(p, str)]

    # R2 (same check as technology identification): the certificate doesn't validate.
    if validation.get("result") == "cert_invalid" and accepted:
        drafts.append(
            Draft(
                check_id="tls.certificate-not-trusted",
                rule_id="R2-certificate-not-trusted",
                title="TLS certificate failed validation",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="The TLS handshake completed only with certificate validation off: "
                f"{str(validation.get('detail') or 'validation failed')[:200]}.",
                impact="Users are trained to click through warnings, and connections can be "
                "intercepted without detection.",
                remediation="Install a certificate from a trusted CA that covers this hostname, "
                "with the full chain.",
            )
        )
    drafts.extend(_certificate_expiry(cert.get("not_after"), now))

    # R7: a deprecated protocol version completed a handshake.
    legacy = [p for p in accepted if p in ("SSLv3", "TLSv1", "TLSv1.1")]
    if legacy:
        drafts.append(
            Draft(
                check_id="tls.legacy-protocol",
                rule_id="R7-legacy-tls-protocol",
                title="Deprecated TLS protocol versions accepted",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=f"The server completed a handshake with {', '.join(legacy)}.",
                impact="TLS 1.0 and 1.1 have known weaknesses and are deprecated (RFC 8996); "
                "clients that can be pushed onto them get weaker protection.",
                remediation="Disable TLS 1.0 and 1.1 and keep TLS 1.2 and 1.3.",
            )
        )
    # R8: no modern protocol version at all.
    if accepted and not {"TLSv1.2", "TLSv1.3"} & set(accepted):
        drafts.append(
            Draft(
                check_id="tls.no-modern-protocol",
                rule_id="R8-no-modern-tls",
                title="TLS 1.2 and 1.3 not supported",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description=f"Only {', '.join(accepted)} completed a handshake.",
                impact="Current browsers refuse to connect, and the protocols offered are "
                "deprecated.",
                remediation="Enable TLS 1.2 and TLS 1.3.",
            )
        )
    # R9: weak public key.
    bits = cert.get("key_bits")
    kind = str(cert.get("key_type") or "")
    if isinstance(bits, int) and kind in ("RSA", "DSA") and bits < 2048:
        drafts.append(
            Draft(
                check_id="tls.weak-key",
                rule_id="R9-weak-certificate-key",
                title="Certificate uses a weak key",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=f"The certificate's key is {kind} {bits} bits.",
                impact="Keys below 2048 bits are within reach of well-resourced attackers.",
                remediation="Reissue the certificate with an RSA 2048+ or ECDSA P-256+ key.",
            )
        )
    # R10: SHA-1 (or weaker) certificate signature.
    if str(cert.get("signature_hash") or "").lower() in ("sha1", "md5"):
        drafts.append(
            Draft(
                check_id="tls.weak-signature",
                rule_id="R10-weak-certificate-signature",
                title="Certificate signed with a weak hash",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=f"The certificate is signed with {cert['signature_hash']}.",
                impact="SHA-1 and MD5 signatures can be forged; browsers reject them.",
                remediation="Reissue the certificate with a SHA-256 signature.",
            )
        )
    return drafts


def _from_headers(audit: dict[str, Any]) -> list[Draft]:
    drafts: list[Draft] = []
    https = audit.get("https")
    plain = audit.get("http")

    if isinstance(https, dict) and 200 <= int(https.get("status") or 0) < 400:
        is_html = "html" in str(https.get("content_type") or "").lower()
        # R11 (same check as the curated Nuclei template): no HSTS.
        if not https.get("hsts"):
            drafts.append(
                Draft(
                    check_id="http.missing-hsts",
                    rule_id="R11-missing-hsts",
                    title="HTTPS site does not send Strict-Transport-Security",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description="The HTTPS response to / has no Strict-Transport-Security header.",
                    impact="Browsers may still try plain HTTP first, which an attacker on the "
                    "network can intercept or downgrade.",
                    remediation="Send Strict-Transport-Security with a max-age of at least six "
                    "months once all subdomains serve HTTPS.",
                )
            )
        else:
            age = https.get("hsts_max_age")
            if not isinstance(age, int) or age < HSTS_MIN_AGE:
                drafts.append(
                    Draft(
                        check_id="http.hsts-short-max-age",
                        rule_id="R12-hsts-short-max-age",
                        title="Strict-Transport-Security max-age is short",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        description=f"Strict-Transport-Security is "
                        f"{str(https.get('hsts'))[:200]!r}; the max-age is under 180 days.",
                        impact="Protection lapses for returning visitors who stay away longer "
                        "than the max-age.",
                        remediation="Use a max-age of at least 15552000 (180 days).",
                    )
                )
        # R13: HTML without a Content-Security-Policy.
        if is_html and not https.get("csp"):
            drafts.append(
                Draft(
                    check_id="http.missing-csp",
                    rule_id="R13-missing-csp",
                    title="No Content-Security-Policy",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description="The HTML response to / has no Content-Security-Policy header.",
                    impact="Without a policy, any script injection runs with the page's full "
                    "privileges.",
                    remediation="Define a Content-Security-Policy, starting with default-src "
                    "'self' and widening only what the site needs.",
                )
            )
        # R14: HTML that can be framed by any site.
        if is_html and not https.get("x_frame_options") and not https.get("csp_frame_ancestors"):
            drafts.append(
                Draft(
                    check_id="http.no-framing-protection",
                    rule_id="R14-no-framing-protection",
                    title="Page can be framed by other sites",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description="The HTML response to / sends neither X-Frame-Options nor a CSP "
                    "frame-ancestors directive.",
                    impact="Other sites can embed the page and trick users into clicking on it "
                    "(clickjacking).",
                    remediation="Send Content-Security-Policy: frame-ancestors 'self' (or "
                    "X-Frame-Options: DENY).",
                )
            )
        # R15: cookies set over HTTPS without Secure / HttpOnly.
        cookies = [c for c in https.get("cookies") or [] if isinstance(c, dict)]
        for c in cookies[:MAX_COOKIE_FINDINGS]:
            name = str(c.get("name") or "?")[:100]
            if not c.get("secure"):
                drafts.append(
                    Draft(
                        check_id=f"http.cookie-not-secure.{_slug(name)}",
                        rule_id="R15-cookie-without-secure",
                        title=f"Cookie {name} is set without the Secure flag",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        description=f"The HTTPS response sets cookie {name} without Secure.",
                        impact="The browser also sends the cookie over plain HTTP, where it can "
                        "be read on the network.",
                        remediation="Add the Secure attribute to the cookie.",
                    )
                )
            if not c.get("httponly"):
                drafts.append(
                    Draft(
                        check_id=f"http.cookie-not-httponly.{_slug(name)}",
                        rule_id="R15-cookie-without-httponly",
                        title=f"Cookie {name} is readable by page scripts",
                        severity=Severity.INFO,
                        confidence=Confidence.MEDIUM,
                        description=f"Cookie {name} is set without HttpOnly. That's correct for "
                        "cookies the page's own scripts read; it's a weakness for session "
                        "cookies.",
                        impact="If it's a session cookie, an injected script can steal it.",
                        remediation="Add HttpOnly to session and authentication cookies.",
                    )
                )

    # R16: plain HTTP serves content instead of redirecting to HTTPS (while HTTPS works).
    if (
        isinstance(https, dict)
        and isinstance(plain, dict)
        and 200 <= int(plain.get("status") or 0) < 300
        and not audit.get("http_redirects_to_https")
    ):
        drafts.append(
            Draft(
                check_id="http.no-https-redirect",
                rule_id="R16-no-https-redirect",
                title="Plain HTTP is not redirected to HTTPS",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=f"http://{audit.get('target')}/ answered {plain.get('status')} "
                "instead of redirecting to HTTPS.",
                impact="Visitors who type the address or follow an old link stay on an "
                "unencrypted connection.",
                remediation="Redirect every plain-HTTP request to the HTTPS URL (301).",
            )
        )
    return drafts
