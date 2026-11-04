"""Deterministic technology fingerprints from one HTTP response (no LLM).

Each rule has a stable id and a confidence. A version is reported only when the response
states it. Rules are versioned with RULESET so results can be replayed later.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

RULESET = "http-fp/2026.11-1"


@dataclass(frozen=True)
class Technology:
    name: str
    version: str | None
    rule_id: str
    confidence: str  # high = stated in a header; medium = inferred from content
    evidence: str  # the matched snippet, truncated

    def as_dict(self) -> dict[str, str | None]:
        return asdict(self)


_HEADER_RULES: list[tuple[str, str, str, str]] = [
    # (header, regex, technology, rule id) — group 1 = version when present
    ("server", r"^nginx(?:/([\d.]+))?", "nginx", "hdr-server-nginx"),
    ("server", r"^Apache(?:/([\d.]+))?", "Apache HTTP Server", "hdr-server-apache"),
    ("server", r"^Microsoft-IIS(?:/([\d.]+))?", "Microsoft IIS", "hdr-server-iis"),
    ("server", r"^cloudflare", "Cloudflare", "hdr-server-cloudflare"),
    ("server", r"^LiteSpeed", "LiteSpeed", "hdr-server-litespeed"),
    ("server", r"^Caddy", "Caddy", "hdr-server-caddy"),
    ("server", r"^openresty(?:/([\d.]+))?", "OpenResty", "hdr-server-openresty"),
    ("x-powered-by", r"PHP(?:/([\d.]+))?", "PHP", "hdr-xpb-php"),
    ("x-powered-by", r"ASP\.NET", "ASP.NET", "hdr-xpb-aspnet"),
    ("x-powered-by", r"Express", "Express", "hdr-xpb-express"),
    ("x-powered-by", r"Next\.js(?:\s+([\d.]+))?", "Next.js", "hdr-xpb-nextjs"),
    ("x-aspnet-version", r"([\d.]+)", "ASP.NET", "hdr-aspnet-version"),
    ("x-generator", r"Drupal(?:\s+([\d.]+))?", "Drupal", "hdr-generator-drupal"),
    ("via", r"varnish", "Varnish", "hdr-via-varnish"),
    ("x-amz-cf-id", r".", "Amazon CloudFront", "hdr-cloudfront"),
    ("x-vercel-id", r".", "Vercel", "hdr-vercel"),
]

_COOKIE_RULES: list[tuple[str, str, str]] = [
    ("PHPSESSID", "PHP", "cookie-phpsessid"),
    ("JSESSIONID", "Java servlet container", "cookie-jsessionid"),
    ("ASP.NET_SessionId", "ASP.NET", "cookie-aspnet"),
    ("laravel_session", "Laravel", "cookie-laravel"),
    ("wordpress_", "WordPress", "cookie-wordpress"),
]

_BODY_RULES: list[tuple[str, str, str]] = [
    (
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)?',
        "WordPress",
        "body-generator-wordpress",
    ),
    (
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal\s*([\d.]+)?',
        "Drupal",
        "body-generator-drupal",
    ),
    (
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla',
        "Joomla",
        "body-generator-joomla",
    ),
    (r"/wp-content/|/wp-includes/", "WordPress", "body-path-wordpress"),
    (r'<script[^>]+id=["\']__NEXT_DATA__', "Next.js", "body-nextdata"),
    (r"data-reactroot|__REACT_DEVTOOLS", "React", "body-react"),
]

TITLE = re.compile(rb"<title[^>]*>(.{0,300}?)</title>", re.IGNORECASE | re.DOTALL)


def fingerprint(headers: list[tuple[str, str]], body: bytes) -> list[Technology]:
    found: dict[tuple[str, str], Technology] = {}

    def add(t: Technology) -> None:
        key = (t.name, t.rule_id)
        if key not in found:
            found[key] = t

    lowered = [(k.lower(), v) for k, v in headers]
    for header, pattern, name, rule in _HEADER_RULES:
        for k, v in lowered:
            if k == header and (m := re.search(pattern, v, re.IGNORECASE)):
                version = m.group(1) if m.groups() and m.group(1) else None
                add(Technology(name, version, rule, "high", f"{k}: {v}"[:200]))
    cookies = " ".join(v for k, v in lowered if k == "set-cookie")
    for prefix, name, rule in _COOKIE_RULES:
        if re.search(rf"(?:^|[\s,;]){re.escape(prefix)}", cookies):
            add(Technology(name, None, rule, "medium", f"set-cookie: {prefix}…"))
    text = body[:MAX_SCAN].decode("utf-8", errors="replace")
    for pattern, name, rule in _BODY_RULES:
        if m := re.search(pattern, text, re.IGNORECASE):
            version = m.group(1) if m.groups() and m.group(1) else None
            add(Technology(name, version, rule, "medium", m.group(0)[:200]))
    return sorted(found.values(), key=lambda t: (t.name, t.rule_id))


MAX_SCAN = 256 * 1024


def page_title(body: bytes) -> str | None:
    m = TITLE.search(body[:MAX_SCAN])
    if not m:
        return None
    return " ".join(m.group(1).decode("utf-8", errors="replace").split())[:200] or None
