"""Nuclei adapter: a curated, pinned set of non-intrusive checks (review §13, decision 10).

Only the templates in CATALOG ever run, each passed by explicit path and verified against
its pinned SHA-256 first, so a template can't change or be added without a code review.
They are NIGHTFALL's own: HTTP protocol only, GET only, fixed paths, no payloads, no
fuzzing, no out-of-band callbacks (interactsh off), no redirects followed.

Nuclei's output is untrusted. Only the template id and the matched URL are kept, and only
when the id is in the catalog and the URL's host is the operation target. Titles,
severities and advice come from the catalog, never from the tool's output.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from nightfall.core.db.models import Severity
from nightfall.scope.normalize import NormalizationError
from nightfall.tools.egress import canonical_host

TEMPLATE_DIR = Path(__file__).parent / "templates"
CATALOG_VERSION = "nuclei-catalog/2026.11-1"
USER_AGENT = "JANUS/0.1 (authorized security assessment)"
MAX_MATCHES = 200


@dataclass(frozen=True)
class Check:
    template_id: str
    sha256: str
    check_id: str
    title: str
    severity: Severity
    description: str
    impact: str
    remediation: str


CATALOG: dict[str, Check] = {
    c.template_id: c
    for c in (
        Check(
            "nf-git-head-exposed",
            "8965c294e7c8189681dea94de0fe898c6e619e8198bc6f38fd8660fa80d5a122",
            "web.git-metadata-exposed",
            "Git repository metadata is publicly readable",
            Severity.MEDIUM,
            "/.git/HEAD is served and names a branch. The check read that one file only.",
            "An exposed .git directory usually lets anyone download the site's source code "
            "and history, which often contains credentials.",
            "Block access to /.git (and other dot-directories) in the web server, and don't "
            "deploy the repository directory to the web root.",
        ),
        Check(
            "nf-directory-listing",
            "113e02988f4c51ffaf9fcdb83bef1f13be6f6a6f30c00394430380280f15c957",
            "web.directory-listing",
            "Directory listing enabled on the web root",
            Severity.LOW,
            "The web root returns a server-generated file index.",
            "Visitors can browse files that were never meant to be linked, such as backups.",
            "Turn off automatic indexes (Apache: Options -Indexes; nginx: autoindex off).",
        ),
        Check(
            "nf-apache-server-status",
            "969559189682558ad2e20a00d95fcc9d2c5b00e24d1351cdb47ff3d285563be0",
            "web.apache-server-status",
            "Apache server-status page is public",
            Severity.MEDIUM,
            "/server-status returns the Apache status page.",
            "Shows client addresses, requested URLs (including tokens in query strings) and "
            "server internals.",
            "Restrict /server-status to local or admin addresses, or disable mod_status.",
        ),
        Check(
            "nf-missing-hsts",
            "7af2e308c950bfe7195a3d00e896ba11a33e7a4db95ca518613b7ad28474e40e",
            "http.missing-hsts",
            "HTTPS site does not send Strict-Transport-Security",
            Severity.LOW,
            "The HTTPS response to / has no Strict-Transport-Security header.",
            "Browsers may still try plain HTTP first, which an attacker on the network can "
            "intercept or downgrade.",
            "Send Strict-Transport-Security with a max-age of at least six months once all "
            "subdomains serve HTTPS.",
        ),
    )
}


class TemplateTampered(RuntimeError):
    pass


def template_paths() -> list[str]:
    """Verified paths of every catalog template, in a fixed order."""
    paths: list[str] = []
    for tid in sorted(CATALOG):
        path = TEMPLATE_DIR / f"{tid}.yaml"
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != CATALOG[tid].sha256:
            raise TemplateTampered(f"Template {tid} doesn't match its pinned hash; nothing ran.")
        paths.append(str(path))
    return paths


def build_invocation(binary: str, target: str, proxy_url: str) -> list[str]:
    host = canonical_host(target)  # raises NormalizationError for anything else
    netloc = f"[{host}]" if ":" in host else host
    argv = [binary]
    for p in template_paths():
        argv += ["-t", p]
    argv += [
        "-u", f"https://{netloc}",
        "-u", f"http://{netloc}",
        "-proxy", proxy_url,
        "-pt", "http",  # HTTP protocol templates only
        "-ni",  # no interactsh (out-of-band callbacks to third-party servers)
        "-duc",  # no update checks or template downloads
        "-dr",  # never follow redirects
        "-or", "-ot",  # omit raw requests/responses and template bodies from output
        "-jsonl", "-silent", "-nc",
        "-H", f"User-Agent: {USER_AGENT}",
        "-rl", "5",
        "-c", "2",
        "-bs", "1",
        "-timeout", "10",
        "-retries", "0",
        "-mhe", "5",
    ]  # fmt: skip
    return argv


def redact(argv: list[str], proxy_url: str) -> list[str]:
    return [a.replace(proxy_url, "http://nf:REDACTED@proxy") for a in argv]


def _catalog_lookup(tid: str) -> tuple[str, str] | None:
    c = CATALOG.get(tid)
    return (c.check_id, c.title) if c else None


def parse(
    stdout: bytes,
    target: str,
    lookup: Callable[[str], tuple[str, str] | None] = _catalog_lookup,
) -> tuple[list[dict[str, str]], int]:
    """Matches for the target from listed templates (by default the curated catalog),
    deduplicated. `lookup` gives (check id, title) for a listed template id, or None.
    Returns (matches, rejected lines)."""
    matches: dict[tuple[str, str], dict[str, str]] = {}
    rejected = 0
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            tid = row["template-id"]
            matched_at = str(row["matched-at"])[:500]
            url = urlsplit(matched_at)
            listed = lookup(tid) if isinstance(tid, str) else None
            ok = (
                listed is not None
                and url.scheme in ("http", "https")
                and url.hostname is not None
                and canonical_host(url.hostname) == target
            )
        except (ValueError, KeyError, TypeError, NormalizationError):
            ok = False
        if not ok:
            rejected += 1
            continue
        clean = re.sub(r"[^\x21-\x7e]", "", matched_at)
        assert listed is not None  # noqa: S101 - narrowed by `ok`
        matches.setdefault(
            (tid, url.scheme),
            {
                "template_id": tid,
                "check_id": listed[0],
                "title": listed[1],
                "matched_at": clean,
            },
        )
        if len(matches) >= MAX_MATCHES:
            break
    return sorted(matches.values(), key=lambda m: (m["template_id"], m["matched_at"])), rejected


def engine_version(stderr: bytes) -> str:
    m = re.search(rb"Engine Version:\s*(v[0-9][0-9A-Za-z.\-]{0,30})", stderr)
    return m.group(1).decode() if m else "unknown"
