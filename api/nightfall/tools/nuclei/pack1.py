"""Lab tool pack 1 (docs/designs/2026-11-lab-tool-pack-1.md): a rule-filtered, pinned
subset of the public nuclei-templates release, for the isolated lab only (moderate risk).

  * pack1.json is the reviewed manifest made by infra/tools/import_nuclei_pack.py: one
    entry per template with its path and SHA-256. The templates themselves are only in the
    lab tool image (NIGHTFALL_LAB_PACK1_DIR), never in the API package.
  * Before every run each template of the group is read and checked against its hash;
    one mismatch or missing file and nothing runs.
  * Three groups, each at most 3,000 templates per run (owner decision 4): cve; config
    (exposure, misconfiguration, takeover and default-login); tech.
  * Off unless BLACKSITE is enabled and NIGHTFALL_LAB_PACK1_REVIEW_REF names the recorded
    independent review of this pack (checked by the API's preflight and again by the
    worker before it runs).
  * Output is untrusted, as for the curated checks: only listed template ids matched on the
    target are kept, and titles and severities come from the manifest.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from nightfall.config import Settings
from nightfall.core.db.models import Severity
from nightfall.tools.egress import canonical_host
from nightfall.tools.nuclei import USER_AGENT, TemplateTampered

MANIFEST = Path(__file__).parent / "pack1.json"
GROUPS: dict[str, tuple[str, ...]] = {
    "cve": ("cve",),
    "config": ("exposure", "misconfig", "takeover", "default-login"),
    "tech": ("tech",),
}
TOOL_PREFIX = "nuclei-pack1-"
MAX_TEMPLATES = 3000
TIMEOUT_S = 1800.0  # 30 minutes per run (owner decision 4)
RATE = "10"  # requests per second
CONCURRENCY = "10"  # templates at once


@dataclass(frozen=True)
class Template:
    id: str
    path: str
    sha256: str
    name: str
    severity: Severity
    category: str
    cves: tuple[str, ...]


@cache
def manifest() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(MANIFEST.read_text())
    return data


@cache
def templates() -> dict[str, Template]:
    return {
        t["id"]: Template(
            id=t["id"],
            path=t["path"],
            sha256=t["sha256"],
            name=t["name"],
            severity=Severity(t["severity"]),
            category=t["category"],
            cves=tuple(t["cves"]),
        )
        for t in manifest()["templates"]
    }


def version() -> str:
    m = manifest()
    return f"lab-pack1/{m['release']}@{m['commit'][:12]}"


def group_of(tool: str) -> str:
    group = tool.removeprefix(TOOL_PREFIX)
    if not tool.startswith(TOOL_PREFIX) or group not in GROUPS:
        raise KeyError(tool)
    return group


def group_templates(group: str) -> list[Template]:
    cats = GROUPS[group]
    return sorted((t for t in templates().values() if t.category in cats), key=lambda t: t.id)


def unavailable_reason(s: Settings) -> str | None:
    """Why the pack can't run here, or None. Same answer for the API and the worker."""
    if not s.blacksite_enabled:
        return "BLACKSITE is off on this deployment."
    from nightfall.control.reviews import review
    from nightfall.core.clock import utcnow

    r = review(s.lab_pack1_review_ref, s, utcnow(), "Lab tool pack 1")
    if not r.ok:
        return f"{r.problem} (NIGHTFALL_LAB_PACK1_REVIEW_REF)"
    return None


def verified_paths(root: Path, group: str) -> list[str]:
    """Absolute paths of the group's templates, each checked against its pinned hash."""
    paths: list[str] = []
    base = root.resolve()
    for t in group_templates(group):
        path = (base / t.path).resolve()
        if base not in path.parents:
            raise TemplateTampered(f"Template {t.id} points outside the pack; nothing ran.")
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise TemplateTampered(f"Template {t.id} is missing; nothing ran.") from exc
        if digest != t.sha256:
            raise TemplateTampered(f"Template {t.id} doesn't match its pinned hash; nothing ran.")
        paths.append(str(path))
    if not paths or len(paths) > MAX_TEMPLATES:
        raise TemplateTampered(f"Group {group} has {len(paths)} templates; 1 to {MAX_TEMPLATES}.")
    return paths


def build_invocation(binary: str, target: str, proxy_url: str, paths: list[str]) -> list[str]:
    host = canonical_host(target)  # raises NormalizationError for anything else
    netloc = f"[{host}]" if ":" in host else host
    argv = [binary]
    for p in paths:
        argv += ["-t", p]
    argv += [
        "-u", f"https://{netloc}",
        "-u", f"http://{netloc}",
        "-proxy", proxy_url,
        "-pt", "http",  # HTTP protocol templates only (the proxy carries HTTP only)
        "-ni",  # no interactsh (out-of-band callbacks)
        "-duc",  # no update checks or template downloads
        "-dr",  # never follow redirects
        "-or", "-ot",  # omit raw requests/responses and template bodies from output
        "-jsonl", "-silent", "-nc",
        "-H", f"User-Agent: {USER_AGENT}",
        "-rl", RATE,
        "-c", CONCURRENCY,
        "-bs", "1",
        "-timeout", "10",
        "-retries", "0",
        "-mhe", "30",
    ]  # fmt: skip
    return argv


def lookup(tid: str) -> tuple[str, str] | None:
    t = templates().get(tid)
    return (f"lab-pack1.{t.id}", t.name) if t else None
