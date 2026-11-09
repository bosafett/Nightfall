#!/usr/bin/env python3
"""Lab tool pack 1: build the reviewed manifest from a pinned nuclei-templates release.

    git clone --depth 1 --branch v10.5.1 https://github.com/projectdiscovery/nuclei-templates.git /tmp/nt
    python3 infra/tools/import_nuclei_pack.py /tmp/nt > api/nightfall/tools/nuclei/pack1.json

Needs PyYAML (development only; the API and workers never parse templates). The output is
committed and reviewed: adding or removing a template is a code change. The design and its
rules are in docs/designs/2026-11-lab-tool-pack-1.md.

Rules (v1). A template is kept only if all of these hold:
  * HTTP protocol only (`http:` or the older `requests:`), with no other protocol section,
    no `flow:` (JavaScript control flow), no `workflows:` and not `self-contained` (those send
    to fixed hosts, not the target).
  * Tagged cve, misconfig, exposure, default-login, takeover or tech, and not tagged dos,
    fuzz, fuzzing, intrusive, bruteforce or osint.
  * No out-of-band interaction (interactsh / oast), no `fuzzing:` section (DAST), no random
    generated values (`{{rand_...}}`), and only GET, HEAD, POST or OPTIONS requests (rules/2:
    PURGE, PUT, DELETE, PATCH and any other method are dropped).
  * rules/2: no request whose target names a state-changing action (delete, purge, remove,
    reset, truncate, wipe, destroy, drop, uninstall, shutdown, reboot, restart, kill, clear,
    register, signup, logout), and no POST whose target names a write (update, create,
    upload, insert, save, install, import, write, edit, add, new, set). Some templates confirm
    a weakness by performing the action (e.g. purging an app's logs, resetting a WordPress
    site); the rule is deliberately broad, and also drops some harmless templates. It can't
    prove a template changes nothing: see the design, section 13.
  * Has an id, a name and a known severity.
Network (TCP) templates aren't kept in v1: the per-run egress proxy carries HTTP only.

Groups: a run may use at most 3,000 templates (owner decision 4), so the pack is run in
three groups, each its own tool and playbook step: cve; exposure, misconfig, takeover and
default-login ("config"); and tech.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

RULES_VERSION = "lab-pack1-rules/2"
KEEP_TAGS = {"cve", "misconfig", "exposure", "default-login", "takeover", "tech"}
DROP_TAGS = {"dos", "fuzz", "fuzzing", "intrusive", "bruteforce", "osint"}
OTHER_PROTOCOLS = {
    "dns", "file", "tcp", "network", "headless", "ssl", "websocket", "whois", "code",
    "javascript", "flow", "workflows",
}  # fmt: skip
SEVERITIES = {"info", "low", "medium", "high", "critical"}
# rules/2: random values anywhere, including nested calls such as {{to_lower(rand_text_alpha(5))}}.
BAD_TEXT = re.compile(r"interactsh|\boast\b|\{\{\s*rand_|rand_(text|int|base|char|ip|str)", re.IGNORECASE)
BAD_METHOD = re.compile(r"(?m)(^\s*method:\s*(PUT|DELETE|PATCH)\b|^\s*-?\s*\|?\s*(PUT|DELETE|PATCH) /)")
OK_METHODS = {"GET", "HEAD", "POST", "OPTIONS"}
REQUEST_LINE = re.compile(r"^\s*([A-Za-z]+)\s+(\S+)\s+HTTP/")
STATE_CHANGING = re.compile(
    r"(?i)delete|purge|remove|reset|truncate|wipe|destroy|drop|uninstall|shutdown|reboot"
    r"|restart|kill|clear|register|signup|logout"
)
# A POST naming a write action is dropped too (a GET with these words is usually a page view).
WRITES = re.compile(
    r"(?i)update|create|upload|insert|save|install|import|write|edit|add|new|set"
)


def requests_of(doc: dict) -> list[tuple[str, str]]:
    """(method, target) of every request a template makes, from the parsed template."""
    out: list[tuple[str, str]] = []
    for section in doc.get("http") or doc.get("requests") or []:
        if not isinstance(section, dict):
            continue
        method = str(section.get("method", "GET")).upper()
        out += [(method, str(p)) for p in section.get("path") or [""]]
        for raw in section.get("raw") or []:
            # Skip blank lines and Nuclei annotations (@timeout, @Host, ...) before the request.
            lines = (ln for ln in str(raw).splitlines() if ln.strip())
            first = next((ln for ln in lines if not ln.lstrip().startswith("@")), "")
            m = REQUEST_LINE.match(first)
            out.append((m.group(1).upper(), m.group(2)) if m else ("UNKNOWN", first))
    return out


def tags_of(info: dict) -> set[str]:
    raw = info.get("tags") or ""
    items = raw if isinstance(raw, list) else str(raw).split(",")
    return {str(t).strip().lower() for t in items if str(t).strip()}


def reason_to_drop(doc: object, text: str) -> str | None:
    if not isinstance(doc, dict):
        return "not a template"
    info = doc.get("info")
    if not isinstance(info, dict) or not doc.get("id") or not info.get("name"):
        return "no id or name"
    if str(info.get("severity", "")).lower() not in SEVERITIES:
        return "unknown severity"
    if not ("http" in doc or "requests" in doc):
        return "not HTTP"
    if OTHER_PROTOCOLS & set(doc):
        return "other protocol"
    if doc.get("self-contained"):
        return "self-contained"
    tags = tags_of(info)
    if not tags & KEEP_TAGS:
        return "category"
    if tags & DROP_TAGS:
        return "dropped tag"
    for section in doc.get("http") or doc.get("requests") or []:
        if isinstance(section, dict) and ("fuzzing" in section or section.get("method", "GET")
                                          in ("PUT", "DELETE", "PATCH")):
            return "fuzzing or method"
    if BAD_TEXT.search(text):
        return "out-of-band or random"
    if BAD_METHOD.search(text):
        return "method"
    reqs = requests_of(doc)
    if any(m not in OK_METHODS for m, _ in reqs):
        return "method"
    if any(STATE_CHANGING.search(t) or (m == "POST" and WRITES.search(t)) for m, t in reqs):
        return "state-changing request"
    return None


def main(root: Path) -> None:
    commit = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    tag = subprocess.run(
        ["git", "-C", str(root), "describe", "--tags", "--exact-match"],
        capture_output=True, text=True, check=False,
    ).stdout.strip() or "untagged"  # fmt: skip
    templates: list[dict[str, object]] = []
    dropped: dict[str, int] = {}
    seen: set[str] = set()
    for path in sorted(root.rglob("*.yaml")):
        rel = path.relative_to(root).as_posix()
        if rel.startswith((".", "helpers/", "profiles/", "workflows/")) or "/." in rel:
            continue
        data = path.read_bytes()
        text = data.decode("utf-8", "replace")
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            dropped["unparseable"] = dropped.get("unparseable", 0) + 1
            continue
        why = reason_to_drop(doc, text)
        if why is None and str(doc["id"]) in seen:
            why = "duplicate id"
        if why:
            dropped[why] = dropped.get(why, 0) + 1
            continue
        info = doc["info"]
        tags = tags_of(info)
        cls = info.get("classification") or {}
        cves = cls.get("cve-id") if isinstance(cls, dict) else None
        cves = [cves] if isinstance(cves, str) else [str(c) for c in (cves or [])]
        seen.add(str(doc["id"]))
        templates.append(
            {
                "id": str(doc["id"]),
                "path": rel,
                "sha256": hashlib.sha256(data).hexdigest(),
                "name": str(info["name"])[:200],
                "severity": str(info["severity"]).lower(),
                "category": next(t for t in ("cve", "default-login", "takeover", "exposure",
                                             "misconfig", "tech") if t in tags),
                "cves": [c.upper() for c in cves if re.fullmatch(r"(?i)cve-\d{4}-\d{4,}", c)],
            }
        )
    manifest = {
        "pack": "lab-pack1",
        "rules": RULES_VERSION,
        "source": "https://github.com/projectdiscovery/nuclei-templates",
        "release": tag,
        "commit": commit,
        "licence": "MIT",
        "counts": {
            "kept": len(templates),
            "by_category": {
                c: sum(1 for t in templates if t["category"] == c)
                for c in sorted({str(t["category"]) for t in templates})
            },
            "dropped": dict(sorted(dropped.items())),
        },
        "templates": templates,
    }
    # One template per line, so a review diff shows exactly which templates changed.
    head = {k: v for k, v in manifest.items() if k != "templates"}
    out = json.dumps(head, indent=1)[:-2] + ',\n "templates": [\n'
    out += ",\n".join("  " + json.dumps(t, separators=(",", ":")) for t in templates)
    sys.stdout.write(out + "\n ]\n}\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
