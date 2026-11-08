#!/usr/bin/env python3
"""WARPATH: build the pinned MITRE ATT&CK technique list from an official STIX release.

    git clone --depth 1 --filter=blob:none --sparse https://github.com/mitre-attack/attack-stix-data.git /tmp/a
    (cd /tmp/a && git sparse-checkout set enterprise-attack)
    python3 infra/tools/import_attack.py /tmp/a/enterprise-attack/enterprise-attack-20.0.json \\
        > api/nightfall/warpath/attack.json

Keeps only what WARPATH shows: technique ID, name and tactics, for techniques and
sub-techniques that aren't revoked or deprecated. The release, its date and the source
file's SHA-256 are recorded so the list can be checked against MITRE's file.
ATT&CK is (c) The MITRE Corporation, used under its terms of use; attribution is shown in
the UI. Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(path: Path) -> None:
    raw = path.read_bytes()
    bundle = json.loads(raw)
    coll = next(o for o in bundle["objects"] if o["type"] == "x-mitre-collection")
    out = []
    for o in bundle["objects"]:
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next(
            (r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext or not ext.get("external_id", "").startswith("T"):
            continue
        tactics = sorted(
            p["phase_name"]
            for p in o.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        )
        out.append({"id": ext["external_id"], "name": o["name"], "tactics": tactics})
    out.sort(key=lambda t: [int(x) if x.isdigit() else x for x in t["id"][1:].split(".")])
    doc = {
        "catalogue": "MITRE ATT&CK Enterprise",
        "release": coll.get("x_mitre_version"),
        "released": coll.get("modified"),
        "source_file": path.name,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "attribution": "MITRE ATT&CK® is a registered trademark of The MITRE Corporation; "
        "used under the ATT&CK terms of use (https://attack.mitre.org/resources/legal-and-branding/).",
        "techniques": out,
    }
    head = {k: v for k, v in doc.items() if k != "techniques"}
    text = json.dumps(head, indent=1, ensure_ascii=False)[:-2] + ',\n "techniques": [\n'
    text += ",\n".join("  " + json.dumps(t, ensure_ascii=False, separators=(",", ":")) for t in out)
    sys.stdout.write(text + "\n ]\n}\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
