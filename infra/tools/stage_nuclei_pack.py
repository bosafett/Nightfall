#!/usr/bin/env python3
"""Image build step for lab tool pack 1: copy exactly the templates listed in the reviewed
manifest out of a checkout of the pinned release, refusing on any hash mismatch.

    python3 stage_nuclei_pack.py <checkout> <pack1.json> <out-dir>

Standard library only. The checkout must be at the manifest's commit; anything not listed
is left behind, so the image carries only reviewed templates.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path


def main(checkout: Path, manifest_path: Path, out: Path) -> None:
    manifest = json.loads(manifest_path.read_text())
    head = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    if head != manifest["commit"]:
        sys.exit(f"checkout is at {head}, the manifest pins {manifest['commit']}")
    for t in manifest["templates"]:
        src = (checkout / t["path"]).resolve()
        if checkout.resolve() not in src.parents:
            sys.exit(f"{t['id']}: path leaves the checkout")
        data = src.read_bytes()
        if hashlib.sha256(data).hexdigest() != t["sha256"]:
            sys.exit(f"{t['id']}: hash mismatch")
        dst = out / t["path"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
        dst.chmod(0o644)
    for d in [out, *[p for p in out.rglob("*") if p.is_dir()]]:
        d.chmod(0o755)
    print(f"staged {len(manifest['templates'])} templates from {manifest['release']}")
    shutil.copy(manifest_path, out / "pack1.json")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
