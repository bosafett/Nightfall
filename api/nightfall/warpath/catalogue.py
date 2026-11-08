"""WARPATH: the pinned ATT&CK catalogue, which techniques each lab playbook may claim, and
the exercise plan format.

A step's technique must be one its playbook's activity actually represents (the reviewed
MAPPING below), so a scorecard can't claim a technique nothing performed. Today's lab
playbooks are discovery and scanning, so v1 exercises cover reconnaissance and probing;
later stages need new reviewed lab playbooks, which then get their own mapping entries.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

ATTACK_FILE = Path(__file__).parent / "attack.json"
MAX_STEPS = 20

# Reviewed mapping: lab playbook -> ATT&CK techniques its activity represents.
MAPPING: dict[str, tuple[str, ...]] = {
    "web-exposure-audit": ("T1595.002", "T1595.003"),  # vulnerability and wordlist scanning
    "tls-configuration-audit": ("T1595", "T1590"),  # active scanning, network information
    "http-security-assessment": ("T1595", "T1592.002"),  # active scanning, software info
    "known-weakness-scan-lab": ("T1595.002", "T1595.003", "T1592.002"),
}


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]


@cache
def attack() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(ATTACK_FILE.read_text())
    return data


@cache
def techniques() -> dict[str, Technique]:
    return {
        t["id"]: Technique(t["id"], t["name"], tuple(t["tactics"])) for t in attack()["techniques"]
    }


def plan_sha256(plan: list[dict[str, Any]]) -> str:
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def check_mapping() -> None:
    """Fails loudly if the mapping names an unknown playbook, a non-lab playbook or a
    technique missing from the pinned catalogue (run at import and by tests)."""
    from nightfall.blackops.catalog import PLAYBOOKS, Profile

    for pid, techs in MAPPING.items():
        p = PLAYBOOKS.get(pid)
        if p is None or Profile.LAB not in p.profiles:
            raise ValueError(f"WARPATH mapping: {pid} isn't a lab playbook")
        for t in techs:
            if t not in techniques():
                raise ValueError(f"WARPATH mapping: {t} isn't in ATT&CK {attack()['release']}")
