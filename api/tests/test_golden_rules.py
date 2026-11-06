"""Golden-file tests for the BLACK ICE finding rules (review §14).

Each file in tests/golden/finding_rules/ holds stored observations (what an evidence record
keeps) and the exact findings the rules must produce from them. A rule change that alters
any output fails here until the golden file is updated on purpose:

    NIGHTFALL_UPDATE_GOLDEN=1 pytest tests/test_golden_rules.py   (then review the diff)

Changing a rule's output also means bumping RULESET in finding_rules.py.
"""

import json
import os
from datetime import datetime
from pathlib import Path

import pytest

from nightfall.blackice.finding_rules import RULESET
from nightfall.blackice.replay import drafts_for

GOLDEN = Path(__file__).parent / "golden" / "finding_rules"
CASES = sorted(GOLDEN.glob("*.json"))


def _render(case: dict) -> list[dict]:
    now = datetime.fromisoformat(case["now"])
    return [
        {
            "check_id": d.check_id,
            "rule_id": d.rule_id,
            "title": d.title,
            "severity": d.severity.value,
            "confidence": d.confidence.value,
            "description": d.description,
        }
        for d in drafts_for(case["observations"], now)
    ]


@pytest.mark.parametrize("path", CASES, ids=[p.stem for p in CASES])
def test_rule_output_matches_golden(path: Path) -> None:
    case = json.loads(path.read_text())
    got = _render(case)
    if os.environ.get("NIGHTFALL_UPDATE_GOLDEN") == "1":
        case["ruleset"], case["expected"] = RULESET, got
        path.write_text(json.dumps(case, indent=2) + "\n")
    assert case["ruleset"] == RULESET, "Rules changed: bump the goldens on purpose"
    assert got == case["expected"]


def test_every_rule_has_a_golden_case() -> None:
    covered = {
        e["rule_id"].split(":")[0] for p in CASES for e in json.loads(p.read_text())["expected"]
    }
    assert covered >= {
        "R1-version-disclosure",
        "R2-certificate-not-trusted",
        "R3-no-https",
        "R4-certificate-expired",
        "R5-certificate-expiring",
        "R6-curated-check",
        "R7-legacy-tls-protocol",
        "R8-no-modern-tls",
        "R9-weak-certificate-key",
        "R10-weak-certificate-signature",
        "R11-missing-hsts",
        "R12-hsts-short-max-age",
        "R13-missing-csp",
        "R14-no-framing-protection",
        "R15-cookie-without-secure",
        "R15-cookie-without-httponly",
        "R16-no-https-redirect",
    }
