"""Live SHIELD phase 2 safeguard validation: a real CrowdSec LAPI and nftables firewall bouncer, the
real janus_sensor code and the real API. Opt-in (JANUS_LIVE_VALIDATION=1), as root, on a machine
whose CrowdSec uses the janus_alert profile (infra/janus-sensor/README.md). It replays a synthetic
sshd log with TEST-NET addresses through crowdsec and leaves no janus: bans behind. Run with -s to
see the EVIDENCE lines; docs/reviews/2026-11-17-shield-phase2-safeguards.md records a run."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from tests.conftest import Factory, audit_actions
from tests.test_janus_sensor import ApiJanus, js
from tests.test_shield_guard import _authorize, _register, _sensor, _ws

pytestmark = pytest.mark.skipif(
    os.environ.get("JANUS_LIVE_VALIDATION") != "1", reason="live CrowdSec validation is opt-in"
)


def sh(*a: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed test commands
        a, capture_output=True, text=True, check=False
    ).stdout


def replay(log: Path, ip: str, minute: int) -> None:
    line = "labhost sshd[99]: Failed password for root from {ip} port 5{i}22 ssh2\n"
    log.write_text("".join(
        f"Nov 17 23:{minute:02d}:{i:02d} " + line.format(ip=ip, i=i)
        for i in range(1, 9)
    ))  # fmt: skip
    sh(
        "crowdsec",
        "-c",
        "/etc/crowdsec/config.yaml",
        "-dsn",
        f"file://{log}",
        "-type",
        "syslog",
        "-no-api",
    )
    time.sleep(2)


def decisions(ip: str) -> list[tuple[str, str]]:
    out = json.loads(sh("cscli", "decisions", "list", "-i", ip, "-o", "json") or "null") or []
    return [(d["type"], d["scenario"]) for a in out for d in a["decisions"] if d["value"] == ip]


def in_nft(ip: str) -> bool:
    rev = ".".join(reversed(ip.split(".")))  # Ubuntu's bouncer 0.0.25 writes bytes reversed
    rules = sh("nft", "list", "ruleset")
    return f"{ip} " in rules or f"{rev} " in rules


def wait_nft(ip: str, present: bool) -> bool:
    for _ in range(20):
        if in_nft(ip) == present:
            return True
        time.sleep(1)
    return False


def test_live(client: TestClient, factory: Factory, owner_db: Session, tmp_path: Path) -> None:
    ev = print
    _, base = _ws(client, factory)
    sid, key = _register(client, base, "lab-host")
    _authorize(
        client, base, [sid], default_block_seconds=900, max_block_seconds=3600, per_hour_cap=2
    )
    client.post(f"{base}/allowlist", json={"cidr": "198.51.100.0/24", "note": "owner"})
    cfg = js.Config(url="http://localhost", key=key, cscli=["cscli"],
                    allowlist=[js.ipaddress.ip_network("192.0.2.0/24")],
                    state_path=str(tmp_path / "s.json"))  # fmt: skip
    cs = js.Cscli(["cscli"])
    replay(tmp_path / "auth.log", "203.0.113.90", 1)
    replay(tmp_path / "auth.log", "198.51.100.30", 2)  # JANUS allow list
    with _sensor(key) as http:
        janus = ApiJanus(cfg, http)

        def cycle() -> dict[str, int]:
            st = js.State.load(cfg.state_path)
            r = js.cycle(cfg, janus, cs, st)
            st.save(cfg.state_path)
            return dict(r)

        # Only alerts from this run: drop older ones from the replay history.
        st = js.State(seen=[a["id"] for a in cs.alerts_since("2h")
                            if "203.0.113.90" not in json.dumps(a["source"])
                            and "198.51.100.30" not in json.dumps(a["source"])])  # fmt: skip
        st.save(cfg.state_path)
        ev("EVIDENCE cycle1", cycle())
        view = client.get(f"{base}/intrusion").json()
        for a in view["alerts"]:
            ev(
                "EVIDENCE alert",
                a["scenario"],
                a["category"],
                a["source"],
                a["count"],
                a["block_ids"],
            )
        b90 = next(b for b in view["blocks"] if b["target"] == "203.0.113.90/32")
        ev("EVIDENCE block .90", b90["tier"], b90["status"], b90["expires_at"])
        assert b90["status"] == "active"
        assert ("ban", f"janus:{b90['id']}") in decisions("203.0.113.90")
        ev("EVIDENCE crowdsec .90", decisions("203.0.113.90"))
        assert wait_nft("203.0.113.90", True)
        ev("EVIDENCE nft has .90:", in_nft("203.0.113.90"))
        assert not any(b["target"].startswith("198.51.100.30") for b in view["blocks"])
        assert not any(t == "ban" and s.startswith("janus:") for t, s in decisions("198.51.100.30"))
        assert not in_nft("198.51.100.30")
        ev("EVIDENCE .30 (JANUS allow list): no block, crowdsec", decisions("198.51.100.30"))

        # Cap of 2 per hour: .90 used one; .91 gets the second; .92 is over the cap.
        replay(tmp_path / "auth.log", "203.0.113.91", 3)
        replay(tmp_path / "auth.log", "203.0.113.92", 4)
        ev("EVIDENCE cycle2", cycle())
        targets = {b["target"] for b in client.get(f"{base}/intrusion").json()["blocks"]}
        ev("EVIDENCE blocks after cap", sorted(targets))
        second = targets & {"203.0.113.91/32", "203.0.113.92/32"}
        assert len(targets) == 2 and len(second) == 1  # cap of 2: exactly one of them

        # Kill switch.
        client.post(f"{base}/response/pause", json={"reason": "validation"})
        owner_db.execute(text("DELETE FROM shield_blocks WHERE target = :t"), {"t": second.pop()})
        owner_db.commit()  # free a cap slot so only the kill switch can stop the next one
        replay(tmp_path / "auth.log", "203.0.113.93", 5)
        ev("EVIDENCE cycle3 paused", cycle())
        targets = {b["target"] for b in client.get(f"{base}/intrusion").json()["blocks"]}
        assert "203.0.113.93/32" not in targets and not in_nft("203.0.113.93")
        client.post(f"{base}/response/resume")

        # Local allow list on the sensor refuses an approved block JANUS sends.
        r = client.post(f"{base}/blocks", json={"target": "192.0.2.10", "sensor_ids": [sid],
                                                "reason": "validation"})  # fmt: skip
        assert r.status_code == 201
        ev("EVIDENCE cycle4 local allow list", cycle())
        assert decisions("192.0.2.10") == [] and not in_nft("192.0.2.10")
        assert "shield.sensor.block_refused" in audit_actions(owner_db)

        # Lift .90: only JANUS's decision goes; CrowdSec's own janus_alert record stays.
        before = decisions("203.0.113.90")
        client.post(f"{base}/blocks/{b90['id']}/lift", json={"reason": "validation"})
        ev("EVIDENCE cycle5 lift", cycle())
        after = decisions("203.0.113.90")
        ev("EVIDENCE .90 decisions before/after lift", before, after)
        assert ("ban", f"janus:{b90['id']}") not in after
        assert [d for d in before if not d[1].startswith("janus:")] == after
        assert wait_nft("203.0.113.90", False)
        ev("EVIDENCE nft has .90 after lift:", in_nft("203.0.113.90"))

    # Revocation: the key stops working; the sensor's one-shot run exits non-zero.
    client.post(f"{base}/sensors/{sid}/revoke", json={"reason": "validation"})
    with _sensor(key) as http:
        assert http.post("/api/sensor/heartbeat", json={}).status_code == 401
    ev("EVIDENCE revoked key -> 401")
    ev("EVIDENCE audit", sorted(set(a for a in audit_actions(owner_db) if a.startswith("shield."))))
