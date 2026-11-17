"""janus-sensor (infra/janus-sensor/janus_sensor.py) against the real API: one cycle sends
CrowdSec alerts, applies the blocks GUARD decided, refuses what its local checks forbid, and
removes a block a person lifted.

CrowdSec is faked by default. With JANUS_SENSOR_REAL_CSCLI=1 the test drives a real local
CrowdSec through cscli instead (its LAPI must be running); that is how it was checked by hand."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import Factory
from tests.test_shield_guard import _authorize, _register, _sensor, _ws

_PATH = Path(__file__).resolve().parents[2] / "infra" / "janus-sensor" / "janus_sensor.py"
_spec = importlib.util.spec_from_file_location("janus_sensor", _PATH)
assert _spec and _spec.loader
js = importlib.util.module_from_spec(_spec)
sys.modules["janus_sensor"] = js
_spec.loader.exec_module(js)

REAL = os.environ.get("JANUS_SENSOR_REAL_CSCLI") == "1"


class FakeCscli(js.Cscli):  # type: ignore[misc,name-defined]
    def __init__(self, alerts: list[dict[str, Any]]) -> None:
        super().__init__(["cscli"])
        self.alerts = alerts
        self.bans: dict[str, tuple[str, int]] = {}  # reason -> (value, seconds)

    def run(self, *args: str) -> str:
        if args[:2] == ("alerts", "list"):
            return json.dumps(self.alerts)
        if args[:2] == ("decisions", "add"):
            a = dict(zip(args[2::2], args[3::2], strict=True))
            value = a.get("--ip") or a["--range"]
            self.bans[a["--reason"]] = (value, int(a["--duration"].removesuffix("s")))
            return ""
        if args[:2] == ("decisions", "list"):
            return json.dumps([{"decisions": [{"id": r, "scenario": r}]} for r in self.bans])
        if args[:2] == ("decisions", "delete"):
            self.bans.pop(args[3], None)
            return ""
        raise AssertionError(args)


class ApiJanus(js.Janus):  # type: ignore[misc,name-defined]
    def __init__(self, cfg: Any, client: TestClient) -> None:
        super().__init__(cfg)
        self.client = client

    def call(self, method: str, path: str, body: Any = None) -> Any:
        r = self.client.request(method, path, json=body)
        assert r.status_code == 200, r.text
        return r.json()


def _crowdsec_alert(aid: int, ip: str, scenario: str = "crowdsecurity/ssh-bf") -> dict[str, Any]:
    return {"id": aid, "scenario": scenario, "events_count": 6, "simulated": False,
            "start_at": "2026-11-17 22:05:07 +0000 UTC", "stop_at": "2026-11-17 22:05:09 +0000 UTC",
            "created_at": "2026-11-17T22:05:09Z", "decisions": [],
            "source": {"scope": "Ip", "value": ip, "ip": ip, "cn": "ZZ"}}  # fmt: skip


def test_to_janus_skips_its_own_and_manual_decisions() -> None:
    assert js.to_janus(_crowdsec_alert(1, "203.0.113.5", "janus:abc")) is None
    manual = {
        **_crowdsec_alert(2, "203.0.113.5", "banned by me"),
        "decisions": [{"origin": "cscli"}],
    }
    assert js.to_janus(manual) is None
    out = js.to_janus(_crowdsec_alert(3, "203.0.113.5"))
    assert out["start_at"] == "2026-11-17T22:05:07+00:00" and out["source"] == "203.0.113.5"


def test_local_refusals() -> None:
    allow = [js.ipaddress.ip_network("198.51.100.0/24")]
    cfg = js.Config(url="http://localhost", key="nfs_x", cscli=["cscli"],
                    allowlist=allow, state_path="/x")  # fmt: skip
    assert js.refuse_reason(cfg, "203.0.113.5/32", 3600) is None
    assert "allow list" in js.refuse_reason(cfg, "198.51.100.9/32", 3600)
    assert "wider" in js.refuse_reason(cfg, "10.0.0.0/8", 3600)
    assert "never-block" in js.refuse_reason(cfg, "127.0.0.1/32", 3600)
    assert "longer" in js.refuse_reason(cfg, "203.0.113.5/32", 8 * 86400)


def test_one_cycle_end_to_end(
    client: TestClient, factory: Factory, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    _authorize(client, base, [sid], default_block_seconds=900)
    # A person-approved block the sensor's own allow list forbids.
    client.post(f"{base}/blocks", json={"target": "198.51.100.9", "sensor_ids": [sid],
                                        "reason": "test"})  # fmt: skip
    cfg = js.Config(url="http://localhost", key=key, cscli=["cscli"],
                    allowlist=[js.ipaddress.ip_network("198.51.100.0/24")],
                    state_path=str(tmp_path / "state.json"))  # fmt: skip
    alerts = [_crowdsec_alert(101, "203.0.113.77"), _crowdsec_alert(102, "203.0.113.78", "x/y")]
    cs = js.Cscli(["cscli"]) if REAL else FakeCscli(alerts)
    if REAL:
        monkeypatch.setattr(cs, "alerts_since", lambda since: alerts)
    with _sensor(key) as http:
        janus = ApiJanus(cfg, http)
        st = js.State.load(cfg.state_path)
        stats = js.cycle(cfg, janus, cs, st)
        st.save(cfg.state_path)
        assert stats == {"sent": 2, "applied": 1, "removed": 0, "refused": 1, "orphans": 0}

        view = client.get(f"{base}/intrusion").json()
        auto = next(b for b in view["blocks"] if b["tier"] == "automatic")
        assert auto["target"] == "203.0.113.77/32" and auto["status"] == "active"
        if not REAL:
            assert cs.bans == {f"janus:{auto['id']}": ("203.0.113.77", pytest.approx(900, abs=5))}

        # Nothing new on the next cycle: alerts already sent, block already applied.
        st = js.State.load(cfg.state_path)
        again = js.cycle(cfg, janus, cs, st)
        st.save(cfg.state_path)
        # A refused block is reported once, not every cycle.
        assert again["sent"] == 0 and again["applied"] == 0 and again["refused"] == 0

        # A person lifts it; the sensor removes exactly its own decision.
        client.post(f"{base}/blocks/{auto['id']}/lift", json={"reason": "false positive"})
        st = js.State.load(cfg.state_path)
        assert js.cycle(cfg, janus, cs, st)["removed"] == 1
        if not REAL:
            assert cs.bans == {}
        # An orphan janus: ban (its block isn't live in JANUS any more) is removed.
        if not REAL:
            cs.bans["janus:00000000-0000-0000-0000-000000000000"] = ("203.0.113.99", 600)
            st = js.State.load(cfg.state_path)
            assert js.cycle(cfg, janus, cs, st)["orphans"] == 1 and cs.bans == {}
    lifted = next(
        b for b in client.get(f"{base}/intrusion").json()["blocks"] if b["id"] == auto["id"]
    )
    assert lifted["status"] == "lifted"
