"""SHIELD v4 step 4a: host state from the osquery module (migration 0026).

API: snapshots, baseline, diffs into the change log, column allow-list, late snapshots, isolation,
retention. Sensor: reading osquery's results log (real line format), rotation and partial lines,
merging query variants, hashing persistence commands. Pack: every query is known to the sensor,
returns only columns the API keeps, and parses as SQL against stub tables of the columns it uses."""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.shield import host as H
from tests.conftest import Factory, audit_actions
from tests.test_janus_sensor import ApiJanus, js
from tests.test_shield_guard import _register, _sensor, _ws

PACK = Path(__file__).resolve().parents[2] / "infra" / "janus-sensor" / "osquery" / "janus.conf"


def _at(minutes_ago: int) -> str:
    return (datetime.now(UTC) - timedelta(minutes=minutes_ago)).isoformat()


def _snap(group: str, items: list[dict[str, Any]], t: str | None = None) -> dict[str, Any]:
    return {"group": group, "observed_at": t or _at(60), "items": items}


def _post(s: TestClient, *snaps: dict[str, Any]) -> list[dict[str, Any]]:
    r = s.post("/api/sensor/host", json={"snapshots": list(snaps)})
    assert r.status_code == 200, r.text
    return list(r.json())


ROOT = {"username": "root", "uid": 0, "shell": "/bin/bash", "directory": "/root"}
EVE = {"username": "eve", "uid": 1001, "shell": "/bin/sh", "directory": "/home/eve"}


def test_baseline_then_diffs(client: TestClient, factory: Factory, owner_db: Session) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    with _sensor(key) as s:
        (r,) = _post(s, _snap("accounts", [ROOT]))
        assert r == {
            "group": "accounts",
            "item_count": 1,
            "added": 0,
            "removed": 0,
            "changed": 0,
            "baseline": True,
        }
        (r,) = _post(s, _snap("accounts", [ROOT, EVE], _at(50)))
        assert (r["added"], r["removed"]) == (1, 0)
        (r,) = _post(s, _snap("accounts", [EVE], _at(40)))
        assert (r["added"], r["removed"]) == (0, 1)
        # A snapshot older than the current state changes nothing.
        (r,) = _post(s, _snap("accounts", [], _at(120)))
        assert (r["added"], r["removed"], r["item_count"]) == (0, 0, 1)
    view = client.get(f"{base}/sensors/{sid}/host").json()
    assert [g["group"] for g in view["groups"]] == ["accounts"]
    assert view["groups"][0]["items"] == [EVE]
    assert [(c["action"], c["item"]["username"]) for c in view["changes"]] == [
        ("removed", "root"), ("added", "eve"),
    ]  # fmt: skip
    assert view["retention_days"] == 90
    assert "shield.sensor.host" in audit_actions(owner_db)


def test_only_known_columns_are_kept(client: TestClient, factory: Factory) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    with _sensor(key) as s:
        _post(s, _snap("persistence", [{"kind": "cron", "name": "x", "path": "/etc/crontab",
                                        "command_sha256": "ab", "command": "curl -u admin:pw ...",
                                        "nested": {"a": 1}}]))  # fmt: skip
        _post(s, _snap("listeners", [{"process": "p" * 900, "path": "/bin/p", "address": "0.0.0.0",  # noqa: S104 - data, not a bind
                                      "port": 22, "protocol": "tcp"}]))  # fmt: skip
    view = client.get(f"{base}/sensors/{sid}/host").json()
    groups = {g["group"]: g["items"] for g in view["groups"]}
    assert groups["persistence"] == [{"kind": "cron", "name": "x", "path": "/etc/crontab",
                                      "command_sha256": "ab"}]  # fmt: skip
    assert len(groups["listeners"][0]["process"]) == H.MAX_VALUE


def test_posture_and_limits(client: TestClient, factory: Factory) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    with _sensor(key) as s:
        _post(s, _snap("posture", [
            {"check": "firewall", "ok": 1, "detail": "Good"},
            {"check": "disk_encryption", "ok": 0, "detail": "BitLocker: 1 volume(s)"},
            {"check": "os_version", "ok": None, "detail": "Ubuntu 24.04"},
        ]))  # fmt: skip
        dup = {"snapshots": [_snap("accounts", []), _snap("accounts", [])]}
        assert s.post("/api/sensor/host", json=dup).status_code == 422
        bad = {"snapshots": [_snap("passwords", [])]}
        assert s.post("/api/sensor/host", json=bad).status_code == 422
        big = {"snapshots": [_snap("software", [{"name": "x"}] * 5001)]}
        assert s.post("/api/sensor/host", json=big).status_code == 422
    posture = client.get(f"{base}/sensors/{sid}/host").json()["posture"]
    assert [(p["check"], p["ok"]) for p in posture] == [
        ("firewall", True), ("disk_encryption", False), ("os_version", None),
    ]  # fmt: skip


def test_isolation_and_revocation(client: TestClient, factory: Factory) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    _, base2 = _ws(client, factory)
    assert client.get(f"{base2}/sensors/{sid}/host").status_code == 404
    _, base = _ws(client, factory)  # back to a fresh owner of another workspace
    with TestClient(client.app) as anon:
        assert (
            anon.post("/api/sensor/host", json={"snapshots": [_snap("accounts", [])]}).status_code
            == 401
        )


def test_retention_and_append_only(
    client: TestClient, factory: Factory, owner_db: Session, app_engine: Any
) -> None:
    owner, base = _ws(client, factory)
    sid, key = _register(client, base)
    with _sensor(key) as s:
        _post(s, _snap("accounts", [ROOT]))
        _post(s, _snap("accounts", [ROOT, EVE], _at(50)))
    owner_db.execute(
        text("UPDATE shield_host_changes SET ingested_at = now() - interval '91 days'")
    )
    owner_db.commit()
    with _sensor(key) as s:
        _post(s, _snap("accounts", [EVE], _at(40)))  # removes root; purges the old row
    left = owner_db.execute(text("SELECT action FROM shield_host_changes")).scalars().all()
    assert left == ["removed"]
    with app_engine.connect() as conn:
        conn.execute(
            text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(owner.workspace_id)}
        )
        with pytest.raises(DBAPIError):
            conn.execute(text("DELETE FROM shield_host_changes"))
        conn.rollback()


# --- Sensor module ---------------------------------------------------------------------------


def _line(name: str, rows: list[dict[str, Any]], t: int) -> str:
    """osquery's filesystem logger, snapshot mode: one JSON object per line."""
    return json.dumps({"snapshot": rows, "action": "snapshot", "name": name,
                       "hostIdentifier": "labhost", "calendarTime": "Thu Nov 19 10:00:00 2026 UTC",
                       "unixTime": t, "epoch": 0, "counter": 0,
                       "numerics": False}) + "\n"  # fmt: skip


def test_sensor_reads_results_log(tmp_path: Path) -> None:
    log = tmp_path / "osqueryd.results.log"
    st = js.State()
    log.write_text(
        _line("pack_janus_janus_accounts", [ROOT], 100)  # pack-style name
        + _line("janus_software_deb", [{"name": "openssl", "version": "3.0", "source": "deb"}], 100)
        + _line("janus_software_rpm", [], 100)
        + _line("janus_persistence_linux", [{"kind": "cron", "name": "/etc/crontab",
                                             "path": "/etc/crontab", "command": "secret"}], 100)
        + _line("someone_elses_query", [{"x": 1}], 100)
        + '{"partial": '  # no newline yet: not consumed
    )  # fmt: skip
    groups = js.read_osquery(str(log), st)
    assert groups == {"accounts", "software", "persistence"}
    snaps = {s["group"]: s for s in js.host_snapshots(st, groups)}
    assert len(snaps["software"]["items"]) == 1
    cmd = snaps["persistence"]["items"][0]
    assert "command" not in cmd and len(cmd["command_sha256"]) == 64
    # The partial line is read once it's complete; older snapshots don't replace newer ones.
    with log.open("a") as f:
        f.write('"x"}\n' + _line("janus_accounts", [ROOT, EVE], 90))
    assert js.read_osquery(str(log), st) == set()
    # Rotation: a new file is read from the start.
    log.unlink()
    log.write_text(_line("janus_accounts", [EVE], 200))
    assert js.read_osquery(str(log), st) == {"accounts"}
    assert js.host_snapshots(st, {"accounts"})[0]["items"] == [EVE]


def test_sensor_osquery_cycle_end_to_end(
    client: TestClient, factory: Factory, tmp_path: Path
) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    log = tmp_path / "results.log"
    log.write_text(_line("janus_accounts", [ROOT], 100))
    cfg = js.Config(url="http://localhost", key=key, cscli=["cscli"], allowlist=[],
                    state_path=str(tmp_path / "s.json"), modules=("osquery",),
                    osquery_results=str(log))  # fmt: skip
    with _sensor(key) as http:
        janus = ApiJanus(cfg, http)
        st = js.State()
        assert js.cycle(cfg, janus, js.Cscli(["false"]), st) == {"host_groups": 1}
        with log.open("a") as f:
            f.write(_line("janus_accounts", [ROOT, EVE], 200))
        assert js.cycle(cfg, janus, js.Cscli(["false"]), st) == {"host_groups": 1}
        assert js.cycle(cfg, janus, js.Cscli(["false"]), st) == {"host_groups": 0}
    changes = client.get(f"{base}/sensors/{sid}/host").json()["changes"]
    assert [(c["action"], c["item"]["username"]) for c in changes] == [("added", "eve")]


def test_sensor_config_needs_results_path() -> None:
    env = {
        "JANUS_URL": "http://localhost",
        "JANUS_SENSOR_KEY": "nfs_x",
        "JANUS_SENSOR_MODULES": "osquery",
    }
    with pytest.raises(SystemExit):
        js.Config.from_env(env)
    with pytest.raises(SystemExit):
        js.Config.from_env({**env, "JANUS_SENSOR_MODULES": "crowdsec,shell"})


# --- The fixed pack --------------------------------------------------------------------------

# Columns of the osquery tables the pack reads (from osquery's schema), enough to parse each query.
STUB_TABLES = {
    "users": "uid, gid, username, description, directory, shell, uuid, type",
    "groups": "gid, groupname",
    "user_groups": "uid, gid",
    "authorized_keys": "uid, algorithm, key, options, comment, key_file",
    "listening_ports": "pid, port, protocol, family, address, fd, socket, path",
    "processes": "pid, name, path, cmdline",
    "systemd_units": (
        "id, description, load_state, active_state, sub_state, unit_file_state, fragment_path"
    ),
    "crontab": "event, minute, hour, day_of_month, month, day_of_week, command, path",
    "kernel_modules": "name, size, used_by, status, address",
    "services": "name, service_type, display_name, status, pid, start_type, path, module_path",
    "scheduled_tasks": "name, action, path, enabled, state, hidden",
    "startup_items": "name, path, args, type, source, status, username",
    "deb_packages": "name, version, source, arch",
    "rpm_packages": "name, version, release, source, arch",
    "programs": "name, version, install_location, publisher",
    "disk_encryption": "name, uuid, encrypted, type",
    "iptables": "filter_name, chain, policy, target, protocol",
    "os_version": "name, version, major, minor, platform",
    "windows_security_center": "firewall, autoupdate, antivirus, antispyware, internet_settings",
    "hash": "path, directory, md5, sha1, sha256",
    "bitlocker_info": "device_id, drive_letter, protection_status, conversion_status",
}


def _pack() -> dict[str, Any]:
    return dict(json.loads(PACK.read_text())["schedule"])


def test_pack_matches_the_sensor_and_the_api() -> None:
    pack = _pack()
    assert set(pack) == set(js.OSQUERY_GROUPS)
    for name, q in pack.items():
        assert q["snapshot"] is True, name  # one mechanism: snapshots, diffed by JANUS
        assert js.OSQUERY_GROUPS[name] in H.COLUMNS
    opts = json.loads(PACK.read_text())["options"]
    assert opts["disable_distributed"] is True and opts["disable_extensions"] is True


@pytest.mark.parametrize("name", sorted(json.loads(PACK.read_text())["schedule"]))
def test_pack_query_parses_and_returns_kept_columns(name: str) -> None:
    db = sqlite3.connect(":memory:")
    for table, cols in STUB_TABLES.items():
        db.execute(f"CREATE TABLE {table} ({cols})")
    cur = db.execute(_pack()[name]["query"])
    returned = {d[0] for d in cur.description}
    group = js.OSQUERY_GROUPS[name]
    kept = set(H.COLUMNS[group]) | ({"command"} if group == "persistence" else set())
    assert returned <= kept, (name, returned - kept)
    assert not re.search(r"\bcmdline\b|\benviron", _pack()[name]["query"])  # data minimization


# --- Step 4b: host alerts, file integrity, value changes ----------------------------------------


def _host_alerts(client: TestClient, base: str, sid: str) -> list[dict[str, Any]]:
    return list(client.get(f"{base}/sensors/{sid}/host").json()["alerts"])


def test_host_alert_rules(client: TestClient, factory: Factory) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    fw_ok = {"check": "firewall", "ok": 1, "detail": "Good"}
    passwd = {"path": "/etc/passwd", "sha256": "a" * 64}
    with _sensor(key) as s:
        baseline = [
            _snap(g, items) for g, items in (
                ("accounts", [ROOT]), ("admins", []), ("ssh_keys", []), ("listeners", []),
                ("persistence", []), ("software", []), ("posture", [fw_ok]), ("files", [passwd]),
            )
        ]  # fmt: skip
        _post(s, *baseline)
        assert _host_alerts(client, base, sid) == []  # the baseline raises nothing
        _post(
            s,
            _snap("accounts", [ROOT, EVE], _at(50)),
            _snap("admins", [{"username": "eve", "groupname": "sudo"}], _at(50)),
            _snap("ssh_keys", [{"username": "eve", "key_file": "/home/eve/.ssh/authorized_keys",
                                "algorithm": "ssh-ed25519", "key": "AAAA"}], _at(50)),
            _snap("listeners", [{"process": "nc", "path": "/usr/bin/nc", "address": "0.0.0.0",  # noqa: S104
                                 "port": 4444, "protocol": "tcp"}], _at(50)),
            _snap("persistence", [{"kind": "cron", "name": "/etc/crontab", "path": "/etc/crontab",
                                   "command_sha256": "b" * 64}], _at(50)),
            _snap("software", [{"name": "nmap", "version": "7", "source": "deb"}], _at(50)),
            _snap("posture", [{**fw_ok, "ok": 0, "detail": "0 rules"}], _at(50)),
            _snap("files", [{**passwd, "sha256": "c" * 64},
                            {"path": "/etc/sudoers.d/eve", "sha256": "d" * 64}], _at(50)),
        )  # fmt: skip
        # Posture getting better raises nothing.
        _post(s, _snap("posture", [fw_ok], _at(40)))
    got = sorted((a["category"], a["severity"]) for a in _host_alerts(client, base, sid))
    assert got == [
        ("file_changed", "high"), ("file_changed", "high"), ("new_account", "medium"),
        ("new_admin", "high"), ("new_listener", "medium"), ("new_persistence", "medium"),
        ("new_ssh_key", "high"), ("posture_degraded", "medium"),
    ]  # fmt: skip
    titles = {a["title"] for a in _host_alerts(client, base, sid)}
    assert {"eve added to sudo", "Watched file changed: /etc/passwd",
            "Watched file appeared: /etc/sudoers.d/eve"} <= titles  # fmt: skip
    assert not any(a["possible_compromise"] for a in _host_alerts(client, base, sid))
    changed = [c for c in client.get(f"{base}/sensors/{sid}/host").json()["changes"]
               if c["action"] == "changed" and c["group"] == "files"]  # fmt: skip
    assert changed[0]["previous"]["sha256"] == "a" * 64 and changed[0]["item"]["sha256"] == "c" * 64


def test_possible_compromise_correlation(client: TestClient, factory: Factory) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    with _sensor(key) as s:
        _post(s, _snap("admins", []))
        old = {"scenario": "crowdsecurity/ssh-bf", "source": "203.0.113.5", "events_count": 6,
               "start_at": _at(200), "stop_at": _at(190)}  # fmt: skip
        assert s.post("/api/sensor/alerts", json={"alerts": [old]}).status_code == 200
        _post(s, _snap("admins", [{"username": "a", "groupname": "sudo"}], _at(50)))
        recent = {**old, "source": "203.0.113.6", "start_at": _at(30), "stop_at": _at(25)}
        assert s.post("/api/sensor/alerts", json={"alerts": [recent]}).status_code == 200
        _post(s, _snap("admins", [{"username": "a", "groupname": "sudo"},
                                  {"username": "b", "groupname": "sudo"}], _at(5)))  # fmt: skip
    by_title = {a["title"]: a for a in _host_alerts(client, base, sid)}
    assert by_title["a added to sudo"]["possible_compromise"] is False  # attack >1 h before
    assert by_title["b added to sudo"]["possible_compromise"] is True
    assert by_title["b added to sudo"]["correlated_alert_id"]


def test_host_alert_lifecycle_and_permissions(client: TestClient, factory: Factory) -> None:
    owner, base = _ws(client, factory)
    sid, key = _register(client, base)
    with _sensor(key) as s:
        _post(s, _snap("accounts", [ROOT]))
        _post(s, _snap("accounts", [ROOT, EVE], _at(50)))
    (alert,) = _host_alerts(client, base, sid)
    view = client.get(f"{base}/intrusion").json()
    assert view["host_alerts_open"] == 1 and view["sensors"][0]["open_host_alerts"] == 1
    from nightfall.core.db.models import Role
    from tests.conftest import use

    viewer = factory.sign_in(factory.member(owner.workspace_id, Role.VIEWER))
    use(client, viewer)
    assert client.post(f"{base}/host-alerts/{alert['id']}/acknowledge").status_code == 403
    use(client, owner)
    assert client.post(f"{base}/host-alerts/{alert['id']}/acknowledge").status_code == 204
    assert client.post(f"{base}/host-alerts/{alert['id']}/resolve").status_code == 204
    (alert,) = _host_alerts(client, base, sid)
    assert alert["state"] == "resolved"
    assert client.get(f"{base}/intrusion").json()["host_alerts_open"] == 0
