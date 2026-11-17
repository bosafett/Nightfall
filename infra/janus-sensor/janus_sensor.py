#!/usr/bin/env python3
"""janus-sensor: connects a machine's CrowdSec to JANUS SHIELD (design
docs/designs/2026-11-shield-v3-intrusion-detection.md §3-4).

Standard library only; runs next to CrowdSec on a machine the owner runs.

* Outbound only. It calls JANUS over HTTPS with its own key; nothing listens.
* Fixed actions only. It reads CrowdSec alerts, and it adds or deletes one kind of CrowdSec
  decision (a ban of an address or range, for a time, tagged "janus:<block id>"). Every cscli
  call is a fixed argument list (no shell). It takes no other instruction from JANUS.
* It checks every block again before applying it: its own local allow list (so a compromised
  JANUS can't block the owner out), never loopback/link-local/multicast/unspecified/reserved,
  never wider than /16 (IPv4) or /32 (IPv6), and never longer than MAX_BLOCK_SECONDS. A block
  it won't apply is reported back as refused.

Configuration (environment):
  JANUS_URL                  e.g. https://janus.example.com (https required unless localhost)
  JANUS_SENSOR_KEY           the sensor key from JANUS (or JANUS_SENSOR_KEY_FILE)
  JANUS_SENSOR_CSCLI         the cscli command, default "cscli" (e.g. "docker exec crowdsec cscli")
  JANUS_SENSOR_ALLOWLIST     comma-separated addresses/ranges never to block (local, authoritative)
  JANUS_SENSOR_STATE         state file, default /var/lib/janus-sensor/state.json
  JANUS_SENSOR_MAX_BLOCK_SECONDS   default 604800 (7 days)
  JANUS_SENSOR_ONCE          "1": one cycle, then exit (for testing)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

VERSION = "0.1.0"
TAG = "janus:"
MIN_PREFIX = {4: 16, 6: 32}
MAX_BATCH = 100
SEEN_KEEP = 5000
FIRST_LOOKBACK = "1h"  # on a fresh start, alerts from the last hour are sent

log = logging.getLogger("janus-sensor")

Net = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class Config:
    url: str
    key: str
    cscli: list[str]
    allowlist: list[Net]
    state_path: str
    max_block_seconds: int = 7 * 24 * 3600
    once: bool = False

    @classmethod
    def from_env(cls, env: dict[str, str]) -> Config:
        url = env.get("JANUS_URL", "").rstrip("/")
        local = url.startswith(("http://127.0.0.1", "http://localhost"))
        if not url.startswith("https://") and not local:
            raise SystemExit("JANUS_URL must be https:// (http only for localhost).")
        key = env.get("JANUS_SENSOR_KEY", "")
        if not key and env.get("JANUS_SENSOR_KEY_FILE"):
            with open(env["JANUS_SENSOR_KEY_FILE"]) as f:
                key = f.read().strip()
        if not key.startswith("nfs_"):
            raise SystemExit(
                "JANUS_SENSOR_KEY (or JANUS_SENSOR_KEY_FILE) is missing or invalid."
            )
        allow = [
            ipaddress.ip_network(p.strip(), strict=False)
            for p in env.get("JANUS_SENSOR_ALLOWLIST", "").split(",")
            if p.strip()
        ]
        return cls(
            url=url,
            key=key,
            cscli=shlex.split(env.get("JANUS_SENSOR_CSCLI", "cscli")),
            allowlist=allow,
            state_path=env.get(
                "JANUS_SENSOR_STATE", "/var/lib/janus-sensor/state.json"
            ),
            max_block_seconds=int(
                env.get("JANUS_SENSOR_MAX_BLOCK_SECONDS", str(7 * 24 * 3600))
            ),
            once=env.get("JANUS_SENSOR_ONCE") == "1",
        )


# --- State -----------------------------------------------------------------------------------


@dataclass
class State:
    seen: list[int] = field(default_factory=list)  # CrowdSec alert ids already sent
    last_poll: str | None = None  # ISO time of the last successful alert read
    applied: list[str] = field(default_factory=list)  # JANUS block ids applied here

    @classmethod
    def load(cls, path: str) -> State:
        try:
            with open(path) as f:
                d = json.load(f)
            return cls(seen=list(d.get("seen", [])), last_poll=d.get("last_poll"),
                       applied=list(d.get("applied", [])))  # fmt: skip
        except (OSError, ValueError):
            return cls()

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w") as f:
            json.dump({"seen": self.seen[-SEEN_KEEP:], "last_poll": self.last_poll,
                       "applied": self.applied}, f)  # fmt: skip
        os.replace(tmp, path)


# --- JANUS -----------------------------------------------------------------------------------


class Janus:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def call(self, method: str, path: str, body: Any = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            self.cfg.url + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.cfg.key}",
                "Content-Type": "application/json",
                "User-Agent": f"janus-sensor/{VERSION}",
            },
        )
        with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 - fixed scheme check
            return json.loads(r.read() or b"null")


# --- CrowdSec --------------------------------------------------------------------------------


class Cscli:
    def __init__(self, base: list[str]) -> None:
        self.base = base

    def run(self, *args: str) -> str:
        p = subprocess.run(  # noqa: S603 - fixed argument list, no shell
            [*self.base, *args], capture_output=True, text=True, timeout=60, check=False
        )
        if p.returncode != 0:
            raise RuntimeError(
                f"cscli {args[0]} {args[1]} failed: {p.stderr.strip()[:300]}"
            )
        return p.stdout

    def alerts_since(self, since: str) -> list[dict[str, Any]]:
        out = self.run("alerts", "list", "-o", "json", "--since", since, "--limit", "0")
        return list(json.loads(out or "null") or [])

    def add_ban(self, net: Net, seconds: int, block_id: str) -> None:
        flag = "--ip" if net.num_addresses == 1 else "--range"
        value = str(net.network_address) if net.num_addresses == 1 else str(net)
        self.run("decisions", "add", flag, value, "--duration", f"{seconds}s",
                 "--type", "ban", "--reason", TAG + block_id)  # fmt: skip

    def delete_ban(self, net: Net, block_id: str) -> int:
        """Delete only the decisions this sensor added for this block. Returns how many."""
        flag = "-i" if net.num_addresses == 1 else "-r"
        value = str(net.network_address) if net.num_addresses == 1 else str(net)
        out = self.run("decisions", "list", flag, value, "-o", "json")
        ids = [
            str(d["id"])
            for a in (json.loads(out or "null") or [])
            for d in (a.get("decisions") or [])
            if d.get("scenario") == TAG + block_id
        ]
        for i in ids:
            self.run("decisions", "delete", "--id", i)
        return len(ids)


def _time(value: Any) -> str | None:
    """CrowdSec prints ISO (created_at) or '2006-01-02 15:04:05.999 +0000 UTC' (start_at)."""
    if not isinstance(value, str) or not value:
        return None
    v = re.sub(
        r"\.\d+", "", value.removesuffix(" UTC").strip()
    )  # drop fractional seconds
    for fmt in (None, "%Y-%m-%d %H:%M:%S %z"):
        try:
            t = datetime.fromisoformat(v) if fmt is None else datetime.strptime(v, fmt)
        except ValueError:
            continue
        return (t if t.tzinfo else t.replace(tzinfo=UTC)).astimezone(UTC).isoformat()
    return None


def to_janus(alert: dict[str, Any]) -> dict[str, Any] | None:
    """A CrowdSec alert as JANUS's SensorAlertIn, or None to skip it."""
    scenario = str(alert.get("scenario") or "")
    decisions = alert.get("decisions") or []
    if not scenario or scenario.startswith(TAG):
        return None  # our own bans, or nothing to say
    if decisions and all(d.get("origin") == "cscli" for d in decisions):
        return None  # a decision someone added by hand
    src = alert.get("source") or {}
    if src.get("scope") not in ("Ip", "Range"):
        return None
    value = str(src.get("value") or src.get("ip") or "")
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    start = _time(alert.get("start_at")) or _time(alert.get("created_at"))
    if start is None:
        return None
    return {
        "ref": str(alert.get("id", ""))[:64],
        "scenario": scenario[:200],
        "source": value,
        "events_count": max(1, min(int(alert.get("events_count") or 1), 1_000_000)),
        "start_at": start,
        "stop_at": _time(alert.get("stop_at")),
        "simulated": bool(alert.get("simulated")),
        "raw": {
            "message": str(alert.get("message") or "")[:500],
            "country": str(src.get("cn") or "")[:8],
            "as_name": str(src.get("as_name") or "")[:200],
            "machine_id": str(alert.get("machine_id") or "")[:100],
        },
    }


# --- The local check before any block -------------------------------------------------------


def refuse_reason(cfg: Config, target: str, seconds: int) -> str | None:
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return "not an address or range"
    if net.prefixlen < MIN_PREFIX[net.version]:
        return f"wider than /{MIN_PREFIX[net.version]}"
    for attr in (
        "is_loopback",
        "is_unspecified",
        "is_multicast",
        "is_link_local",
        "is_reserved",
    ):
        if getattr(net.network_address, attr) or getattr(net.broadcast_address, attr):
            return f"never-block address ({attr.removeprefix('is_')})"
    if any(net.overlaps(a) for a in cfg.allowlist):
        return "on this machine's local allow list"
    if seconds > cfg.max_block_seconds:
        return f"longer than this sensor allows ({cfg.max_block_seconds}s)"
    return None


# --- One cycle -------------------------------------------------------------------------------


def cycle(cfg: Config, janus: Janus, cs: Cscli, st: State) -> dict[str, int]:
    stats = {"sent": 0, "applied": 0, "removed": 0, "refused": 0}
    janus.call("POST", "/api/sensor/heartbeat", {"agent_version": VERSION})

    # 1. Alerts: everything since the last read (with overlap), minus what was already sent.
    since = FIRST_LOOKBACK
    if st.last_poll:
        age = datetime.now(UTC) - datetime.fromisoformat(st.last_poll)
        since = f"{max(60, int(age.total_seconds()) + 60)}s"
    started = datetime.now(UTC)
    seen = set(st.seen)
    batch: list[dict[str, Any]] = []
    for a in cs.alerts_since(since):
        aid = a.get("id")
        if not isinstance(aid, int) or aid in seen:
            continue
        seen.add(aid)
        st.seen.append(aid)
        if (j := to_janus(a)) is not None:
            batch.append(j)
    for i in range(0, len(batch), MAX_BATCH):
        janus.call("POST", "/api/sensor/alerts", {"alerts": batch[i : i + MAX_BATCH]})
        stats["sent"] += len(batch[i : i + MAX_BATCH])
    st.last_poll = started.isoformat()

    # 2. Decisions: apply new blocks, remove lifted ones, report back.
    d = janus.call("GET", "/api/sensor/decisions")
    applied, removed, refused = [], [], []
    done = set(st.applied)
    for b in d.get("apply", []):
        bid, target, left = str(b["id"]), str(b["target"]), int(b["seconds_left"])
        if b.get("applied") and bid in done:
            continue
        if left <= 0:
            continue
        if why := refuse_reason(cfg, target, left):
            refused.append({"id": bid, "reason": why})
            log.warning("refused block %s of %s: %s", bid, target, why)
            continue
        cs.add_ban(ipaddress.ip_network(target, strict=False), left, bid)
        applied.append(bid)
        done.add(bid)
        log.info("applied block %s: %s for %ss", bid, target, left)
    for b in d.get("remove", []):
        bid, target = str(b["id"]), str(b["target"])
        n = cs.delete_ban(ipaddress.ip_network(target, strict=False), bid)
        removed.append(bid)
        done.discard(bid)
        log.info("removed block %s of %s (%d decision(s))", bid, target, n)
    live = {str(b["id"]) for b in d.get("apply", [])}
    st.applied = [b for b in done if b in live]
    if applied or removed or refused:
        janus.call("POST", "/api/sensor/decisions/report",
                   {"applied": applied, "removed": removed, "refused": refused})  # fmt: skip
    stats.update(applied=len(applied), removed=len(removed), refused=len(refused))
    return stats


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    cfg = Config.from_env(dict(os.environ))
    janus, cs = Janus(cfg), Cscli(cfg.cscli)
    delay, ok = 30, True
    while True:
        st = State.load(cfg.state_path)
        try:
            stats = cycle(cfg, janus, cs, st)
            st.save(cfg.state_path)
            log.info("cycle: %s", stats)
            delay, ok = 30, True
        except urllib.error.HTTPError as exc:
            ok = False
            if exc.code == 401:
                log.error(
                    "JANUS rejected this sensor's key (revoked?). Retrying in 5 minutes."
                )
                delay = 300
            else:
                log.error("JANUS returned %s; retrying.", exc.code)
                delay = min(delay * 2, 300)
        except Exception as exc:  # noqa: BLE001 - keep running; CrowdSec keeps protecting
            ok = False
            log.error("cycle failed: %s", exc)
            delay = min(delay * 2, 300)
        if cfg.once:
            return 0 if ok else 1
        time.sleep(delay)


if __name__ == "__main__":
    sys.exit(main())
