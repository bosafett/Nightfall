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
  JANUS_SENSOR_MODULES       comma-separated: crowdsec (default), osquery
  JANUS_SENSOR_OSQUERY_RESULTS   osquery's results log (filesystem logger), for the osquery module

The osquery module (SHIELD v4 step 4a) only reads osquery's local results log, written by the
fixed pack in osquery/janus.conf. It sends the latest full snapshot of each group. JANUS sends
no queries back: osquery's remote (distributed) features stay off.
"""

from __future__ import annotations

import hashlib
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
API_APPLY_LIMIT = 1000  # the API lists at most this many live blocks per sensor
FIRST_LOOKBACK = "1h"  # on a fresh start, alerts from the last hour are sent
MAX_READ = 64 * 1024 * 1024  # osquery results read per cycle

# Query name in the fixed pack -> JANUS group. Several queries can feed one group (platform or
# package-manager variants); the sensor merges the latest snapshot of each.
OSQUERY_GROUPS = {
    "janus_accounts": "accounts",
    "janus_admins": "admins",
    "janus_ssh_keys": "ssh_keys",
    "janus_listeners": "listeners",
    "janus_persistence_linux": "persistence",
    "janus_persistence_windows": "persistence",
    "janus_software_deb": "software",
    "janus_software_rpm": "software",
    "janus_software_windows": "software",
    "janus_posture_linux": "posture",
    "janus_posture_windows": "posture",
}

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
    modules: tuple[str, ...] = ("crowdsec",)
    osquery_results: str = ""

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
        modules = tuple(
            m.strip()
            for m in env.get("JANUS_SENSOR_MODULES", "crowdsec").split(",")
            if m.strip()
        )
        if unknown := set(modules) - {"crowdsec", "osquery"}:
            raise SystemExit(
                f"Unknown JANUS_SENSOR_MODULES: {', '.join(sorted(unknown))}"
            )
        osq = env.get("JANUS_SENSOR_OSQUERY_RESULTS", "")
        if "osquery" in modules and not osq:
            raise SystemExit("The osquery module needs JANUS_SENSOR_OSQUERY_RESULTS.")
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
            modules=modules,
            osquery_results=osq,
        )


# --- State -----------------------------------------------------------------------------------


@dataclass
class State:
    seen: list[int] = field(default_factory=list)  # CrowdSec alert ids already sent
    last_poll: str | None = None  # ISO time of the last successful alert read
    applied: list[str] = field(default_factory=list)  # JANUS block ids applied here
    refused: list[str] = field(
        default_factory=list
    )  # block ids refused (reported once)
    osquery_inode: int = 0  # where the results log was read up to
    osquery_offset: int = 0
    # Latest snapshot per pack query: {name: {"t": unixTime, "items": [...]}}
    osquery_cache: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str) -> State:
        try:
            with open(path) as f:
                d = json.load(f)
            return cls(seen=list(d.get("seen", [])), last_poll=d.get("last_poll"),
                       applied=list(d.get("applied", [])),
                       refused=list(d.get("refused", [])),
                       osquery_inode=int(d.get("osquery_inode", 0)),
                       osquery_offset=int(d.get("osquery_offset", 0)),
                       osquery_cache=dict(d.get("osquery_cache", {})))  # fmt: skip
        except (OSError, ValueError):
            return cls()

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w") as f:
            json.dump({"seen": self.seen[-SEEN_KEEP:], "last_poll": self.last_poll,
                       "applied": self.applied, "refused": self.refused,
                       "osquery_inode": self.osquery_inode,
                       "osquery_offset": self.osquery_offset,
                       "osquery_cache": self.osquery_cache}, f)  # fmt: skip
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
        out = self.run("decisions", "list", flag, value, "-l", "0", "-o", "json")
        ids = [
            str(d["id"])
            for a in (json.loads(out or "null") or [])
            for d in (a.get("decisions") or [])
            if d.get("scenario") == TAG + block_id
        ]
        for i in ids:
            self.run("decisions", "delete", "--id", i)
        return len(ids)

    def janus_bans(self) -> dict[str, str]:
        """Every live decision this sensor added: CrowdSec decision id -> JANUS block id."""
        out = self.run(
            "decisions", "list", "--origin", "cscli", "-l", "0", "-o", "json"
        )
        return {
            str(d["id"]): str(d["scenario"]).removeprefix(TAG)
            for a in (json.loads(out or "null") or [])
            for d in (a.get("decisions") or [])
            if str(d.get("scenario", "")).startswith(TAG)
        }

    def delete_id(self, decision_id: str) -> None:
        self.run("decisions", "delete", "--id", decision_id)


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


# --- osquery ---------------------------------------------------------------------------------


def _sanitize(name: str, row: dict[str, Any]) -> dict[str, Any]:
    """Persistence commands can carry secrets: send only their sha256."""
    if OSQUERY_GROUPS.get(name) == "persistence":
        row = dict(row)
        cmd = str(row.pop("command", "") or "")
        row["command_sha256"] = hashlib.sha256(cmd.encode()).hexdigest() if cmd else ""
    return row


def read_osquery(path: str, st: State) -> set[str]:
    """Read new lines of osquery's results log and update the per-query snapshot cache.
    Returns the groups that got a newer snapshot. Handles rotation and partial lines."""
    try:
        info = os.stat(path)
    except OSError:
        return set()
    if info.st_ino != st.osquery_inode or info.st_size < st.osquery_offset:
        st.osquery_inode, st.osquery_offset = info.st_ino, 0
    with open(path, "rb") as f:
        f.seek(st.osquery_offset)
        chunk = f.read(MAX_READ)
    end = chunk.rfind(b"\n")
    if end < 0:
        return set()
    st.osquery_offset += end + 1
    changed: set[str] = set()
    for line in chunk[: end + 1].splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        name = str(rec.get("name", "")).removeprefix("pack_janus_")
        if name not in OSQUERY_GROUPS or rec.get("action") != "snapshot":
            continue
        t = int(rec.get("unixTime") or 0)
        cached = st.osquery_cache.get(name)
        if cached is not None and int(cached.get("t", 0)) > t:
            continue
        rows = rec.get("snapshot") or []
        items = [_sanitize(name, r) for r in rows if isinstance(r, dict)]
        st.osquery_cache[name] = {"t": t, "items": items}
        changed.add(OSQUERY_GROUPS[name])
    return changed


def host_snapshots(st: State, groups: set[str]) -> list[dict[str, Any]]:
    """One merged snapshot per changed group, from the latest snapshot of each of its queries."""
    out = []
    for group in sorted(groups):
        names = [
            n for n, g in OSQUERY_GROUPS.items() if g == group and n in st.osquery_cache
        ]
        t = max(int(st.osquery_cache[n]["t"]) for n in names)
        items = [it for n in names for it in st.osquery_cache[n]["items"]]
        observed = datetime.fromtimestamp(t, UTC).isoformat()
        out.append({"group": group, "observed_at": observed, "items": items[:5000]})
    return out


# --- One cycle -------------------------------------------------------------------------------


def cycle(cfg: Config, janus: Janus, cs: Cscli, st: State) -> dict[str, int]:
    janus.call("POST", "/api/sensor/heartbeat", {"agent_version": VERSION})
    stats: dict[str, int] = {}
    if "crowdsec" in cfg.modules:
        stats.update(crowdsec_cycle(cfg, janus, cs, st))
    if "osquery" in cfg.modules:
        groups = read_osquery(cfg.osquery_results, st)
        snaps = host_snapshots(st, groups)
        if snaps:
            janus.call("POST", "/api/sensor/host", {"snapshots": snaps})
        stats["host_groups"] = len(snaps)
    return stats


def crowdsec_cycle(cfg: Config, janus: Janus, cs: Cscli, st: State) -> dict[str, int]:
    stats = {"sent": 0, "applied": 0, "removed": 0, "refused": 0, "orphans": 0}

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
    done, refused_before = set(st.applied), set(st.refused)
    for b in d.get("apply", []):
        bid, target, left = str(b["id"]), str(b["target"]), int(b["seconds_left"])
        if (b.get("applied") and bid in done) or bid in refused_before:
            continue
        if left <= 0:
            continue
        if why := refuse_reason(cfg, target, left):
            refused.append({"id": bid, "reason": why})
            refused_before.add(bid)
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
    st.refused = [b for b in refused_before if b in live]
    # 3. Reconcile: JANUS is the source of truth for janus: bans. Remove any it no longer lists
    # (lifted while a report was lost, or left by a revoked sensor). Skipped if the list from
    # JANUS may be truncated, so a valid ban is never removed.
    if len(d.get("apply", [])) < API_APPLY_LIMIT:
        for decision_id, bid in cs.janus_bans().items():
            if bid not in live:
                cs.delete_id(decision_id)
                stats["orphans"] += 1
                log.info(
                    "removed orphan ban %s (block %s not live in JANUS)",
                    decision_id,
                    bid,
                )
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
