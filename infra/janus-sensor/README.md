# janus-sensor: CrowdSec → JANUS SHIELD (SHIELD v3 phase 2)

Connects CrowdSec on a Linux machine you run to JANUS. Design:
`docs/designs/2026-11-shield-v3-intrusion-detection.md` §3–4.

- **Outbound only.** The sensor calls JANUS over HTTPS with its own key. JANUS never connects to the machine; nothing
  listens.
- **Fixed actions only.** It sends CrowdSec alerts, and adds or deletes one kind of CrowdSec decision: a ban of an
  address or range for a time, tagged `janus:<block id>`. Every `cscli` call is a fixed argument list; there is no
  shell and no other instruction it will take.
- **Checks every block again before applying it:** its own local allow list (so a compromised JANUS can't lock you
  out), never loopback/link-local/multicast/reserved addresses, never wider than /16 (IPv4) or /32 (IPv6), never
  longer than 7 days. A block it won't apply is reported to JANUS as refused and shows in the audit trail.
- Standard-library Python 3.11+, one file. No paid services.

## How blocking works

| Tier | Who decides | Limits |
|---|---|---|
| **GUARD** (automatic) | Deterministic rules in JANUS, only under the standing **response authorization** the owner records | One address, on the machine that saw it, ≤4 h (default 1 h), per-hour cap (default 50), allow list, kill switch |
| **Approved** | An owner or admin, with a fresh two-factor check | An address or range (≤/16), on chosen sensors, ≤7 days |

Every block expires and can be lifted in one click; the sensor removes it on its next poll (30 s). Pausing GUARD or
ending the authorization stops new automatic blocks at once; blocks already applied run out or can be lifted.

## Set up (about 15 minutes, per machine)

1. **CrowdSec and the firewall bouncer.** Install CrowdSec with the collections you want (e.g.
   `crowdsecurity/linux`, `crowdsecurity/sshd`, `crowdsecurity/nginx`) and `crowdsec-firewall-bouncer-nftables`,
   following CrowdSec's own instructions.
2. **Let JANUS decide the bans.** CrowdSec's default profile bans for 4 hours by itself, outside JANUS's
   authorization, allow list and caps. CrowdSec also drops an alert whose profile makes no decision, so removing
   the `decisions:` block would stop alerts reaching JANUS too. Instead, give the default IP profile in
   `/etc/crowdsec/profiles.yaml` a decision type the firewall bouncer doesn't enforce (it acts on `ban` only):
   ```yaml
   name: default_ip_remediation
   filters:
    - Alert.Remediation == true && Alert.GetScope() == "Ip"
   decisions:
    - type: janus_alert   # recorded, not enforced; JANUS decides the bans
      duration: 1m
   on_success: break
   ```
   Then `systemctl reload crowdsec`. Check after the first alert: `cscli decisions list` shows `janus_alert`, and
   `nft list ruleset` doesn't contain that address. Keep `type: ban` only if you accept that CrowdSec's own bans
   bypass JANUS.
3. **Register the sensor in JANUS.** SHIELD → Intrusion Detection → *Register sensor* (owner, fresh two-factor).
   JANUS shows the key once; it keeps only its hash.
4. **Install the sensor** (as root):
   ```bash
   install -d -m 700 /etc/janus-sensor /opt/janus-sensor
   install -m 644 janus_sensor.py /opt/janus-sensor/
   install -m 600 sensor.env.example /etc/janus-sensor/sensor.env   # then edit it
   install -m 644 janus-sensor.service /etc/systemd/system/
   systemctl daemon-reload && systemctl enable --now janus-sensor
   ```
   Put your own addresses in `JANUS_SENSOR_ALLOWLIST`, and add the same ones to the allow list in JANUS.
5. **Check it.** `journalctl -u janus-sensor -f` shows each cycle; the sensor shows *online* in JANUS within a
   minute. Test once with `JANUS_SENSOR_ONCE=1 python3 /opt/janus-sensor/janus_sensor.py` (exit code 0 = OK).
6. **Turn on GUARD (optional).** In JANUS, record the response authorization: which sensors, longest and default
   block, per-hour cap, up to 90 days. Without it every alert stays alert-only.

## Host state with osquery (SHIELD v4 step 4a, optional)

The `osquery` module reports the machine's own state: local accounts, administrators, SSH keys, listening
services, services/scheduled tasks/startup items, installed software, and posture (firewall, disk encryption,
OS version). Detection only; nothing is changed on the machine. Design:
`docs/designs/2026-11-shield-v4-host-network-monitoring.md`.

- **The query pack is fixed:** `osquery/janus.conf` in this repository. JANUS never sends a query back, and the
  pack turns osquery's remote (distributed) queries and extensions off.
- **Kept to a minimum:** names and paths; no process command lines, environment or file contents. Cron and
  scheduled-task commands are sent only as a sha256.
- JANUS diffs each snapshot against the last one; the first is the baseline. The change log is kept 90 days.

**Linux:**

1. Install osquery from osquery's own packages (osquery.io), then
   `install -m 644 osquery/janus.conf /etc/osquery/osquery.conf` and `systemctl enable --now osqueryd`.
2. In `/etc/janus-sensor/sensor.env` add:
   ```
   JANUS_SENSOR_MODULES=crowdsec,osquery
   JANUS_SENSOR_OSQUERY_RESULTS=/var/log/osquery/osqueryd.results.log
   ```
   (`JANUS_SENSOR_MODULES=osquery` alone on a machine without CrowdSec.) Then `systemctl restart janus-sensor`.
3. Within about ten minutes the machine's page in JANUS (SHIELD → Intrusion Detection → the sensor's name)
   shows its state.

**Windows** (not yet tested on Windows): install osquery's MSI and Python 3.11+, copy `osquery\janus.conf` to
`C:\Program Files\osquery\osquery.conf`, restart the `osqueryd` service, and run
`python janus_sensor.py` at start-up (Task Scheduler, "At startup", as SYSTEM) with `JANUS_URL`,
`JANUS_SENSOR_KEY`, `JANUS_SENSOR_MODULES=osquery`, `JANUS_SENSOR_OSQUERY_RESULTS=C:\Program
Files\osquery\log\osqueryd.results.log` and `JANUS_SENSOR_STATE=C:\ProgramData\janus-sensor\state.json` set
as system environment variables.

## Revoking

Revoke the sensor in JANUS (owner, fresh two-factor): its key stops working at once. Then
`systemctl disable --now janus-sensor`. Bans it already applied expire on their own in CrowdSec
(`cscli decisions list` shows them; `cscli decisions delete --id <id>` removes one).

## Tested

`api/tests/test_janus_sensor.py` runs a full cycle against the real API with CrowdSec faked. With a local CrowdSec
LAPI running, `JANUS_SENSOR_REAL_CSCLI=1 pytest tests/test_janus_sensor.py` applies and removes real CrowdSec
decisions (checked against CrowdSec 1.4.6). See `docs/reviews/2026-11-17-shield-phase2-safeguards.md` for the
safeguard validation, including real `crowdsecurity/ssh-bf` alerts from a replayed sshd log.

The osquery module is tested against osquery's documented results-log format (`api/tests/test_shield_host.py`),
and every pack query is parsed by SQLite against stub tables of the columns it uses. **It hasn't yet run against
a real osquery**, on Linux or Windows: that's the first step of its validation.
