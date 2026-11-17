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
   authorization, allow list and caps. To route every block through JANUS, edit `/etc/crowdsec/profiles.yaml` and
   remove the `decisions:` block from the default IP profile (alerts are still recorded), then
   `systemctl reload crowdsec`. Keep CrowdSec's own bans only if you accept that they bypass JANUS.
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

## Revoking

Revoke the sensor in JANUS (owner, fresh two-factor): its key stops working at once. Then
`systemctl disable --now janus-sensor`. Bans it already applied expire on their own in CrowdSec
(`cscli decisions list` shows them; `cscli decisions delete --id <id>` removes one).

## Tested

`api/tests/test_janus_sensor.py` runs a full cycle against the real API with CrowdSec faked. With a local CrowdSec
LAPI running, `JANUS_SENSOR_REAL_CSCLI=1 pytest tests/test_janus_sensor.py` applies and removes real CrowdSec
decisions (checked against CrowdSec 1.4.6). Alert parsing has been checked against `cscli alerts list -o json`
output, but not yet with live scenario alerts from a real attack log.
