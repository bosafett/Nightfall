#!/bin/sh
# Tool sandbox network lock (docs/PHASE0_ARCHITECTURE_REVIEW.md §13).
#
# Runs as root once at container start, then never again:
#   1. Installs a kernel firewall rule: processes of the tool user may open exactly one
#      kind of connection, TCP to 127.0.0.1:$NIGHTFALL_EGRESS_PORT (the per-run egress
#      proxy). Everything else they send (other ports, other hosts, DNS, IPv6) is rejected.
#   2. Drops to the worker user, keeping only CAP_SETUID/CAP_SETGID (to start tools as
#      the tool user), with no_new_privs set and everything else removed from the
#      bounding set. The worker clears the two capabilities again in each tool process
#      before exec, and checks the lock before every live run (nightfall/tools/runner.py).
# The container needs CAP_NET_ADMIN (step 1) and CAP_SETPCAP (to shrink the bounding set in
# step 2); neither survives into the worker.
#
# Lab mode (NIGHTFALL_WORKER_MODE=lab, isolated lab machine, infra/lab/): the worker user is
# locked down too. It may reach only the lab networks, DNS, and the database port
# (NIGHTFALL_LAB_DB_PORT, default 5432); everything else it sends is rejected. So even the
# worker process itself can't browse the internet from the lab machine.
set -eu

TOOL_USER="${NIGHTFALL_TOOL_USER:-nftool}"
WORKER_USER="${NIGHTFALL_WORKER_USER:-nfworker}"
PORT="${NIGHTFALL_EGRESS_PORT:-3128}"
case "$PORT" in *[!0-9]*|'') echo "egress-lock: bad NIGHTFALL_EGRESS_PORT" >&2; exit 1;; esac
TOOL_UID="$(id -u "$TOOL_USER")"
WORKER_RULES=""
if [ "${NIGHTFALL_WORKER_MODE:-standard}" = "lab" ]; then
  WORKER_UID="$(id -u "$WORKER_USER")"
  LABNETS="${NIGHTFALL_LAB_NETWORKS:-172.30.99.0/24}"
  DBPORT="${NIGHTFALL_LAB_DB_PORT:-5432}"
  case "$LABNETS" in *[!0-9./,]*|'') echo "egress-lock: bad NIGHTFALL_LAB_NETWORKS (IPv4 CIDRs, comma-separated)" >&2; exit 1;; esac
  case "$DBPORT" in *[!0-9]*|'') echo "egress-lock: bad NIGHTFALL_LAB_DB_PORT" >&2; exit 1;; esac
  WORKER_RULES="meta skuid $WORKER_UID oifname \"lo\" accept
    meta skuid $WORKER_UID ip daddr { $LABNETS } accept
    meta skuid $WORKER_UID udp dport 53 accept
    meta skuid $WORKER_UID tcp dport { 53, $DBPORT } accept
    meta skuid $WORKER_UID counter reject"
fi

nft -f - <<RULES
table inet nightfall_tools
delete table inet nightfall_tools
table inet nightfall_tools {
  chain output {
    type filter hook output priority filter; policy accept;
    meta skuid $TOOL_UID oifname "lo" ip daddr 127.0.0.1 tcp dport $PORT accept
    meta skuid $TOOL_UID counter reject
    $WORKER_RULES
  }
}
RULES
echo "egress-lock: $TOOL_USER (uid $TOOL_UID) may reach only 127.0.0.1:$PORT" >&2
if [ -n "$WORKER_RULES" ]; then
  echo "egress-lock: lab mode: $WORKER_USER may reach only $LABNETS, DNS and port $DBPORT" >&2
fi

if [ "${NIGHTFALL_EGRESS_LOCK_ONLY:-}" = "1" ]; then
  exit 0
fi
# setpriv keeps the environment, so HOME would still be /root. The worker can't read it, and
# libpq treats "permission denied" on ~/.postgresql/postgresql.crt as fatal. Use the worker's
# own (nonexistent) home, so libpq finds no client certificate and carries on.
HOME="$(getent passwd "$WORKER_USER" | cut -d: -f6)"
export HOME
exec setpriv --reuid "$WORKER_USER" --regid "$WORKER_USER" --init-groups --no-new-privs \
  --inh-caps -all,+setuid,+setgid --ambient-caps -all,+setuid,+setgid \
  --bounding-set -all,+setuid,+setgid -- "$@"
