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
set -eu

TOOL_USER="${NIGHTFALL_TOOL_USER:-nftool}"
WORKER_USER="${NIGHTFALL_WORKER_USER:-nfworker}"
PORT="${NIGHTFALL_EGRESS_PORT:-3128}"
case "$PORT" in *[!0-9]*|'') echo "egress-lock: bad NIGHTFALL_EGRESS_PORT" >&2; exit 1;; esac
TOOL_UID="$(id -u "$TOOL_USER")"

nft -f - <<RULES
table inet nightfall_tools
delete table inet nightfall_tools
table inet nightfall_tools {
  chain output {
    type filter hook output priority filter; policy accept;
    meta skuid $TOOL_UID oifname "lo" ip daddr 127.0.0.1 tcp dport $PORT accept
    meta skuid $TOOL_UID counter reject
  }
}
RULES
echo "egress-lock: $TOOL_USER (uid $TOOL_UID) may reach only 127.0.0.1:$PORT" >&2

if [ "${NIGHTFALL_EGRESS_LOCK_ONLY:-}" = "1" ]; then
  exit 0
fi
exec setpriv --reuid "$WORKER_USER" --regid "$WORKER_USER" --init-groups --no-new-privs \
  --inh-caps -all,+setuid,+setgid --ambient-caps -all,+setuid,+setgid \
  --bounding-set -all,+setuid,+setgid -- "$@"
