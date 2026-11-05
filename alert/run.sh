#!/bin/bash
# vulnfeed-freshness: twice-daily external check of the live host vulnerability feed, run FROM this box (in the
# shape of relay-health). Fetches v1/manifest.json + .minisig, verifies them against the installed public keys,
# and files (or refreshes, or closes) ONE private issue in AG-Studio-Apps/meshTerm, label `vulnfeed`.
#
#   run.sh                          # dry run (the default): prints the would-be issue
#   VULNFEED_ALERT_DRY_RUN=0        # files for real (set it in ~/.config/vulnfeed-freshness.env)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${VULNFEED_ALERT_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/vulnfeed-freshness}"
mkdir -p "$STATE"
export VULNFEED_ALERT_STATE="$STATE"
LOG="$STATE/run.log"
exec 9>"$STATE/lock"
flock -n 9 || { printf '%s another run holds the lock; exiting\n' "$(date -u +%FT%TZ)" >>"$LOG"; exit 0; }
python3 "$HERE/check.py" run 2>&1 | tee -a "$LOG"
exit "${PIPESTATUS[0]}"
