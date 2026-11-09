#!/bin/bash
# vulnfeed-trigger: starts the feed build (workflow_dispatch on main) from this box at 00:20, 06:20, 12:20 and
# 18:20 UTC. GitHub runs a dispatch at once; its own schedule ran 3.5 to 8.6 hours late (2026-11-05..09), so the
# workflow's schedule is now only a fallback that builds when the live feed is over 7 h old (James 2026-11-09).
# A failed dispatch fails the unit; the freshness watch (alert/) files an issue if the feed then goes stale.
set -u
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/vulnfeed-trigger"
mkdir -p "$STATE"
LOG="$STATE/run.log"
REPO="${VULNFEED_REPO:-AG-Studio-Apps/meshterm-vulnfeed}"
ts() { date -u +%FT%TZ; }
if out=$(gh workflow run build.yml -R "$REPO" --ref main 2>&1); then
    printf '%s dispatched: %s\n' "$(ts)" "$out" | tee -a "$LOG"
else
    printf '%s dispatch FAILED: %s\n' "$(ts)" "$out" | tee -a "$LOG"
    exit 1
fi
