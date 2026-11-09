#!/bin/bash
# Installs the vulnfeed build trigger for THIS user: copies run.sh to ~/.local/lib/vulnfeed-trigger (the unit runs
# that copy, never the working tree) and the units to ~/.config/systemd/user. It does NOT enable anything.
#
#   bash trigger/install.sh
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$HOME/.local/lib/vulnfeed-trigger"
UNITS="$HOME/.config/systemd/user"
mkdir -p "$LIB" "$UNITS"
install -m 755 "$REPO/trigger/run.sh" "$LIB/"
install -m 644 "$REPO/trigger/systemd/vulnfeed-trigger.service" "$REPO/trigger/systemd/vulnfeed-trigger.timer" "$UNITS/"
echo "Installed to $LIB and $UNITS (commit $(git -C "$REPO" rev-parse --short=12 HEAD 2>/dev/null || echo unknown))."
echo "To enable (not done here):    systemctl --user daemon-reload && systemctl --user enable --now vulnfeed-trigger.timer"
