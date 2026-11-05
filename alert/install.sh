#!/bin/bash
# Installs the vulnfeed freshness watch for THIS user: copies the checker, its two helper modules and the public
# keys to ~/.local/lib/vulnfeed-freshness (the unit runs that copy, never the working tree) and the units to
# ~/.config/systemd/user. It does NOT enable or start anything; it prints the commands for that.
#
#   bash alert/install.sh
#
# Re-run it after any change to alert/, builder/feedlib.py, scripts/sign.py or keys/ (a key rotation).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$HOME/.local/lib/vulnfeed-freshness"
UNITS="$HOME/.config/systemd/user"
mkdir -p "$LIB/keys" "$UNITS"
install -m 755 "$REPO/alert/run.sh" "$REPO/alert/check.py" "$LIB/"
install -m 644 "$REPO/builder/feedlib.py" "$REPO/scripts/sign.py" "$LIB/"
install -m 644 "$REPO/keys/vulnfeed-feed.pub" "$REPO/keys/vulnfeed-emergency.pub" "$LIB/keys/"
install -m 644 "$REPO/alert/systemd/vulnfeed-freshness.service" "$REPO/alert/systemd/vulnfeed-freshness.timer" "$UNITS/"
echo "Installed to $LIB and $UNITS (commit $(git -C "$REPO" rev-parse --short=12 HEAD 2>/dev/null || echo unknown))."
echo "Dry run by default. Try it:   $LIB/run.sh"
echo "To file issues for real:      echo VULNFEED_ALERT_DRY_RUN=0 > ~/.config/vulnfeed-freshness.env"
echo "To enable (not done here):    systemctl --user daemon-reload && systemctl --user enable --now vulnfeed-freshness.timer"
