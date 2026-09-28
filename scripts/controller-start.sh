#!/bin/sh
set -eu
LABEL=com.openduck.controller
PLIST=${HOME:?}/Library/LaunchAgents/$LABEL.plist
uid=$(id -u)
if [ ! -r "$PLIST" ]; then
  echo "LaunchAgent is not installed; run scripts/controller-install.sh first" >&2
  exit 1
fi
/bin/launchctl print "gui/$uid/$LABEL" >/dev/null 2>&1 || /bin/launchctl bootstrap "gui/$uid" "$PLIST"
/bin/launchctl kickstart -k "gui/$uid/$LABEL"
exec "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/controller-status.sh"
