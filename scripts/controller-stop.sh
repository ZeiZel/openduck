#!/bin/sh
set -eu
LABEL=com.openduck.controller
uid=$(id -u)
/bin/launchctl bootout "gui/$uid/$LABEL" >/dev/null 2>&1 || true
echo "Controller stopped"
