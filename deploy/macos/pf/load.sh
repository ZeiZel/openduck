#!/bin/sh
set -eu
exec /sbin/pfctl -a com.openduck -f "/Library/Application Support/OpenDuck/pf/openduck.conf"
