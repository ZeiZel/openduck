#!/bin/sh
set -eu
PATH='/usr/bin:/bin:/usr/sbin:/sbin'; export PATH; unset CDPATH ENV BASH_ENV
if [ "${OPENDUCK_BOUNDARY_TEST_MODE:-0}" = 1 ]; then
  [ "$(id -u)" -ne 0 ] || { echo 'test mode forbidden for root' >&2; exit 2; }
  root=${OPENDUCK_BOUNDARY_TEST_ROOT:?}
  [ -d "$root/state" ] && [ -d "$root/releases" ] && [ -d "$root/keys" ] || { echo 'status=BLOCKED reason=topology-incomplete'; exit 1; }
  echo 'status=BLOCKED reason=production-principals-and-evidence-unavailable'
  exit 1
fi
[ "$#" -eq 0 ] || { echo "usage: $0" >&2; exit 2; }
READINESS='/Library/Application Support/OpenDuck/.openduck-readiness'
[ -x "$READINESS" ] || { echo 'status=BLOCKED reason=readiness-helper-missing' >&2; exit 1; }
exec "$READINESS"
