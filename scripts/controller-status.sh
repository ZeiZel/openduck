#!/bin/sh
set -eu
if ! /usr/bin/curl --silent --show-error --fail --max-time 3 --noproxy '*' http://127.0.0.1:8788/readyz >/dev/null; then
  echo "Controller: not ready" >&2
  exit 1
fi
echo "Controller: ready"
/usr/bin/curl --silent --show-error --fail --max-time 3 --noproxy '*' http://127.0.0.1:8788/v1/controller/status
echo
