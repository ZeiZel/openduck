#!/bin/sh
# Run the synthetic native owner-auth canary. This opens the helper UI and may
# invoke Touch ID, but never contacts Controller or executes an effect.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -ne 2 ]; then
	printf '%s\n' FAIL
	exit 2
fi
HELPER=$1
DIGEST=$2
case "$HELPER" in /*) ;; *) printf '%s\n' FAIL; exit 2;; esac
if [ -z "$DIGEST" ]; then printf '%s\n' FAIL; exit 2; fi
cd "$ROOT"
exec go run ./cmd/openduck-auth-canary -helper "$HELPER" -sha256 "$DIGEST"
