#!/bin/sh
# Build the native owner-auth helper for local development only.
# This script does not install, launch, or wire the helper into any service.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE="$ROOT/native/openduck-auth-helper/main.swift"
OUTPUT="$ROOT/.openduck/bin/openduck-auth-helper"

if [ ! -r "$SOURCE" ]; then
  echo "owner-auth helper source is missing: $SOURCE" >&2
  exit 1
fi

umask 077
mkdir -p "$(dirname -- "$OUTPUT")"
chmod 700 "$ROOT/.openduck" "$(dirname -- "$OUTPUT")"
/usr/bin/xcrun swiftc \
  -O \
  -o "$OUTPUT" \
  "$SOURCE"
chmod 700 "$OUTPUT"
echo "Owner-auth helper built (not installed or launched): $OUTPUT"
