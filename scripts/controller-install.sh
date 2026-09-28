#!/bin/sh
# Prepare the Controller runtime and (optionally) install its per-user LaunchAgent.
# This script never prints or accepts the Keychain value. It does not start the
# service unless --activate is supplied explicitly.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SERVICE=openduck
ACCOUNT=controller-state
SENSOR_ACCOUNT=sensor-hmac
LABEL=com.openduck.controller
LAUNCH_AGENTS=${HOME:?}/Library/LaunchAgents
PLIST="$LAUNCH_AGENTS/$LABEL.plist"
STATE_DIR="$ROOT/.openduck"
BIN="$STATE_DIR/bin/openduck-controller"

usage() { echo "usage: $0 [--activate] [--origin-probe] [--sensor-enabled]" >&2; exit 2; }
activate=0
origin_probe=0
sensor_enabled=0
for arg in "$@"; do
  case "$arg" in
    --activate) activate=1 ;;
    --origin-probe) origin_probe=1 ;;
    --sensor-enabled) sensor_enabled=1 ;;
    *) usage ;;
  esac
done

umask 077
mkdir -p "$STATE_DIR" "$LAUNCH_AGENTS"
chmod 700 "$STATE_DIR"

if [ ! -x "$BIN" ]; then
  echo "controller binary is missing: $BIN" >&2
  echo "build it with: go build -o $BIN ./cmd/openduck-controller" >&2
  exit 1
fi

# Provision the independent sensor signing secret without exposing either
# secret to the repository or model-facing process.
if /usr/bin/security find-generic-password -s "$SERVICE" -a "$SENSOR_ACCOUNT" -w 2>/dev/null |
  /usr/bin/awk 'length($0) == 32 { ok=1 } END { exit(ok ? 0 : 1) }'; then
  :
else
  if /usr/bin/security find-generic-password -s "$SERVICE" -a "$SENSOR_ACCOUNT" >/dev/null 2>&1; then
    echo "existing sensor Keychain item has invalid length; refusing replacement" >&2
    exit 1
  fi
  sensor_key=$(LC_ALL=C /usr/bin/openssl rand -base64 48 | LC_ALL=C /usr/bin/awk '{gsub(/[^A-Za-z0-9]/,""); value=value $0} END {if (length(value)<32) exit 1; printf "%s", substr(value,1,32)}')
  /usr/bin/security add-generic-password -s "$SERVICE" -a "$SENSOR_ACCOUNT" -w "$sensor_key" >/dev/null
  unset sensor_key
fi

# Refuse to overwrite an existing item. Validate its length without exposing the
# value to stdout/stderr. The Go provider consumes exactly 32 ASCII bytes.
if /usr/bin/security find-generic-password -s "$SERVICE" -a "$ACCOUNT" -w 2>/dev/null |
  /usr/bin/awk 'length($0) == 32 { ok=1 } END { exit(ok ? 0 : 1) }'; then
  :
else
  # A present-but-malformed item must not be silently replaced. Distinguish a
  # missing item from a malformed item with a metadata-only lookup.
  if /usr/bin/security find-generic-password -s "$SERVICE" -a "$ACCOUNT" >/dev/null 2>&1; then
    echo "existing Controller Keychain item has invalid length; refusing replacement" >&2
    exit 1
  fi
  # Generate a finite base64 stream before filtering it. LC_ALL=C makes the
  # character class byte-oriented on macOS, and awk consumes the complete
  # stream so set -e cannot observe the producer-side SIGPIPE caused by head.
  # The value is passed directly to security and is never echoed or written to
  # a repository file.
  if key=$(LC_ALL=C /usr/bin/openssl rand -base64 48 |
    LC_ALL=C /usr/bin/awk '
      { gsub(/[^A-Za-z0-9]/, ""); value = value $0 }
      END {
        if (length(value) < 32) exit 1
        printf "%s", substr(value, 1, 32)
      }
    '); then
    :
  else
    unset key
    echo "unable to generate Controller Keychain value" >&2
    exit 1
  fi
  if [ "${#key}" -ne 32 ]; then
    unset key
    echo "unable to generate Controller Keychain value" >&2
    exit 1
  fi
  /usr/bin/security add-generic-password -s "$SERVICE" -a "$ACCOUNT" -w "$key" >/dev/null
  unset key
fi

# Paths are controlled by this local repository. Reject XML metacharacters so
# generated LaunchAgent values cannot change plist structure.
case "$ROOT" in
  *[\&\<\>\"\']*) echo "repository path contains unsupported XML characters" >&2; exit 1 ;;
esac

tmp="$PLIST.tmp.$$"
trap '/bin/rm -f "$tmp"' EXIT HUP INT TERM
{
  echo '<?xml version="1.0" encoding="UTF-8"?>'
  echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
  echo '<plist version="1.0"><dict>'
  echo '<key>Label</key><string>'"$LABEL"'</string>'
  echo '<key>ProgramArguments</key><array>'
  echo '<string>'"$BIN"'</string><string>-listen</string><string>127.0.0.1:8788</string><string>-state</string><string>.openduck/controller.enc</string>'
  if [ "$origin_probe" -eq 1 ]; then
    echo '<string>-origin-probe</string>'
  fi
  if [ "$sensor_enabled" -eq 1 ]; then
    echo '<string>-sensor-enabled</string>'
  fi
  echo '</array><key>WorkingDirectory</key><string>'"$ROOT"'</string>'
  echo '<key>Umask</key><integer>63</integer><key>ProcessType</key><string>Background</string>'
  echo '<key>KeepAlive</key><true/>'
  echo '<key>StandardOutPath</key><string>'"$STATE_DIR/controller.log"'</string>'
  echo '<key>StandardErrorPath</key><string>'"$STATE_DIR/controller.err.log"'</string>'
  echo '<key>LimitLoadToSessionType</key><string>Aqua</string>'
  echo '</dict></plist>'
} >"$tmp"
/bin/mv -f "$tmp" "$PLIST"
chmod 600 "$PLIST"
trap - EXIT HUP INT TERM

if [ "$activate" -eq 1 ]; then
  uid=$(id -u)
  /bin/launchctl bootout "gui/$uid/$LABEL" >/dev/null 2>&1 || true
  /bin/launchctl bootstrap "gui/$uid" "$PLIST"
  /bin/launchctl kickstart -k "gui/$uid/$LABEL"
fi
echo "Controller LaunchAgent prepared: $PLIST"
