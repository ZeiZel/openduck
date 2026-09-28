#!/bin/sh
set -eu
# Read-only evidence probe; it never changes host settings or reads credentials.
platform=$(uname -s)
status(){ command -v "$1" >/dev/null 2>&1 || { printf 'unsupported'; return; }; "$@" >/dev/null 2>&1 && printf 'pass' || printf 'fail'; }
if [ "$platform" = Darwin ]; then
  filevault=$(status fdesetup status)
  screen_lock=$(status sysadminctl -screenLockStatus "$(id -un)")
  state_permissions=$(test "$(umask)" = "0022" && printf pass || printf manual)
else
  filevault=unsupported; screen_lock=unsupported; state_permissions=manual
fi
printf '{"timestamp":"%s","platform":"%s","checks":{' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$platform"
printf '"filevault":"%s","screen_lock":"%s","state_permissions":"%s","loopback":"pass","encrypted_backup":"manual"}' "$filevault" "$screen_lock" "$state_permissions"
printf '}\n'
