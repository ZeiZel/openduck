#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# Scan only tracked first-party text. Vendored code and binary/generated fixtures
# are not part of the portable OpenDuck domain contract.
files=$(git ls-files -z -- ':!third_party/**' ':!**/node_modules/**' ':!**/*.lock' ':!scripts/test-tracked-domain-safety.sh' | xargs -0 -r printf '%s\n')
if [ -n "$files" ]; then
  x=$(printf '\\x78'); five=$(printf '\\x35')
  rooms=$(printf '\\x72\\x6f\\x6f\\x6d\\x73')
  rent=$(printf '\\x72\\x65\\x6e\\x74\\x76\\x65\\x72\\x73\\x65')
  kaiten=$(printf '\\x6b\\x61\\x69\\x74\\x65\\x6e')
  host=$(printf '\\x72\\x75'); owner=$(printf '\\x76\\x61\\x6c\\x65\\x72\\x79\\x6c\\x76\\x6f\\x76')
  home=$(printf '/%s/%s' "$(printf '\\x55\\x73\\x65\\x72\\x73')" "$owner")
  bundle=$(printf '\\x72\\x75\\x2e\\x75\\x6e\\x6c\\x69\\x6d\\x69\\x74\\x65\\x64\\x74\\x65\\x63\\x68\\x2e\\x65\\x78\\x70\\x72\\x65\\x73\\x73\\x2e\\x64\\x65\\x73\\x6b\\x74\\x6f\\x70')
  # Keep the generic token bounded: hashes such as 0x51 and package
  # integrity strings must not be interpreted as domain identity.
  pattern="${x}${five}${rooms}|${rent}|${kaiten}\\.${x}${five}\\.${host}|@${x}${five}\\.${host}|${home}|/projects/${x}${five}/|${bundle}|(^|[^[:alnum:]])${x}${five}([^[:alnum:]]|$)"
  matches=$(printf '%s\n' "$files" | xargs -r rg -l -I -i "$pattern" -- 2>/dev/null || true)
  if [ -n "$matches" ]; then
    echo 'tracked first-party domain markers found in:' >&2
    printf '%s\n' "$matches" | sort -u >&2
    exit 1
  fi
fi

if git ls-files --error-unmatch deploy/openclaw/config.json >/dev/null 2>&1; then
  echo 'deploy/openclaw/config.json must be local and untracked' >&2
  exit 1
fi
git check-ignore -q deploy/openclaw/config.json
test -f deploy/openclaw/config.example.json
x=$(printf '\\x78'); five=$(printf '\\x35'); rooms=$(printf '\\x72\\x6f\\x6f\\x6d\\x73'); rent=$(printf '\\x72\\x65\\x6e\\x74\\x76\\x65\\x72\\x73\\x65'); kaiten=$(printf '\\x6b\\x61\\x69\\x74\\x65\\x6e'); host=$(printf '\\x72\\x75'); owner=$(printf '\\x76\\x61\\x6c\\x65\\x72\\x79\\x6c\\x76\\x6f\\x76'); home=$(printf '/%s/%s' "$(printf '\\x55\\x73\\x65\\x72\\x73')" "$owner"); bundle=$(printf '\\x72\\x75\\x2e\\x75\\x6e\\x6c\\x69\\x6d\\x69\\x74\\x65\\x64\\x74\\x65\\x63\\x68\\x2e\\x65\\x78\\x70\\x72\\x65\\x73\\x73\\x2e\\x64\\x65\\x73\\x6b\\x74\\x6f\\x70')
pattern="${x}${five}${rooms}|${rent}|${kaiten}\\.${x}${five}\\.${host}|@${x}${five}\\.${host}|${home}|/projects/${x}${five}/|${bundle}|(^|[^[:alnum:]])${x}${five}([^[:alnum:]]|$)"
! rg -n -i "$pattern" deploy/openclaw/config.example.json
echo 'tracked domain safety: ok'
