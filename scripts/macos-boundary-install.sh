#!/bin/sh
# Retired: this wrapper formerly executed a staged helper and is intentionally not a production path.
set -eu
echo 'macos-boundary-install: disabled; use deploy/ansible/site.yml with a signed ReleaseEnvelope and ManifestV2' >&2
exit 64
