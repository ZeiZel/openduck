import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import {
  applyNativePackageLifecycle, authorizeNativePackage, canonicalJSON, CHILD_OPERATIONS, generateNativePackage,
  nativePackageDigest, NATIVE_MCP_PROTOCOL, NATIVE_MCP_TOOL_NAMES, NATIVE_PACKAGE_NAME, NATIVE_PROVIDERS, NATIVE_PROVIDER_REGISTRATIONS, NATIVE_PUBLISHER_CONTRACT, NATIVE_RUNTIME_PREREQUISITES, PINNED_CONTROLLER_KEY_ID, sha256, verifyNativeLifecycleProjectionGolden,
} from '../src/native-packages.js'

const now = Date.parse('2026-08-30T12:00:00Z')
const lifecycleProjection = '{"schema":"openduck.native-mcp-lifecycle.v1","release_id":"revision-7","release_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","manifest_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","shim_artifact_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","socket_generation":3,"socket_identity_digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","host_catalog_generation":4,"provider_topology_digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","host_artifact_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","host_team_id":"2DC432GLL2","host_image_identity":"sha256:2222222222222222222222222222222222222222222222222222222222222222","observed_at":"2026-08-30T11:55:00Z","expires_at":"2026-08-30T12:10:00Z","signer_key_id":"openduck-controller-lifecycle-2026-08","digest":"sha256:57c86822fdf6c51f89e718c46eabd0a7e45c85555cb3d8d9e016e370766971bd","signature":"7ca40d58f042ae813251fed7a4b6c53e32c95d4a3810617086bb85f3f2a601bb3c11c6de5d038ac400e7885c92db2fdb76427e3be9ca43dc3dae789a30ed940c"}'
function unsigned(value) { return Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'receipt_digest' && key !== 'signature')) }
const baseReceipt = Object.freeze({ schema_version: 'openduck-native-package-lifecycle-receipt.v1', provider: 'codex', profile_id: 'codex.subscription', profile_revision: 'revision-7', package_id: NATIVE_PACKAGE_NAME, package_digest: 'dfdba38659c4a0e53b3e1f4e596bf8c7e800995413f22662c8ad477e640b1ca3', controller_binding_id: 'controller-binding-4', ui_session_id: 'ui-session-9', ui_channel_id: 'ui-channel-2', root_run_id: 'root-run-8', run_id: 'run-13', mesh_session_id: 'mesh-session-5', endpoint_id: 'controller-mesh-endpoint', endpoint_generation: 3, endpoint_expires_at: '2026-08-30T14:00:00Z', association_digest: 'a'.repeat(64), capability_digest: 'd67d66786fbde2a9d197f22d1fb4d1e23e4ecf9d5cc93471138288eacbff757a', capabilities: [...CHILD_OPERATIONS], key_id: PINNED_CONTROLLER_KEY_ID, native_lifecycle_projection_digest: '57c86822fdf6c51f89e718c46eabd0a7e45c85555cb3d8d9e016e370766971bd', native_release_id: 'revision-7', native_release_digest: 'b'.repeat(64), native_manifest_digest: 'c'.repeat(64), native_shim_artifact_digest: 'd'.repeat(64), native_socket_generation: 3, native_socket_identity_digest: 'e'.repeat(64), native_host_catalog_generation: 4, native_provider_topology_digest: 'f'.repeat(64), native_host_artifact_digest: '1'.repeat(64), native_host_team_id: '2DC432GLL2', native_host_image_identity: '2'.repeat(64), native_lifecycle_expires_at: '2026-08-30T12:10:00Z' })
function signed(action, suffix, previous, issued, expires, signature, receiptDigest) { return Object.freeze({ ...baseReceipt, action, receipt_id: `codex-receipt-${suffix}`, previous_receipt_digest: previous, issued_at: issued, expires_at: expires, nonce: `codex-nonce-${suffix}`, signature, receipt_digest: receiptDigest }) }
const enabled = signed('enable', 1, '', '2026-08-30T11:00:00Z', '2026-08-30T13:00:00Z', '4A8Hf6w5AnMo6L-7WLwuziGXKVC8HxhtN5Q8F80wEGkDUwBAUVfaDm_xJ7ugGo6ll_i2rVkySXGjfsN1bofOCQ', '7f8b0c33a28ccd099e0bdb330b2e8516f08791849e7f94b942753f2a8a3f2dc1')
const disabled = signed('disable', 2, enabled.receipt_digest, '2026-08-30T11:30:00Z', '2026-08-30T13:30:00Z', 'V7kqUBKZdDG7LEFNnqq07PF_W35w97rop6bYuwtM9Knzrwc1ktX18skms4NLX8JVsJwpOwNhb-GY9hZ7iDMIDg', '026abf7b441e228a937f3a431461d6fd345dbc863755551ad0bdcf2a7860d207')
const reenabled = signed('enable', 3, disabled.receipt_digest, '2026-08-30T11:30:00Z', '2026-08-30T13:30:00Z', 'Dek3tS3YQaTiMpMVE-U-5cCpg2TBEPJzxIzxWfX_JQoopz2Rx0r2IYhuQmysos-PJgNh4Fa4CgeGXgwPvZNdCA', 'c66048683409ae0eda47142e8d90fc4d94b6b0aabf0b0a862bd9ff2222f8d79f')
const revoked = signed('revoke', 4, reenabled.receipt_digest, '2026-08-30T11:30:00Z', '2026-08-30T13:30:00Z', '5flzWdQQh1LQCF2W-9W-etv-xPhMnxEj41fMfKeu0G0Hk2mm83D1sVJggIzxPfio2gzZbfKk-BT0cRWteSzUAw', 'cd92154970e9c2e3ce8dfbd288ef92c1f886c81c1a76ebe94011d46323605c5d')
const afterRevoke = signed('enable', 5, revoked.receipt_digest, '2026-08-30T11:30:00Z', '2026-08-30T13:30:00Z', 'iwCtmN0U10brIJ_jB7Gq5C7i5eroHUkkIU-H8dfJqaXLlV-v4jt9ljxkrQZo25WYX5aFH8kSQe19PNq6aWMzDw', '227e1ea734c4f255a96a4a5fe3fcd24c63de870c2ea484da3946c3578d0fc265')
test('official registrations stay unavailable and Kimi uses only its plugin-relative helper', async () => {
  assert.equal(NATIVE_MCP_PROTOCOL, '2025-11-25')
  assert.deepEqual(NATIVE_MCP_TOOL_NAMES, CHILD_OPERATIONS.map(operation => `openduck_mesh_${operation}`))
  assert.deepEqual(NATIVE_RUNTIME_PREREQUISITES, { helper_command: '/Library/Application Support/OpenDuck/.openduck-native-mcp', installed_helper_path: '/Library/Application Support/OpenDuck/.openduck-native-mcp', socket_path: '/private/var/run/openduck/native-mcp.sock', installed_helper_evidence: 'required', root_owned_listener: 'required', host_catalog: 'required' })
  assert.deepEqual(NATIVE_PUBLISHER_CONTRACT, { authority: 'macosattest.VerifyNativePackageCommit', marker: '.openduck-commit.json', schema: 'openduck.native-package-commit.v1', owner: 'root', group: 'trusted_provider_group', mode: '0440', inventory_digest: 'exact_published_files', package_digest: 'exact_signed_receipt', receipt_digest: 'exact_signed_receipt', provider_writable: 'forbidden' })
  assert.deepEqual(Object.keys(NATIVE_PROVIDER_REGISTRATIONS), NATIVE_PROVIDERS)
  for (const provider of NATIVE_PROVIDERS) {
    const registration = NATIVE_PROVIDER_REGISTRATIONS[provider]
    assert.deepEqual({ available: registration.available, status: registration.status, reason: registration.reason }, { available: false, status: 'unavailable', reason: 'production_official_host_launch_unavailable' })
    assert.match(registration.source, /^https:\/\//u)
    assert.equal(registration.verified_at, '2026-08-30')
    assert.equal(registration.bridge_contract, 'docs/native-mcp-bridge-contract.md')
    assert.equal(registration.consumer, NATIVE_PUBLISHER_CONTRACT)
    assert.deepEqual(registration.mcp.server, { name: 'openduck-mesh', command: provider === 'kimi' ? './bin/openduck-native-mcp' : '/Library/Application Support/OpenDuck/.openduck-native-mcp', args: [] })
    assert.equal(registration.mcp.location, provider === 'codex' || provider === 'claude' ? '.mcp.json' : `${provider === 'qwen' ? 'qwen-extension.json' : 'kimi.plugin.json'}#mcpServers`)
    assert.equal(registration.mcp.manifest_reference, provider === 'codex' ? './.mcp.json' : '')
  }
  await assert.rejects(generateNativePackage({ outputDirectory: '/tmp/openduck-mesh', receipts: [enabled], lifecycleProjection, now }), /TRUSTED_NATIVE_PUBLISHER_REQUIRED/)
  await assert.rejects(authorizeNativePackage({ receipts: [enabled], lifecycleProjection, now }), /NATIVE_BRIDGE_UNAVAILABLE/)
  const forgedProjection = JSON.stringify({ ...JSON.parse(lifecycleProjection), socket_generation: 9 })
  await assert.rejects(authorizeNativePackage({ receipts: [enabled], lifecycleProjection: forgedProjection, now }), /INVALID_NATIVE_LIFECYCLE_SIGNATURE/)
})

test('pinned Ed25519 receipt verification cannot be bypassed by a caller callback', async () => {
  const valid = enabled
  await assert.rejects(authorizeNativePackage({ receipts: [valid], lifecycleProjection, now }), /NATIVE_BRIDGE_UNAVAILABLE/)
  const forged = { ...valid, key_id: 'attacker-key', signature: 'a'.repeat(86) }
  forged.receipt_digest = sha256(canonicalJSON(unsigned(forged)))
  await assert.rejects(authorizeNativePackage({ receipts: [forged], verifyControllerReceipt: async () => true, now }), /UNTRUSTED_CONTROLLER_RECEIPT/)
  const altered = { ...valid, signature: `${valid.signature[0] === 'A' ? 'B' : 'A'}${valid.signature.slice(1)}` }
  await assert.rejects(authorizeNativePackage({ receipts: [altered], verifyControllerReceipt: async () => true, now }), /CONTROLLER_SIGNATURE_REJECTED/)
})

test('canonical binding, expiry, capabilities, schema, and DeepSeek remain fail closed', async () => {
  assert.equal(canonicalJSON({ z: 1, a: { y: true, x: 'v' } }), canonicalJSON({ a: { x: 'v', y: true }, z: 1 }))
  const valid = enabled
  await assert.rejects(authorizeNativePackage({ receipts: [{ ...valid, unexpected: 'x' }], now }), /INVALID_RECEIPT_SHAPE/)
  await assert.rejects(authorizeNativePackage({ receipts: [{ ...valid, package_digest: 'b'.repeat(64) }], now }), /PACKAGE_BINDING_MISMATCH/)
  const caps = { ...valid, capabilities: [...CHILD_OPERATIONS].reverse() }
  await assert.rejects(authorizeNativePackage({ receipts: [caps], now }), /INVALID_CHILD_CAPABILITIES/)
  const expired = { ...enabled, expires_at: '2026-08-30T11:59:59Z' }
  await assert.rejects(authorizeNativePackage({ receipts: [expired], now }), /RECEIPT_DIGEST_MISMATCH/)
  await assert.rejects(authorizeNativePackage({ receipts: [enabled], now: Date.parse('2026-08-30T13:00:01Z') }), /ENABLE_RECEIPT_EXPIRED/)
  await assert.rejects(authorizeNativePackage({ receipts: [enabled], lifecycleProjection, now: Date.parse('2026-08-30T12:10:01Z') }), /NATIVE_LIFECYCLE_EVIDENCE_EXPIRED/)
  const providerSubstitution = { ...enabled, provider: 'claude', profile_id: 'claude.subscription' }
  await assert.rejects(authorizeNativePackage({ receipts: [providerSubstitution], lifecycleProjection, now }), /PACKAGE_BINDING_MISMATCH/)
  const topologySubstitution = JSON.stringify({ ...JSON.parse(lifecycleProjection), provider_topology_digest: `sha256:${'0'.repeat(64)}` })
  await assert.rejects(authorizeNativePackage({ receipts: [enabled], lifecycleProjection: topologySubstitution, now }), /INVALID_NATIVE_LIFECYCLE_SIGNATURE/)
  await assert.rejects(authorizeNativePackage({ receipts: [{ ...enabled, provider: 'deepseek' }], now }), /UNSUPPORTED_NATIVE_PROVIDER/)
})

test('JavaScript has no publish/quarantine authority and revoke stays terminal', async () => {
  await assert.rejects(applyNativePackageLifecycle({ outputDirectory: '/tmp/ignored', receipts: [enabled, disabled], now }), /TRUSTED_NATIVE_PUBLISHER_REQUIRED/)
  await assert.rejects(applyNativePackageLifecycle({ outputDirectory: '/tmp/ignored', receipts: [enabled, disabled, reenabled], lifecycleProjection, now }), /TRUSTED_NATIVE_PUBLISHER_REQUIRED/)
  await assert.rejects(applyNativePackageLifecycle({ outputDirectory: '/tmp/ignored', receipts: [enabled, disabled, reenabled, revoked], now }), /TRUSTED_NATIVE_PUBLISHER_REQUIRED/)
  await assert.rejects(applyNativePackageLifecycle({ outputDirectory: '/tmp/ignored', receipts: [enabled, disabled, reenabled, revoked, afterRevoke], now }), /REVOKED_PACKAGE_TERMINAL/)
})

test('Go-produced canonical lifecycle golden verifies in JavaScript with exact host identity fields', async () => {
  const raw = (await readFile(new URL('../../../internal/macosattest/testdata/lifecycle-projection.golden.json', import.meta.url), 'utf8')).trimEnd()
  const verified = verifyNativeLifecycleProjectionGolden(raw, Date.parse('2026-08-30T12:01:00Z'))
  assert.deepEqual(verified, { digest: 'sha256:6600d0988813c84d815df8808d3059643519cd2d10262de362e004402b16c74e', host_artifact_digest: `sha256:${'a'.repeat(64)}`, host_team_id: '2DC432GLL2', host_image_identity: `sha256:${'a'.repeat(64)}` })
  await assert.rejects(Promise.resolve().then(() => verifyNativeLifecycleProjectionGolden(JSON.stringify({ ...JSON.parse(raw), host_team_id: 'ATTACKER' }), Date.parse('2026-08-30T12:01:00Z'))), /INVALID_NATIVE_LIFECYCLE_SIGNATURE/)
  const missingHostIdentity = JSON.parse(raw); delete missingHostIdentity.host_image_identity
  await assert.rejects(Promise.resolve().then(() => verifyNativeLifecycleProjectionGolden(JSON.stringify(missingHostIdentity), Date.parse('2026-08-30T12:01:00Z'))), /INVALID_NATIVE_LIFECYCLE_EVIDENCE/)
  const source = await readFile(new URL('../src/native-packages.js', import.meta.url), 'utf8')
  assert.doesNotMatch(source, /node:fs|writeFile|rename\(|mkdir\(|rm\(|lstat|outputDirectory/u)
})

test('Go and JavaScript produce identical canonical package digests for every provider', async () => {
  const golden = JSON.parse(await readFile(new URL('../../../internal/macosattest/testdata/native-package-digests.golden.json', import.meta.url), 'utf8'))
  const fixture = { profile_id: 'profile', profile_revision: 'revision', package_id: 'openduck-mesh', controller_binding_id: 'binding', endpoint_id: 'endpoint', endpoint_generation: 7, endpoint_expires_at: '2026-09-01T00:00:00Z', association_digest: '1'.repeat(64), ui_session_id: 'ui-session', ui_channel_id: 'ui-channel', root_run_id: 'root-run', run_id: 'run', mesh_session_id: 'mesh-session', native_lifecycle_projection_digest: '2'.repeat(64), native_release_id: 'release', native_release_digest: '3'.repeat(64), native_manifest_digest: '4'.repeat(64), native_shim_artifact_digest: '5'.repeat(64), native_socket_generation: 8, native_socket_identity_digest: '6'.repeat(64), native_host_catalog_generation: 9, native_provider_topology_digest: '7'.repeat(64), native_host_artifact_digest: '8'.repeat(64), native_host_team_id: 'TEAMID', native_host_image_identity: '9'.repeat(64), native_lifecycle_expires_at: '2026-09-01T00:00:00Z', capabilities: [...CHILD_OPERATIONS], capability_digest: 'a'.repeat(64) }
  for (const provider of NATIVE_PROVIDERS) assert.equal(nativePackageDigest({ ...fixture, provider }), golden[provider], provider)
})
