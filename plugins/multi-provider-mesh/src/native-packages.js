import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto'

export const NATIVE_PROVIDERS = Object.freeze(['codex', 'claude', 'qwen', 'kimi'])
export const CHILD_OPERATIONS = Object.freeze(['spawn', 'spawnBatch', 'send', 'steer', 'wait', 'collect', 'cancel', 'list', 'status', 'result', 'listProfiles'])
export const NATIVE_PACKAGE_NAME = 'openduck-mesh'
export const NATIVE_MCP_PROTOCOL = '2025-11-25'
export const NATIVE_MCP_TOOL_NAMES = Object.freeze(CHILD_OPERATIONS.map(operation => `openduck_mesh_${operation}`))
const NATIVE_BRIDGE_CONTRACT = 'docs/native-mcp-bridge-contract.md'
const NATIVE_MCP_SERVER_NAME = 'openduck-mesh'
const FIXED_NATIVE_HELPER = '/Library/Application Support/OpenDuck/.openduck-native-mcp'
const KIMI_NATIVE_HELPER = './bin/openduck-native-mcp'
export const NATIVE_RUNTIME_PREREQUISITES = Object.freeze({
  helper_command: FIXED_NATIVE_HELPER,
  installed_helper_path: FIXED_NATIVE_HELPER,
  socket_path: '/private/var/run/openduck/native-mcp.sock',
  installed_helper_evidence: 'required',
  root_owned_listener: 'required',
  host_catalog: 'required',
})
export const NATIVE_PUBLISHER_CONTRACT = Object.freeze({ authority: 'macosattest.VerifyNativePackageCommit', marker: '.openduck-commit.json', schema: 'openduck.native-package-commit.v1', owner: 'root', group: 'trusted_provider_group', mode: '0440', inventory_digest: 'exact_published_files', package_digest: 'exact_signed_receipt', receipt_digest: 'exact_signed_receipt', provider_writable: 'forbidden' })
function registration(manifest, source, location, manifestReference = '', command = FIXED_NATIVE_HELPER) { return Object.freeze({ manifest, available: false, status: 'unavailable', reason: 'production_official_host_launch_unavailable', source, verified_at: '2026-08-30', bridge_contract: NATIVE_BRIDGE_CONTRACT, consumer: NATIVE_PUBLISHER_CONTRACT, mcp: Object.freeze({ location, manifest_reference: manifestReference, server: Object.freeze({ name: NATIVE_MCP_SERVER_NAME, command, args: Object.freeze([]) }) }) }) }
export const NATIVE_PROVIDER_REGISTRATIONS = Object.freeze({
  codex: registration('.codex-plugin/plugin.json', 'https://developers.openai.com/plugins', '.mcp.json', './.mcp.json'),
  claude: registration('.claude-plugin/plugin.json', 'https://code.claude.com/docs/en/plugins-reference', '.mcp.json'),
  qwen: registration('qwen-extension.json', 'https://qwenlm.github.io/qwen-code-docs/en/users/extension/introduction/', 'qwen-extension.json#mcpServers'),
  kimi: registration('kimi.plugin.json', 'https://moonshotai.github.io/kimi-code/en/customization/plugins.html', 'kimi.plugin.json#mcpServers', '', KIMI_NATIVE_HELPER),
})

// Release-pinned, public-only Controller lifecycle trust. Callers cannot
// substitute a verifier or key; a key rotation requires a reviewed plugin
// release carrying the next pinned public key.
export const PINNED_CONTROLLER_KEY_ID = 'openduck-controller-lifecycle-2026-08'
export const PINNED_CONTROLLER_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAZSd56jp9RJgMKQ/djtPvrBZB3VBXeRQ/W7zqSAJ/ilM=
-----END PUBLIC KEY-----
`
const PINNED_CONTROLLER_PUBLIC_KEY = createPublicKey(PINNED_CONTROLLER_PUBLIC_KEY_PEM)
const GOLDEN_CONTROLLER_KEY_ID = 'controller-golden'
const GOLDEN_CONTROLLER_PUBLIC_KEY = createPublicKey({ key: Buffer.from(`302a300506032b657003210079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664`, 'hex'), format: 'der', type: 'spki' })

const RECEIPT_KEYS = Object.freeze(['action', 'association_digest', 'capabilities', 'capability_digest', 'controller_binding_id', 'endpoint_expires_at', 'endpoint_generation', 'endpoint_id', 'expires_at', 'issued_at', 'key_id', 'mesh_session_id', 'native_host_artifact_digest', 'native_host_catalog_generation', 'native_host_image_identity', 'native_host_team_id', 'native_lifecycle_expires_at', 'native_lifecycle_projection_digest', 'native_manifest_digest', 'native_provider_topology_digest', 'native_release_digest', 'native_release_id', 'native_shim_artifact_digest', 'native_socket_generation', 'native_socket_identity_digest', 'nonce', 'package_digest', 'package_id', 'previous_receipt_digest', 'profile_id', 'profile_revision', 'provider', 'receipt_digest', 'receipt_id', 'root_run_id', 'run_id', 'schema_version', 'signature', 'ui_channel_id', 'ui_session_id'])
const UNSIGNED_KEYS = RECEIPT_KEYS.filter(key => key !== 'receipt_digest' && key !== 'signature')
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u
const DIGEST = /^[a-f0-9]{64}$/u
const SECRET_KEY = /(?:credential|secret|token|password|api[_-]?key|authorization|cookie)/iu
const PROVIDER_MANIFEST = Object.freeze(Object.fromEntries(Object.entries(NATIVE_PROVIDER_REGISTRATIONS).map(([provider, registration]) => [provider, registration.manifest])))

function fail(code) { throw new Error(code) }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype }
function exact(value, keys, code) { if (!plain(value) || Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) fail(code); for (const key of Object.keys(value)) if (SECRET_KEY.test(key)) fail('SECRET_FIELD_FORBIDDEN'); return value }
function bounded(value, code, pattern = ID) { if (typeof value !== 'string' || !pattern.test(value)) fail(code); return value }
function instant(value, code) { if (typeof value !== 'string' || value.length > 40 || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/u.test(value)) fail(code); const parsed = new Date(value); if (Number.isNaN(parsed.valueOf()) || parsed.toISOString().replace('.000Z', 'Z') !== value) fail(code); return value }
function projectionInstant(value) { if (typeof value !== 'string' || value.length > 40 || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)$/u.test(value) || Number.isNaN(Date.parse(value))) fail('INVALID_NATIVE_LIFECYCLE_EVIDENCE'); return value }
function inspect(value) { if (typeof value === 'string') { if (value.length > 2048 || SECRET_KEY.test(value)) fail('SECRET_OR_UNBOUNDED_VALUE'); return }; if (Array.isArray(value)) { if (value.length > 32) fail('UNBOUNDED_ARRAY'); value.forEach(inspect); return }; if (plain(value)) { for (const [key, child] of Object.entries(value)) { if (SECRET_KEY.test(key)) fail('SECRET_FIELD_FORBIDDEN'); inspect(child) }; return }; if (value === null || typeof value === 'boolean' || (Number.isSafeInteger(value) && value >= 0)) return; fail('NON_CANONICAL_VALUE') }
export function canonicalJSON(value) { inspect(value); if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`; if (plain(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(',')}}`; return JSON.stringify(value) }
export function sha256(value) { return createHash('sha256').update(value).digest('hex') }

function manifest(provider) {
  const common = { name: NATIVE_PACKAGE_NAME, version: '0.1.0', description: 'Controller-authenticated OpenDuck child-session operations.', author: { name: 'OpenDuck' } }
  const server = NATIVE_PROVIDER_REGISTRATIONS[provider].mcp.server
  const mcpServers = { [server.name]: { command: server.command, args: [] } }
  if (provider === 'codex') return { ...common, author: { name: 'OpenDuck' }, mcpServers: './.mcp.json', interface: { displayName: 'OpenDuck Mesh', shortDescription: 'Authenticated child sessions', longDescription: 'Child-session operations are authorized and relayed exclusively by OpenDuck Controller.', developerName: 'OpenDuck', category: 'Developer Tools', capabilities: [], defaultPrompt: [] } }
  if (provider === 'qwen' || provider === 'kimi') return { ...common, mcpServers }
  return common
}
function descriptorFrom(receipt) { return { schema_version: 'openduck-native-package.v1', provider: receipt.provider, profile_id: receipt.profile_id, profile_revision: receipt.profile_revision, package_id: receipt.package_id, controller: { audience: 'mesh', binding_id: receipt.controller_binding_id, endpoint_id: receipt.endpoint_id, generation: receipt.endpoint_generation, expires_at: receipt.endpoint_expires_at, association_digest: receipt.association_digest, ui_session_id: receipt.ui_session_id, ui_channel_id: receipt.ui_channel_id, root_run_id: receipt.root_run_id, run_id: receipt.run_id, mesh_session_id: receipt.mesh_session_id }, lifecycle: { projection_digest: receipt.native_lifecycle_projection_digest, release_id: receipt.native_release_id, release_digest: receipt.native_release_digest, manifest_digest: receipt.native_manifest_digest, shim_artifact_digest: receipt.native_shim_artifact_digest, socket_generation: receipt.native_socket_generation, socket_identity_digest: receipt.native_socket_identity_digest, host_catalog_generation: receipt.native_host_catalog_generation, provider_topology_digest: receipt.native_provider_topology_digest, host_artifact_digest: receipt.native_host_artifact_digest, host_team_id: receipt.native_host_team_id, host_image_identity: receipt.native_host_image_identity, expires_at: receipt.native_lifecycle_expires_at }, capabilities: [...receipt.capabilities], capability_digest: receipt.capability_digest } }
// The host receives only the fixed, manifest-bound relay command. Session and
// association authority are resolved server-side from the authenticated local
// peer; no token, endpoint, provider credential, or caller-supplied binding is
// written into the package.
function packageFiles(receipt) {
  const descriptor = descriptorFrom(receipt)
  const files = { [PROVIDER_MANIFEST[receipt.provider]]: `${canonicalJSON(manifest(receipt.provider))}\n`, 'openduck.controller-tools.json': `${canonicalJSON(descriptor)}\n` }
  if (receipt.provider === 'codex' || receipt.provider === 'claude') { const server = NATIVE_PROVIDER_REGISTRATIONS[receipt.provider].mcp.server; files['.mcp.json'] = `${canonicalJSON({ mcpServers: { [server.name]: { command: server.command, args: [] } } })}\n` }
  return Object.freeze(files)
}
export function nativePackageDigest(receiptLike) { if (!plain(receiptLike) || !NATIVE_PROVIDERS.includes(receiptLike.provider)) fail('UNSUPPORTED_NATIVE_PROVIDER'); const files = packageFiles(receiptLike); const rows = Object.entries(files).map(([path, contents]) => ({ path, sha256: sha256(contents) })); if (receiptLike.provider === 'kimi') { bounded(receiptLike.native_shim_artifact_digest, 'INVALID_NATIVE_SHIM_ARTIFACT_DIGEST', DIGEST); rows.push({ path: 'bin/openduck-native-mcp', sha256: receiptLike.native_shim_artifact_digest }) }; rows.sort((a, b) => a.path.localeCompare(b.path)); return sha256(canonicalJSON(rows)) }
function signatureBytes(value) { if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{86}$/u.test(value)) fail('INVALID_SIGNATURE'); const decoded = Buffer.from(value, 'base64url'); if (decoded.length !== 64 || decoded.toString('base64url') !== value) fail('INVALID_SIGNATURE'); return decoded }

function validateReceipt(receipt, now) {
  exact(receipt, RECEIPT_KEYS, 'INVALID_RECEIPT_SHAPE')
  if (receipt.schema_version !== 'openduck-native-package-lifecycle-receipt.v1') fail('INVALID_RECEIPT_SCHEMA')
  if (!['enable', 'disable', 'revoke'].includes(receipt.action)) fail('INVALID_LIFECYCLE_ACTION')
  if (!NATIVE_PROVIDERS.includes(receipt.provider)) fail('UNSUPPORTED_NATIVE_PROVIDER')
  if (receipt.package_id !== NATIVE_PACKAGE_NAME || receipt.key_id !== PINNED_CONTROLLER_KEY_ID) fail('UNTRUSTED_CONTROLLER_RECEIPT')
  for (const key of ['receipt_id', 'profile_id', 'profile_revision', 'controller_binding_id', 'ui_session_id', 'ui_channel_id', 'root_run_id', 'run_id', 'mesh_session_id', 'endpoint_id', 'nonce']) bounded(receipt[key], `INVALID_${key.toUpperCase()}`)
  bounded(receipt.native_release_id, 'INVALID_NATIVE_RELEASE_ID')
  if (!Number.isSafeInteger(receipt.endpoint_generation) || receipt.endpoint_generation < 1 || !Number.isSafeInteger(receipt.native_socket_generation) || receipt.native_socket_generation < 1 || !Number.isSafeInteger(receipt.native_host_catalog_generation) || receipt.native_host_catalog_generation < 1) fail('INVALID_NATIVE_GENERATION')
  for (const key of ['association_digest', 'capability_digest', 'package_digest', 'receipt_digest', 'native_lifecycle_projection_digest', 'native_manifest_digest', 'native_provider_topology_digest', 'native_release_digest', 'native_shim_artifact_digest', 'native_socket_identity_digest', 'native_host_artifact_digest', 'native_host_image_identity']) bounded(receipt[key], `INVALID_${key.toUpperCase()}`, DIGEST)
  bounded(receipt.native_host_team_id, 'INVALID_NATIVE_HOST_TEAM_ID')
  if (receipt.previous_receipt_digest !== '' && !DIGEST.test(receipt.previous_receipt_digest)) fail('INVALID_PREVIOUS_RECEIPT_DIGEST')
  instant(receipt.issued_at, 'INVALID_ISSUED_AT'); instant(receipt.expires_at, 'INVALID_EXPIRES_AT'); instant(receipt.endpoint_expires_at, 'INVALID_ENDPOINT_EXPIRY'); instant(receipt.native_lifecycle_expires_at, 'INVALID_NATIVE_LIFECYCLE_EXPIRY')
  if (Date.parse(receipt.issued_at) >= Date.parse(receipt.expires_at) || Date.parse(receipt.issued_at) >= Date.parse(receipt.endpoint_expires_at)) fail('INVALID_RECEIPT_WINDOW')
  if (!Array.isArray(receipt.capabilities) || receipt.capabilities.length !== CHILD_OPERATIONS.length || receipt.capabilities.some((item, index) => item !== CHILD_OPERATIONS[index])) fail('INVALID_CHILD_CAPABILITIES')
  if (receipt.capability_digest !== sha256(canonicalJSON(receipt.capabilities)) || receipt.package_digest !== nativePackageDigest(receipt)) fail('PACKAGE_BINDING_MISMATCH')
  const bytes = canonicalJSON(Object.fromEntries(UNSIGNED_KEYS.map(key => [key, receipt[key]])))
  if (receipt.receipt_digest !== sha256(bytes)) fail('RECEIPT_DIGEST_MISMATCH')
  if (!verifySignature(null, Buffer.from(bytes), PINNED_CONTROLLER_PUBLIC_KEY, signatureBytes(receipt.signature))) fail('CONTROLLER_SIGNATURE_REJECTED')
  if (receipt.action === 'enable' && (Date.parse(receipt.expires_at) <= now || Date.parse(receipt.endpoint_expires_at) <= now)) fail('ENABLE_RECEIPT_EXPIRED')
}
function verifyNativeLifecycle(receipts, now) {
  if (!Array.isArray(receipts) || receipts.length < 1 || receipts.length > 64) fail('INVALID_RECEIPT_CHAIN')
  const seen = new Map(); let previous = ''; let current = null; let revoked = false
  for (const receipt of receipts) {
    validateReceipt(receipt, now)
    const known = seen.get(receipt.receipt_id)
    if (known) { if (known !== receipt.receipt_digest) fail('RECEIPT_ID_COLLISION'); if (receipt.receipt_digest !== previous) fail('NON_CONTIGUOUS_REPLAY'); continue }
    if (receipt.previous_receipt_digest !== previous) fail('RECEIPT_CHAIN_BROKEN')
    if (current && ['provider', 'profile_id', 'profile_revision', 'package_id', 'package_digest', 'controller_binding_id', 'ui_session_id', 'ui_channel_id', 'root_run_id', 'run_id', 'mesh_session_id', 'endpoint_id', 'endpoint_generation', 'association_digest', 'capability_digest', 'native_lifecycle_projection_digest', 'native_release_id', 'native_release_digest', 'native_manifest_digest', 'native_shim_artifact_digest', 'native_socket_generation', 'native_socket_identity_digest', 'native_host_catalog_generation', 'native_provider_topology_digest', 'native_host_artifact_digest', 'native_host_team_id', 'native_host_image_identity', 'native_lifecycle_expires_at'].some(key => receipt[key] !== current[key])) fail('LIFECYCLE_BINDING_CHANGED')
    if (revoked) fail('REVOKED_PACKAGE_TERMINAL')
    seen.set(receipt.receipt_id, receipt.receipt_digest); previous = receipt.receipt_digest; current = receipt
    if (receipt.action === 'revoke') revoked = true
  }
  return Object.freeze({ status: revoked ? 'revoked' : current.action === 'enable' ? 'enabled' : 'disabled', receipt: current, files: packageFiles(current) })
}
const PROJECTION_KEYS = Object.freeze(['schema', 'release_id', 'release_digest', 'manifest_digest', 'shim_artifact_digest', 'socket_generation', 'socket_identity_digest', 'host_catalog_generation', 'provider_topology_digest', 'host_artifact_digest', 'host_team_id', 'host_image_identity', 'observed_at', 'expires_at', 'signer_key_id', 'digest', 'signature'])
function decodeAndVerifyProjection(raw, key, keyID, now) {
  if (typeof raw !== 'string' || raw.length < 2 || raw.length > 16 << 10) fail('NATIVE_LIFECYCLE_EVIDENCE_REQUIRED')
  let projection; try { projection = JSON.parse(raw) } catch { fail('INVALID_NATIVE_LIFECYCLE_EVIDENCE') }
  exact(projection, PROJECTION_KEYS, 'INVALID_NATIVE_LIFECYCLE_EVIDENCE')
  if (JSON.stringify(projection) !== raw || projection.schema !== 'openduck.native-mcp-lifecycle.v1' || projection.signer_key_id !== keyID) fail('INVALID_NATIVE_LIFECYCLE_EVIDENCE')
  projectionInstant(projection.observed_at); projectionInstant(projection.expires_at)
  if (Date.parse(projection.observed_at) > now || Date.parse(projection.expires_at) <= now || Date.parse(projection.expires_at) - Date.parse(projection.observed_at) > 15 * 60 * 1000) fail('NATIVE_LIFECYCLE_EVIDENCE_EXPIRED')
  if (!Number.isSafeInteger(projection.socket_generation) || projection.socket_generation < 1 || !Number.isSafeInteger(projection.host_catalog_generation) || projection.host_catalog_generation < 1) fail('INVALID_NATIVE_LIFECYCLE_EVIDENCE')
  for (const key of ['release_digest', 'manifest_digest', 'shim_artifact_digest', 'socket_identity_digest', 'provider_topology_digest', 'host_artifact_digest', 'host_image_identity', 'digest']) if (typeof projection[key] !== 'string' || !/^sha256:[a-f0-9]{64}$/u.test(projection[key])) fail('INVALID_NATIVE_LIFECYCLE_EVIDENCE')
  bounded(projection.release_id, 'INVALID_NATIVE_LIFECYCLE_EVIDENCE'); bounded(projection.host_team_id, 'INVALID_NATIVE_LIFECYCLE_EVIDENCE')
  const unsigned = { ...projection, digest: '', signature: '' }; const digest = `sha256:${sha256(JSON.stringify(unsigned))}`
  if (projection.digest !== digest || typeof projection.signature !== 'string' || !/^[a-f0-9]{128}$/u.test(projection.signature) || !verifySignature(null, Buffer.from(digest), key, Buffer.from(projection.signature, 'hex'))) fail('INVALID_NATIVE_LIFECYCLE_SIGNATURE')
  return projection
}
function verifyNativeProjection(raw, receipt, now) {
  const projection = decodeAndVerifyProjection(raw, PINNED_CONTROLLER_PUBLIC_KEY, PINNED_CONTROLLER_KEY_ID, now)
  const matches = projection.digest.slice(7) === receipt.native_lifecycle_projection_digest && projection.release_id === receipt.native_release_id && projection.release_digest.slice(7) === receipt.native_release_digest && projection.manifest_digest.slice(7) === receipt.native_manifest_digest && projection.shim_artifact_digest.slice(7) === receipt.native_shim_artifact_digest && projection.socket_generation === receipt.native_socket_generation && projection.socket_identity_digest.slice(7) === receipt.native_socket_identity_digest && projection.host_catalog_generation === receipt.native_host_catalog_generation && projection.provider_topology_digest.slice(7) === receipt.native_provider_topology_digest && projection.host_artifact_digest.slice(7) === receipt.native_host_artifact_digest && projection.host_team_id === receipt.native_host_team_id && projection.host_image_identity.slice(7) === receipt.native_host_image_identity && projection.expires_at === receipt.native_lifecycle_expires_at
  if (!matches) fail('NATIVE_LIFECYCLE_BINDING_MISMATCH')
}
// Cross-language compatibility seam pinned to the public-only Go golden key;
// it cannot authorize a package or substitute production Controller trust.
export function verifyNativeLifecycleProjectionGolden(raw, now = Date.now()) { const projection = decodeAndVerifyProjection(raw, GOLDEN_CONTROLLER_PUBLIC_KEY, GOLDEN_CONTROLLER_KEY_ID, now); return Object.freeze({ digest: projection.digest, host_artifact_digest: projection.host_artifact_digest, host_team_id: projection.host_team_id, host_image_identity: projection.host_image_identity }) }
export async function authorizeNativePackage({ receipts, lifecycleProjection, now = Date.now() }) { const result = verifyNativeLifecycle(receipts, now); if (result.status !== 'enabled') fail(result.status === 'disabled' ? 'PACKAGE_DISABLED' : 'PACKAGE_REVOKED'); verifyNativeProjection(lifecycleProjection, result.receipt, now); if (NATIVE_PROVIDER_REGISTRATIONS[result.receipt.provider].available !== true) fail('NATIVE_BRIDGE_UNAVAILABLE'); return Object.freeze({ provider: result.receipt.provider, package_digest: result.receipt.package_digest, receipt_digest: result.receipt.receipt_digest, files: result.files }) }
// JavaScript is verification-only. Publication, quarantine, and removal require
// the trusted root-owned publisher; pathname authority is never accepted here.
export async function applyNativePackageLifecycle({ receipts, lifecycleProjection, now = Date.now() }) { const lifecycle = verifyNativeLifecycle(receipts, now); if (lifecycle.status === 'enabled') verifyNativeProjection(lifecycleProjection, lifecycle.receipt, now); fail('TRUSTED_NATIVE_PUBLISHER_REQUIRED') }
export async function generateNativePackage(options) { return applyNativePackageLifecycle(options) }
