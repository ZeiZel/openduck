const PROJECTION_SCHEMA = 'openduck-mesh-ui.v1'
const RESPONSE_SCHEMA = 'mesh-ui-response.v1'
const MAX_ITEMS = 64
// Must match mesh.ProposeSpawnBatch's authoritative maximum. Reject excess
// items at the plugin boundary instead of sending a doomed Controller call.
const MAX_BATCH_ITEMS = 16
const MAX_OUTPUT_BYTES = 64 * 1024
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype'])
const PROVIDERS = Object.freeze({
  'codex.chatgpt.app-server': ['codex', 'gpt-5.6'],
  'claude.code.cli': ['claude', 'claude-code'],
  'qwen.general.headless': ['qwen', 'qwen-coder'],
  'qwen.local-pd': ['qwen', 'qwen-local'],
  'kimi.code.acp': ['kimi', 'kimi-code'],
  'deepseek.api': ['deepseek', 'deepseek-chat'],
})
const PROFILE_STATUSES = new Set(['disabled', 'configured', 'auth_required', 'ready', 'degraded', 'compatible', 'incompatible'])
const PROVIDER_NAMES = new Set(['codex', 'claude', 'qwen', 'kimi', 'deepseek'])
const FRESHNESS = new Set(['current', 'stale', 'unknown'])
const RUN_STATUSES = new Set(['queued', 'proposed', 'admitted', 'starting', 'running', 'partial', 'completed', 'failed', 'cancelled', 'uncertain'])
const SESSION_STATES = new Set(['proposed', 'admitted', 'starting', 'running', 'completed', 'failed', 'cancelled', 'uncertain', 'unknown'])
const USAGE_SOURCES = new Set(['unknown', 'provider', 'controller', 'attested'])
const DEPLOYMENT_STATUSES = new Set(['disabled', 'healthy', 'degraded', 'failed', 'unknown'])
const EXPLICITLY_UNAVAILABLE = new Set(['run-synthesis', 'deployment-diagnostics', 'plugin-lifecycle'])
const HEX_DIGEST = /^sha256:[a-f0-9]{64}$/u
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u
const SECRET_SHAPED = /(secret|password|passwd|bearer|authorization|credential|api_key|apikey|private_key|access_key|session_token|oauth|token)/iu

export const SURFACES = Object.freeze([
  'provider-directory', 'ui-provider-switcher', 'session-mesh', 'ui-session-graph',
  'run-compare', 'run-synthesis', 'run-templates', 'policy-approval-inspector',
  'provider-diagnostics', 'deployment-diagnostics', 'plugin-lifecycle',
])

function fail(code) { throw new TypeError(code) }
function record(value, keys, code = 'INVALID_PROJECTION', optional = []) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail(code)
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const own = Object.keys(descriptors)
    if (own.length < keys.length || own.length > keys.length + optional.length || own.some(key => FORBIDDEN_KEYS.has(key) || (!keys.includes(key) && !optional.includes(key)))) fail(code)
    const out = Object.create(null)
    for (const key of keys) {
      const descriptor = descriptors[key]
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value') || !descriptor.enumerable) fail(code)
      out[key] = descriptor.value
    }
	for (const key of optional) {
	  const descriptor = descriptors[key]
	  if (descriptor !== undefined) {
	    if (!Object.prototype.hasOwnProperty.call(descriptor, 'value') || !descriptor.enumerable) fail(code)
	    out[key] = descriptor.value
	  }
	}
    return out
  } catch (error) {
    if (error instanceof TypeError && error.message === code) throw error
    fail(code)
  }
}
function array(value, max = MAX_ITEMS, code = 'INVALID_PROJECTION') {
  try {
    if (!Array.isArray(value) || value.length > max) fail(code)
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const out = []
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)]
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value') || !descriptor.enumerable) fail(code)
      out.push(descriptor.value)
    }
    return out
  } catch (error) {
    if (error instanceof TypeError && error.message === code) throw error
    fail(code)
  }
}
function text(value, max = 256, code = 'INVALID_PROJECTION') {
  if (typeof value !== 'string' || value.length === 0 || value.length > max || /[\0\r\n]/u.test(value) || SECRET_SHAPED.test(value)) fail(code)
  return value
}
function id(value, code = 'INVALID_PROJECTION') { const result = text(value, 256, code); if (!SAFE_ID.test(result)) fail(code); return result }
function digest(value, code = 'INVALID_PROJECTION') { if (typeof value !== 'string' || !HEX_DIGEST.test(value)) fail(code); return value }
function timestamp(value, code = 'INVALID_PROJECTION') { const result = text(value, 64, code); const date = new Date(result); if (Number.isNaN(date.valueOf()) || date.toISOString() !== result) fail(code); return result }
function positiveInteger(value, code = 'INVALID_PROJECTION') { if (!Number.isSafeInteger(value) || value <= 0) fail(code); return value }
function finiteQuantity(value, code = 'INVALID_PROJECTION') { if (!Number.isSafeInteger(value) || value < 0) fail(code); return value }
function freeze(value) {
  if (Array.isArray(value)) { for (const item of value) freeze(item) } else if (value && typeof value === 'object') { for (const key of Object.keys(value)) freeze(value[key]) }
  return Object.freeze(value)
}
function budget(value, code) {
  // value is freshly reconstructed from primitive validated fields; rejected raw
  // input is never stringified or logged.
  let bytes
  try { bytes = new TextEncoder().encode(JSON.stringify(value)).length } catch { fail(code) }
  if (bytes > MAX_OUTPUT_BYTES) fail(code)
  return freeze(value)
}
function cloneSafe(value) { return JSON.parse(JSON.stringify(value)) }
function unique(values, key, code) {
  const seen = new Set()
  for (const value of values) { const item = key(value); if (seen.has(item)) fail(code); seen.add(item) }
  return values
}

function profile(value, code = 'INVALID_PROJECTION') {
  const v = record(value, ['profile_id', 'provider', 'model', 'status', 'mesh_spawn', 'local_only'], code)
  const profileID = id(v.profile_id, code)
  const expected = PROVIDERS[profileID]
  // "ready" is informational only: v1 mesh capability comes solely from an
  // explicitly compatible Controller profile.
  if (!expected || v.provider !== expected[0] || v.model !== expected[1] || !PROFILE_STATUSES.has(v.status) || typeof v.mesh_spawn !== 'boolean' || typeof v.local_only !== 'boolean' || (v.mesh_spawn && v.status !== 'compatible')) fail(code)
  return { profile_id: profileID, provider: v.provider, model: v.model, status: v.status, mesh_spawn: v.mesh_spawn, local_only: v.local_only }
}
function profiles(value, code = 'INVALID_PROJECTION') {
  const values = array(value, MAX_ITEMS, code).map(item => profile(item, code))
  if (values.length !== Object.keys(PROVIDERS).length) fail(code)
  unique(values, item => item.profile_id, code)
  if (values.some(item => !Object.prototype.hasOwnProperty.call(PROVIDERS, item.profile_id))) fail(code)
  return values
}
function profileSubset(value, code = 'INVALID_RESPONSE') {
  const values = array(value, Object.keys(PROVIDERS).length, code).map(item => profile(item, code))
  unique(values, item => item.profile_id, code)
  return values
}
function providerProfile(provider, profileID, code) { const expected = PROVIDERS[profileID]; if (!expected || expected[0] !== provider) fail(code) }
function graph(value, code = 'INVALID_PROJECTION') {
  const v = record(value, ['nodes', 'edges'], code)
  const nodes = array(v.nodes, MAX_ITEMS, code).map(raw => {
    const node = record(raw, ['id', 'status', 'provider', 'profile_id'], code)
    const nodeID = id(node.id, code); const profileID = id(node.profile_id, code); providerProfile(node.provider, profileID, code)
    if (!RUN_STATUSES.has(node.status)) fail(code)
    return { id: nodeID, status: node.status, provider: node.provider, profile_id: profileID }
  })
  unique(nodes, node => node.id, code)
  const nodeIDs = new Set(nodes.map(node => node.id))
  const edges = array(v.edges, MAX_ITEMS, code).map(raw => {
    const edge = record(raw, ['from', 'to', 'type'], code); const from = id(edge.from, code); const to = id(edge.to, code)
    if (!nodeIDs.has(from) || !nodeIDs.has(to) || from === to || !['spawn', 'send', 'steer', 'synthesis'].includes(edge.type)) fail(code)
    return { from, to, type: edge.type }
  })
  unique(edges, edge => `${edge.from}\u0000${edge.to}\u0000${edge.type}`, code)
  return { nodes, edges }
}
function compare(value, code = 'INVALID_PROJECTION') {
  const v = record(value, ['runs'], code)
  const runs = array(v.runs, MAX_ITEMS, code).map(raw => {
    const run = record(raw, ['provider', 'profile_id', 'status', 'result_available'], code, ['result_ref']); const profileID = id(run.profile_id, code)
    providerProfile(run.provider, profileID, code); if (!RUN_STATUSES.has(run.status)) fail(code)
    if (typeof run.result_available !== 'boolean' || (run.result_available && !Object.prototype.hasOwnProperty.call(run, 'result_ref')) || (!run.result_available && Object.prototype.hasOwnProperty.call(run, 'result_ref'))) fail(code)
    const result = { provider: run.provider, profile_id: profileID, status: run.status, result_available: run.result_available }
    if (run.result_available) result.result_ref = id(run.result_ref, code)
    return result
  })
  unique(runs, run => `${run.profile_id}\u0000${run.status}\u0000${run.result_ref ?? ''}`, code)
  return { runs }
}
function diagnostics(value, code = 'INVALID_PROJECTION') {
  const v = record(value, ['providers'], code)
  const providers = array(v.providers, MAX_ITEMS, code).map(raw => {
    const entry = record(raw, ['profile_id', 'status', 'freshness'], code); const profileID = id(entry.profile_id, code)
    if (!PROVIDERS[profileID] || !PROFILE_STATUSES.has(entry.status) || !FRESHNESS.has(entry.freshness)) fail(code)
    return { profile_id: profileID, status: entry.status, freshness: entry.freshness }
  })
  unique(providers, entry => entry.profile_id, code)
  return { providers }
}
function policy(value, code = 'INVALID_PROJECTION') {
  const v = record(value, ['approvals'], code)
  const approvals = array(v.approvals, MAX_ITEMS, code).map(raw => {
    const entry = record(raw, ['decision_type', 'status', 'expires_at'], code)
    if (!['provider-switch', 'fanout-grant', 'cloud-disclosure', 'plugin-lifecycle', 'deployment'].includes(entry.decision_type) || !['pending', 'approved', 'denied', 'revoked', 'expired'].includes(entry.status)) fail(code)
    return { decision_type: entry.decision_type, status: entry.status, expires_at: timestamp(entry.expires_at, code) }
  })
  unique(approvals, entry => `${entry.decision_type}\u0000${entry.status}\u0000${entry.expires_at}`, code)
  return { approvals }
}
function templates(value, code = 'INVALID_PROJECTION') {
  const v = record(value, ['approved'], code)
  const approved = array(v.approved, MAX_ITEMS, code).map(raw => { const entry = record(raw, ['template_id', 'version'], code); return { template_id: id(entry.template_id, code), version: id(entry.version, code) } })
  unique(approved, entry => `${entry.template_id}\u0000${entry.version}`, code)
  return { approved }
}
function lifecycle(value, code = 'INVALID_PROJECTION') {
  const v = record(value, ['packages'], code)
  const packages = array(v.packages, MAX_ITEMS, code).map(raw => {
    const entry = record(raw, ['package_id', 'digest', 'status'], code)
    if (!['disabled', 'planned', 'enabled', 'rolled_back', 'incompatible', 'revoked'].includes(entry.status)) fail(code)
    return { package_id: id(entry.package_id, code), digest: digest(entry.digest, code), status: entry.status }
  })
  unique(packages, entry => entry.package_id, code)
  return { packages }
}
function unavailable(value, code = 'INVALID_PROJECTION') {
  const values = array(value, MAX_ITEMS, code).map(item => id(item, code))
  unique(values.map(item => ({ item })), entry => entry.item, code)
  if (values.some(item => !EXPLICITLY_UNAVAILABLE.has(item))) fail(code)
  return values
}
function projection(value) {
  const v = record(value, ['schema_version', 'revision_id', 'profiles', 'graph', 'compare', 'diagnostics', 'policy', 'templates', 'lifecycle', 'unavailable'])
  if (v.schema_version !== PROJECTION_SCHEMA) fail('INVALID_PROJECTION')
  const selectedProfiles = profiles(v.profiles)
  const selectedDiagnostics = diagnostics(v.diagnostics)
  const selectedLifecycle = lifecycle(v.lifecycle)
  const byProfile = new Map(selectedProfiles.map(item => [item.profile_id, item]))
  for (const entry of selectedDiagnostics.providers) {
    const selected = byProfile.get(entry.profile_id)
    if (!selected || selected.status !== entry.status) fail('INVALID_PROJECTION')
  }
  const freshness = new Map(selectedDiagnostics.providers.map(entry => [entry.profile_id, entry.freshness]))
  const hasEligibleProfile = selectedProfiles.some(item => item.status === 'compatible' && item.mesh_spawn && freshness.get(item.profile_id) === 'current')
  if (selectedLifecycle.packages.some(item => item.status === 'enabled') && !hasEligibleProfile) fail('INVALID_PROJECTION')
  return budget({ schema_version: v.schema_version, revision_id: id(v.revision_id), profiles: selectedProfiles, graph: graph(v.graph), compare: compare(v.compare), diagnostics: selectedDiagnostics, policy: policy(v.policy), templates: templates(v.templates), lifecycle: selectedLifecycle, unavailable: unavailable(v.unavailable) }, 'INVALID_PROJECTION')
}

function profileFilter(value) {
  const v = record(value, [], 'INVALID_PROFILE_FILTER', ['provider', 'status', 'local_only', 'mesh_eligible', 'freshness'])
  if (Object.prototype.hasOwnProperty.call(v, 'provider') && (typeof v.provider !== 'string' || !PROVIDER_NAMES.has(v.provider))) fail('INVALID_PROFILE_FILTER')
  if (Object.prototype.hasOwnProperty.call(v, 'status') && (typeof v.status !== 'string' || !PROFILE_STATUSES.has(v.status))) fail('INVALID_PROFILE_FILTER')
  if (Object.prototype.hasOwnProperty.call(v, 'local_only') && typeof v.local_only !== 'boolean') fail('INVALID_PROFILE_FILTER')
  if (Object.prototype.hasOwnProperty.call(v, 'mesh_eligible') && typeof v.mesh_eligible !== 'boolean') fail('INVALID_PROFILE_FILTER')
  if (Object.prototype.hasOwnProperty.call(v, 'freshness') && (typeof v.freshness !== 'string' || !FRESHNESS.has(v.freshness))) fail('INVALID_PROFILE_FILTER')
  return v
}
function switchProfileOptions(current, filter) {
  const freshness = new Map(current.diagnostics.providers.map(entry => [entry.profile_id, entry.freshness]))
  const options = current.profiles.map(item => {
    const evidenceFreshness = freshness.get(item.profile_id) ?? 'unknown'
    const meshEligible = item.status === 'compatible' && item.mesh_spawn && evidenceFreshness === 'current'
    return { ...item, freshness: evidenceFreshness, mesh_eligible: meshEligible }
  }).filter(item =>
    (!Object.prototype.hasOwnProperty.call(filter, 'provider') || item.provider === filter.provider) &&
    (!Object.prototype.hasOwnProperty.call(filter, 'status') || item.status === filter.status) &&
    (!Object.prototype.hasOwnProperty.call(filter, 'local_only') || item.local_only === filter.local_only) &&
    (!Object.prototype.hasOwnProperty.call(filter, 'mesh_eligible') || item.mesh_eligible === filter.mesh_eligible) &&
    (!Object.prototype.hasOwnProperty.call(filter, 'freshness') || item.freshness === filter.freshness),
  )
  return budget(options, 'INVALID_PROFILE_FILTER')
}

function limits(value) {
  const v = record(value, ['max_depth', 'max_children_per_parent', 'max_concurrent_runs', 'max_input_tokens', 'max_output_tokens', 'max_wall_ms', 'max_attempts', 'max_result_bytes', 'cost'])
  for (const key of ['max_depth', 'max_children_per_parent', 'max_concurrent_runs', 'max_input_tokens', 'max_output_tokens', 'max_wall_ms', 'max_attempts', 'max_result_bytes']) positiveInteger(v[key])
  const cost = record(v.cost, ['kind', 'currency', 'minor_unit_exponent', 'max_minor_units', 'unit', 'max_quantity'])
  if (cost.kind === 'monetary') {
    if (typeof cost.currency !== 'string' || !/^[A-Z]{3}$/u.test(cost.currency) || !Number.isSafeInteger(cost.minor_unit_exponent) || cost.minor_unit_exponent < 0 || cost.minor_unit_exponent > 3 || !positiveInteger(cost.max_minor_units) || cost.unit !== '' || cost.max_quantity !== 0) fail('INVALID_PROJECTION')
  } else if (cost.kind === 'non_monetary') {
    if (cost.currency !== '' || cost.minor_unit_exponent !== 0 || cost.max_minor_units !== 0 || !['request', 'token', 'compute_ms'].includes(cost.unit) || !positiveInteger(cost.max_quantity)) fail('INVALID_PROJECTION')
  } else fail('INVALID_PROJECTION')
  return { max_depth: v.max_depth, max_children_per_parent: v.max_children_per_parent, max_concurrent_runs: v.max_concurrent_runs, max_input_tokens: v.max_input_tokens, max_output_tokens: v.max_output_tokens, max_wall_ms: v.max_wall_ms, max_attempts: v.max_attempts, max_result_bytes: v.max_result_bytes, cost: { kind: cost.kind, currency: cost.currency, minor_unit_exponent: cost.minor_unit_exponent, max_minor_units: cost.max_minor_units, unit: cost.unit, max_quantity: cost.max_quantity } }
}
function meshRequest(operation, request) {
  if (operation === 'spawn') {
    const v = record(request, ['client_nonce', 'objective', 'preferred_profile', 'requested_role', 'output_schema_ref', 'requested_limits'], 'INVALID_MESH_PROPOSAL')
    const preferred = id(v.preferred_profile, 'INVALID_MESH_PROPOSAL'); if (!PROVIDERS[preferred]) fail('INVALID_MESH_PROPOSAL')
    return budget({ client_nonce: id(v.client_nonce, 'INVALID_MESH_PROPOSAL'), objective: text(v.objective, 4096, 'INVALID_MESH_PROPOSAL'), preferred_profile: preferred, requested_role: id(v.requested_role, 'INVALID_MESH_PROPOSAL'), output_schema_ref: id(v.output_schema_ref, 'INVALID_MESH_PROPOSAL'), requested_limits: limits(v.requested_limits) }, 'INVALID_MESH_PROPOSAL')
  }
  if (operation === 'spawnBatch') { const v = record(request, ['proposals'], 'INVALID_MESH_PROPOSAL'); const proposals = array(v.proposals, MAX_BATCH_ITEMS, 'INVALID_MESH_PROPOSAL'); if (proposals.length === 0) fail('INVALID_MESH_PROPOSAL'); return budget({ proposals: proposals.map(item => meshRequest('spawn', item)) }, 'INVALID_MESH_PROPOSAL') }
  if (operation === 'send' || operation === 'steer') { const v = record(request, ['run_id', 'input_ref'], 'INVALID_MESH_PROPOSAL'); return budget({ run_id: id(v.run_id, 'INVALID_MESH_PROPOSAL'), input_ref: id(v.input_ref, 'INVALID_MESH_PROPOSAL') }, 'INVALID_MESH_PROPOSAL') }
  if (['wait', 'collect', 'status', 'result'].includes(operation)) { const v = record(request, ['run_id', 'revision_ref'], 'INVALID_MESH_PROPOSAL'); return budget({ run_id: id(v.run_id, 'INVALID_MESH_PROPOSAL'), revision_ref: id(v.revision_ref, 'INVALID_MESH_PROPOSAL') }, 'INVALID_MESH_PROPOSAL') }
  if (operation === 'cancel') { const v = record(request, ['run_id', 'reason_ref', 'revision_ref'], 'INVALID_MESH_PROPOSAL'); return budget({ run_id: id(v.run_id, 'INVALID_MESH_PROPOSAL'), reason_ref: id(v.reason_ref, 'INVALID_MESH_PROPOSAL'), revision_ref: id(v.revision_ref, 'INVALID_MESH_PROPOSAL') }, 'INVALID_MESH_PROPOSAL') }
  if (operation === 'list') { const v = record(request, ['root_id', 'revision_ref'], 'INVALID_MESH_PROPOSAL'); return budget({ root_id: id(v.root_id, 'INVALID_MESH_PROPOSAL'), revision_ref: id(v.revision_ref, 'INVALID_MESH_PROPOSAL') }, 'INVALID_MESH_PROPOSAL') }
  if (operation === 'listProfiles') { record(request, [], 'INVALID_MESH_PROPOSAL'); return freeze({}) }
  fail('INVALID_MESH_PROPOSAL')
}
function lifecycleRequest(value) {
  const v = record(value, ['schema_version', 'action', 'package_id', 'package_digest', 'profile_revision', 'controller_binding_id', 'expires_at'])
  if (v.schema_version !== 'plugin-lifecycle-request.v1' || !['enable', 'disable', 'update', 'rollback'].includes(v.action)) fail('INVALID_PROJECTION')
  return budget({ schema_version: v.schema_version, action: v.action, package_id: id(v.package_id), package_digest: digest(v.package_digest), profile_revision: id(v.profile_revision), controller_binding_id: id(v.controller_binding_id), expires_at: timestamp(v.expires_at) }, 'INVALID_PROJECTION')
}
function surfaceRequest(surface, request) {
  if (surface === 'plugin-lifecycle') return lifecycleRequest(request)
  if (surface === 'provider-directory' || surface === 'provider-diagnostics') { const v = record(request, ['action', 'profile_id']); const profileID = id(v.profile_id); if (v.action !== 'refresh' || !PROVIDERS[profileID]) fail('INVALID_PROJECTION'); return budget({ action: v.action, profile_id: profileID }, 'INVALID_PROJECTION') }
  if (surface === 'ui-session-graph') { const v = record(request, ['root_id']); return budget({ root_id: id(v.root_id) }, 'INVALID_PROJECTION') }
  if (surface === 'run-compare') { const v = record(request, ['run_ids']); const runIDs = array(v.run_ids, MAX_ITEMS).map(item => id(item)); if (runIDs.length === 0) fail('INVALID_PROJECTION'); unique(runIDs.map(value => ({ value })), item => item.value, 'INVALID_PROJECTION'); return budget({ run_ids: runIDs }, 'INVALID_PROJECTION') }
  if (surface === 'run-synthesis') { const v = record(request, ['template_id', 'source_result_refs']); const refs = array(v.source_result_refs, MAX_ITEMS).map(item => id(item)); if (refs.length === 0) fail('INVALID_PROJECTION'); unique(refs.map(value => ({ value })), item => item.value, 'INVALID_PROJECTION'); return budget({ template_id: id(v.template_id), source_result_refs: refs }, 'INVALID_PROJECTION') }
  if (surface === 'run-templates') { const v = record(request, ['template_id', 'version']); return budget({ template_id: id(v.template_id), version: id(v.version) }, 'INVALID_PROJECTION') }
  if (surface === 'policy-approval-inspector') { const v = record(request, ['decision_ref']); return budget({ decision_ref: id(v.decision_ref) }, 'INVALID_PROJECTION') }
  if (surface === 'deployment-diagnostics') { const v = record(request, ['action']); if (v.action !== 'doctor') fail('INVALID_PROJECTION'); return budget({ action: v.action }, 'INVALID_PROJECTION') }
  fail('INVALID_PROPOSAL')
}

function proposalOutput(value, code) {
  const v = record(value, ['proposal_id', 'run_id', 'session_id', 'order_id', 'binding_id', 'replayed'], code)
  if (typeof v.replayed !== 'boolean') fail(code)
  return { proposal_id: id(v.proposal_id, code), run_id: id(v.run_id, code), session_id: id(v.session_id, code), order_id: id(v.order_id, code), binding_id: id(v.binding_id, code), replayed: v.replayed }
}
function acknowledgement(value, code, expectedStatus, referenceKind) {
  const fields = referenceKind === 'input'
    ? ['target_run_id', 'input_ref', 'digest', 'status']
    : referenceKind === 'cancel'
      ? ['target_run_id', 'revision_ref', 'reason_ref', 'digest', 'status']
      : referenceKind === 'revision'
        ? ['target_run_id', 'revision_ref', 'digest', 'status']
        : null
  if (fields === null) fail(code)
  const v = record(value, fields, code)
  if (v.status !== expectedStatus) fail(code)
  const base = { target_run_id: id(v.target_run_id, code), digest: digest(v.digest, code), status: v.status }
  if (referenceKind === 'input') return { ...base, input_ref: id(v.input_ref, code) }
  if (referenceKind === 'cancel') return { ...base, revision_ref: id(v.revision_ref, code), reason_ref: id(v.reason_ref, code) }
  return { ...base, revision_ref: id(v.revision_ref, code) }
}
function sessionStatus(value, code) {
  const v = record(value, ['state', 'usage_source'], code)
  if (!SESSION_STATES.has(v.state) || !USAGE_SOURCES.has(v.usage_source)) fail(code)
  return { state: v.state, usage_source: v.usage_source }
}
function resultEnvelope(value, code) {
  const v = record(value, ['run_id', 'attempt_id', 'status', 'output_artifact_ref', 'schema_ref', 'provenance_digest', 'classification'], code)
  if (!SESSION_STATES.has(v.status) || !['L0', 'L1', 'L2', 'L3', 'PD'].includes(v.classification)) fail(code)
  return { run_id: id(v.run_id, code), attempt_id: id(v.attempt_id, code), status: v.status, output_artifact_ref: id(v.output_artifact_ref, code), schema_ref: id(v.schema_ref, code), provenance_digest: digest(v.provenance_digest, code), classification: v.classification }
}
function runListItem(value, code) {
  const v = record(value, ['run_id', 'profile_id', 'provider', 'status', 'depth'], code); const profileID = id(v.profile_id, code)
  providerProfile(v.provider, profileID, code); if (!SESSION_STATES.has(v.status)) fail(code)
  return { run_id: id(v.run_id, code), profile_id: profileID, provider: v.provider, status: v.status, depth: finiteQuantity(v.depth, code) }
}
function selectionOutput(value, code) { const v = record(value, ['revision_id', 'active_turn_changed'], code); if (v.active_turn_changed !== false) fail(code); return { revision_id: id(v.revision_id, code), active_turn_changed: false } }
function spawnOutput(value, code) { const v = record(value, ['proposal'], code); return { proposal: proposalOutput(v.proposal, code) } }
function spawnBatchOutput(value, code) { const v = record(value, ['batch_id', 'results', 'partial'], code); if (typeof v.partial !== 'boolean') fail(code); const results = array(v.results, MAX_BATCH_ITEMS, code).map(item => proposalOutput(item, code)); if (results.length === 0) fail(code); unique(results, item => item.proposal_id, code); return { batch_id: id(v.batch_id, code), results, partial: v.partial } }
function acknowledgementOutput(value, code, status, referenceKind) { const v = record(value, ['acknowledgement'], code); return { acknowledgement: acknowledgement(v.acknowledgement, code, status, referenceKind) } }
function listOutput(value, code) { const v = record(value, ['runs'], code); const runs = array(v.runs, MAX_ITEMS, code).map(item => runListItem(item, code)); unique(runs, item => item.run_id, code); return { runs } }
function profilesOutput(value, code) { const v = record(value, ['profiles'], code); return { profiles: profileSubset(v.profiles, code) } }
function graphOutput(value, code) { const v = record(value, ['graph'], code); return { graph: graph(v.graph, code) } }
function compareOutput(value, code) { const v = record(value, ['compare'], code); return { compare: compare(v.compare, code) } }
function templatesOutput(value, code) { const v = record(value, ['templates'], code); return { templates: templates(v.templates, code) } }
function policyOutput(value, code) { const v = record(value, ['policy'], code); return { policy: policy(v.policy, code) } }
function diagnosticsOutput(value, code) { const v = record(value, ['diagnostics'], code); return { diagnostics: diagnostics(v.diagnostics, code) } }
function deploymentOutput(value, code) { const v = record(value, ['status', 'acknowledgement'], code); if (!DEPLOYMENT_STATUSES.has(v.status)) fail(code); return { status: v.status, acknowledgement: acknowledgement(v.acknowledgement, code, 'completed', 'revision') } }
function lifecycleOutput(value, code) { const v = record(value, ['package', 'acknowledgement'], code); const packageValue = lifecycle({ packages: [v.package] }, code).packages[0]; return { package: packageValue, acknowledgement: acknowledgement(v.acknowledgement, code, 'completed', 'revision') } }

const RESPONSE_PAYLOAD = Object.freeze({
  'selection-revision': ['selection', selectionOutput],
  'mesh-spawn': ['spawn', spawnOutput],
  'mesh-spawnBatch': ['spawn_batch', spawnBatchOutput],
  'mesh-send': ['send', value => acknowledgementOutput(value, 'INVALID_RESPONSE', 'sent', 'input')],
  'mesh-steer': ['steer', value => acknowledgementOutput(value, 'INVALID_RESPONSE', 'sent', 'input')],
  'mesh-wait': ['wait', sessionStatus],
  'mesh-collect': ['collect', resultEnvelope],
  'mesh-cancel': ['cancel', value => acknowledgementOutput(value, 'INVALID_RESPONSE', 'cancelled', 'cancel')],
  'mesh-list': ['list', listOutput],
  'mesh-status': ['status', sessionStatus],
  'mesh-result': ['result', resultEnvelope],
  'mesh-listProfiles': ['list_profiles', profilesOutput],
  'provider-directory': ['directory', profilesOutput],
  'ui-session-graph': ['graph', graphOutput],
  'run-compare': ['compare', compareOutput],
  'run-synthesis': ['synthesis', resultEnvelope],
  'run-templates': ['templates', templatesOutput],
  'policy-approval-inspector': ['policy', policyOutput],
  'provider-diagnostics': ['diagnostics', diagnosticsOutput],
  'deployment-diagnostics': ['deployment', deploymentOutput],
  'plugin-lifecycle': ['plugin_lifecycle', lifecycleOutput],
})
function response(expectedKind, value) {
  const definition = RESPONSE_PAYLOAD[expectedKind]
  if (!definition) fail('INVALID_RESPONSE')
  const [payloadKey, payloadValidator] = definition
  const v = record(value, ['schema_version', 'kind', payloadKey], 'INVALID_RESPONSE')
  if (v.schema_version !== RESPONSE_SCHEMA || v.kind !== expectedKind) fail('INVALID_RESPONSE')
  return budget({ schema_version: v.schema_version, kind: v.kind, [payloadKey]: payloadValidator(v[payloadKey], 'INVALID_RESPONSE') }, 'INVALID_RESPONSE')
}

// createMeshUI uses an injected, authenticated Controller UI client. It has no
// DSH, model, session, event-log, storage, network, or native-plugin imports.
export function createMeshUI({ uiClient }) {
  if (!uiClient || typeof uiClient.readProjection !== 'function' || typeof uiClient.propose !== 'function') fail('INVALID_UI_CLIENT')
  let current = null
  let disposed = false
  const requireLive = () => { if (disposed) fail('UI_DISPOSED') }
  const refresh = async () => { requireLive(); try { current = projection(await uiClient.readProjection('mesh')); return current } catch (error) { current = null; throw error } }
  const state = () => current === null ? null : cloneSafe(current)
  const requireProfile = profileID => { if (current === null) fail('PROJECTION_REQUIRED'); const value = id(profileID); const found = current.profiles.find(item => item.profile_id === value); if (!found) fail('UNKNOWN_PROFILE'); return found }
  const profileOptions = (filter = {}) => { requireLive(); if (current === null) fail('PROJECTION_REQUIRED'); return switchProfileOptions(current, profileFilter(filter)) }
  const submit = async (kind, request) => response(kind, await uiClient.propose(kind, request))
  const selection = async value => {
    requireLive(); const request = record(value, ['profile_id', 'operation'], 'INVALID_SWITCH_OPERATION'); const selected = requireProfile(request.profile_id)
    if (!['new-root', 'new-child', 'clean-fork', 'model-only-new-session'].includes(request.operation)) fail('INVALID_SWITCH_OPERATION')
    const selectedOption = profileOptions({ provider: selected.provider }).find(item => item.profile_id === selected.profile_id)
    if (!selectedOption || !selectedOption.mesh_eligible) fail('PROFILE_NOT_MESH_ELIGIBLE')
    return submit('selection-revision', freeze({ profile_id: selected.profile_id, operation: request.operation, base_revision_id: current.revision_id }))
  }
  const mesh = async (operation, request) => {
    requireLive(); if (!['spawn', 'spawnBatch', 'send', 'steer', 'wait', 'collect', 'cancel', 'list', 'status', 'result', 'listProfiles'].includes(operation)) fail('INVALID_MESH_PROPOSAL')
    return submit(`mesh-${operation}`, meshRequest(operation, request))
  }
  const proposal = async (surface, request) => {
    requireLive(); if (!SURFACES.includes(surface) || surface === 'ui-provider-switcher' || surface === 'session-mesh') fail('INVALID_PROPOSAL')
    if (current !== null && current.unavailable.includes(surface)) fail('SURFACE_UNAVAILABLE')
    return submit(surface, surfaceRequest(surface, request))
  }
  const children = Object.freeze({
    spawn: request => mesh('spawn', request), spawnBatch: request => mesh('spawnBatch', request),
    send: request => mesh('send', request), steer: request => mesh('steer', request),
    wait: request => mesh('wait', request), collect: request => mesh('collect', request),
    cancel: request => mesh('cancel', request), list: request => mesh('list', request),
    status: request => mesh('status', request), result: request => mesh('result', request),
    listProfiles: () => mesh('listProfiles', {}),
  })
  return Object.freeze({ refresh, state, profileOptions, select: selection, mesh, children, proposal, dispose: () => { disposed = true; current = null } })
}

export { applyNativePackageLifecycle, authorizeNativePackage, canonicalJSON, CHILD_OPERATIONS, generateNativePackage, nativePackageDigest, NATIVE_MCP_PROTOCOL, NATIVE_MCP_TOOL_NAMES, NATIVE_PACKAGE_NAME, NATIVE_PROVIDERS, NATIVE_PROVIDER_REGISTRATIONS, NATIVE_PUBLISHER_CONTRACT, NATIVE_RUNTIME_PREREQUISITES, PINNED_CONTROLLER_KEY_ID, PINNED_CONTROLLER_PUBLIC_KEY_PEM, sha256, verifyNativeLifecycleProjectionGolden } from './native-packages.js'
