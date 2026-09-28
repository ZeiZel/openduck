import test from 'node:test'
import assert from 'node:assert/strict'
import { createMeshUI, SURFACES } from '../src/index.js'

const digest = 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const limits = () => ({ max_depth: 1, max_children_per_parent: 1, max_concurrent_runs: 1, max_input_tokens: 1, max_output_tokens: 1, max_wall_ms: 1, max_attempts: 1, max_result_bytes: 1, cost: { kind: 'non_monetary', currency: '', minor_unit_exponent: 0, max_minor_units: 0, unit: 'token', max_quantity: 1 } })
const profiles = () => [
  { profile_id: 'codex.chatgpt.app-server', provider: 'codex', model: 'gpt-5.6', status: 'disabled', mesh_spawn: false, local_only: false },
  { profile_id: 'claude.code.cli', provider: 'claude', model: 'claude-code', status: 'disabled', mesh_spawn: false, local_only: false },
  { profile_id: 'qwen.general.headless', provider: 'qwen', model: 'qwen-coder', status: 'disabled', mesh_spawn: false, local_only: false },
  { profile_id: 'qwen.local-pd', provider: 'qwen', model: 'qwen-local', status: 'disabled', mesh_spawn: false, local_only: true },
  { profile_id: 'kimi.code.acp', provider: 'kimi', model: 'kimi-code', status: 'disabled', mesh_spawn: false, local_only: false },
  { profile_id: 'deepseek.api', provider: 'deepseek', model: 'deepseek-chat', status: 'disabled', mesh_spawn: false, local_only: false },
]
const safeProjection = () => ({ schema_version: 'openduck-mesh-ui.v1', revision_id: 'mesh-disabled', profiles: profiles(), graph: { nodes: [{ id: 'run-1', status: 'running', provider: 'codex', profile_id: 'codex.chatgpt.app-server' }], edges: [] }, compare: { runs: [{ provider: 'codex', profile_id: 'codex.chatgpt.app-server', status: 'running', result_available: false }] }, diagnostics: { providers: [{ profile_id: 'codex.chatgpt.app-server', status: 'disabled', freshness: 'unknown' }] }, policy: { approvals: [{ decision_type: 'plugin-lifecycle', status: 'pending', expires_at: '2026-08-26T00:00:00.000Z' }] }, templates: { approved: [{ template_id: 'research', version: 'v1' }] }, lifecycle: { packages: [] }, unavailable: [] })
const switchableProjection = ({ status = 'compatible', mesh_spawn = true, freshness = 'current' } = {}) => {
  const value = safeProjection()
  const selected = value.profiles.find(item => item.profile_id === 'deepseek.api')
  selected.status = status
  selected.mesh_spawn = mesh_spawn
  value.diagnostics.providers.push({ profile_id: selected.profile_id, status, freshness })
  return value
}
const enabledProjection = options => {
  const value = switchableProjection(options)
  value.lifecycle.packages = [{ package_id: 'openduck-mesh', digest, status: 'enabled' }]
  return value
}
const proposal = () => ({ proposal_id: 'proposal-1', run_id: 'run-1', session_id: 'session-1', order_id: 'order-1', binding_id: 'binding-1', replayed: false })
const spawnRequest = nonce => ({ client_nonce: `nonce-${nonce}`, objective: 'bounded', preferred_profile: 'deepseek.api', requested_role: 'worker', output_schema_ref: 'result-v1', requested_limits: limits() })
const inputAcknowledgement = () => ({ target_run_id: 'run-1', input_ref: 'input-1', digest, status: 'sent' })
const cancelAcknowledgement = () => ({ target_run_id: 'run-1', revision_ref: 'revision-1', reason_ref: 'reason-1', digest, status: 'cancelled' })
const revisionAcknowledgement = status => ({ target_run_id: 'run-1', revision_ref: 'revision-1', digest, status })
const sessionStatus = () => ({ state: 'running', usage_source: 'unknown' })
const envelope = () => ({ run_id: 'run-1', attempt_id: 'attempt-1', status: 'completed', output_artifact_ref: 'artifact-1', schema_ref: 'result-v1', provenance_digest: digest, classification: 'L1' })
const response = kind => {
  const base = { schema_version: 'mesh-ui-response.v1', kind }
  switch (kind) {
    case 'selection-revision': return { ...base, selection: { revision_id: 'revision-2', active_turn_changed: false } }
    case 'mesh-spawn': return { ...base, spawn: { proposal: proposal() } }
    case 'mesh-spawnBatch': return { ...base, spawn_batch: { batch_id: 'batch-1', results: [proposal()], partial: false } }
    case 'mesh-send': case 'mesh-steer': return { ...base, [kind.slice(5)]: { acknowledgement: inputAcknowledgement() } }
    case 'mesh-wait': case 'mesh-status': return { ...base, [kind.slice(5)]: sessionStatus() }
    case 'mesh-collect': case 'mesh-result': return { ...base, [kind.slice(5)]: envelope() }
    case 'mesh-cancel': return { ...base, cancel: { acknowledgement: cancelAcknowledgement() } }
    case 'mesh-list': return { ...base, list: { runs: [{ run_id: 'run-1', profile_id: 'deepseek.api', provider: 'deepseek', status: 'running', depth: 1 }] } }
    case 'mesh-listProfiles': return { ...base, list_profiles: { profiles: [profiles()[0]] } }
    case 'provider-directory': return { ...base, directory: { profiles: [profiles()[0]] } }
    case 'ui-session-graph': return { ...base, graph: { graph: { nodes: [], edges: [] } } }
    case 'run-compare': return { ...base, compare: { compare: { runs: [] } } }
    case 'run-synthesis': return { ...base, synthesis: envelope() }
    case 'run-templates': return { ...base, templates: { templates: { approved: [] } } }
    case 'policy-approval-inspector': return { ...base, policy: { policy: { approvals: [] } } }
    case 'provider-diagnostics': return { ...base, diagnostics: { diagnostics: { providers: [] } } }
    case 'deployment-diagnostics': return { ...base, deployment: { status: 'healthy', acknowledgement: revisionAcknowledgement('completed') } }
    case 'plugin-lifecycle': return { ...base, plugin_lifecycle: { package: { package_id: 'openduck-mesh', digest, status: 'disabled' }, acknowledgement: revisionAcknowledgement('completed') } }
    default: throw new Error(`missing ${kind}`)
  }
}
const client = (calls, projected = safeProjection()) => ({ readProjection: async route => { calls.push({ read: route }); return projected }, propose: async (kind, value) => { calls.push({ kind, value }); return response(kind) } })

test('typed Controller projection is copied, bounded, frozen, and remains disabled', async () => {
  const calls = []; const ui = createMeshUI({ uiClient: client(calls) })
  const current = await ui.refresh()
  assert.equal(calls[0].read, 'mesh')
  assert.equal(current.profiles.length, 6)
  assert.ok(current.profiles.every(item => item.status === 'disabled' && item.mesh_spawn === false))
  assert.equal(Object.isFrozen(current), true)
  assert.equal(Object.isFrozen(current.graph.nodes), true)
})

test('each response kind is exact and selection never mutates the cached revision', async () => {
  const calls = []; const ui = createMeshUI({ uiClient: client(calls, switchableProjection()) }); await ui.refresh()
  const selected = await ui.select({ profile_id: 'deepseek.api', operation: 'new-root' })
  assert.deepEqual(selected, response('selection-revision'))
  assert.deepEqual(calls[1], { kind: 'selection-revision', value: { profile_id: 'deepseek.api', operation: 'new-root', base_revision_id: 'mesh-disabled' } })
  assert.equal(ui.state().revision_id, 'mesh-disabled')
  const mesh = [
    ['spawn', { client_nonce: 'nonce-1', objective: 'bounded', preferred_profile: 'deepseek.api', requested_role: 'worker', output_schema_ref: 'result-v1', requested_limits: limits() }],
    ['spawnBatch', { proposals: [{ client_nonce: 'nonce-2', objective: 'bounded', preferred_profile: 'deepseek.api', requested_role: 'worker', output_schema_ref: 'result-v1', requested_limits: limits() }] }],
    ['send', { run_id: 'run-1', input_ref: 'revision-1' }], ['steer', { run_id: 'run-1', input_ref: 'revision-1' }],
    ['wait', { run_id: 'run-1', revision_ref: 'revision-1' }], ['collect', { run_id: 'run-1', revision_ref: 'revision-1' }],
    ['cancel', { run_id: 'run-1', reason_ref: 'reason-1', revision_ref: 'revision-1' }], ['list', { root_id: 'root-1', revision_ref: 'revision-1' }],
    ['status', { run_id: 'run-1', revision_ref: 'revision-1' }], ['result', { run_id: 'run-1', revision_ref: 'revision-1' }], ['listProfiles', {}],
  ]
  for (const [operation, request] of mesh) assert.deepEqual(await ui.mesh(operation, request), response(`mesh-${operation}`))
  const childRequests = Object.fromEntries(mesh)
  for (const [method, request] of Object.entries(childRequests)) {
    const actual = method === 'listProfiles' ? await ui.children.listProfiles() : await ui.children[method](request)
    assert.deepEqual(actual, response(`mesh-${method}`))
  }
  const surfaces = {
    'provider-directory': { action: 'refresh', profile_id: 'deepseek.api' }, 'ui-session-graph': { root_id: 'root-1' }, 'run-compare': { run_ids: ['run-1'] },
    'run-synthesis': { template_id: 'template-1', source_result_refs: ['result-1'] }, 'run-templates': { template_id: 'template-1', version: 'v1' },
    'policy-approval-inspector': { decision_ref: 'decision-1' }, 'provider-diagnostics': { action: 'refresh', profile_id: 'deepseek.api' }, 'deployment-diagnostics': { action: 'doctor' },
    'plugin-lifecycle': { schema_version: 'plugin-lifecycle-request.v1', action: 'enable', package_id: 'openduck-mesh', package_digest: digest, profile_revision: 'revision-1', controller_binding_id: 'binding-1', expires_at: '2026-08-26T00:00:00.000Z' },
  }
  for (const [surface, request] of Object.entries(surfaces)) assert.deepEqual(await ui.proposal(surface, request), response(surface))
  assert.ok(SURFACES.includes('provider-diagnostics'))
})

test('projection explicitly disables unsupported lifecycle, deployment, and synthesis actions', async () => {
  const calls = []
  const projected = safeProjection()
  projected.unavailable = ['deployment-diagnostics', 'plugin-lifecycle', 'run-synthesis']
  const ui = createMeshUI({ uiClient: client(calls, projected) })
  await ui.refresh()
  const before = calls.length
  await assert.rejects(ui.proposal('run-synthesis', { template_id: 'template-1', source_result_refs: ['result-1'] }), /SURFACE_UNAVAILABLE/)
  await assert.rejects(ui.proposal('deployment-diagnostics', { action: 'doctor' }), /SURFACE_UNAVAILABLE/)
  await assert.rejects(ui.proposal('plugin-lifecycle', { schema_version: 'plugin-lifecycle-request.v1', action: 'enable', package_id: 'openduck-mesh', package_digest: digest, profile_revision: 'revision-1', controller_binding_id: 'binding-1', expires_at: '2026-08-26T00:00:00.000Z' }), /SURFACE_UNAVAILABLE/)
  assert.equal(calls.length, before)
})

test('spawnBatch matches the authoritative 16-item coordinator boundary before proposing', async () => {
  const calls = []; const ui = createMeshUI({ uiClient: client(calls, switchableProjection()) })
  await ui.refresh()
  const accepted = { proposals: Array.from({ length: 16 }, (_, index) => spawnRequest(index)) }
  assert.deepEqual(await ui.mesh('spawnBatch', accepted), response('mesh-spawnBatch'))
  const proposed = calls.filter(call => call.kind === 'mesh-spawnBatch')
  assert.equal(proposed.length, 1)
  assert.equal(proposed[0].value.proposals.length, 16)
  const before = calls.length
  await assert.rejects(ui.mesh('spawnBatch', { proposals: Array.from({ length: 17 }, (_, index) => spawnRequest(index)) }), /INVALID_MESH_PROPOSAL/)
  assert.equal(calls.length, before)
})

test('provider options deterministically expose six profiles and exact bounded filters', async () => {
  const calls = []; const ui = createMeshUI({ uiClient: client(calls, switchableProjection()) }); await ui.refresh()
  const all = ui.profileOptions()
  assert.deepEqual(all.map(item => item.profile_id), profiles().map(item => item.profile_id))
  assert.equal(all.find(item => item.profile_id === 'deepseek.api').mesh_eligible, true)
  assert.equal(all.find(item => item.profile_id === 'qwen.local-pd').local_only, true)
  assert.deepEqual(ui.profileOptions({ provider: 'qwen' }).map(item => item.profile_id), ['qwen.general.headless', 'qwen.local-pd'])
  assert.deepEqual(ui.profileOptions({ local_only: true }).map(item => item.profile_id), ['qwen.local-pd'])
  assert.deepEqual(ui.profileOptions({ mesh_eligible: true }).map(item => item.profile_id), ['deepseek.api'])
  assert.equal(Object.isFrozen(all), true)
  assert.equal(calls.filter(call => call.kind).length, 0)
  const state = ui.state()
  // Bun emits "readonly", while Node may use "read only" or "Cannot assign".
  assert.throws(() => { all[0].status = 'compatible' }, /readonly|read only|Cannot assign/i)
  assert.equal(ui.state().profiles[0].status, state.profiles[0].status)
})

test('selection refuses every unavailable profile before a Controller proposal and preserves state', async () => {
  const cases = [
    switchableProjection({ status: 'disabled', mesh_spawn: false, freshness: 'unknown' }),
    switchableProjection({ status: 'degraded', mesh_spawn: false, freshness: 'stale' }),
    switchableProjection({ status: 'compatible', mesh_spawn: false, freshness: 'current' }),
    switchableProjection({ status: 'compatible', mesh_spawn: true, freshness: 'stale' }),
  ]
  for (const projected of cases) {
    const calls = []; const ui = createMeshUI({ uiClient: client(calls, projected) }); await ui.refresh(); const before = ui.state()
    await assert.rejects(ui.select({ profile_id: 'deepseek.api', operation: 'new-child' }), /PROFILE_NOT_MESH_ELIGIBLE/)
    assert.equal(calls.filter(call => call.kind).length, 0)
    assert.deepEqual(ui.state(), before)
  }
})

test('ready cannot advertise mesh spawning and malformed switch inputs never propose', async () => {
  const ready = switchableProjection({ status: 'ready', mesh_spawn: true, freshness: 'current' })
  const readyUI = createMeshUI({ uiClient: client([], ready) })
  await assert.rejects(readyUI.refresh(), /INVALID_PROJECTION/)
  const calls = []; const ui = createMeshUI({ uiClient: client(calls, switchableProjection()) }); await ui.refresh(); const before = calls.length
  for (const invalid of [
    () => ui.select(null), () => ui.select({ profile_id: 'deepseek.api' }), () => ui.select({ profile_id: 'unknown.profile', operation: 'new-root' }),
    () => ui.select({ profile_id: 'deepseek.api', operation: 'active-turn-mutation' }),
  ]) await assert.rejects(invalid, /(INVALID_SWITCH_OPERATION|UNKNOWN_PROFILE|INVALID_PROFILE_FILTER)/)
  for (const invalid of [
    () => ui.profileOptions({ provider: 'invented' }), () => ui.profileOptions({ freshness: 'invented' }), () => ui.profileOptions({ mesh_eligible: 'true' }),
  ]) assert.throws(invalid, /INVALID_PROFILE_FILTER/)
  assert.equal(calls.length, before)
})

test('selection rejects a response that claims active-turn mutation or wrong kind', async () => {
  for (const projectedResponse of [
    { ...response('selection-revision'), selection: { revision_id: 'revision-2', active_turn_changed: true } },
    response('mesh-spawn'),
  ]) {
    const ui = createMeshUI({ uiClient: { readProjection: async () => switchableProjection(), propose: async () => projectedResponse } })
    await ui.refresh(); const before = ui.state()
    await assert.rejects(ui.select({ profile_id: 'deepseek.api', operation: 'new-root' }), /INVALID_RESPONSE/)
    assert.deepEqual(ui.state(), before)
  }
})

test('enabled lifecycle projection requires a compatible spawn profile with current diagnostics', async () => {
  const rejected = [
    enabledProjection({ status: 'ready', mesh_spawn: false, freshness: 'current' }),
    enabledProjection({ status: 'compatible', mesh_spawn: false, freshness: 'current' }),
    enabledProjection({ status: 'compatible', mesh_spawn: true, freshness: 'stale' }),
    enabledProjection({ status: 'degraded', mesh_spawn: false, freshness: 'stale' }),
  ]
  const missingDiagnostics = enabledProjection({ status: 'compatible', mesh_spawn: true, freshness: 'current' })
  missingDiagnostics.diagnostics.providers = missingDiagnostics.diagnostics.providers.filter(item => item.profile_id !== 'deepseek.api')
  rejected.push(missingDiagnostics)
  for (const projected of rejected) {
    const ui = createMeshUI({ uiClient: client([], projected) })
    await assert.rejects(ui.refresh(), /INVALID_PROJECTION/)
    assert.equal(ui.state(), null)
  }

  const ui = createMeshUI({ uiClient: client([], enabledProjection()) })
  const projected = await ui.refresh()
  assert.equal(projected.lifecycle.packages[0].status, 'enabled')
  assert.deepEqual(ui.profileOptions({ mesh_eligible: true }).map(item => item.profile_id), ['deepseek.api'])
})

test('request DTOs reject omitted revision, free-form reason, duplicate, oversized, and typed variants before proposing', async () => {
  const calls = []; const ui = createMeshUI({ uiClient: client(calls) }); await ui.refresh(); const before = calls.length
  const rejects = [
    () => ui.mesh('wait', { run_id: 'run-1' }), () => ui.mesh('collect', { run_id: 'run-1' }), () => ui.mesh('status', { run_id: 'run-1' }), () => ui.mesh('result', { run_id: 'run-1' }),
    () => ui.mesh('cancel', { run_id: 'run-1', reason: 'text' }), () => ui.mesh('list', { root_id: 'root-1' }),
    () => ui.mesh('send', { run_id: 'run-1', input_ref: 'input-1', revision_ref: 'revision-1' }), () => ui.mesh('wait', { run_id: 'run-1', input_ref: 'input-1' }),
    () => ui.mesh('cancel', { run_id: 'run-1', input_ref: 'input-1', revision_ref: 'revision-1', reason_ref: 'reason-1' }),
    () => ui.mesh('send', { run_id: 'run-1', input_ref: 'secret-token' }), () => ui.proposal('run-compare', { run_ids: [] }),
    () => ui.proposal('run-compare', { run_ids: ['run-1', 'run-1'] }), () => ui.proposal('run-compare', { run_ids: Array.from({ length: 65 }, (_, index) => `run-${index}`) }),
    () => ui.proposal('provider-directory', { action: 'invented', profile_id: 'deepseek.api' }), () => ui.proposal('deployment-diagnostics', { action: 'wrong' }),
  ]
  for (const reject of rejects) await assert.rejects(reject, /INVALID_/)
  await assert.rejects(ui.children.wait({ run_id: 'run-1' }), /INVALID_MESH_PROPOSAL/)
  await assert.rejects(ui.children.cancel({ run_id: 'run-1', revision_ref: 'revision-1' }), /INVALID_MESH_PROPOSAL/)
  assert.equal(calls.length, before)
})

test('malicious response values are rejected without returning raw injected data', async () => {
  const malicious = []
  const prototype = Object.create({ polluted: true }); Object.assign(prototype, response('mesh-result')); malicious.push(prototype)
  const getter = response('mesh-result'); Object.defineProperty(getter, 'result', { enumerable: true, get: () => envelope() }); malicious.push(getter)
  const extra = response('mesh-result'); extra.result.extra = 'untrusted'; malicious.push(extra)
  const oversized = response('mesh-result'); oversized.result.output_artifact_ref = 'x'.repeat(65537); malicious.push(oversized)
  const secret = response('mesh-result'); secret.result.output_artifact_ref = 'password-value'; malicious.push(secret)
  const output = response('mesh-result'); output.result.stdout = 'untrusted'; malicious.push(output)
  const transcript = response('mesh-result'); transcript.result.transcript = 'untrusted'; malicious.push(transcript)
  const wrongSchema = response('mesh-result'); wrongSchema.schema_version = 'wrong'; malicious.push(wrongSchema)
  const wrongKind = response('mesh-result'); wrongKind.kind = 'mesh-status'; malicious.push(wrongKind)
  const crossKind = { ...response('mesh-status'), result: envelope() }; malicious.push(crossKind)
  const nonFinite = response('mesh-list'); nonFinite.list.runs[0].depth = Infinity; malicious.push(nonFinite)
  const cyclic = response('mesh-result'); cyclic.result.self = cyclic; malicious.push(cyclic)
  const deep = response('mesh-result'); let nested = {}; for (let index = 0; index < 20; index += 1) nested = { nested }; deep.result.nested = nested; malicious.push(deep)
  for (const value of malicious) {
    const ui = createMeshUI({ uiClient: { readProjection: async () => safeProjection(), propose: async () => value } }); await ui.refresh()
    await assert.rejects(ui.mesh('result', { run_id: 'run-1', revision_ref: 'revision-1' }), /INVALID_RESPONSE/)
  }
  const wrongAcknowledgements = []
  const sendWithRevision = response('mesh-send'); sendWithRevision.send.acknowledgement = revisionAcknowledgement('sent'); wrongAcknowledgements.push(['send', { run_id: 'run-1', input_ref: 'input-1' }, sendWithRevision])
  const cancelWithInput = response('mesh-cancel'); cancelWithInput.cancel.acknowledgement = inputAcknowledgement(); wrongAcknowledgements.push(['cancel', { run_id: 'run-1', revision_ref: 'revision-1', reason_ref: 'reason-1' }, cancelWithInput])
  for (const [operation, request, value] of wrongAcknowledgements) {
    const ui = createMeshUI({ uiClient: { readProjection: async () => safeProjection(), propose: async () => value } }); await ui.refresh()
    await assert.rejects(ui.mesh(operation, request), /INVALID_RESPONSE/)
  }
})

test('malicious projection values reject prototypes, accessors, cycles, secrets, extra fields, and non-finite values', async () => {
  const cases = []
  const prototype = Object.create({ polluted: true }); Object.assign(prototype, safeProjection()); cases.push(prototype)
  const getter = safeProjection(); Object.defineProperty(getter, 'profiles', { enumerable: true, get: profiles }); cases.push(getter)
  const extra = safeProjection(); extra.graph.nodes[0].stderr = 'untrusted'; cases.push(extra)
  const oversized = safeProjection(); oversized.revision_id = 'x'.repeat(65537); cases.push(oversized)
  const secret = safeProjection(); secret.revision_id = 'secret-revision'; cases.push(secret)
  const nonFinite = safeProjection(); nonFinite.graph.nodes.push({ id: 'run-2', status: 'running', provider: 'codex', profile_id: 'codex.chatgpt.app-server', depth: NaN }); cases.push(nonFinite)
  const cyclic = safeProjection(); cyclic.graph.self = cyclic; cases.push(cyclic)
  const deep = safeProjection(); let nested = {}; for (let index = 0; index < 20; index += 1) nested = { nested }; deep.graph.nested = nested; cases.push(deep)
  for (const value of cases) {
    const ui = createMeshUI({ uiClient: { readProjection: async () => value, propose: async kind => response(kind) } })
    await assert.rejects(ui.refresh(), /INVALID_PROJECTION/)
    assert.equal(ui.state(), null)
  }
})

test('negative proof: no DSH/model/session-log surface appears in the plugin source', async () => {
  const source = await import('node:fs/promises').then(fs => fs.readFile(new URL('../src/index.js', import.meta.url), 'utf8'))
  for (const forbidden of ['agentLoop', 'sessionLog', 'appendEvent', 'modelPrompt', 'localStorage', 'fetch(', 'stdout', 'stderr', 'transcript']) assert.equal(source.includes(forbidden), false, forbidden)
})
