import assert from 'node:assert/strict'
import { LOCAL_PD_UNAVAILABLE, createBeadsMemoryExplorer } from '../src/index.js'

const digest = `sha256:${'b'.repeat(64)}`
const client = {
  async read(route) {
    if (route === 'beads/project-graph') return { schema_version: 'beads-project-graph.v1', project_id: 'demo-project', version: 1, digest, nodes: [{ id: 'demo-1', label: 'Demo task', state: 'open' }], edges: [] }
    return { schema_version: 'beads-global-metadata.v1', version: 1, digest, updated_at: '2026-08-20T00:00:00Z', records: [{ record_id: 'global-1', version: 1, updated_at: '2026-08-20T00:00:00Z', availability: LOCAL_PD_UNAVAILABLE }] }
  },
}
const explorer = createBeadsMemoryExplorer(client)
const state = await explorer.refresh()
assert.equal(state.status, 'ready')
assert.equal(explorer.openMemoryChat('global').code, LOCAL_PD_UNAVAILABLE)
process.stdout.write('beads-memory-explorer synthetic harness: PASS\n')
