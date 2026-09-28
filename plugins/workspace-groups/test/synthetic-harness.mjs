import assert from 'node:assert/strict'
import { createWorkspaceGroups } from '../src/index.js'

const digest = `sha256:${'d'.repeat(64)}`
const client = { read: async () => ({ schema_version: 'workspace-groups.v1', freshness: 'current', groups: [{ schema_version: 'workspace-group.v1', group_id: 'demo-group', display_label: 'Demo', primary_root_id: 'root-1', roots: [{ root_id: 'root-1', label: 'Primary', mode: 'read' }], version: 1, digest, updated_at: '2026-08-20T00:00:00Z' }] }) }
const groups = createWorkspaceGroups(client)
await groups.refresh()
assert.equal(groups.select('demo-group').ok, true)
process.stdout.write('workspace-groups synthetic harness: PASS\n')
