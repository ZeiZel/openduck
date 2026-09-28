import test from 'node:test'
import assert from 'node:assert/strict'
import { apply } from '../src/dsh-client.js'

test('registers both additive seats and rolls them back', () => {
  const entries = []
  const disposers = []
  const slots = {
    inject(key, callback) {
      const dispose = callback()
      disposers.push(() => { dispose(); assert.equal(entries.filter(entry => entry.key === key).length, 0) })
      return () => {}
    },
    register(options) {
      const entry = { key: options.name, id: options.id, order: options.order }
      entries.push(entry)
      return () => { const index = entries.indexOf(entry); if (index !== -1) entries.splice(index, 1) }
    },
  }
  apply({ slots })
  assert.deepEqual(entries, [
    { key: 'conversation.session.header.actions', id: 'openduck-workspace-groups', order: 50 },
    { key: 'conversation.session.header.utilities', id: 'openduck-workspace-groups-utility', order: 50 },
  ])
  for (const dispose of disposers) dispose()
  assert.deepEqual(entries, [])
})
