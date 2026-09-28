import test from 'node:test'
import assert from 'node:assert/strict'
import { initialHistoryView, reduceHistoryView } from '../src/history/client.js'

test('history viewer clears a prior project selection on an error', () => {
  const sessions = reduceHistoryView(initialHistoryView, { type: 'sessions', items: [{ sessionId: 's1' }], nextCursor: 'next' })
  const messages = reduceHistoryView(sessions, { type: 'messages', sessionId: 's1', items: [{ id: 'm1' }] })
  const failed = reduceHistoryView(messages, { type: 'error', message: 'History unavailable' })
  assert.equal(failed.phase, 'error')
  assert.equal(failed.selected, null)
  assert.deepEqual(failed.messages, [])
})
