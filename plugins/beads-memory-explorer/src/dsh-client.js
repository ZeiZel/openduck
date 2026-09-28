/**
 * Disabled-by-default DSH browser registration. The real Controller read
 * client is intentionally not injected until its authenticated route exists.
 * These null seats prove additive slot ownership without session state.
 */
export const inject = ['slots', 'controllerReadBridge']

import { createBeadsMemoryExplorer } from './index.js'

/** Register the synthetic-safe action and utility seats when the host enables this entry. */
export function apply(ctx) {
  const client = ctx.controllerReadBridge ?? ctx.readBridge
  const explorer = client && typeof client.read === 'function' ? createBeadsMemoryExplorer(client) : Object.freeze({ getState: () => Object.freeze({ project: null, global: Object.freeze({ status: 'blocked', code: 'UI_BRIDGE_UNAVAILABLE', records: Object.freeze([]) }), status: 'controller_down' }) })
  ctx.slots.inject('conversation.session.header.actions', () => ctx.slots.register({
    name: 'conversation.session.header.actions',
    id: 'openduck-beads-memory-explorer',
    order: 40,
  }, () => explorer))
  ctx.slots.inject('conversation.session.header.utilities', () => ctx.slots.register({
    name: 'conversation.session.header.utilities',
    id: 'openduck-beads-memory-explorer-utility',
    order: 40,
  }, () => explorer))
}
