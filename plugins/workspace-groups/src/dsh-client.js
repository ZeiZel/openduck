/**
 * Disabled-by-default DSH browser registration. The real Controller read
 * client is intentionally not injected until its authenticated route exists.
 * These null seats prove additive slot ownership without changing the session header workspace.
 */
export const inject = ['slots', 'controllerReadBridge']

import { createWorkspaceGroups } from './index.js'

/** Register the synthetic-safe action and utility seats when the host enables this entry. */
export function apply(ctx) {
  const client = ctx.controllerReadBridge ?? ctx.readBridge
  const groups = client && typeof client.read === 'function' ? createWorkspaceGroups(client) : Object.freeze({ getState: () => Object.freeze({ status: 'controller_down', code: 'CONTROLLER_DOWN', freshness: 'unknown', groups: Object.freeze([]), selected: null }) })
  ctx.slots.inject('conversation.session.header.actions', () => ctx.slots.register({
    name: 'conversation.session.header.actions',
    id: 'openduck-workspace-groups',
    order: 50,
  }, () => groups))
  ctx.slots.inject('conversation.session.header.utilities', () => ctx.slots.register({
    name: 'conversation.session.header.utilities',
    id: 'openduck-workspace-groups-utility',
    order: 50,
  }, () => groups))
}
