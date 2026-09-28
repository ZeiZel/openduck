import { createBrowserReadBridge } from './browser-client.js'

export const inject = ['slots']

export function apply(ctx) {
  const bridge = createBrowserReadBridge()
  const dispose = []
  const register = (name, id, order) => {
    const remove = ctx.slots.inject(name, () => ctx.slots.register({ name, id, order }, () => bridge))
    dispose.push(remove)
  }
  const provided = typeof ctx.provide === 'function' ? ctx.provide('controllerReadBridge', bridge) : undefined
  register('conversation.session.header.utilities', 'openduck-controller-read-bridge', 30)
  const cleanup = () => { bridge.dispose(); provided?.(); for (const remove of dispose) remove() }
  if (import.meta.hot && typeof import.meta.hot.dispose === 'function') import.meta.hot.dispose(cleanup)
  return cleanup
}
