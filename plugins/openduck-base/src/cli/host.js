import { CLI_PROVIDERS } from './availability.js'
import { createCliAuth } from './auth.js'

const providers = Object.freeze(Object.values(CLI_PROVIDERS))
const ok = value => Object.freeze({ ok: true, value: Object.freeze(value) })
const fail = message => Object.freeze({ ok: false, error: Object.freeze({ code: 'internal', message, details: Object.freeze({}) }) })
const providerOf = value => typeof value?.provider === 'string' ? providers.find(provider => provider.id === value.provider) : undefined

/** Loopback-only DTO boundary for installed CLI status and explicit Terminal sign-in. */
export function createCliRootRpc({ auth = createCliAuth() } = {}) {
  return Object.freeze({
    async handle(endpoint, payload) {
      try {
        if (endpoint === 'status') {
          if (payload !== null && (typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).length !== 0)) return fail('CLI status request is invalid')
          const items = await Promise.all(providers.map(async provider => {
            const state = await auth.status(provider.id)
            return Object.freeze({ provider: provider.id, label: provider.label, installed: state.installed === true, auth: ['authenticated', 'not-signed-in', 'unknown'].includes(state.auth) ? state.auth : 'unknown' })
          }))
          return ok({ items: Object.freeze(items) })
        }
        if (endpoint === 'login') {
          const provider = providerOf(payload)
          if (provider === undefined || Object.keys(payload).length !== 1) return fail('CLI sign-in request is invalid')
          await auth.launch(provider.id)
          return ok({ provider: provider.id, launched: true })
        }
        return fail('CLI endpoint is unavailable')
      } catch {
        return fail('OpenDuck could not start CLI sign-in')
      }
    },
  })
}
