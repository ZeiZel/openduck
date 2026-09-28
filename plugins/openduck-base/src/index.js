import z from '@deepseek-ai/schemastery'
import { DEFAULT_SETTINGS, OPENDUCK_SETTINGS_NAMESPACE, OPENDUCK_SERVICE, validateSettings } from './contract.js'

/** Cordis function-plugin name. */
export const name = OPENDUCK_SERVICE
/** The native settings provider is supplied by dsh-base. */
export const inject = ['settings']

const Settings = z.object({
  controller: z.object({
    enabled: z.boolean().default(false),
    origin: z.string().default(DEFAULT_SETTINGS.controller.origin),
  }).default(DEFAULT_SETTINGS.controller),
  externalPackages: z.array(z.string()).default([]),
})

/**
 * Mount the generic OpenDuck runtime service and register its native settings.
 * No network request or Controller connection is made by this package.
 * @param {import('@deepseek-ai/cordis').Context} ctx - plugin context.
 * @param {object} config - profile composition defaults.
 * @returns {void}
 */
export function apply(ctx, config = {}) {
  const scope = ctx.settings.register(OPENDUCK_SETTINGS_NAMESPACE, Settings, {
    base: { ...DEFAULT_SETTINGS, ...config },
    validate: validateSettings,
  })
  const service = Object.freeze({
    settings: () => scope.get(),
    status: () => scope.get().controller.enabled ? 'configured' : 'disabled',
    controller: Object.freeze({
      enabled: () => scope.get().controller.enabled,
      origin: () => scope.get().controller.origin,
    }),
    externalPackages: () => [...scope.get().externalPackages],
  })
  const dispose = ctx.provide(OPENDUCK_SERVICE, service)
  ctx.effect(() => () => { if (typeof dispose === 'function') dispose() }, 'openduck-base.service()')
}

export { DEFAULT_SETTINGS, OPENDUCK_SETTINGS_NAMESPACE, OPENDUCK_SERVICE, validateSettings }
