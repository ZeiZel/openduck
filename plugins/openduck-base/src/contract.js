/** Stable names and defaults shared by OpenDuck bundles. */
export const OPENDUCK_SETTINGS_NAMESPACE = 'openduck'
export const OPENDUCK_SERVICE = 'openduckBase'
export const DEFAULT_SETTINGS = Object.freeze({
  controller: Object.freeze({ enabled: false, origin: 'http://127.0.0.1:8788' }),
  externalPackages: Object.freeze([]),
})

/**
 * Validate the deployment-neutral OpenDuck settings.
 * @param {unknown} value - resolved settings value.
 * @returns {void}
 */
export function validateSettings(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('openduck: settings must be an object')
  const controller = value.controller
  if (controller === null || typeof controller !== 'object' || Array.isArray(controller)) throw new TypeError('openduck: controller settings are required')
  if (typeof controller.enabled !== 'boolean') throw new TypeError('openduck: controller.enabled must be boolean')
  if (typeof controller.origin !== 'string') throw new TypeError('openduck: controller.origin must be a loopback HTTP origin')
  const match = /^http:\/\/127\.0\.0\.1:(\d{1,5})$/.exec(controller.origin)
  if (match === null || Number(match[1]) < 1 || Number(match[1]) > 65535) throw new TypeError('openduck: controller.origin must be a loopback HTTP origin')
  if (!Array.isArray(value.externalPackages) || value.externalPackages.some(item => typeof item !== 'string' || item.length === 0 || item.length > 128)) throw new TypeError('openduck: externalPackages must be package names')
}
