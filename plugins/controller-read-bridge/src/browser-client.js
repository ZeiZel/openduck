export const BROWSER_PLUGIN_READ_PATHS = Object.freeze({
  'beads/project-graph': '/v1/plugin-reads/beads/project-graph',
  'beads/global-metadata': '/v1/plugin-reads/beads/global-metadata',
  'workspace-groups': '/v1/plugin-reads/workspace-groups',
})
const MAX_BYTES = 256 * 1024
function fail(code) { throw new TypeError(code) }
async function readJSON(response, origin) {
  if (!response || !response.ok || response.redirected) return null
  if (response.url && origin && new URL(response.url, origin).origin !== origin) return null
  const type = response.headers?.get?.('content-type'); const length = response.headers?.get?.('content-length')
  if (!/^application\/json(?:\s*;|$)/iu.test(type ?? '') || !/^\d+$/u.test(length ?? '') || Number(length) > MAX_BYTES) return null
  let text
  if (response.body?.getReader) { const reader = response.body.getReader(); const parts = []; let total = 0; while (true) { const part = await reader.read(); if (part.done) break; total += part.value.byteLength; if (total > MAX_BYTES) { await reader.cancel(); return null }; parts.push(part.value) }; const bytes = new Uint8Array(total); let offset = 0; for (const part of parts) { bytes.set(part, offset); offset += part.byteLength }; text = new TextDecoder('utf-8', { fatal: true }).decode(bytes) }
  else { text = await response.text(); if (new TextEncoder().encode(text).byteLength > MAX_BYTES) return null }
  try { const value = JSON.parse(text); return value && typeof value === 'object' && !Array.isArray(value) ? value : null } catch { return null }
}
export function createBrowserReadBridge({ fetchImpl = globalThis.fetch, origin = globalThis.location?.origin ?? '' } = {}) {
  if (typeof fetchImpl !== 'function') fail('FETCH_UNAVAILABLE')
  let disposed = false
  const read = async route => { if (disposed || !Object.hasOwn(BROWSER_PLUGIN_READ_PATHS, route)) return null; const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 10_000); try { return await readJSON(await fetchImpl(BROWSER_PLUGIN_READ_PATHS[route], { method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error', headers: { Accept: 'application/json' }, signal: controller.signal }), origin) } catch { return null } finally { clearTimeout(timer) } }
  const dispose = () => { disposed = true }
  return Object.freeze({ read, dispose })
}
