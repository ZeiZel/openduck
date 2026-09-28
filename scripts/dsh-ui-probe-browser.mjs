/**
 * Capture the standard DSH web boot browser/storage projection.
 * Run from the isolated DSH source copy where Playwright is materialized.
 * This intentionally does not assert DR-018: the standard profile is known to
 * expose model/session services and its storage output is evidence only.
 */
import { createRequire } from 'node:module'

// Resolve from the isolated DSH workspace's package graph, not this repository.
const { chromium } = createRequire(`${process.cwd()}/package.json`)('playwright')

const url = process.argv[2] ?? 'http://127.0.0.1:4173'
const parsed = new URL(url)
if (parsed.hostname !== '127.0.0.1' && parsed.hostname !== 'localhost') {
  throw new Error(`browser probe accepts loopback only: ${url}`)
}

const profile = process.env.DSH_PROBE_BROWSER_PROFILE ?? '/private/tmp/dsh-ui-probe-browser-profile'
const browser = await chromium.launchPersistentContext(profile, { headless: true })
try {
  const page = await browser.newPage()
  const requests = []
  page.on('request', request => requests.push(request.url()))
  await page.goto(url, { waitUntil: 'domcontentloaded' })
  await page.waitForTimeout(2_000)
  const state = await page.evaluate(async () => ({
    title: document.title,
    bodyPrefix: (document.body?.innerText ?? '').slice(0, 500),
    localStorageKeys: Object.keys(localStorage),
    sessionStorageKeys: Object.keys(sessionStorage),
    indexedDbNames: typeof indexedDB?.databases === 'function'
      ? (await indexedDB.databases()).map(database => database.name ?? null)
      : [],
    cacheNames: typeof caches === 'undefined' ? [] : await caches.keys(),
    serviceWorkerScopes: typeof navigator.serviceWorker === 'undefined'
      ? []
      : (await navigator.serviceWorker.getRegistrations()).map(registration => registration.scope),
  }))
  const loopbackRequests = requests.filter(request => new URL(request).hostname === parsed.hostname)
  const externalRequests = requests.filter(request => {
    const requestUrl = new URL(request)
    return requestUrl.hostname !== parsed.hostname
  })
  console.log(JSON.stringify({ schema: 'deepseek-harness.dr018.browser-capture.v1', url, state, loopbackRequestCount: loopbackRequests.length, externalRequests }, null, 2))
} finally {
  await browser.close()
}
