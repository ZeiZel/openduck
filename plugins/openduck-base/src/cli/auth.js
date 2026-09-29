import { spawn } from 'node:child_process'
import { cliProvider, createCliAvailability } from './availability.js'

const MAX_STATUS_BYTES = 16 * 1024
const STATUS_TIMEOUT_MS = 5_000
const LOGIN_TIMEOUT_MS = 10_000
const terminalScript = 'on run argv\n  tell application "Terminal"\n    activate\n    do script (item 1 of argv)\n  end tell\nend run'
const shellWord = value => `'${value.replaceAll("'", "'\\''")}'`

function normalizeStatus(provider, code, text) {
  const value = text.trim().toLowerCase()
  if (provider.id === 'claude') {
    try {
      const parsed = JSON.parse(text)
      if ((parsed?.loggedIn === true || parsed?.authenticated === true) && code === 0) return 'authenticated'
      if (parsed?.loggedIn === false || parsed?.authenticated === false) return 'not-signed-in'
    } catch {}
  }
  if (provider.id === 'codex' && code === 1 && /^not logged in(?:\b|$)/.test(value)) return 'not-signed-in'
  if (code === 0 && /^(logged in|signed in|authenticated)(?:\b|$)/.test(value)) return 'authenticated'
  // Any unrecognized provider response, timeout, or spawn failure is unknown.
  return 'unknown'
}

/** Run only documented app-managed status commands and return no raw output. */
export function createCliAuth({ availability = createCliAvailability(), spawnProcess = spawn, platform = process.platform } = {}) {
  const launched = new Set()
  const status = providerName => new Promise(resolve => {
    const provider = cliProvider(providerName); const executable = availability.executable(providerName)
    if (provider === undefined || executable === undefined) { resolve(Object.freeze({ installed: false, auth: 'unknown' })); return }
    if (provider.status === undefined) { resolve(Object.freeze({ installed: true, auth: 'unknown' })); return }
    let child; let bytes = 0; let output = ''; let settled = false; let timer
    const finish = (code, value = output) => { if (settled) return; settled = true; clearTimeout(timer); resolve(Object.freeze({ installed: true, auth: normalizeStatus(provider, code, value) })) }
    try { child = spawnProcess(executable, provider.status, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true }) } catch { resolve(Object.freeze({ installed: true, auth: 'unknown' })); return }
    const append = chunk => { if (bytes >= MAX_STATUS_BYTES) return; const text = String(chunk); bytes += Buffer.byteLength(text); output += text.slice(0, Math.max(0, MAX_STATUS_BYTES - output.length)) }
    // Codex documents its login status on stderr. Keep both streams private,
    // bounded and normalized at this boundary; neither is returned or logged.
    child.stdout?.on('data', append); child.stderr?.on('data', append)
    child.once('error', () => finish(-1, ''))
    child.once('close', code => finish(Number.isInteger(code) ? code : -1))
    timer = setTimeout(() => { try { child.kill('SIGTERM') } catch {}; finish(-1, '') }, STATUS_TIMEOUT_MS)
  })
  const launch = providerName => new Promise((resolve, reject) => {
    const provider = cliProvider(providerName); const executable = availability.executable(providerName)
    if (provider === undefined || executable === undefined) { reject(new Error('CLI is not installed')); return }
    if (platform !== 'darwin') { reject(new Error('OpenDuck can launch sign-in only in a local macOS Terminal')); return }
    if (launched.has(provider.id)) { reject(new Error('A sign-in Terminal is already open for this CLI')); return }
    launched.add(provider.id)
    const command = `exec ${[executable, ...provider.login].map(shellWord).join(' ')}`
    let child
    try { child = spawnProcess('osascript', ['-e', terminalScript, '--', command], { stdio: 'ignore', windowsHide: true }) } catch { launched.delete(provider.id); reject(new Error('OpenDuck could not open Terminal for sign-in')); return }
    let settled = false
    let timer
    const finish = success => {
      if (settled) return
      settled = true; clearTimeout(timer); launched.delete(provider.id)
      if (success) resolve(Object.freeze({ launched: true }))
      else reject(new Error('OpenDuck could not open Terminal for sign-in'))
    }
    const fail = () => { finish(false) }
    child.once('error', fail)
    child.once('close', code => finish(code === 0))
    timer = setTimeout(() => { try { child.kill('SIGTERM') } catch {}; finish(false) }, LOGIN_TIMEOUT_MS)
  })
  return Object.freeze({ status, launch })
}
