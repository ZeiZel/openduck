import { spawn as nodeSpawn } from 'node:child_process'
import { createHistoryService } from './index.js'

const MAX_OUTPUT_BYTES = 256 * 1024
const DEFAULT_TIMEOUT_MS = 5000

function asError(value, fallback) { return value instanceof Error ? value : new Error(fallback) }

/** Bounded JSONL JSON-RPC client for a short-lived local stdio child. */
export function createJsonRpcChild({ command, args, spawn = nodeSpawn, timeoutMs = DEFAULT_TIMEOUT_MS, maxOutputBytes = MAX_OUTPUT_BYTES }) {
  if (typeof command !== 'string' || !command || !Array.isArray(args) || args.some(arg => typeof arg !== 'string')) throw new TypeError('history: child command is invalid')
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) throw new TypeError('history: child timeout is invalid')
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true })
  if (!child?.stdin || !child?.stdout || typeof child.stdin.write !== 'function' || typeof child.stdout.on !== 'function') throw new Error('history: child did not provide stdio')
  let closed = false; let nextId = 1; let buffered = ''; let outputBytes = 0
  const pending = new Map(); const notifications = []
  const fail = error => { if (closed) return; closed = true; const failure = asError(error, 'history: child transport failed'); for (const item of pending.values()) item.reject(failure); pending.clear(); if (typeof child.kill === 'function') child.kill() }
  const consume = chunk => {
    outputBytes += Buffer.byteLength(chunk); if (outputBytes > maxOutputBytes) return fail(new Error('history: child output exceeded limit'))
    buffered += chunk
    for (;;) {
      const newline = buffered.indexOf('\n'); if (newline < 0) break
      const line = buffered.slice(0, newline); buffered = buffered.slice(newline + 1); if (!line.trim()) continue
      let message; try { message = JSON.parse(line) } catch { return fail(new Error('history: child emitted invalid JSONL')) }
      if (Object.prototype.hasOwnProperty.call(message, 'id') && typeof message.method === 'string') { try { child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'method not allowed' } })}\n`) } catch { fail(new Error('history: child denial write failed')) } } else if (Object.prototype.hasOwnProperty.call(message, 'id')) { const item = pending.get(message.id); if (!item) continue; pending.delete(message.id); if (message.error) item.reject(new Error('history: child RPC request failed')); else item.resolve(message.result) } else if (typeof message.method === 'string') notifications.push(message)
    }
  }
  child.stdout.on('data', chunk => consume(String(chunk))); child.stdout.on('error', fail); child.stderr?.on?.('data', chunk => { outputBytes += Buffer.byteLength(String(chunk)); if (outputBytes > maxOutputBytes) fail(new Error('history: child output exceeded limit')) }); child.on?.('error', fail); child.on?.('exit', code => { if (!closed && pending.size) fail(new Error(`history: child exited before response (${code ?? 'signal'})`)) })
  const timer = setTimeout(() => fail(new Error('history: child request timed out')), timeoutMs)
  const request = (method, params) => new Promise((resolve, reject) => { if (closed) return reject(new Error('history: child transport is closed')); const id = nextId++; pending.set(id, { resolve, reject }); try { child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, id, params })}\n`) } catch (error) { pending.delete(id); reject(asError(error, 'history: child write failed')) } })
  const notify = (method, params) => { if (closed) throw new Error('history: child transport is closed'); child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`) }
  return Object.freeze({ request, notify, notifications, close: () => { clearTimeout(timer); if (!closed) { closed = true; if (typeof child.kill === 'function') child.kill() } } })
}

async function withChild(spec, action) { const rpc = createJsonRpcChild(spec); try { return await action(rpc) } finally { rpc.close() } }

/** Starts a local Codex app-server and exposes exactly thread/list and thread/read. */
export function createCodexRpcPort(options = {}) {
  const spawn = options.spawn ?? nodeSpawn
  return async (method, params) => {
    if (!['thread/list', 'thread/read'].includes(method)) throw new Error('history: Codex method is not allowlisted')
    return withChild({ command: options.command ?? 'codex', args: options.args ?? ['app-server', '--listen', 'stdio://'], spawn, timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS, maxOutputBytes: options.maxOutputBytes ?? MAX_OUTPUT_BYTES }, async rpc => { await rpc.request('initialize', { clientInfo: { name: 'openduck-history', title: 'OpenDuck History', version: '1' } }); rpc.notify('initialized', {}); return rpc.request(method, params) })
  }
}

/** Runs only Kimi's documented, metadata-only `session list` command. */
export function createKimiCliPort(options = {}) {
  const spawn = options.spawn ?? nodeSpawn
  return async ({ command, args, timeoutMs, maxOutputBytes }) => {
    if (command !== 'kimi' || !Array.isArray(args) || args[0] !== 'session' || args[1] !== 'list' || !args.includes('--json')) throw new Error('history: Kimi command is not allowlisted')
    return new Promise(resolve => {
      let stdout = ''; let stderr = ''; let bytes = 0; let settled = false
      const finish = value => { if (!settled) { settled = true; clearTimeout(timer); resolve(value) } }
      const child = spawn('kimi', args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true })
      const stop = () => { if (typeof child.kill === 'function') child.kill() }
      const timer = setTimeout(() => { stop(); finish({ exitCode: -1, stdout: '', stderr: 'timeout' }) }, timeoutMs ?? DEFAULT_TIMEOUT_MS)
      const collect = target => chunk => { bytes += Buffer.byteLength(String(chunk)); if (bytes > (maxOutputBytes ?? MAX_OUTPUT_BYTES)) { stop(); return finish({ exitCode: -1, stdout: '', stderr: 'output limit' }) }; if (target === 'out') stdout += String(chunk); else stderr += String(chunk) }
      child.stdout?.on?.('data', collect('out')); child.stderr?.on?.('data', collect('err')); child.on?.('error', () => finish({ exitCode: -1, stdout: '', stderr: 'spawn failed' })); child.on?.('exit', code => finish({ exitCode: typeof code === 'number' ? code : -1, stdout, stderr }))
    })
  }
}

function acpText(update) { const content = update?.content; if (typeof content === 'string') return content; if (content && typeof content === 'object' && content.type === 'text' && typeof content.text === 'string') return content.text; return undefined }

/** Read-only Kimi ACP replay: initialize then session/load; it never prompts or grants capabilities. */
export function createKimiAcpReader(options = {}) {
  const spawn = options.spawn ?? nodeSpawn
  return async ({ sessionId, limit, cwd }) => withChild({ command: options.command ?? 'kimi', args: options.args ?? ['acp'], spawn, timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS, maxOutputBytes: options.maxOutputBytes ?? MAX_OUTPUT_BYTES }, async rpc => {
    await rpc.request('initialize', { protocolVersion: 1, clientInfo: { name: 'openduck-history', version: '1' }, clientCapabilities: {} })
    await rpc.request('session/load', { sessionId, cwd, mcpServers: [] })
    const messages = []
    for (const event of rpc.notifications) {
      if (event.method === 'session/request_permission' || event.method === 'elicitation/create' || event.method.startsWith('fs/') || event.method.startsWith('terminal/')) throw new Error('history: Kimi ACP requested an unsupported capability')
      if (event.method !== 'session/update') continue
      const update = event.params?.update; const kind = update?.sessionUpdate; const body = acpText(update)
      if (!body || (kind !== 'agent_message_chunk' && kind !== 'user_message_chunk')) continue
      const role = kind === 'user_message_chunk' ? 'user' : 'assistant'; const previous = messages.at(-1)
      if (previous?.message.role === role) previous.message.content += body; else messages.push({ type: role, uuid: `acp-${messages.length + 1}`, timestamp: event.params?.timestamp, message: { role, content: body } })
      if (messages.length >= limit) break
    }
    return { items: messages, nextCursor: null }
  })
}

/** @typedef {import('@agentclientprotocol/sdk').schema.ListSessionsResponse} AcpListSessionsResponse */
/** Read-only ACP session inventory using the protocol's session/list contract. */
export function createKimiAcpList(options = {}) {
  const spawn = options.spawn ?? nodeSpawn
  return async ({ cwd, cursor }) => {
    if (typeof cwd !== 'string' || !cwd.startsWith('/') || (cursor !== undefined && typeof cursor !== 'string')) throw new Error('history: Kimi ACP list request is invalid')
    return withChild({ command: options.command ?? 'kimi', args: options.args ?? ['acp'], spawn, timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS, maxOutputBytes: options.maxOutputBytes ?? MAX_OUTPUT_BYTES }, async rpc => {
      await rpc.request('initialize', { protocolVersion: 1, clientInfo: { name: 'openduck-history', version: '1' }, clientCapabilities: {} })
      return rpc.request('session/list', { cwd, cursor: cursor ?? null })
    })
  }
}

/** Lazy official SDK loader; the native host adds @anthropic-ai/claude-agent-sdk. */
export function createClaudeSdkSource(load = () => import('@anthropic-ai/claude-agent-sdk')) {
  let sdk
  const get = async () => { if (!sdk) sdk = await load(); if (typeof sdk.listSessions !== 'function' || typeof sdk.getSessionMessages !== 'function') throw new Error('history: installed Claude Agent SDK lacks session history helpers'); return sdk }
  return Object.freeze({ async listSessions({ directory }) { return (await get()).listSessions({ dir: directory }) }, async getSessionMessages(sessionId) { return (await get()).getSessionMessages(sessionId) } })
}

/** Production convenience constructor; projects remain exact allowlist entries. */
export function createDefaultHistoryService(policy, ports = {}) {
  const projects = policy?.projects?.map(project => ({ ...project, sources: { ...(project.sources ?? {}), codex: project.sources?.codex ?? { rpc: ports.codexRpc ?? createCodexRpcPort(ports.codex) }, claude: project.sources?.claude ?? createClaudeSdkSource(ports.loadClaudeSdk), kimi: project.sources?.kimi ?? { listSessions: ports.kimiList ?? createKimiAcpList(ports.kimiAcp), readTranscript: ports.kimiRead ?? createKimiAcpReader(ports.kimiAcp) } } }))
  return createHistoryService({ ...policy, projects })
}
