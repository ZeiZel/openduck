/**
 * Read-only project-scoped adapters for local coding-agent history.
 *
 * This module deliberately has no default filesystem or child-process access.
 * A host supplies narrowly scoped ports after it has obtained the user's
 * explicit project allowlist.  That makes imports deterministic in tests and
 * prevents a DSH plugin from discovering a home directory by itself.
 */

const PROVIDERS = new Set(['codex', 'claude', 'kimi'])
const MAX_LIMIT = 100
const DEFAULT_LIMIT = 25
const MAX_TEXT = 1024
const MAX_MESSAGE_TEXT = 8192

/** @typedef {{ provider: 'codex'|'claude'|'kimi', projectRoot?: string, cursor?: string, limit?: number }} HistoryListRequest */
/** @typedef {{ provider: 'codex'|'claude'|'kimi', projectRoot?: string, sessionId: string, cursor?: string, limit?: number }} HistoryReadRequest */

function object(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`history: ${label} must be an object`)
  return value
}

function text(value, maximum = MAX_TEXT) {
  if (typeof value !== 'string') return undefined
  const normalized = value.replace(/\u0000/g, '').trim()
  return normalized.length > maximum ? `${normalized.slice(0, maximum)}…` : normalized || undefined
}

function id(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_.:-]{1,256}$/.test(value)) throw new TypeError(`history: ${label} is invalid`)
  return value
}

function timestamp(value) {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value > 1e11 ? new Date(value).toISOString() : new Date(value * 1000).toISOString()
  if (typeof value === 'string' && Number.isFinite(Date.parse(value))) return new Date(value).toISOString()
  return undefined
}

function pageLimit(value) {
  if (value === undefined) return DEFAULT_LIMIT
  if (!Number.isInteger(value) || value < 1 || value > MAX_LIMIT) throw new TypeError(`history: limit must be an integer from 1 to ${MAX_LIMIT}`)
  return value
}

function cursor(value) {
  if (value === undefined || value === null) return undefined
  if (typeof value !== 'string' || value.length < 1 || value.length > 4096) throw new TypeError('history: cursor is invalid')
  return value
}

function sourceFor(policy, provider, projectRoot) {
  const root = typeof projectRoot === 'string' ? projectRoot : undefined
  if (!root || !root.startsWith('/') || root.includes('\u0000')) throw new TypeError('history: projectRoot must be an absolute canonical path')
  const project = policy.projects.find(entry => entry.root === root)
  if (!project) throw new Error('history: project is not allowlisted')
  const source = project.sources?.[provider]
  if (!source) throw new Error(`history: ${provider} is not enabled for this project`)
  return { project, source }
}

function projectView(project) {
  return Object.freeze({ root: project.root, displayName: text(project.displayName, 200) || project.root.split('/').filter(Boolean).at(-1) || project.root })
}

function unsupported(provider, reason) {
  return Object.freeze({ status: 'unsupported', provider, reason, items: Object.freeze([]), nextCursor: null })
}

function flattenContent(content) {
  if (typeof content === 'string') return text(content)
  if (!Array.isArray(content)) return undefined
  return text(content.filter(block => block && typeof block === 'object' && block.type === 'text' && typeof block.text === 'string').map(block => block.text).join('\n'))
}

function normalizedMessage(raw, fallbackId) {
  const entry = object(raw, 'message')
  const payload = entry.message && typeof entry.message === 'object' ? entry.message : entry
  const role = payload.role === 'user' || entry.type === 'user' ? 'user' : payload.role === 'assistant' || entry.type === 'assistant' ? 'assistant' : undefined
  const body = flattenContent(payload.content)
  if (!role || !body) return undefined
  return Object.freeze({ id: typeof entry.uuid === 'string' ? id(entry.uuid, 'message id') : fallbackId, role, text: body, createdAt: timestamp(entry.timestamp) })
}

function codexMessage(item, fallbackId) {
  if (!item || typeof item !== 'object') return undefined
  let role; let body
  if (item.type === 'userMessage') { role = 'user'; body = Array.isArray(item.content) ? item.content.filter(part => part?.type === 'text' && typeof part.text === 'string').map(part => part.text).join('\n') : undefined }
  if (item.type === 'agentMessage') { role = 'assistant'; body = item.text }
  if (!role || typeof body !== 'string' || !body.trim()) return undefined
  const clean = body.replace(/\u0000/g, '').trim()
  return Object.freeze({ id: typeof item.id === 'string' ? id(item.id, 'message id') : fallbackId, role, text: clean.slice(0, MAX_MESSAGE_TEXT), truncated: clean.length > MAX_MESSAGE_TEXT })
}

function offsetCursor(value) { if (value === undefined || value === null) return 0; if (typeof value !== 'string' || !/^offset:[0-9]+$/.test(value)) throw new TypeError('history: read cursor is invalid'); return Number(value.slice(7)) }
function pageMessages(messages, request, provider, sessionId) { const start = offsetCursor(request.cursor); const limit = pageLimit(request.limit); const items = messages.slice(start, start + limit); return Object.freeze({ status: 'ok', provider, sessionId, items: Object.freeze(items), nextCursor: start + items.length < messages.length ? `offset:${start + items.length}` : null }) }

function normalizeCodexSummary(raw, project) {
  const item = object(raw, 'Codex thread')
  return Object.freeze({ provider: 'codex', sessionId: id(item.id, 'session id'), sessionRootId: typeof item.sessionId === 'string' ? id(item.sessionId, 'session root id') : undefined, project: projectView(project), title: text(item.name, 200), preview: text(item.preview), createdAt: timestamp(item.createdAt), updatedAt: timestamp(item.updatedAt), archived: Boolean(item.archived), forkedFrom: typeof item.forkedFromId === 'string' ? id(item.forkedFromId, 'fork id') : undefined, sourceVersion: 'codex-app-server.v1' })
}

function normalizeClaudeSummary(raw, project) {
  const item = object(raw, 'Claude session')
  return Object.freeze({ provider: 'claude', sessionId: id(item.session_id ?? item.sessionId, 'session id'), project: projectView(project), title: text(item.custom_title ?? item.customTitle ?? item.summary, 200), preview: text(item.first_prompt ?? item.firstPrompt), createdAt: timestamp(item.created_at ?? item.createdAt), updatedAt: timestamp(item.last_modified ?? item.lastModified ?? item.mtime), archived: false, sourceVersion: 'claude-agent-sdk.v1' })
}

function normalizeKimiSummary(raw, project) {
  const item = object(raw, 'Kimi session')
  if (typeof item.cwd !== 'string' || item.cwd !== project.root) throw new Error('history: Kimi session is not a member of this project')
  return Object.freeze({ provider: 'kimi', sessionId: id(item.sessionId, 'session id'), project: projectView(project), title: text(item.title, 200), updatedAt: timestamp(item.updatedAt), sourceVersion: 'kimi-acp.v1' })
}

async function codexList(source, request, project) {
  if (typeof source.rpc !== 'function') return unsupported('codex', 'Codex app-server RPC is unavailable')
  const result = await source.rpc('thread/list', { cursor: cursor(request.cursor) ?? null, limit: pageLimit(request.limit), sortKey: 'updated_at', sortDirection: 'desc', cwd: project.root, sourceKinds: ['cli', 'vscode', 'exec', 'appServer'] })
  const data = object(result, 'Codex response').data
  if (!Array.isArray(data)) throw new Error('history: unsupported Codex thread/list response')
  return Object.freeze({ status: 'ok', provider: 'codex', items: Object.freeze(data.map(item => normalizeCodexSummary(item, project))), nextCursor: result.nextCursor ?? null })
}

async function codexRead(source, request, project) {
  if (typeof source.rpc !== 'function') return unsupported('codex', 'Codex app-server RPC is unavailable')
  const sessionId = id(request.sessionId, 'session id')
  const metadata = object(await source.rpc('thread/read', { threadId: sessionId, includeTurns: false }), 'Codex metadata response').thread
  if (!metadata || metadata.cwd !== project.root) throw new Error('history: Codex session is not a member of this project')
  const result = await source.rpc('thread/read', { threadId: sessionId, includeTurns: true })
  const thread = object(result, 'Codex response').thread
  if (thread.cwd !== project.root) throw new Error('history: Codex session project changed during read')
  if (!thread || !Array.isArray(thread.turns)) return unsupported('codex', 'Codex thread history is unavailable for this storage format')
  const messages = []
  for (const turn of thread.turns) {
    for (const item of Array.isArray(turn.items) ? turn.items : []) {
      const message = codexMessage(item, `turn-${messages.length + 1}`)
      if (message) messages.push(message)
    }
  }
  return pageMessages(messages, request, 'codex', id(thread.id ?? sessionId, 'session id'))
}

async function claudeList(source, request, project) {
  if (typeof source.listSessions !== 'function') return unsupported('claude', 'Claude Agent SDK session API is unavailable')
  const records = await source.listSessions({ directory: project.root, limit: pageLimit(request.limit), cursor: cursor(request.cursor) })
  const data = Array.isArray(records) ? records : records?.items
  if (!Array.isArray(data)) throw new Error('history: unsupported Claude Agent SDK list response')
  return Object.freeze({ status: 'ok', provider: 'claude', items: Object.freeze(data.slice(0, pageLimit(request.limit)).map(item => normalizeClaudeSummary(item, project))), nextCursor: records?.nextCursor ?? null })
}

async function claudeRead(source, request) {
  if (typeof source.getSessionMessages !== 'function') return unsupported('claude', 'Claude Agent SDK session API is unavailable')
  if (typeof source.listSessions !== 'function') return unsupported('claude', 'Claude Agent SDK session API is unavailable')
  const sessionId = id(request.sessionId, 'session id')
  const summaries = await source.listSessions({ directory: request.projectRoot })
  const recordsList = Array.isArray(summaries) ? summaries : summaries?.items
  if (!Array.isArray(recordsList) || !recordsList.some(entry => (entry.session_id ?? entry.sessionId) === sessionId && (!entry.cwd || entry.cwd === request.projectRoot))) throw new Error('history: Claude session is not a member of this project')
  const records = await source.getSessionMessages(sessionId)
  if (!Array.isArray(records)) throw new Error('history: unsupported Claude Agent SDK messages response')
  const items = records.map((entry, index) => normalizedMessage(entry, `message-${index + 1}`)).filter(Boolean)
  return pageMessages(items, request, 'claude', sessionId)
}

async function kimiList(source, request, project) {
  if (typeof source.listSessions !== 'function') return unsupported('kimi', 'Kimi ACP session/list is unavailable')
  const records = await source.listSessions({ cwd: project.root, cursor: cursor(request.cursor) })
  if (!records || !Array.isArray(records.sessions) || (records.nextCursor !== undefined && records.nextCursor !== null && typeof records.nextCursor !== 'string')) throw new Error('history: unsupported Kimi ACP session/list response')
  return Object.freeze({ status: 'ok', provider: 'kimi', items: Object.freeze(records.sessions.slice(0, pageLimit(request.limit)).map(item => normalizeKimiSummary(item, project))), nextCursor: records.nextCursor ?? null })
}

async function kimiRead(source, request) {
  // Kimi's documented CLI list API is metadata-only.  A host may supply a
  // version-pinned ACP transcript reader; raw wire.jsonl is intentionally not
  // guessed because it also contains tool/MCP request traces.
  if (typeof source.readTranscript !== 'function') return unsupported('kimi', 'Kimi message replay requires a version-pinned ACP transcript reader')
  const sessionId = id(request.sessionId, 'session id')
  if (typeof source.listSessions !== 'function') return unsupported('kimi', 'Kimi ACP session/list is unavailable')
  let membership; let pageCursor
  for (let page = 0; page < 100; page += 1) {
    const listed = await source.listSessions({ cwd: request.projectRoot, cursor: pageCursor })
    if (!listed || !Array.isArray(listed.sessions)) throw new Error('history: unsupported Kimi ACP session/list response')
    membership = listed.sessions.find(entry => entry?.sessionId === sessionId && entry.cwd === request.projectRoot)
    if (membership || !listed.nextCursor) break
    if (typeof listed.nextCursor !== 'string') throw new Error('history: Kimi ACP cursor is invalid')
    pageCursor = listed.nextCursor
  }
  if (!membership) throw new Error('history: Kimi session is not a member of this project')
  const records = await source.readTranscript({ sessionId, limit: 100, cursor: undefined, cwd: request.projectRoot, mcpServers: [] })
  if (!records || !Array.isArray(records.items)) return unsupported('kimi', 'Kimi transcript reader emitted an unknown schema')
  const items = records.items.map((entry, index) => normalizedMessage(entry, `message-${index + 1}`)).filter(Boolean)
  return pageMessages(items, request, 'kimi', sessionId)
}

/**
 * Creates the shared read-only source API. policy.projects is an immutable
 * array of `{ root, displayName?, sources: { codex?, claude?, kimi? } }`.
 * Ports are provider-local and injected by the native host, never discovered.
 */
export function createHistoryService(policy) {
  object(policy, 'policy')
  if (!Array.isArray(policy.projects)) throw new TypeError('history: policy.projects must be an array')
  for (const project of policy.projects) {
    object(project, 'project')
    if (typeof project.root !== 'string' || !project.root.startsWith('/')) throw new TypeError('history: project root must be absolute')
    object(project.sources ?? {}, 'project sources')
  }
  const frozen = Object.freeze({ projects: Object.freeze(policy.projects.map(project => Object.freeze({ ...project, sources: Object.freeze({ ...project.sources }) }))) })
  return Object.freeze({
    async list(request) {
      object(request, 'list request')
      if (!PROVIDERS.has(request.provider)) throw new TypeError('history: provider is invalid')
      const { project, source } = sourceFor(frozen, request.provider, request.projectRoot)
      if (request.provider === 'codex') return codexList(source, request, project)
      if (request.provider === 'claude') return claudeList(source, request, project)
      return kimiList(source, request, project)
    },
    async read(request) {
      object(request, 'read request')
      if (!PROVIDERS.has(request.provider)) throw new TypeError('history: provider is invalid')
      const { project, source } = sourceFor(frozen, request.provider, request.projectRoot)
      if (request.provider === 'codex') return codexRead(source, request, project)
      if (request.provider === 'claude') return claudeRead(source, request, project)
      return kimiRead(source, request, project)
    },
  })
}

export const HISTORY_LIMITS = Object.freeze({ defaultPageSize: DEFAULT_LIMIT, maxPageSize: MAX_LIMIT, maxTextBytes: MAX_TEXT })

export { createClaudeSdkSource, createCodexRpcPort, createDefaultHistoryService, createJsonRpcChild, createKimiAcpList, createKimiAcpReader, createKimiCliPort } from './ports.js'
