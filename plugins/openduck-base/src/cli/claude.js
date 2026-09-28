const textOf = value => {
  if (!value || typeof value !== 'object') return undefined
  return value.type === 'content_block_delta' && value.delta?.type === 'text_delta' && typeof value.delta.text === 'string' ? value.delta.text : undefined
}
const sessionOf = value => typeof value?.session_id === 'string' ? value.session_id : typeof value?.sessionId === 'string' ? value.sessionId : undefined
const valid = value => typeof value === 'string' && value.length > 0 && value.length <= 200000 && !value.includes('\0')
const selectedModel = model => model === 'default' ? undefined : model

/** Injected Claude Code stream-json protocol; auth stays inside the subscribed CLI. */
export function createClaudeRunner({ transport, command = 'claude' } = {}) {
  if (!transport || typeof transport.start !== 'function') throw new TypeError('claude runner requires a transport')
  const launch = ({ sessionId, prompt, model, cwd, signal, onText }) => {
    if (!valid(prompt) || (sessionId !== undefined && !valid(sessionId))) throw new TypeError('claude runner request is invalid')
    if (model !== undefined && !valid(model)) throw new TypeError('claude model is invalid')
    if (cwd !== undefined && (typeof cwd !== 'string' || !cwd.startsWith('/') || cwd.includes('\0'))) throw new TypeError('claude cwd is invalid')
    const args = ['--print', '--output-format', 'stream-json', '--verbose', '--restricted', '--tools', '', '--permission-mode', 'dontAsk', '--permission-prompts', 'none', '--strict-mcp-config', ...(selectedModel(model) ? ['--model', selectedModel(model)] : []), ...(sessionId ? ['--resume', sessionId] : [])]
    const child = transport.start({ command, args, cwd, input: `${prompt}\n`, signal })
    if (!child?.events || typeof child.events[Symbol.asyncIterator] !== 'function') throw new TypeError('claude transport did not provide events')
    let remoteSessionId = sessionId; let terminal; let finish; const consumed = new Promise(resolve => { finish = resolve })
    const events = (async function * () { try { for await (const raw of child.events) { let event = raw; if (typeof raw === 'string') { try { event = JSON.parse(raw) } catch { continue } } remoteSessionId ??= sessionOf(event); if (event?.type === 'result') { terminal = event; break } const text = textOf(event); if (text) { onText?.(text); yield Object.freeze({ type: 'text', text }) } } } finally { finish() } })()
    const result = Promise.all([Promise.resolve(child.result), consumed]).then(() => { if (!terminal || terminal.is_error === true) throw new Error('Claude CLI stream failed'); return { continuation: remoteSessionId ? { provider: 'claude', remoteSessionId } : undefined } }); void result.catch(() => {})
    return Object.freeze({ events, result, cancel: typeof child.cancel === 'function' ? () => child.cancel() : undefined })
  }
  return Object.freeze({ catalog: async () => Object.freeze([{ id: 'claude-cli', label: 'Claude Code' }]), stream: request => launch(request), continue: ({ continuation, ...request }) => { if (continuation?.provider !== 'claude' || !valid(continuation.remoteSessionId)) throw new TypeError('claude continuation is invalid'); return launch({ ...request, sessionId: continuation.remoteSessionId }) } })
}
