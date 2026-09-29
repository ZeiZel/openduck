/**
 * Text carried by one Claude Code `stream-json` line.
 * Without `--include-partial-messages` (our invocation) the CLI emits whole
 * top-level `{type:'assistant', message:{content:[{type:'text',text}]}}` lines,
 * then a `{type:'result', result}` line. With partial messages it wraps API
 * deltas as `{type:'stream_event', event:{type:'content_block_delta', ...}}`.
 * Both shapes (and a bare delta) are accepted; subagent turns
 * (`parent_tool_use_id`) are ignored.
 */
const deltaText = value => value?.type === 'content_block_delta' && value.delta?.type === 'text_delta' && typeof value.delta.text === 'string' ? value.delta.text : undefined
const textOf = (value, sawDeltas) => {
  if (!value || typeof value !== 'object') return undefined
  const direct = deltaText(value) ?? (value.type === 'stream_event' ? deltaText(value.event) : undefined)
  if (direct !== undefined) return { text: direct, delta: true }
  if (value.type !== 'assistant' || value.parent_tool_use_id || sawDeltas) return undefined
  const content = Array.isArray(value.message?.content) ? value.message.content : []
  const text = content.filter(block => block?.type === 'text' && typeof block.text === 'string').map(block => block.text).join('')
  return text ? { text, delta: false } : undefined
}
const sessionOf = value => typeof value?.session_id === 'string' ? value.session_id : typeof value?.sessionId === 'string' ? value.sessionId : undefined
const valid = value => typeof value === 'string' && value.length > 0 && value.length <= 200000 && !value.includes('\0')
const selectedModel = model => model === 'default' ? undefined : model
const exitDetail = exit => exit && typeof exit === 'object' && exit.code !== undefined && exit.code !== 0 ? ` (exit code ${String(exit.code)})` : ''

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
    const events = (async function * () {
      let sawDeltas = false; let emitted = ''
      try {
        for await (const raw of child.events) {
          let event = raw; if (typeof raw === 'string') { try { event = JSON.parse(raw) } catch { continue } }
          remoteSessionId ??= sessionOf(event)
          if (event?.type === 'result') {
            terminal = event
            // A result without any streamed assistant text still carries the answer.
            if (terminal.is_error !== true && emitted.length === 0 && typeof terminal.result === 'string' && terminal.result.length > 0) { emitted = terminal.result; onText?.(terminal.result); yield Object.freeze({ type: 'text', text: terminal.result }) }
            break
          }
          const piece = textOf(event, sawDeltas)
          if (!piece) continue
          if (piece.delta) sawDeltas = true
          emitted += piece.text; onText?.(piece.text); yield Object.freeze({ type: 'text', text: piece.text })
        }
      } finally { finish() }
    })()
    const result = Promise.all([Promise.resolve(child.result), consumed]).then(([exit]) => {
      if (!terminal) throw new Error(`Claude CLI ended without a result${exitDetail(exit)}`)
      if (terminal.is_error === true) throw new Error(`Claude CLI reported an error: ${String(terminal.result ?? terminal.subtype ?? 'unknown').slice(0, 300)}`)
      return { continuation: remoteSessionId ? { provider: 'claude', remoteSessionId } : undefined }
    }); void result.catch(() => {})
    return Object.freeze({ events, result, cancel: typeof child.cancel === 'function' ? () => child.cancel() : undefined })
  }
  return Object.freeze({ catalog: async () => Object.freeze([{ id: 'claude-cli', label: 'Claude Code' }]), stream: request => launch(request), continue: ({ continuation, ...request }) => { if (continuation?.provider !== 'claude' || !valid(continuation.remoteSessionId)) throw new TypeError('claude continuation is invalid'); return launch({ ...request, sessionId: continuation.remoteSessionId }) } })
}
