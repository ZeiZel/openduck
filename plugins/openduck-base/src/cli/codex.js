const valid = value => typeof value === 'string' && value.length > 0 && value.length <= 200000 && !value.includes('\0')
const selectedModel = model => model === 'default' ? undefined : model
const rpc = (id, method, params) => ({ jsonrpc: '2.0', id, method, params })
const responseError = event => event?.error ? new Error('Codex app-server rejected a protocol request') : undefined
const deniedRequest = event => {
  const id = event.id
  if (event.method === 'item/commandExecution/requestApproval' || event.method === 'item/fileChange/requestApproval') return { jsonrpc: '2.0', id, result: { decision: 'decline' } }
  if (event.method === 'item/permissions/requestApproval') return { jsonrpc: '2.0', id, result: { permissions: {}, scope: 'turn' } }
  if (event.method === 'item/tool/requestUserInput') return { jsonrpc: '2.0', id, result: { answers: {} } }
  if (event.method === 'mcpServer/elicitation/request') return { jsonrpc: '2.0', id, result: { action: 'decline', content: null, _meta: null } }
  return { jsonrpc: '2.0', id, error: { code: -32601, message: 'OpenDuck CLI root chat does not provide host capabilities' } }
}

/** Codex app-server v2 root-chat runner. It never reads Codex auth or history. */
export function createCodexRunner({ transport, command = 'codex', args = ['app-server', '--stdio'] } = {}) {
  if (!transport || typeof transport.start !== 'function') throw new TypeError('codex runner requires a transport')
  const launch = ({ sessionId, prompt, model, cwd, signal, onText }) => {
    if (!valid(prompt) || !valid(model) || (sessionId !== undefined && !valid(sessionId)) || typeof cwd !== 'string' || !cwd.startsWith('/') || cwd.includes('\0')) throw new TypeError('codex app-server request is invalid')
    const chosenModel = selectedModel(model)
    const child = transport.start({ command, args, cwd, signal })
    if (!child?.events || typeof child.events[Symbol.asyncIterator] !== 'function' || typeof child.send !== 'function') throw new TypeError('codex transport lacks app-server stdin')
    let remoteSessionId = sessionId; let turnId; let final; let fallback; let emitted = ''; let terminal; let settle
    const protocol = new Promise((resolve, reject) => { settle = { resolve, reject } }); void protocol.catch(() => {})
    const emitTerminal = event => {
      const turn = event.params?.turn
      if (event.params?.threadId !== remoteSessionId || !turn || (turnId && turn.id !== turnId)) return false
      terminal = turn
      if (turn.status === 'completed') settle.resolve()
      else {
        // Codex reports actionable failures (usage limit, auth, model) in turn.error.message.
        const detail = typeof turn.error?.message === 'string' && turn.error.message.length > 0 ? `: ${turn.error.message.slice(0, 400)}` : ''
        settle.reject(new Error(`Codex turn ${String(turn.status)}${detail}`))
      }
      return true
    }
    const events = (async function * () {
      try {
        await child.send(rpc(1, 'initialize', { clientInfo: { name: 'openduck', title: 'OpenDuck', version: '1' }, capabilities: { experimentalApi: false, requestAttestation: false } }))
        for await (const raw of child.events) {
          let event = raw; if (typeof raw === 'string') { try { event = JSON.parse(raw) } catch { continue } }
          const rejected = responseError(event); if (rejected) throw rejected
          if (event?.method && event.id !== undefined) { await child.send(deniedRequest(event)); continue }
          if (event?.id === 1) {
            await child.send({ jsonrpc: '2.0', method: 'initialized', params: {} })
            await child.send(sessionId ? rpc(2, 'thread/resume', { threadId: sessionId, cwd, ...(chosenModel ? { model: chosenModel } : {}), sandbox: 'read-only', approvalPolicy: 'never' }) : rpc(2, 'thread/start', { cwd, ...(chosenModel ? { model: chosenModel } : {}), ephemeral: false, sandbox: 'read-only', approvalPolicy: 'never' }))
            continue
          }
          if (event?.id === 2) {
            const id = event.result?.thread?.id
            if (!valid(id)) throw new Error('Codex app-server did not return a thread id')
            remoteSessionId = id
            await child.send(rpc(3, 'turn/start', { threadId: id, input: [{ type: 'text', text: prompt, text_elements: [] }], ...(chosenModel ? { model: chosenModel } : {}), approvalPolicy: 'never', sandboxPolicy: { type: 'readOnly', networkAccess: false } }))
            continue
          }
          if (event?.id === 3) { if (!valid(event.result?.turn?.id)) throw new Error('Codex app-server did not return a turn id'); turnId = event.result.turn.id; continue }
          if (event?.method === 'item/agentMessage/delta') {
            const p = event.params
            if (p?.threadId === remoteSessionId && (!turnId || p?.turnId === turnId) && typeof p.delta === 'string' && p.delta.length > 0) { emitted += p.delta; onText?.(p.delta); yield Object.freeze({ type: 'text', text: p.delta }) }
            continue
          }
          if (event?.method === 'item/completed') {
            const p = event.params; if (p?.threadId !== remoteSessionId || (turnId && p?.turnId !== turnId)) continue
            const item = p?.item; if (item?.type !== 'agentMessage' || typeof item.text !== 'string') continue
            if (item.phase === 'final_answer') final = item.text; else if (item.phase === null) fallback = item.text
            else if (item.phase !== 'commentary') throw new Error('Codex app-server returned an unsupported agent message phase')
            continue
          }
          if (event?.method === 'turn/completed' && emitTerminal(event)) {
            const text = final ?? fallback
            if (text && emitted.length === 0) { onText?.(text); yield Object.freeze({ type: 'text', text }) }
            else if (text?.startsWith(emitted) && text.length > emitted.length) { const suffix = text.slice(emitted.length); onText?.(suffix); yield Object.freeze({ type: 'text', text: suffix }) }
            break
          }
        }
        if (!terminal) throw new Error('Codex app-server closed without turn completion')
      } catch (error) { settle.reject(error); throw error }
    })()
    const result = protocol.then(() => ({ continuation: remoteSessionId ? { provider: 'codex', remoteSessionId } : undefined })); void result.catch(() => {})
    return Object.freeze({ events, result, cancel: typeof child.cancel === 'function' ? () => child.cancel() : undefined })
  }
  return Object.freeze({ catalog: async () => Object.freeze([{ id: 'codex-cli', label: 'Codex CLI' }]), stream: request => launch(request), continue: ({ continuation, ...request }) => { if (continuation?.provider !== 'codex' || !valid(continuation.remoteSessionId)) throw new TypeError('codex continuation is invalid'); return launch({ ...request, sessionId: continuation.remoteSessionId }) } })
}
