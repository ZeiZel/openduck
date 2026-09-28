const valid = value => typeof value === 'string' && value.length > 0 && value.length <= 200000 && !value.includes('\0')
const acp = (id, method, params) => ({ jsonrpc: '2.0', id, method, params })

/** Kimi's documented ACP route. The persistent ACP child is released after each turn. */
export function createKimiRunner({ transport, command = 'kimi', args = ['acp'] } = {}) {
  if (!transport || typeof transport.start !== 'function') throw new TypeError('kimi runner requires a transport')
  const launch = ({ sessionId, prompt, model, cwd, signal, onText }) => {
    if (!valid(prompt) || !valid(model) || (sessionId !== undefined && !valid(sessionId)) || typeof cwd !== 'string' || !cwd.startsWith('/') || cwd.includes('\0')) throw new TypeError('kimi ACP request is invalid')
    // Kimi ACP documents `kimi acp`; its prompt-mode model switch is not an
    // ACP-server argument. Preserve the DSH selector for routing, but let the
    // subscribed ACP server select its configured model.
    const child = transport.start({ command, args, cwd, signal })
    if (!child?.events || typeof child.events[Symbol.asyncIterator] !== 'function' || typeof child.send !== 'function') throw new TypeError('kimi transport lacks ACP stdin')
    let remoteSessionId = sessionId; let prompted = false; let terminal = false; let settle
    const protocol = new Promise((resolve, reject) => { settle = { resolve, reject } }); void protocol.catch(() => {})
    const events = (async function * () {
      try {
        await child.send(acp(1, 'initialize', { protocolVersion: 1, clientInfo: { name: 'openduck', version: '1' }, clientCapabilities: {} }))
        for await (const raw of child.events) {
          let event = raw; if (typeof raw === 'string') { try { event = JSON.parse(raw) } catch { continue } }
          if (event?.error) throw new Error('Kimi ACP rejected a protocol request')
          if (event?.method && event.id !== undefined) {
            await child.send({ jsonrpc: '2.0', id: event.id, error: { code: -32601, message: 'OpenDuck CLI root chat does not provide filesystem, terminal, permission, or MCP capabilities' } })
            continue
          }
          if (event?.id === 1) {
            await child.send(sessionId ? acp(2, 'session/load', { sessionId, cwd, mcpServers: [] }) : acp(2, 'session/new', { cwd, mcpServers: [] }))
            continue
          }
          if (event?.id === 2) {
            const id = sessionId ?? event.result?.sessionId
            if (!valid(id)) throw new Error('Kimi ACP did not return a session id')
            remoteSessionId = id; prompted = true
            await child.send(acp(3, 'session/prompt', { sessionId: id, prompt: [{ type: 'text', text: prompt }] }))
            continue
          }
          if (event?.method === 'session/update') {
            const update = event.params?.update
            if (prompted && event.params?.sessionId === remoteSessionId && update?.sessionUpdate === 'agent_message_chunk' && update.content?.type === 'text' && typeof update.content.text === 'string') { onText?.(update.content.text); yield Object.freeze({ type: 'text', text: update.content.text }) }
            continue
          }
          if (event?.id === 3) {
            if (['cancelled', 'canceled', 'refused'].includes(String(event.result?.stopReason))) throw new Error(`Kimi ACP prompt ended with ${String(event.result.stopReason)}`)
            terminal = true; settle.resolve(); break
          }
        }
        if (!prompted) throw new Error('Kimi ACP closed before starting a prompt')
        if (!remoteSessionId) throw new Error('Kimi ACP closed without a session')
        if (!terminal) throw new Error('Kimi ACP closed before the prompt completed')
      } catch (error) { settle.reject(error); throw error }
    })()
    const result = protocol.then(() => ({ continuation: remoteSessionId ? { provider: 'kimi', remoteSessionId } : undefined })); void result.catch(() => {})
    return Object.freeze({ events, result, cancel: typeof child.cancel === 'function' ? () => child.cancel() : undefined })
  }
  return Object.freeze({ catalog: async () => Object.freeze([{ id: 'kimi-cli', label: 'Kimi CLI' }]), stream: request => launch(request), continue: ({ continuation, ...request }) => { if (continuation?.provider !== 'kimi' || !valid(continuation.remoteSessionId)) throw new TypeError('kimi continuation is invalid'); return launch({ ...request, sessionId: continuation.remoteSessionId }) } })
}
