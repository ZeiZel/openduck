import { LlmAdapter, LlmError } from '@deepseek-ai/dsh-llm'

const ROUTES = Object.freeze(['codex-cli', 'claude-cli', 'kimi-acp'])
const routeLabels = Object.freeze({ 'codex-cli': 'Codex CLI', 'claude-cli': 'Claude CLI', 'kimi-acp': 'Kimi ACP' })
const unsupported = message => { throw new LlmError(message, 'UNSUPPORTED_REQUEST') }
function textContent(message) {
  if (!Array.isArray(message?.content)) unsupported('CLI subscription root chat accepts text messages only.')
  const parts = []
  for (const block of message.content) {
    if (block?.type !== 'text' || typeof block.text !== 'string') unsupported('CLI subscription root chat does not translate images, reasoning, or tool blocks.')
    parts.push(block.text)
  }
  return parts.join('\n')
}
function transcript(options, excludedIndex = -1) {
  const rows = []
  if (options.system) rows.push(`System:\n${options.system}`)
  for (let index = 0; index < options.messages.length; index += 1) {
    if (index === excludedIndex) continue
    const message = options.messages[index]
    if (!['user', 'assistant', 'system'].includes(message.role)) unsupported('CLI subscription root chat received an unsupported message role.')
    rows.push(`${message.role[0].toUpperCase()}${message.role.slice(1)}:\n${textContent(message)}`)
  }
  return rows.join('\n\n')
}
function newestUserIndex(options) {
  for (let index = options.messages.length - 1; index >= 0; index -= 1) if (options.messages[index].role === 'user') return index
  unsupported('CLI subscription continuation requires a user message.')
}

/** Projects subscription-CLI text into DSH chunks while retaining an in-memory remote continuation. */
export class CliSubscriptionAdapter extends LlmAdapter {
  constructor(runners, models, cwd = '') { super(); this.runners = runners; this.models = models; this.cwd = cwd; this.bindings = new Map(); this.busy = new Set() }
  providerInfo(provider) { return { id: provider, name: routeLabels[provider] ?? provider } }
  async listModels(provider) { return (this.models[provider] ?? []).map(id => ({ provider, id, name: id, inputModalities: ['text'] })) }
  async resolveModel(provider, model) {
    if (!ROUTES.includes(provider)) throw new LlmError(`Unknown CLI route ${provider}`, 'NO_ADAPTER')
    if (!(this.models[provider] ?? []).includes(model)) throw new LlmError(`CLI model ${model} is not enabled for ${provider}`, 'UNKNOWN_MODEL')
    return { provider, id: model, name: model, inputModalities: ['text'] }
  }
  async *stream(options) {
    const runner = this.runners[options.provider]
    if (!runner) throw new LlmError(`CLI route ${options.provider} is disabled`, 'NO_ADAPTER')
    // A deployment extension can contribute a host-scoped schema even though
    // this preset mounts none. Do not forward it: every runner below accepts
    // only text and never receives `options.tools`. Tool blocks in the actual
    // transcript remain rejected by textContent(), so a root session cannot
    // turn a prior host call into a pretend subscription-CLI capability.
    await this.resolveModel(options.provider, options.model)
    const latestUser = newestUserIndex(options)
    const auxiliary = options.purpose !== undefined
    const key = auxiliary || options.sessionId === undefined ? undefined : `${options.provider}:${options.model}:${options.sessionId}`
    if (key !== undefined && this.busy.has(key)) throw new LlmError('CLI subscription continuation is already running for this session.', 'CONCURRENT_REQUEST')
    const binding = key === undefined ? undefined : this.bindings.get(key)
    const canContinue = binding !== undefined && binding.history === transcript(options, latestUser)
    if (binding !== undefined && !canContinue) this.bindings.delete(key)
    const run = canContinue
      ? runner.continue({ continuation: binding.continuation, dshSessionId: options.sessionId, prompt: textContent(options.messages[latestUser]), model: options.model, cwd: this.cwd, signal: options.signal })
      : runner.stream({ dshSessionId: options.sessionId, prompt: transcript(options), model: options.model, cwd: this.cwd, signal: options.signal })
    void Promise.resolve(run.result).catch(() => {})
    if (key !== undefined) this.busy.add(key)
    let output = ''; let started = false
    try {
      for await (const event of run.events) {
        if (event?.type !== 'text' || typeof event.text !== 'string' || event.text.length === 0) continue
        if (!started) { started = true; yield { type: 'block-start', index: 0, blockType: 'text' } }
        output += event.text; yield { type: 'text-delta', index: 0, text: event.text }
      }
      const complete = await run.result
      if (key !== undefined && complete?.continuation) this.bindings.set(key, { continuation: complete.continuation, history: `${transcript(options)}\n\nAssistant:\n${output}` })
      if (started) yield { type: 'block-end', index: 0, block: { type: 'text', text: output } }
      yield { type: 'finish', reason: { kind: 'stop' } }
    } catch (error) { if (key !== undefined) this.bindings.delete(key); throw error } finally { if (key !== undefined) this.busy.delete(key); run.cancel?.() }
  }
}
export { ROUTES }
