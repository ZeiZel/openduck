import { CliSubscriptionAdapter } from './adapter.js'
import { createCliTransport } from './transport.js'
import { createCodexRunner } from './codex.js'
import { createClaudeRunner } from './claude.js'
import { createKimiRunner } from './kimi.js'
import { createCliAvailability } from './availability.js'
/** Mount enabled subscription CLIs as native root-model routes. */
export function mountCliRoot(ctx, config = {}, { availability = createCliAvailability(), sessionFor } = {}) {
  if (config.enabled === false || process.env.OPENDUCK_CLI_ROOT_DISABLED === '1') return () => {}
  const transport = createCliTransport()
  const runners = { 'codex-cli': createCodexRunner({ transport }), 'claude-cli': createClaudeRunner({ transport }), 'kimi-acp': createKimiRunner({ transport }) }
  const models = { 'codex-cli': config.models?.codex ?? [], 'claude-cli': config.models?.claude ?? [], 'kimi-acp': config.models?.kimi ?? [] }
  // Do not register unavailable routes: an absent binary must not make the
  // native onboarding believe that a usable non-key provider exists.
  const routes = Object.keys(models).filter(route => availability.installed(route))
  if (routes.length === 0) return () => {}
  return ctx.llm.registerAdapter(routes, new CliSubscriptionAdapter(runners, models, { availability, sessionFor }))
}
