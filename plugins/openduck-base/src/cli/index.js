import { CliSubscriptionAdapter } from './adapter.js'
import { createCliTransport } from './transport.js'
import { createCodexRunner } from './codex.js'
import { createClaudeRunner } from './claude.js'
import { createKimiRunner } from './kimi.js'
/** Mount enabled subscription CLIs as native root-model routes. */
export function mountCliRoot(ctx, config, selected = process.env.OPENDUCK_CLI_ROOT_ENABLED === '1') {
  if (!selected || !config.enabled) return () => {}
  const transport = createCliTransport()
  const runners = { 'codex-cli': createCodexRunner({ transport }), 'claude-cli': createClaudeRunner({ transport }), 'kimi-acp': createKimiRunner({ transport }) }
  const models = { 'codex-cli': config.models.codex, 'claude-cli': config.models.claude, 'kimi-acp': config.models.kimi }
  const routes = Object.entries(models).filter(([, ids]) => ids.length > 0).map(([route]) => route)
  if (!routes.length) return () => {}
  return ctx.llm.registerAdapter(routes, new CliSubscriptionAdapter(runners, models, config.cwd))
}
