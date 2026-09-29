import { Button } from '@deepseek-ai/dsh-client-ui-primitives'
import React from 'react'
import { OpenDuckSettingsCard, type SettingsScope } from './OpenDuckSettingsCard.js'
import { HistoryViewer, type HistoryRpc } from './HistoryViewer.js'
import { HistorySidebarAction } from './HistorySidebarAction.js'
import { CliRootAuthAction, type ModelDirectories, type PresetApi, type Sessions } from './CliRootAuthAction.js'

type Slots = {
  inject: (name: string, callback: () => unknown) => () => void
  register: (options: { name: string; key?: string; id?: string; order?: number; label?: () => string; locale?: string; inject: (sessionId?: string) => Record<string, unknown> }, component: (props: { wide?: boolean; sessionId?: string; dockSessionId?: string; view?: 'summary' | 'page' | 'detail' }) => React.JSX.Element | string | null) => unknown
}
type ClientContext = { slots: Slots; connection: { rpc: HistoryRpc }; configForms: { get: <T>(entryId: string) => T; whileServed: (entryIds: string[], register: () => () => void) => () => void }; remote: PresetApi; modelDirectories: ModelDirectories; sessions: Sessions; effect: (callback: () => () => void, name: string) => void }

// Typert Remote namespaces must be declared individually in DSH 0.1.7.
export const inject = ['slots', 'connection', 'configForms', 'remote', 'remote.agentPresets', 'modelDirectories', 'sessions']
export const apply = (ctx: ClientContext): void => {
  // ConfigForms is keyed by the active host entry id from cordis.patch.yml.
  // This preserves the legacy `openduck` settings section during RC2 import.
  const form = ctx.configForms.get<SettingsScope>('openduck')
  ctx.effect(() => ctx.configForms.whileServed(['openduck'], () => ctx.slots.inject('plugins.item', () => ctx.slots.register({
    name: 'plugins.item', id: 'openduck', order: 30, label: () => 'OpenDuck', inject: () => ({}),
  }, ({ view }) => view === 'summary' ? 'CLI subscriptions, root chat and external history.' : <OpenDuckSettingsCard scope={form} rpc={ctx.connection.rpc} />))), 'openduck-base.settings-page')
  ctx.slots.inject('sidebar.footer.action', () => ctx.slots.register({
    name: 'sidebar.footer.action', id: 'openduck-cli-history', locale: 'settings.plugins', inject: () => ({}),
  }, ({ wide }) => <HistorySidebarAction rpc={ctx.connection.rpc} wide={wide === true} />))
  // The composer dock is session-scoped and rendered on the blank hero composer
  // as well as in running sessions, so selecting a CLI model in a new chat is
  // observed before the first turn. (The session header is absent on blank chats.)
  ctx.slots.inject('conversation.input.dock', () => ctx.slots.register({
    name: 'conversation.input.dock', id: 'openduck-cli-auth', order: 30, inject: (sessionId?: string) => ({ dockSessionId: sessionId }),
  }, ({ dockSessionId }) => dockSessionId === undefined ? null : <CliRootAuthAction sessionId={dockSessionId} modelDirectories={ctx.modelDirectories} sessions={ctx.sessions} presets={ctx.remote} rpc={ctx.connection.rpc} />))
}
export const NativeButton = Button
