import { Button } from '@deepseek-ai/dsh-client-ui-primitives'
import React from 'react'
import { OpenDuckSettingsCard, type SettingsScope } from './OpenDuckSettingsCard.js'
import { HistoryViewer, type HistoryRpc } from './HistoryViewer.js'
import { HistorySidebarAction } from './HistorySidebarAction.js'

type Slots = {
  inject: (name: string, callback: () => unknown) => void
  register: (options: { name: string; key?: string; id?: string; locale: string; inject: () => Record<string, never> }, component: (props: { wide?: boolean }) => React.JSX.Element) => unknown
}
type ClientContext = { slots: Slots; connection: { rpc: HistoryRpc }; settingsScope: { bind: <T>(spec: { namespace: string }) => T } }

export const inject = ['slots', 'connection', 'settingsScope']
export const apply = (ctx: ClientContext): void => {
  ctx.slots.inject('settings.plugin.item', () => ctx.slots.register({
    name: 'settings.plugin.item', key: 'openduck', locale: 'settings.plugins', inject: () => ({}),
  }, () => <OpenDuckSettingsCard scope={ctx.settingsScope.bind<SettingsScope>({ namespace: 'openduck' })} />))
  ctx.slots.inject('sidebar.footer.action', () => ctx.slots.register({
    name: 'sidebar.footer.action', id: 'openduck-cli-history', locale: 'settings.plugins', inject: () => ({}),
  }, ({ wide }) => <HistorySidebarAction rpc={ctx.connection.rpc} wide={wide === true} />))
}
export const NativeButton = Button
