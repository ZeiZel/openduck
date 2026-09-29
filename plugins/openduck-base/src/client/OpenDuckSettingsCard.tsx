import React, { useEffect, useState, useSyncExternalStore } from 'react'
import { Button, Input } from '@deepseek-ai/dsh-client-ui-primitives'
import { saveAcceptedHistory, saveAcceptedCliRoot } from './settings-save.js'
import type { HistoryRpc } from './HistoryViewer.js'

type Project = { root: string; displayName?: string }
type CliRoot = { enabled: boolean; cwd: string; models: { codex: string[]; claude: string[]; kimi: string[] } }
type Snapshot = { value?: { history?: { projects?: Project[] }; cliRoot?: Partial<CliRoot> }; writable?: boolean; status?: string }
export type SettingsScope = { getSnapshot: () => Snapshot; subscribe: (listener: () => void) => () => void; set: (field: string, value: unknown) => Promise<boolean> }
type Provider = 'codex' | 'claude' | 'kimi'
type ProviderStatus = { provider: Provider; label: string; installed: boolean; auth: 'authenticated' | 'not-signed-in' | 'unknown' }
const rootIsValid = (root: string): boolean => /^\/(?:[^/\0]+\/?)*$/.test(root) && !root.includes('/../') && !root.endsWith('/..')
const cliRootOf = (value: NonNullable<Snapshot['value']>['cliRoot']): CliRoot => ({ enabled: value?.enabled === true, cwd: value?.cwd ?? '', models: { codex: value?.models?.codex ?? [], claude: value?.models?.claude ?? [], kimi: value?.models?.kimi ?? [] } })
function statusItems(value: unknown): ProviderStatus[] {
  if (value === null || typeof value !== 'object' || !Array.isArray((value as { items?: unknown }).items)) return []
  return (value as { items: unknown[] }).items.filter((item): item is ProviderStatus => Boolean(item && typeof item === 'object' && ['codex', 'claude', 'kimi'].includes((item as ProviderStatus).provider) && typeof (item as ProviderStatus).label === 'string' && typeof (item as ProviderStatus).installed === 'boolean' && ['authenticated', 'not-signed-in', 'unknown'].includes((item as ProviderStatus).auth)))
}

/** Native configuration card; settings persist only after their resolved snapshot accepts them. */
export const OpenDuckSettingsCard = ({ scope, rpc }: { scope: SettingsScope; rpc: HistoryRpc }) => {
  const snapshot = useSyncExternalStore(scope.subscribe.bind(scope), scope.getSnapshot.bind(scope))
  const [root, setRoot] = useState(''); const [pending, setPending] = useState(false); const [error, setError] = useState('')
  const value = snapshot.value ?? {}
  const projects = value.history?.projects ?? []; const persistedCli = cliRootOf(value.cliRoot)
  const [cliDraft, setCliDraft] = useState<CliRoot>(persistedCli); const [cliDirty, setCliDirty] = useState(false)
  const [providers, setProviders] = useState<ProviderStatus[]>([]); const [providerBusy, setProviderBusy] = useState(false); const [providerError, setProviderError] = useState('')
  const writable = snapshot.writable !== false
  useEffect(() => { if (!cliDirty) setCliDraft(persistedCli) }, [value.cliRoot, cliDirty])
  useEffect(() => { if (root && projects.some(project => project.root === root.trim())) { setRoot(''); setPending(false); setError('') } }, [projects, root])
  const save = async (next: Project[]): Promise<void> => {
    if (!writable) { setError('This settings source is read-only.'); return }
    setPending(true); setError('')
    try { if (!await saveAcceptedHistory(scope, next)) throw new Error('settings snapshot did not accept history'); setPending(false) } catch { setPending(false); setError('DSH rejected this history configuration. The project directory must exist and be canonical.') }
  }
  const saveCli = async (): Promise<void> => {
    if (!writable) { setError('This settings source is read-only.'); return }
    setPending(true); setError('')
    try { if (!await saveAcceptedCliRoot(scope, cliDraft)) throw new Error('settings snapshot did not accept CLI root chat'); setCliDirty(false); setPending(false) } catch { setPending(false); setError('DSH rejected CLI root-chat settings.') }
  }
  const setCli = (next: CliRoot): void => { setCliDraft(next); setCliDirty(true) }
  const refreshProviders = async (): Promise<void> => {
    setProviderBusy(true)
    setProviderError('')
    try { const response = await rpc.call('/api', 'openduck-cli/status', {}); setProviders(response.ok ? statusItems(response.value) : []) } catch { setProviders([]); setProviderError('CLI status is unavailable.') } finally { setProviderBusy(false) }
  }
  const signIn = async (provider: Provider): Promise<void> => { setProviderBusy(true); setProviderError(''); try { const response = await rpc.call('/api', 'openduck-cli/login', { provider }); if (!response.ok) setProviderError('Terminal sign-in could not start.') } catch { setProviderError('Terminal sign-in could not start.') } finally { setProviderBusy(false) } }
  useEffect(() => { void refreshProviders() }, [rpc])
  const addProject = (): void => { const candidate = root.trim(); if (!rootIsValid(candidate)) { setError('Enter an absolute canonical project directory.'); return }; if (projects.some(project => project.root === candidate)) { setError('This project is already configured.'); return }; void save([...projects, { root: candidate }]) }
  const removeProject = (candidate: string): void => { void save(projects.filter(project => project.root !== candidate)) }
  return <section>
    <h2>CLI subscriptions</h2><p>Installed Codex, Claude and Kimi CLIs are detected automatically; no connection step is needed for chat. Pick one of their models in a new chat. Optional delegation and Computer MCP overlays still use <code>make connect-codex</code>, <code>make connect-claude</code>, <code>make connect-kimi</code> and <code>make connect-computer</code>.</p>
    <h2>CLI root chat</h2><p>Installed Codex, Claude, and Kimi CLIs appear with their configured default model. Select a CLI model in a blank session and OpenDuck switches it to the CLI root preset. Each turn uses that session’s selected workspace. Root chat is text-only: host-tool schemas are never sent to a subscription CLI and DSH tools cannot run in this mode.</p>
    <label><input type="checkbox" checked={cliDraft.enabled} disabled={!writable || pending} onChange={event => setCli({ ...cliDraft, enabled: event.target.checked })} /> Enable CLI root chat</label>
    <Button disabled={!writable || pending || !cliDirty} onClick={() => { void saveCli() }}>Save CLI root chat</Button><p>Changes to this switch take effect when DSH restarts.</p>
    <div style={{ display: 'grid', gap: 6, marginTop: 10 }}><strong>CLI sign-in</strong><Button disabled={providerBusy} onClick={() => { void refreshProviders() }}>Refresh CLI status</Button>{providers.length === 0 && !providerBusy && <p role="status">No installed CLI status is available yet.</p>}{providers.map(provider => <div key={provider.provider}>{provider.label}: {!provider.installed ? 'not installed' : provider.auth === 'authenticated' ? 'signed in' : provider.auth === 'not-signed-in' ? 'sign-in required' : 'status unavailable'} {provider.installed && provider.auth !== 'authenticated' && <Button disabled={providerBusy} onClick={() => { void signIn(provider.provider) }}>{provider.auth === 'unknown' ? 'Sign in' : 'Open sign-in'}</Button>}</div>)}{providerError && <p role="alert">{providerError}</p>}</div>
    <h2>External history projects</h2><p>Only exact existing project directories listed here can be queried by the read-only history viewer.</p>
    {snapshot.status && snapshot.status !== 'ready' && <p role="status">Settings are {snapshot.status}.</p>}{!writable && <p role="status">This settings source is read-only.</p>}
    <ul>{projects.map(project => <li key={project.root}>{project.displayName || project.root} <Button disabled={!writable || pending} onClick={() => removeProject(project.root)}>Remove</Button></li>)}</ul>
    <label>Project directory <Input value={root} disabled={!writable || pending} onChange={event => { setRoot(event.target.value); setError('') }} placeholder="/absolute/project" /></label>
    <Button onClick={addProject} disabled={!writable || pending || !root.trim()}>Add project</Button>{pending && <p role="status">Saving configuration…</p>}{error && <p role="alert">{error}</p>}
  </section>
}
