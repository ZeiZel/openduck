import React, { useEffect, useState, useSyncExternalStore } from 'react'
import { Button, Input } from '@deepseek-ai/dsh-client-ui-primitives'
import { saveAcceptedHistory, saveAcceptedCliRoot } from './settings-save.js'

type Project = { root: string; displayName?: string }
type CliRoot = { enabled: boolean; cwd: string; models: { codex: string[]; claude: string[]; kimi: string[] } }
type Snapshot = { value: { history?: { projects?: Project[] }; cliRoot?: Partial<CliRoot> }; writable?: boolean; status?: string }
export type SettingsScope = { getSnapshot: () => Snapshot; subscribe: (listener: () => void) => () => void; set: (field: string, value: unknown) => Promise<void> }
const rootIsValid = (root: string): boolean => /^\/(?:[^/\0]+\/?)*$/.test(root) && !root.includes('/../') && !root.endsWith('/..')
const cliRootOf = (value: Snapshot['value']['cliRoot']): CliRoot => ({ enabled: value?.enabled === true, cwd: value?.cwd ?? '', models: { codex: value?.models?.codex ?? [], claude: value?.models?.claude ?? [], kimi: value?.models?.kimi ?? [] } })

/** Native configuration card; settings persist only after their resolved snapshot accepts them. */
export const OpenDuckSettingsCard = ({ scope }: { scope: SettingsScope }) => {
  const snapshot = useSyncExternalStore(scope.subscribe.bind(scope), scope.getSnapshot.bind(scope))
  const [root, setRoot] = useState(''); const [pending, setPending] = useState(false); const [error, setError] = useState('')
  const projects = snapshot.value.history?.projects ?? []; const persistedCli = cliRootOf(snapshot.value.cliRoot)
  const [cliDraft, setCliDraft] = useState<CliRoot>(persistedCli); const [cliDirty, setCliDirty] = useState(false)
  const writable = snapshot.writable !== false
  useEffect(() => { if (!cliDirty) setCliDraft(persistedCli) }, [snapshot.value.cliRoot, cliDirty])
  useEffect(() => { if (root && projects.some(project => project.root === root.trim())) { setRoot(''); setPending(false); setError('') } }, [projects, root])
  const save = async (next: Project[]): Promise<void> => {
    if (!writable) { setError('This settings source is read-only.'); return }
    setPending(true); setError('')
    try { if (!await saveAcceptedHistory(scope, next)) throw new Error('settings snapshot did not accept history'); setPending(false) } catch { setPending(false); setError('DSH rejected this history configuration. The project directory must exist and be canonical.') }
  }
  const saveCli = async (): Promise<void> => {
    if (!writable) { setError('This settings source is read-only.'); return }
    setPending(true); setError('')
    try { if (!await saveAcceptedCliRoot(scope, cliDraft)) throw new Error('settings snapshot did not accept CLI root chat'); setCliDirty(false); setPending(false) } catch { setPending(false); setError('DSH rejected CLI root-chat settings. Choose an existing canonical workspace and at least one explicit model.') }
  }
  const setCli = (next: CliRoot): void => { setCliDraft(next); setCliDirty(true) }
  const addProject = (): void => { const candidate = root.trim(); if (!rootIsValid(candidate)) { setError('Enter an absolute canonical project directory.'); return }; if (projects.some(project => project.root === candidate)) { setError('This project is already configured.'); return }; void save([...projects, { root: candidate }]) }
  const removeProject = (candidate: string): void => { void save(projects.filter(project => project.root !== candidate)) }
  return <section>
    <h2>OpenDuck connections</h2><p>Connect configured CLI subscriptions in a local terminal, then restart DSH.</p>
    <ul><li>Codex: <code>make connect-codex</code></li><li>Claude: <code>make connect-claude</code></li><li>Kimi ACP: <code>make connect-kimi</code></li><li>Computer MCP: <code>make connect-computer</code></li></ul><p>Use <code>make doctor</code> for installed-provider readiness.</p>
    <h2>CLI root chat</h2><p>Use <code>make connect-cli-chat</code>, configure an explicit workspace and model allowlist, save this section, then restart DSH. This fixed workspace applies to every CLI root-chat turn. Root chat is text-only: DSH host-tool schemas are dropped and DSH tools cannot run in this mode.</p>
    <label><input type="checkbox" checked={cliDraft.enabled} disabled={!writable || pending} onChange={event => setCli({ ...cliDraft, enabled: event.target.checked })} /> Enable CLI root chat</label>
    <label>Workspace directory <Input value={cliDraft.cwd} disabled={!writable || pending} onChange={event => setCli({ ...cliDraft, cwd: event.target.value })} placeholder="/canonical/project" /></label>
    <label>Codex model <Input value={cliDraft.models.codex[0] ?? ''} disabled={!writable || pending} onChange={event => setCli({ ...cliDraft, models: { ...cliDraft.models, codex: event.target.value ? [event.target.value] : [] } })} placeholder="default or installed CLI model id" /></label>
    <label>Claude model <Input value={cliDraft.models.claude[0] ?? ''} disabled={!writable || pending} onChange={event => setCli({ ...cliDraft, models: { ...cliDraft.models, claude: event.target.value ? [event.target.value] : [] } })} placeholder="default or installed CLI model id" /></label>
    <label>Kimi route label <Input value={cliDraft.models.kimi[0] ?? ''} disabled={!writable || pending} onChange={event => setCli({ ...cliDraft, models: { ...cliDraft.models, kimi: event.target.value ? [event.target.value] : [] } })} placeholder="default (Kimi ACP configured default)" /></label>
    <Button disabled={!writable || pending || !cliDirty} onClick={() => { void saveCli() }}>Save CLI root chat</Button>
    <h2>External history projects</h2><p>Only exact existing project directories listed here can be queried by the read-only history viewer.</p>
    {snapshot.status && snapshot.status !== 'ready' && <p role="status">Settings are {snapshot.status}.</p>}{!writable && <p role="status">This settings source is read-only.</p>}
    <ul>{projects.map(project => <li key={project.root}>{project.displayName || project.root} <Button disabled={!writable || pending} onClick={() => removeProject(project.root)}>Remove</Button></li>)}</ul>
    <label>Project directory <Input value={root} disabled={!writable || pending} onChange={event => { setRoot(event.target.value); setError('') }} placeholder="/absolute/project" /></label>
    <Button onClick={addProject} disabled={!writable || pending || !root.trim()}>Add project</Button>{pending && <p role="status">Saving configuration…</p>}{error && <p role="alert">{error}</p>}
  </section>
}
