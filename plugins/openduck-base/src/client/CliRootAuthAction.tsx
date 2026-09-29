import React, { useEffect, useRef, useState } from 'react'
import { Button } from '@deepseek-ai/dsh-client-ui-primitives'
import type { HistoryRpc } from './HistoryViewer.js'

type Provider = 'codex' | 'claude' | 'kimi'
type DirectoryState = { status: string; current: { provider?: string } | null }
type Directory = { store: { getSnapshot: () => DirectoryState; subscribe: (listener: () => void) => () => void } }
export type ModelDirectories = { directoryFor: (sessionId: string) => Directory }
type SessionSummary = { blank: boolean; projectionValues?: { agentPreset?: unknown } }
export type Sessions = { list: { getSnapshot: () => { byId: Record<string, SessionSummary | undefined> } } }
type PresetResult = { ok: true; value: string } | { ok: false }
export type PresetApi = { agentPresets: { select: (sessionId: string, agentPreset: string) => Promise<PresetResult> } }

const routeProvider: Record<string, Provider | undefined> = { 'codex-cli': 'codex', 'claude-cli': 'claude', 'kimi-acp': 'kimi' }
const labels: Record<Provider, string> = { codex: 'Codex', claude: 'Claude', kimi: 'Kimi' }
type AuthState = 'authenticated' | 'not-signed-in' | 'unknown'
type Notice = { kind: 'auth'; provider: Provider; auth: AuthState; launched: boolean; failed?: boolean } | { kind: 'new-session' }

function authFor(value: unknown, provider: Provider): AuthState | undefined {
  if (value === null || typeof value !== 'object' || !Array.isArray((value as { items?: unknown }).items)) return undefined
  const item = (value as { items: unknown[] }).items.find(entry => entry !== null && typeof entry === 'object' && (entry as { provider?: unknown }).provider === provider)
  const auth = item !== null && typeof item === 'object' ? (item as { auth?: unknown }).auth : undefined
  return auth === 'authenticated' || auth === 'not-signed-in' || auth === 'unknown' ? auth : undefined
}

/**
 * Last provider observed per session. Kept outside React because the composer
 * dock remounts its entries around a selection; the first ready observation is
 * only a baseline, so reloading a session never triggers sign-in by itself.
 */
const observedProvider = new Map<string, string | null>()

/** Watches only a native user model-selection change; it never replaces DSH's picker. */
export const CliRootAuthAction = ({ sessionId, modelDirectories, sessions, presets, rpc }: { sessionId: string; modelDirectories: ModelDirectories; sessions: Sessions; presets: PresetApi; rpc: HistoryRpc }) => {
  const [notice, setNotice] = useState<Notice | undefined>()
  const launched = useRef(new Set<Provider>())
  const selectionEpoch = useRef(0)
  useEffect(() => {
    let directory: Directory
    try { directory = modelDirectories.directoryFor(sessionId) } catch { return }
    let alive = true
    const selectRootPreset = async (epoch: number, quiet = false): Promise<boolean> => {
      if (!alive || epoch !== selectionEpoch.current) return false
      const refuse = (): false => { if (alive && !quiet) setNotice({ kind: 'new-session' }); return false }
      const session = sessions.list.getSnapshot().byId[sessionId]
      if (session === undefined || !session.blank) return refuse()
      if (session.projectionValues?.agentPreset === 'openduck-cli-root') return true
      try {
        const response = await presets.agentPresets.select(sessionId, 'openduck-cli-root')
        if (!alive || epoch !== selectionEpoch.current) return false
        return response.ok ? true : refuse()
      } catch { return refuse() }
    }
    const inspect = (): void => {
      const state = directory.store.getSnapshot()
      if (state.status !== 'ready') return
      const current = state.current?.provider ?? null
      const hadBaseline = observedProvider.has(sessionId)
      const previous = observedProvider.get(sessionId)
      observedProvider.set(sessionId, current)
      const changed = hadBaseline && previous !== current
      const provider = routeProvider[current ?? '']
      if (provider === undefined) return
      // A blank session that already carries a CLI model (e.g. inherited from
      // the last chat) still gets the text-only preset, but only an explicit
      // model change may open a provider sign-in.
      if (!changed) {
        const session = sessions.list.getSnapshot().byId[sessionId]
        if (session?.blank === true && session.projectionValues?.agentPreset !== 'openduck-cli-root') void selectRootPreset(++selectionEpoch.current, true)
        return
      }
      const epoch = ++selectionEpoch.current
      void (async () => {
        if (!await selectRootPreset(epoch) || !alive || epoch !== selectionEpoch.current) return
        try {
          const response = await rpc.call('/api', 'openduck-cli/status', {})
          const auth = response.ok ? authFor(response.value, provider) : undefined
          if (!alive || epoch !== selectionEpoch.current || auth === undefined || auth === 'authenticated') return
          if (auth === 'not-signed-in' && !launched.current.has(provider)) {
            launched.current.add(provider)
            const login = await rpc.call('/api', 'openduck-cli/login', { provider })
            if (!alive || epoch !== selectionEpoch.current) return
            if (!login.ok) { setNotice({ kind: 'auth', provider, auth, launched: false, failed: true }); return }
            setNotice({ kind: 'auth', provider, auth, launched: true }); return
          }
          setNotice({ kind: 'auth', provider, auth, launched: false })
        } catch { if (alive && epoch === selectionEpoch.current) setNotice({ kind: 'auth', provider, auth: 'unknown', launched: false, failed: true }) }
      })()
    }
    const stop = directory.store.subscribe(inspect)
    inspect()
    return () => { alive = false; stop() }
  }, [modelDirectories, presets, rpc, sessionId, sessions])
  if (notice === undefined) return null
  if (notice.kind === 'new-session') return <span role="status">Start a new OpenDuck CLI root chat to use this CLI model.</span>
  if (notice.launched) return <span role="status">Finish {labels[notice.provider]} sign-in in Terminal.</span>
  return <span>{notice.failed && <span role="alert">Terminal sign-in could not start. </span>}<Button onClick={() => { void rpc.call('/api', 'openduck-cli/login', { provider: notice.provider }).then(result => { setNotice({ ...notice, launched: result.ok, failed: !result.ok }) }).catch(() => { setNotice({ ...notice, launched: false, failed: true }) }) }}>{notice.auth === 'unknown' ? `Sign in to ${labels[notice.provider]}` : `Open ${labels[notice.provider]} sign-in`}</Button></span>
}
