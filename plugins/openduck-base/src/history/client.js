/** Pure browser-side state reducer for the read-only external-history viewer. */
export const initialHistoryView = Object.freeze({ phase: 'idle', projects: Object.freeze([]), sessions: Object.freeze([]), messages: Object.freeze([]), selected: null, error: null, nextCursor: null })

/** Apply one bounded RPC result without retaining stale rows from another project/provider selection. */
export function reduceHistoryView(state, event) {
  switch (event.type) {
    case 'loading': return { ...state, phase: 'loading', error: null }
    case 'projects': return { ...state, phase: 'ready', projects: Object.freeze(event.projects), error: null }
    case 'sessions': return { ...state, phase: 'ready', sessions: Object.freeze(event.items), messages: Object.freeze([]), selected: null, nextCursor: event.nextCursor ?? null, error: null }
    case 'messages': return { ...state, phase: 'ready', messages: Object.freeze(event.items), selected: event.sessionId, error: null }
    case 'empty': return { ...state, phase: 'empty', sessions: Object.freeze([]), messages: Object.freeze([]), selected: null, error: null, nextCursor: null }
    case 'error': return { ...state, phase: 'error', error: event.message, sessions: Object.freeze([]), messages: Object.freeze([]), selected: null, nextCursor: null }
    default: throw new TypeError(`history client: unknown event ${String(event.type)}`)
  }
}
