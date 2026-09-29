/**
 * Loopback unary RPC for profile plugins on DSH 0.1.7.
 *
 * `connection.rpc.handle()` mounts a top-level channel through the caller's
 * `webServer`, which a profile plugin cannot reach, so those channels answered
 * the static frontend's 405. Exact `/api/<channel>/<endpoint>` Fetch routes are
 * the supported package surface: they sit behind the shared `/api` route's
 * Host/Origin fence and browser authentication, and speak the same
 * client-request / server-response envelope as `connection.rpc.call()`.
 * Browsers call them with `rpc.call('/api', '<channel>/<endpoint>', payload)`.
 */

const ENVELOPE_FAILURE = Object.freeze({ ok: false, error: Object.freeze({ code: 'internal', message: 'handler failure', details: Object.freeze({}) }) })

/**
 * Register exact POST routes for each endpoint of one logical channel.
 * @param {{ fetch: { register(route: object): (() => void) | void } }} connection - Host Connection service.
 * @param {string} channel - channel name without slashes, e.g. `openduck-cli`.
 * @param {readonly string[]} endpoints - endpoint names served under the channel.
 * @param {(endpoint: string, payload: unknown) => Promise<unknown> | unknown} handler - returns `{ ok, value | error }`.
 * @returns {() => void} disposer for every registered route.
 */
export function registerRpcRoutes(connection, channel, endpoints, handler) {
  const disposers = endpoints.map(endpoint => connection.fetch.register({
    path: `/api/${channel}/${endpoint}`,
    methods: ['POST'],
    requestBody: 'buffered',
    fetch: async request => {
      const type = (request.headers.get('content-type') ?? '').split(';', 1)[0].trim().toLowerCase()
      if (type !== 'application/json') return new Response('content type must be application/json', { status: 415 })
      let body
      try { body = await request.json() } catch { return new Response('body is not JSON', { status: 400 }) }
      if (body === null || typeof body !== 'object' || body.type !== 'client-request' || typeof body.rpcId !== 'string' || body.method !== `${channel}/${endpoint}`) {
        return new Response('invalid client-request message', { status: 400 })
      }
      let result
      try { result = await handler(endpoint, body.payload) } catch { result = ENVELOPE_FAILURE }
      return Response.json({ type: 'server-response', rpcId: body.rpcId, result })
    },
  }))
  return () => { for (const dispose of disposers) if (typeof dispose === 'function') dispose() }
}
