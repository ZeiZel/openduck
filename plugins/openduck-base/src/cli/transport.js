import { spawn } from 'node:child_process'

const MAX_BUFFERED_BYTES = 1024 * 1024
const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000
const TERMINATE_GRACE_MS = 1_000

const deferred = () => {
  let resolve; let reject
  const promise = new Promise((ok, fail) => { resolve = ok; reject = fail })
  return { promise, resolve, reject }
}

/** Bounded JSONL child transport; the subscribed CLI retains all authentication. */
export function createCliTransport({ maxBufferedBytes = MAX_BUFFERED_BYTES, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (!Number.isSafeInteger(maxBufferedBytes) || maxBufferedBytes < 1024) throw new TypeError('CLI transport maxBufferedBytes is invalid')
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000) throw new TypeError('CLI transport timeoutMs is invalid')
  return Object.freeze({ start({ command, args = [], cwd, input, signal, timeoutMs: requestTimeoutMs = timeoutMs }) {
    if (typeof command !== 'string' || command.length === 0 || !Array.isArray(args) || args.some(arg => typeof arg !== 'string')) throw new TypeError('CLI transport command is invalid')
    if (cwd !== undefined && (typeof cwd !== 'string' || !cwd.startsWith('/') || cwd.includes('\0'))) throw new TypeError('CLI transport cwd is invalid')
    if (input !== undefined && typeof input !== 'string') throw new TypeError('CLI transport input is invalid')
    if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 1000) throw new TypeError('CLI transport timeout is invalid')
    const completion = deferred(); void completion.promise.catch(() => {})
    let child; let done = false; let closed = false; let failure; let stdoutBuffer = ''; let queuedBytes = 0; let timeout; let killTimer
    const queue = []; const waiters = []
    const wake = () => { while (waiters.length) waiters.shift()() }
    const detachAbort = () => signal?.removeEventListener('abort', onAbort)
    const settle = error => {
      if (done) return
      done = true; failure = error; clearTimeout(timeout); detachAbort()
      if (error) completion.reject(error); else completion.resolve()
      wake()
    }
    const terminate = reason => {
      if (done) return
      queue.length = 0; queuedBytes = 0; stdoutBuffer = ''
      settle(reason)
      try { child?.stdin?.end() } catch {}
      try { if (child && !child.killed) child.kill('SIGTERM') } catch {}
      killTimer = setTimeout(() => { try { if (child && !closed) child.kill('SIGKILL') } catch {} }, TERMINATE_GRACE_MS)
    }
    const onAbort = () => terminate(new Error('CLI process aborted'))
    try { child = spawn(command, args, { cwd, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true }) } catch (error) { settle(error instanceof Error ? error : new Error(String(error))) }
    if (child) {
      child.stdout.setEncoding('utf8')
      child.stdout.on('data', chunk => {
        if (done) return
        stdoutBuffer += String(chunk)
        if (Buffer.byteLength(stdoutBuffer) + queuedBytes > maxBufferedBytes) { terminate(new Error('CLI process exceeded the bounded stdout buffer')); return }
        for (;;) {
          const index = stdoutBuffer.indexOf('\n'); if (index < 0) break
          const line = stdoutBuffer.slice(0, index); stdoutBuffer = stdoutBuffer.slice(index + 1)
          queuedBytes += Buffer.byteLength(line); queue.push(line)
        }
        wake()
      })
      // Drain stderr without retaining it: provider diagnostics can contain
      // prompt or account details and must never become a DSH error payload.
      child.stderr.on('data', () => {})
      child.stdin.on('error', error => { if (!done) terminate(error instanceof Error ? error : new Error('CLI stdin failed')) })
      child.on('error', error => terminate(error instanceof Error ? error : new Error(String(error))))
      child.on('close', code => {
        closed = true; clearTimeout(killTimer)
        if (done) return
        if (stdoutBuffer) { queuedBytes += Buffer.byteLength(stdoutBuffer); queue.push(stdoutBuffer); stdoutBuffer = '' }
        settle(code === 0 ? undefined : new Error(`CLI process exited with code ${String(code)}`))
      })
      if (signal?.aborted) onAbort(); else signal?.addEventListener('abort', onAbort, { once: true })
      if (!done) timeout = setTimeout(() => terminate(new Error(`CLI process timed out after ${requestTimeoutMs}ms`)), requestTimeoutMs)
    }
    const wait = () => new Promise(resolve => waiters.push(resolve))
    async function *events() {
      while (queue.length || !done) {
        if (!queue.length) { await wait(); continue }
        const line = queue.shift(); queuedBytes -= Buffer.byteLength(line); yield line
      }
      if (failure) throw failure
    }
    const send = value => new Promise((resolve, reject) => {
      if (done || !child?.stdin?.writable) { reject(failure ?? new Error('CLI stdin is unavailable')); return }
      let line
      try { line = `${JSON.stringify(value)}\n` } catch (error) { reject(error); return }
      child.stdin.write(line, error => error ? reject(error) : resolve())
    })
    if (input !== undefined && child) {
      void new Promise((resolve, reject) => child.stdin.write(input, error => error ? reject(error) : resolve()))
        .then(() => { try { child.stdin.end() } catch {} })
        .catch(error => terminate(error instanceof Error ? error : new Error(String(error))))
    }
    return Object.freeze({ events: events(), result: completion.promise, cancel: () => terminate(new Error('CLI process cancelled')), send })
  } })
}
