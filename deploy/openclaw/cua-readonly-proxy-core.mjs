import {lstatSync, realpathSync, statSync, readFileSync} from 'node:fs';
import {StringDecoder} from 'node:string_decoder';

export const MAX_FRAME = 1024 * 1024;
export const TRUSTED_DRIVER_ROOT = '/Library/Application Support/OpenDuck/bin';

export function loadOverlay(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return null; }
}

export function validateDriverPath(path, trustedRoot = TRUSTED_DRIVER_ROOT) {
  try {
    if (typeof path !== 'string' || !path.startsWith('/')) return '';
    if (path.split('/').includes('..')) return '';
    const root = realpathSync(trustedRoot);
    const rootStat = lstatSync(trustedRoot);
    if (rootStat.isSymbolicLink() || rootStat.uid !== 0 || (rootStat.mode & 0o022) !== 0) return '';
    const resolved = realpathSync(path);
    if (!resolved.startsWith(root + '/')) return '';
    const relative = resolved.slice(root.length + 1).split('/');
    let current = root;
    for (const part of relative) {
      current += '/' + part;
      const st = lstatSync(current);
      if (st.isSymbolicLink() || st.uid !== 0 || (st.mode & 0o022) !== 0) return '';
    }
    const link = lstatSync(path);
    const file = statSync(resolved);
    if (!link.isFile() || link.isSymbolicLink() || !file.isFile() || link.uid !== 0 || file.uid !== 0 || (link.mode & 0o022) !== 0 || (file.mode & 0o022) !== 0) return '';
    if (file.dev !== link.dev || file.ino !== link.ino) return '';
    return resolved;
  } catch { return ''; }
}

export class JsonlDecoder {
  constructor(maxFrame = MAX_FRAME) { this.maxFrame = maxFrame; this.buffer = ''; this.bytes = 0; this.decoder = new StringDecoder('utf8'); }
  push(chunk) {
    const input = Buffer.from(chunk); this.bytes += input.length;
    if (this.bytes > this.maxFrame * 2) throw new Error('frame buffer exceeded');
    this.buffer += this.decoder.write(input);
    const frames = [];
    let nl;
    while ((nl = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, nl); this.buffer = this.buffer.slice(nl + 1);
      this.bytes = Buffer.byteLength(this.buffer);
      if (Buffer.byteLength(line) > this.maxFrame) throw new Error('frame exceeded');
      frames.push(JSON.parse(line));
    }
    return frames;
  }
}

export function windowIdentity(window) {
  return {pid: window.pid, window_id: window.window_id || window.windowId, bundle_id: window.bundle_id || window.bundleId || window.application_bundle_id};
}

export function sameWindowIdentity(a, b) {
  return Boolean(a && b) && a.pid === b.pid && a.window_id === b.window_id && a.bundle_id === b.bundle_id;
}
