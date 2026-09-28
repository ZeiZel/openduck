#!/usr/bin/env node
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {JsonlDecoder, MAX_FRAME, loadOverlay, sameWindowIdentity, validateDriverPath, windowIdentity} from './cua-readonly-proxy-core.mjs';

const overlayPath = fileURLToPath(new URL('./local-overlay.json', import.meta.url));
const overlay = loadOverlay(overlayPath);
const configuredPath = typeof overlay?.cua?.driverPath === 'string' ? overlay.cua.driverPath : '';
const allowedBundles = Array.isArray(overlay?.cua?.allowedBundles) ? overlay.cua.allowedBundles : [];
const validBundle = x => typeof x === 'string' && /^[A-Za-z0-9.-]{1,128}$/.test(x);
const driverPath = validateDriverPath(configuredPath);
const ALLOWED_BUNDLES = new Set(allowedBundles.filter(validBundle));
if (!driverPath || ALLOWED_BUNDLES.size === 0) {
  process.stderr.write('cua-readonly-proxy: local overlay is required; refusing to start\n');
  process.exit(78);
}
const child = spawn(driverPath, ['mcp'], {stdio: ['pipe', 'pipe', 'ignore']});
let next = 1000;
const pending = new Map();
const send = msg => child.stdin.write(JSON.stringify(msg) + '\n');
const callUnderlying = (method, params) => new Promise((resolve, reject) => {
  const id = next++;
  pending.set(id, {resolve, reject});
  send({jsonrpc: '2.0', id, method, params});
  setTimeout(() => { if (pending.has(id)) { pending.delete(id); reject(new Error('cua timeout')); } }, 10000);
});
const decoder = new JsonlDecoder(MAX_FRAME);
child.stdout.on('data', buf => {
  try { for (const msg of decoder.push(buf)) {
    try {
      if (msg.id !== undefined && pending.has(msg.id)) {
        const p = pending.get(msg.id); pending.delete(msg.id);
        msg.error ? p.reject(new Error(msg.error.message || 'cua error')) : p.resolve(msg.result);
      }
    } catch { /* malformed child frames are ignored */ }
  } } catch { child.kill('SIGTERM'); }
});
const safe = new Set(['get_config', 'health_report', 'get_screen_size', 'get_recording_state', 'get_agent_cursor_state']);
const allowed = x => typeof x === 'string' && ALLOWED_BUNDLES.has(x);
const extractWindows = value => {
  let o = value;
  const txt = o?.structuredContent?.text || o?.content?.find?.(x => x.type === 'text')?.text;
  if (typeof txt === 'string') { try { o = JSON.parse(txt); } catch { o = {}; } }
  const arr = o?.windows || o?.result?.windows || o?.data || [];
  return Array.isArray(arr) ? arr.filter(w => allowed(w.bundle_id || w.bundleId || w.application_bundle_id)) : [];
};
const tools = [
  {name: 'list_allowed_windows', description: 'List locally allowlisted enterprise-chat windows (metadata only).', inputSchema: {type: 'object', additionalProperties: false}},
  ...[...safe].map(name => ({name, description: 'Read-only CuaDriver status.', inputSchema: {type: 'object', additionalProperties: false}})),
];
const reply = (id, result, error) => process.stdout.write(JSON.stringify({jsonrpc: '2.0', id, ...(error ? {error: {code: -32000, message: error.message}} : {result})}) + '\n');
const inputDecoder = new JsonlDecoder(MAX_FRAME);
process.stdin.on('data', async chunk => {
  let frames;
  try { frames = inputDecoder.push(chunk); } catch { process.stdin.pause(); return; }
  for (const m of frames) {
  if (m.method === 'initialize') { reply(m.id, {protocolVersion: '2024-11-05', capabilities: {tools: {}}, serverInfo: {name: 'cua-readonly-proxy', version: '1.1'}}); return; }
  if (m.method === 'notifications/initialized') return;
  if (m.method === 'tools/list') { reply(m.id, {tools}); return; }
  if (m.method !== 'tools/call') { reply(m.id, null, new Error('method denied')); return; }
  const name = m.params?.name;
  try {
    if (name === 'list_allowed_windows') {
      const r = await callUnderlying('tools/call', {name: 'list_windows', arguments: {}});
      reply(m.id, {content: [{type: 'text', text: JSON.stringify({windows: extractWindows(r).map(windowIdentity)})}]}); return;
    }
    if (name === 'read_allowed_window') throw new Error('atomic_identity_unavailable');
    if (!safe.has(name)) throw new Error('tool denied');
    reply(m.id, await callUnderlying('tools/call', {name, arguments: m.params.arguments || {}}));
  } catch (e) { reply(m.id, null, e); }
  }
});
process.on('SIGTERM', () => child.kill('SIGTERM'));
