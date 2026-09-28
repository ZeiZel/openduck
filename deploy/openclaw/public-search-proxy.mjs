#!/usr/bin/env node
import readline from 'node:readline';
import dns from 'node:dns/promises';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';

const ENDPOINT = new URL('https://html.duckduckgo.com/html/');
const MAX_QUERY = 200, MAX_BYTES = 500000, TIMEOUT_MS = 10000, MAX_REDIRECTS = 5;
const SENSITIVE = /(?:[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|\+?\d[\d ()-]{7,}\d|\b(?:bearer|token|password|passwd|api[_ -]?key|secret|authorization)\b|(?:^|[\s/])(?:~\/|\/Users\/|\/home\/|127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+))/i;
const CONTROL = /[\u0000-\u001f\u007f]/;
const htmlDecode = s => s.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&#39;|&#x27;/g,"'").replace(/&quot;/g,'"');
const strip = s => htmlDecode(s.replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim()).slice(0,1000);
export function validateQuery(query) {
  if (typeof query !== 'string' || !query.trim() || query.length > MAX_QUERY) throw new Error('query must be 1-200 characters');
  if (CONTROL.test(query) || SENSITIVE.test(query)) throw new Error('query rejected by public-search safety filter');
  return query.trim();
}
export function parseResults(body) {
  const out=[]; const re=/<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
  for (const m of body.matchAll(re)) { if(!/\bclass\s*=\s*["'][^"']*\bresult__a\b/i.test(m[1])) continue; const hm=m[1].match(/\bhref\s*=\s*["']([^"']+)["']/i); if(!hm) continue; let raw=htmlDecode(hm[1]),u; try { if(raw.startsWith('/l/')) { const p=new URL(raw,ENDPOINT); const target=p.searchParams.get('uddg'); if(!target) continue; u=new URL(target); } else if(raw.startsWith('//')) { const p=new URL(`https:${raw}`); if(!['duckduckgo.com','html.duckduckgo.com'].includes(p.hostname)||!p.pathname.startsWith('/l/')) continue; const target=p.searchParams.get('uddg'); if(!target) continue; u=new URL(target); } else u=new URL(raw); } catch { continue; } if(!['http:','https:'].includes(u.protocol)||u.username||u.password||isPrivateAddress(u.hostname)) continue; const sn=(body.slice(m.index+m[0].length).match(/class\s*=\s*["'][^"']*\bresult__snippet\b[^"']*["'][^>]*>([\s\S]*?)<\//i)||[])[1]||''; out.push({title:strip(m[2]).slice(0,300),url:u.href,snippet:strip(sn).slice(0,700),untrusted:true}); }
  return out;
}
function isPrivateAddress(host) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
  const ip = net.isIP(h); if (!ip) return false;
  if (ip === 4) { const p=h.split('.').map(Number); return p[0]===0||p[0]===10||p[0]===127||p[0]===169&&p[1]===254||p[0]===192&&p[1]===168||p[0]===172&&p[1]>=16&&p[1]<=31; }
  const groups = expandIPv6(h);
  if (!groups) return true;
  // Treat IPv4-mapped and IPv4-compatible IPv6 addresses as IPv4 too. Node's
  // net.isIP reports these as IPv6, so checking only textual ::ffff prefixes
  // is insufficient (hex and compressed forms bypass it).
  if (groups.slice(0, 6).every((g) => g === 0) || (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff)) {
    const v4 = [(groups[6] >>> 8) & 255, groups[6] & 255, (groups[7] >>> 8) & 255, groups[7] & 255];
    return isPrivateIPv4(v4);
  }
  const first = groups[0], second = groups[1];
  return (groups.every((g) => g === 0)) || (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) ||
    (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
}
function isPrivateIPv4(p) {
  return p[0]===0 || p[0]===10 || p[0]===127 || (p[0]===169&&p[1]===254) || (p[0]===192&&p[1]===168) || (p[0]===172&&p[1]>=16&&p[1]<=31);
}
function expandIPv6(value) {
  const parts = value.split('::');
  if (parts.length > 2) return null;
  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  if ([...left, ...right].some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  if (parts.length === 1 && left.length !== 8) return null;
  if (parts.length === 2 && left.length + right.length >= 8) return null;
  const groups = [...left.map((g) => parseInt(g, 16)), ...Array(8 - left.length - right.length).fill(0), ...right.map((g) => parseInt(g, 16))];
  return groups.length === 8 ? groups : null;
}
export function validatePublicUrl(value) {
  if (typeof value !== 'string' || value.length > 4096 || CONTROL.test(value)) throw new Error('url rejected');
  const u = new URL(value); if (!['http:','https:'].includes(u.protocol) || u.username || u.password || u.port === '0') throw new Error('only public HTTP(S) URLs without credentials are allowed');
  if (isPrivateAddress(u.hostname)) throw new Error('private, local, or link-local host denied');
  return u;
}
async function requestResolved(u, method) {
  const addresses = await dns.lookup(u.hostname, {all:true, verbatim:true});
  if (!addresses.length || addresses.some(a => isPrivateAddress(a.address))) throw new Error('DNS resolved to private or local address');
  const ip = addresses[0].address, transport = u.protocol === 'https:' ? https : http;
  return await new Promise((resolve,reject) => {
    const req = transport.request({protocol:u.protocol, hostname:ip, port:u.port || undefined, path:u.pathname+u.search, method, servername:u.hostname, headers:{host:u.host,accept:'text/html, text/plain;q=0.9'}}, resolve);
    req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error('upstream timeout'))); req.on('error', reject); req.end();
  });
}
export async function fetchPublicUrl(args={}) {
  const method = args.method || 'GET'; if (!['GET','HEAD'].includes(method)) throw new Error('only GET and HEAD are allowed');
  let u = validatePublicUrl(args.url); let redirects = 0;
  while (true) { const r = await requestResolved(u, method); if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) { if (++redirects > MAX_REDIRECTS) throw new Error('too many redirects'); u = validatePublicUrl(new URL(r.headers.location, u).href); r.resume(); continue; } if ((r.statusCode||500) >= 400) { r.resume(); throw new Error(`upstream HTTP ${r.statusCode}`); } if (method === 'HEAD') { r.resume(); return {url:u.href,status:r.statusCode,headers:{'content-type':r.headers['content-type']||''},body:'',untrusted:true}; } let size=0; const chunks=[]; for await (const chunk of r) { size += chunk.length; if (size > MAX_BYTES) { r.destroy(); throw new Error('upstream response too large'); } chunks.push(chunk); } return {url:u.href,status:r.statusCode,headers:{'content-type':r.headers['content-type']||''},body:Buffer.concat(chunks).toString('utf8'),untrusted:true}; }
}
async function searchPublicWeb(args={}) {
  const q=validateQuery(args.query); const u=new URL(ENDPOINT); u.searchParams.set('q',q); u.searchParams.set('kp','-2');
  const c=new AbortController(); const timer=setTimeout(()=>c.abort(),TIMEOUT_MS);
  try { const r=await fetch(u,{redirect:'manual',signal:c.signal,headers:{accept:'text/html'}}); if(r.status>=300&&r.status<400) throw new Error('redirect denied'); if(!r.ok) throw new Error(`upstream HTTP ${r.status}`); const b=await r.arrayBuffer(); if(b.byteLength>MAX_BYTES) throw new Error('upstream response too large'); const results=parseResults(new TextDecoder().decode(b)); if(!results.length) throw new Error('no safe public results'); return {query:q,results,untrusted:true}; } finally { clearTimeout(timer); }
}
const tools=[{name:'search_public_web',description:'Read-only DuckDuckGo public search with untrusted results.',inputSchema:{type:'object',required:['query'],additionalProperties:false,properties:{query:{type:'string',minLength:1,maxLength:200}}}},{name:'fetch_public_web',description:'Read-only arbitrary public HTTP(S) GET or HEAD. No credentials, forms, uploads, cookies, or private hosts.',inputSchema:{type:'object',required:['url'],additionalProperties:false,properties:{url:{type:'string',maxLength:4096},method:{type:'string',enum:['GET','HEAD']}}}}];
const reply=(id,result,error)=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',id,...(error?{error:{code:-32000,message:error.message}}:{result})})+'\n');
if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) {
  const rl=readline.createInterface({input:process.stdin});
  rl.on('line',async line=>{let m;try{m=JSON.parse(line)}catch{return} if(m.method==='initialize'){reply(m.id,{protocolVersion:'2024-11-05',capabilities:{tools:{}},serverInfo:{name:'public-search-proxy',version:'1.1'}});return} if(m.method==='notifications/initialized')return; if(m.method==='tools/list'){reply(m.id,{tools});return} if(m.method!=='tools/call'||!['search_public_web','fetch_public_web'].includes(m.params?.name)){reply(m.id,null,new Error('method/tool denied'));return} try{const out=m.params.name==='search_public_web'?await searchPublicWeb(m.params.arguments):await fetchPublicUrl(m.params.arguments);reply(m.id,{content:[{type:'text',text:JSON.stringify(out)}]})}catch(e){reply(m.id,null,e)}});
}
