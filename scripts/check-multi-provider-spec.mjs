#!/usr/bin/env node
import { lstat, readFile, readdir, realpath } from 'node:fs/promises'
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from 'node:path'

const requestedRoot = resolve(process.env.MULTI_PROVIDER_SPEC_ROOT ?? 'projects/openduck/tasks/personal-assistant/multi-provider-agent-mesh-harness')
const requestedRepository = resolve(process.env.MULTI_PROVIDER_REPOSITORY_ROOT ?? resolve(requestedRoot, '../../../../../'))
const root = await realpath(requestedRoot)
const repository = await realpath(requestedRepository)
const files = (await readdir(root)).filter(name => extname(name) === '.md').sort()
const documents = new Map(await Promise.all(files.map(async name => [name, await readFile(join(root, name), 'utf8')])))
const errors = []
const anchorCache = new Map()
const fail = message => errors.push(message)

function isContained(base, candidate) {
  const path = relative(base, candidate)
  return path === '' || (!isAbsolute(path) && path !== '..' && !path.startsWith(`..${sep}`))
}
function definitions(file, expression) {
  return [...documents.get(file).matchAll(expression)].map(match => match[1])
}
function once(values, label) {
  for (const value of new Set(values)) if (values.filter(candidate => candidate === value).length !== 1) fail(`${label} ${value} is duplicate`)
}
function exact(actual, expected, label) {
  const missing = [...expected].filter(value => !actual.has(value))
  const extra = [...actual].filter(value => !expected.has(value))
  if (missing.length || extra.length) fail(`${label} mismatch: missing=${missing.join(',') || '-'} extra=${extra.join(',') || '-'}`)
}
function anchor(value) {
  return decodeURIComponent(value).toLowerCase().replace(/[ `~!@#$%^&*()=+\[\]{}\\|;:'",.<>/?]/gu, '').replace(/\s+/gu, '-')
}
async function anchorsFor(path) {
  if (!anchorCache.has(path)) {
    const text = await readFile(path, 'utf8')
    anchorCache.set(path, new Set([...text.matchAll(/^#{1,6}\s+(.+)$/gmu)].map(match => anchor(match[1]))))
  }
  return anchorCache.get(path)
}
function localTarget(value) {
  const target = value.trim().replace(/^<|>$/gu, '').split(/\s+/u)[0]
  return /^[a-z][a-z+.-]*:/iu.test(target) ? null : target
}

const requirements = definitions('02-requirements.md', /^\| ((?:FR|NFR)-\d{3}) \|/gmu)
const traceRows = definitions('15-traceability.md', /^\| ((?:FR|NFR)-\d{3}) \|/gmu)
once(requirements, 'requirement')
once(traceRows, 'traceability row')
exact(new Set(traceRows), new Set(requirements), 'requirements/traceability')

const acceptance = definitions('12-acceptance-and-test-matrix.md', /^\| (AC-\d{3}) \|/gmu)
const sources = definitions('14-source-register.md', /^\| (SRC-[A-Z]+-\d{3}) \|/gmu)
once(acceptance, 'acceptance')
once(sources, 'source')
const trace = documents.get('15-traceability.md')
const traceReferences = trace.split('\n').filter(line => /^\| (?:FR|NFR)-\d{3} \|/u.test(line)).join('\n')
for (const id of acceptance) if (!(traceReferences.match(new RegExp(`\\b${id}\\b`, 'gu')) ?? []).length) fail(`acceptance ${id} is orphaned`)
for (const id of sources) if (!(traceReferences.match(new RegExp(`\\b${id}\\b`, 'gu')) ?? []).length) fail(`source ${id} is orphaned`)
for (const [file, text] of documents) {
  for (const id of new Set(text.match(/\bAC-\d{3}\b/gu) ?? [])) if (!acceptance.includes(id)) fail(`${file}: unknown acceptance reference ${id}`)
  for (const id of new Set(text.match(/\bSRC-[A-Z]+-\d{3}\b/gu) ?? [])) if (!sources.includes(id)) fail(`${file}: unknown source reference ${id}`)
}

for (const [file, text] of documents) {
  const source = join(root, file)
  for (const match of text.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/gu)) {
    const target = localTarget(match[1])
    if (target === null) continue
    const [rawPath, rawFragment = ''] = target.split('#', 2)
    const path = rawPath ? decodeURIComponent(rawPath) : source
    const lexical = resolve(dirname(source), path)
    if (!isContained(repository, lexical)) { fail(`${file}: link lexically escapes repository: ${target}`); continue }
    try { await lstat(lexical) } catch { fail(`${file}: unresolved link: ${target}`); continue }
    let resolved
    try { resolved = await realpath(lexical) } catch { fail(`${file}: unresolved link: ${target}`); continue }
    if (!isContained(repository, resolved)) { fail(`${file}: link target escapes repository: ${target}`); continue }
    if (rawFragment && extname(resolved) === '.md') {
      const headings = await anchorsFor(resolved)
      if (!headings.has(anchor(rawFragment))) fail(`${file}: unresolved anchor: ${target}`)
    }
  }
  for (const marker of [/\bTODO\b/iu, /\bTBD\b/iu, /implementation absent/iu, /DRAFT\s*\/\s*specification-only/iu]) if (marker.test(text)) fail(`${file}: forbidden placeholder ${marker}`)
  for (const phase of text.match(/\bP\d+\b/gu) ?? []) if (!/^P[0-7]$/u.test(phase)) fail(`${file}: invalid phase ${phase}`)
  if (/\bP[0-7]\+/u.test(text)) fail(`${file}: phase ranges must use explicit P0–P7 notation`)
}

if (errors.length) {
  console.error('multi-provider spec check failed:')
  for (const error of errors) console.error(`- ${error}`)
  process.exitCode = 1
} else console.log(`multi-provider spec check passed (${files.length} Markdown files)`)
