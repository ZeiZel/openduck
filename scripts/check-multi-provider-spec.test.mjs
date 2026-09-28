import assert from 'node:assert/strict'
import { cp, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const checker = join(process.cwd(), 'scripts/check-multi-provider-spec.mjs')
const source = join(process.cwd(), 'projects/openduck/tasks/personal-assistant/multi-provider-agent-mesh-harness')

async function withFixture(mutate, expected) {
  const fixture = await mkdtemp(join(tmpdir(), 'openduck-spec-negative-'))
  try {
    const spec = join(fixture, 'spec')
    await cp(source, spec, { recursive: true })
    const cleanup = await mutate({ fixture, spec })
    const result = spawnSync(process.execPath, [checker], {
      cwd: process.cwd(), encoding: 'utf8',
      env: { ...process.env, MULTI_PROVIDER_SPEC_ROOT: spec, MULTI_PROVIDER_REPOSITORY_ROOT: fixture },
    })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, expected)
    await cleanup?.()
  } finally { await rm(fixture, { recursive: true, force: true }) }
}
async function append(spec, file, value) {
  const path = join(spec, file)
  await writeFile(path, `${await readFile(path, 'utf8')}\n${value}\n`)
}

test('checker rejects a missing traceability row', () => withFixture(async ({ spec }) => {
  const path = join(spec, '15-traceability.md')
  await writeFile(path, (await readFile(path, 'utf8')).replace(/^\| FR-001 \|.*\n/mu, ''))
}, /requirements\/traceability mismatch: missing=FR-001/u))

test('checker rejects an orphan acceptance criterion', () => withFixture(async ({ spec }) => {
  const path = join(spec, '15-traceability.md')
  await writeFile(path, (await readFile(path, 'utf8')).replaceAll('AC-001', 'AC-002'))
}, /acceptance AC-001 is orphaned/u))

test('checker rejects an unknown acceptance reference', () => withFixture(async ({ spec }) => {
  const path = join(spec, '15-traceability.md')
  await writeFile(path, (await readFile(path, 'utf8')).replace('AC-001', 'AC-999'))
}, /unknown acceptance reference AC-999/u))

test('checker rejects an orphan source', () => withFixture(async ({ spec }) => {
  const path = join(spec, '15-traceability.md')
  await writeFile(path, (await readFile(path, 'utf8')).replaceAll('SRC-ANS-003', 'SRC-ANS-001'))
}, /source SRC-ANS-003 is orphaned/u))

test('checker rejects an unknown source reference', () => withFixture(async ({ spec }) => {
  const path = join(spec, '15-traceability.md')
  await writeFile(path, (await readFile(path, 'utf8')).replace('SRC-ANS-003', 'SRC-FAKE-999'))
}, /unknown source reference SRC-FAKE-999/u))

test('checker rejects a broken local Markdown link', () => withFixture(({ spec }) => append(spec, 'README.md', '[missing](missing.md)'), /unresolved link: missing\.md/u))
test('checker rejects a lexical repository escape', () => withFixture(({ spec }) => append(spec, 'README.md', '[escape](../../../../../../etc/passwd)'), /link lexically escapes repository/u))

test('checker rejects a symlink whose target is outside the repository', () => withFixture(async ({ fixture, spec }) => {
  const outside = await mkdtemp(join(tmpdir(), 'openduck-spec-outside-'))
  try {
    await writeFile(join(outside, 'outside.md'), '# outside\n')
    await symlink(join(outside, 'outside.md'), join(spec, 'escaped.md'))
    await append(spec, 'README.md', '[symlink](escaped.md)')
    return () => rm(outside, { recursive: true, force: true })
  } catch (error) {
    await rm(outside, { recursive: true, force: true })
    throw error
  }
}, /link target escapes repository: escaped\.md/u))

test('checker rejects a forbidden placeholder', () => withFixture(({ spec }) => append(spec, 'README.md', 'TODO'), /forbidden placeholder/u))
test('checker rejects an invalid phase', () => withFixture(({ spec }) => append(spec, 'README.md', 'P8'), /invalid phase P8/u))
