import { mkdir, writeFile } from 'node:fs/promises'
const result = await Bun.build({ entrypoints: ['src/client/index.tsx'], target: 'browser', format: 'cjs', jsx: { runtime: 'classic', factory: 'React.createElement', fragment: 'React.Fragment', development: false }, external: ['react', '@deepseek-ai/dsh-client-runtime/client', '@deepseek-ai/dsh-client-ui-settings-plugins/client', '@deepseek-ai/dsh-client-ui-primitives'] })
if (!result.success) throw new Error(result.logs.map(log => log.message).join('\n'))
const artifact = result.outputs.find(output => output.kind === 'entry-point')
if (artifact === undefined) throw new Error('missing client entrypoint')
const source = await artifact.text()
await mkdir('lib', { recursive: true })
await writeFile('lib/client.js', `window.__ModuleLoader__.load({\n  id: '@openduck/openduck-base',\n  factory: (require) => {\n    var module = { exports: {} };\n    var exports = module.exports;\n${source}\n    return module.exports;\n  },\n})\n`)
