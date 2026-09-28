# Local CLI history sources

`@openduck/openduck-base/src/history` presents a read-only, project-scoped
source API to a native host. It does not search a home directory, read a
credential store, or persist imported data. On an explicit panel request, the
native host may start a bounded local provider stdio adapter for the selected
allowlisted project only.

The host must inject an exact canonical project allowlist. A request whose
`projectRoot` is not an exact member of that allowlist is rejected. List pages
default to 25 records and are limited to 100. Titles and previews are reduced
to bounded plain text; session messages include only user and assistant text.
Tool calls, tool results, MCP listings, attachments, credentials, command
arguments, logs, and thinking blocks are never projected.

## Codex

The Codex adapter expects a host-provided JSON-RPC function backed by a local
`codex app-server` stdio child. Its only methods are `thread/list` and
`thread/read`; it never invokes shell, archive, delete, resume, or mutation
methods. `thread/list` uses exact `cwd` matching and retains the provider's
thread id and root session id separately. The native history panel requests
full turns only after the user explicitly opens a listed session; unsupported
storage modes return `unsupported`.

## Claude Code

The Claude adapter lazily loads the official `@anthropic-ai/claude-agent-sdk`
with only `listSessions` and `getSessionMessages`. The native host must declare
that package as a dependency. These official helpers provide
session summaries and structured user/assistant records without an OpenDuck
parser guessing the private transcript JSONL format. The bridge must pass the
allowlisted project directory to the SDK and must not expose raw transcript
events to the UI.

## Kimi Code

Kimi uses ACP `session/list` rather than guessing fields from the CLI JSON
output. The native host sends the exact allowlisted `cwd` and an opaque ACP
cursor, then accepts only `sessionId`, exact matching `cwd`, optional `title`,
and optional `updatedAt` from the documented `SessionInfo` schema. It rejects
an entry whose returned working directory differs from the selected project.

Message replay uses ACP over stdio: the adapter advertises no filesystem,
terminal, permission, or MCP capability and sends only `initialize` then
`session/load`. It accepts only replayed text `session/update` chunks and
rejects capability requests. It never sends `session/prompt`, `session/new`,
`session/delete`, or `session/fork`.

All provider ids, project paths, titles, previews, and message text are
untrusted display data. The UI must render them as text and must not use them
as instructions, file paths, URLs, or executable input.
