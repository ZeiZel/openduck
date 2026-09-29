function normalized(projects) {
  return projects.map(project => ({ root: project.root, displayName: project.displayName ?? '' }))
}
function normalizedCliRoot(value) {
  return { enabled: value.enabled === true, cwd: value.cwd ?? '', models: { codex: value.models?.codex ?? [], claude: value.models?.claude ?? [], kimi: value.models?.kimi ?? [] } }
}
/** Persist a history project list and confirm the settings snapshot actually accepted it. */
export async function saveAcceptedHistory(scope, projects) {
  if (!await scope.set('history', { projects })) return false
  const accepted = scope.getSnapshot().value?.history?.projects ?? []
  return JSON.stringify(normalized(accepted)) === JSON.stringify(normalized(projects))
}
/** Persist CLI root settings and confirm the resolved snapshot accepted exactly this value. */
export async function saveAcceptedCliRoot(scope, cliRoot) {
  if (!await scope.set('cliRoot', cliRoot)) return false
  return JSON.stringify(normalizedCliRoot(scope.getSnapshot().value?.cliRoot ?? {})) === JSON.stringify(normalizedCliRoot(cliRoot))
}
