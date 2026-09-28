type Project = { root: string; displayName?: string }
type CliRoot = { enabled: boolean; cwd: string; models: { codex: string[]; claude: string[]; kimi: string[] } }
type Scope = { set: (field: string, value: unknown) => Promise<void>; getSnapshot: () => { value: { history?: { projects?: Project[] }; cliRoot?: Partial<CliRoot> } } }
export function saveAcceptedHistory(scope: Scope, projects: Project[]): Promise<boolean>
export function saveAcceptedCliRoot(scope: Scope, cliRoot: CliRoot): Promise<boolean>
