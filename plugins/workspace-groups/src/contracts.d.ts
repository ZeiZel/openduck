export type OpaqueId = string
export type Digest = `sha256:${string}`
export type RootMode = 'read' | 'write'
export interface WorkspaceRoot { readonly root_id: OpaqueId; readonly label: string; readonly mode: RootMode }
export interface WorkspaceGroup { readonly schema_version: 'workspace-group.v1'; readonly group_id: OpaqueId; readonly display_label: string; readonly primary_root_id: OpaqueId; readonly roots: readonly WorkspaceRoot[]; readonly version: number; readonly digest: Digest; readonly updated_at: string }
export interface WorkspaceGroupsProjection { readonly schema_version: 'workspace-groups.v1'; readonly freshness: 'current' | 'stale'; readonly groups: readonly WorkspaceGroup[] }
export interface ControllerReadClient { read(route: 'workspace-groups'): Promise<unknown> }
export declare function parseWorkspaceGroups(value: unknown): WorkspaceGroupsProjection
export declare function createWorkspaceGroups(client: ControllerReadClient): Readonly<Record<string, unknown>>
