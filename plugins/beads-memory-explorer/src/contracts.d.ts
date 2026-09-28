export type OpaqueId = string
export type Digest = `sha256:${string}`
export type NodeState = 'open' | 'in_progress' | 'blocked' | 'closed'
export interface ProjectNode { readonly id: OpaqueId; readonly label: string; readonly state: NodeState }
export interface ProjectEdge { readonly from: OpaqueId; readonly to: OpaqueId }
export interface ProjectGraph { readonly schema_version: 'beads-project-graph.v1'; readonly project_id: OpaqueId; readonly version: number; readonly digest: Digest; readonly nodes: readonly ProjectNode[]; readonly edges: readonly ProjectEdge[] }
export interface GlobalRecord { readonly record_id: OpaqueId; readonly version: number; readonly updated_at: string; readonly availability: 'LOCAL_PD_UNAVAILABLE' }
export interface GlobalMetadata { readonly schema_version: 'beads-global-metadata.v1'; readonly version: number; readonly digest: Digest; readonly updated_at: string; readonly records: readonly GlobalRecord[] }
export interface ControllerReadClient { read(route: 'beads/project-graph' | 'beads/global-metadata'): Promise<unknown> }
export declare function parseProjectGraph(value: unknown): ProjectGraph
export declare function parseGlobalMetadata(value: unknown): GlobalMetadata
export declare function searchGraph(graph: ProjectGraph, query: string): readonly ProjectNode[]
export declare function openMemoryChat(scope: 'project' | 'global'): Readonly<Record<string, unknown>>
export declare function createBeadsMemoryExplorer(client: ControllerReadClient): Readonly<Record<string, unknown>>
