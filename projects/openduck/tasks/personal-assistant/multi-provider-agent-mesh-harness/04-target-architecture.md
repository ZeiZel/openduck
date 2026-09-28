# 04. Целевая архитектура

## Authority model

```text
Owner / trusted approval renderer
              |
              v
OpenDuck Controller (TCB)
  admission · policy · grants · MeshCoordinator · state · audit · effects
       |                 |                    |
       v                 v                    v
ProviderDirectory   per-session mesh MCP   capability endpoints
       |                 |                    |
       +-------> isolated provider adapter/runtime <------+
                         |
                   model session
```

Session root — orchestration role, не authority role. Она может вызвать mesh tool, но Controller валидирует order/binding/classification/budget/lineage/destination и создаёт child независимо. Default separate Controller UI client рендерит projections; DSH получает их только после feasibility gate. Canonical state живёт в Controller repository.

Model/plugin caller не передаёт sealed order. Model-facing `spawn`/`spawnBatch` — совместимые имена для `MeshCoordinator.ProposeSpawn/ProposeSpawnBatch`: они принимают bounded `SpawnProposal.v1`. Только внутренний Controller admission после authoritative reread mint’ит IDs, limits, reservations, effective capabilities, lease, `WorkOrder.v2` и `RunDispatchBinding.v2`, затем вызывает adapter `SessionStarter`.

## Go boundaries

```go
type SessionStarter interface {
    Start(context.Context, StartRequest) (SessionRef, error)
}

type TurnStreamer interface {
    StartTurn(context.Context, TurnRequest) (EventStream, error)
}

type SessionController interface {
    Send(context.Context, SendRequest) error
    Steer(context.Context, SteerRequest) error
    Cancel(context.Context, CancelRequest) error
    Status(context.Context, SessionRef) (SessionStatus, error)
    Result(context.Context, ResultRequest) (RunResult, error)
}

type UsageReporter interface {
    Usage(context.Context, SessionRef) (UsageSnapshot, error)
}

type HealthChecker interface {
    Health(context.Context, ProfileRef) (HealthSnapshot, error)
}

type MeshToolTransport interface {
    Attach(context.Context, MeshEndpointBinding) (MeshTransportSession, error)
    Mapping(context.Context, ProfileRef) (MeshTransportMapping, error)
}
```

`PROPOSAL`: интерфейсы объявляются consumer package, не provider package. `MeshCoordinator` зависит от них и repositories/clock/id generator/policy/sealer services; adapters реализуют только поддерживаемые capabilities и fail-loud для остальных. `MeshToolTransport` отделяет provider-specific delivery of the same mesh tool contract from admission. `cmd/openduck-controller/main.go` конструирует concrete dependencies вручную и не содержит policy logic.

## Deployment units

| Unit | Principal/home | Network | Credentials | Authority |
|---|---|---|---|---|
| Controller | dedicated | allowlisted | refs/keys для собственных ledgers | TCB |
| DSH UI/host | unprivileged | Controller loopback only baseline | none | projection only |
| Provider broker | per provider/account | exact provider endpoints | native isolated auth | session transport only |
| Provider runtime | per session/profile | model transport separately attested | no other-provider auth | no effects |
| Capability endpoint | per session/run/attempt | per capability | non-model-visible audience-bound credential + authenticated peer/mTLS-equivalent | Controller-enforced |
| Local PD Qwen | dedicated local principal | none | none | local inference only |

## State ownership

`MeshCoordinator` stores `RootRun`, `SessionNode`, `Attempt`, `Edge`, `Lease`, `BudgetReservation`, `DisclosureReservation`, `ResultEnvelope` and `RecoveryRecord`. Provider IDs are evidence fields, not canonical identifiers. Separate UI/native clients receive bounded projections; DSH only after DR-007. Provider session store may retain provider-local transcript under its own policy, but cannot authorize Controller transitions.

## UI projection boundary

Default path — отдельный Controller UI projection service/client с authenticated session, bounded schema и no model/session-log append. DSH `ui-subagent`, AgentLoop и session events остаются feasibility candidate: P0 выбирает, способен ли target DSH build рендерить Controller projection без model visibility, durable transcript append и agent wakeup. До положительного evidence P3 не монтирует DSH integration и использует separate UI channel.

## Migration

Current `controller-snapshot.v1` and hard-coded Codex `WorkOrder` remain readable. Migration produces new additive records referencing legacy hashes, never edits historical bytes. Dual-read/single-write v2 precedes v1 retirement; replay equivalence, downgrade/read-only rollback and orphan detection are gates.
