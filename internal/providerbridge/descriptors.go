package providerbridge

import (
	"fmt"
	"strings"
	"time"
)

type profileDefinition struct {
	Provider                                   Provider
	Model, RuntimeKind, AuthModality, Revision string
	LocalOnly                                  bool
}

var profileDefinitions = map[string]profileDefinition{
	ProfileCodexChatGPT: {ProviderCodex, "gpt-5.6", "codex-app-server", "chatgpt-subscription", "codex-app-server.v1", false},
	ProfileClaudeCode:   {ProviderClaude, "claude-code", "claude-code-cli", "account-login-or-api", "claude-code-cli.v1", false},
	ProfileQwenGeneral:  {ProviderQwen, "qwen-coder", "qwen-headless", "coding-plan-or-api", "qwen-headless.v1", false},
	ProfileQwenLocalPD:  {ProviderQwen, "qwen-local", "local-compatible", "local-no-auth", "qwen-local-pd.v1", true},
	ProfileKimiCode:     {ProviderKimi, "kimi-code", "kimi-acp", "membership-oauth-or-api", "kimi-acp.v1", false},
	ProfileDeepSeekAPI:  {ProviderDeepSeek, "deepseek-chat", "deepseek-api", "api-key", "deepseek-api.v1", false},
}

func definitionFor(profileID string) (profileDefinition, bool) {
	definition, found := profileDefinitions[profileID]
	return definition, found
}
func validProfileIdentity(profile Profile) bool {
	definition, found := definitionFor(profile.ID)
	return found && profile.Provider == definition.Provider && profile.Model == definition.Model && profile.RuntimeKind == definition.RuntimeKind && profile.AuthModality == definition.AuthModality && profile.Revision == definition.Revision && profile.LocalOnly == definition.LocalOnly && validStatus(profile.Status) && validOpaqueAccountRef(profile.AccountRef)
}

func validOpaqueAccountRef(value string) bool {
	if value == "" {
		return true // disabled declarations intentionally have no account route.
	}
	const prefix = "opaque-account-ref.v1:"
	if len(value) <= len(prefix) || len(value) > 160 || value[:len(prefix)] != prefix {
		return false
	}
	for _, r := range value[len(prefix):] {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

const syntheticVersionPrefix = "synthetic/"

// validCompatibilityVersion rejects the historical @pinned placeholder. A
// pinned record carries the exact concrete version observed by the external
// probe; only local mechanics fixtures may use the synthetic namespace.
func validCompatibilityVersion(value string, maturity CompatibilityMaturity) bool {
	if !validSafeToken(value, 160) || strings.HasSuffix(strings.ToLower(value), "@pinned") {
		return false
	}
	hasDigit := false
	for _, r := range value {
		if r >= '0' && r <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return false
	}
	synthetic := strings.HasPrefix(value, syntheticVersionPrefix)
	return (maturity == CompatibilitySynthetic && synthetic) || (maturity == CompatibilityPinned && !synthetic)
}

// DeclaredProfiles are metadata-only, disabled-by-default directory entries.
// Without a persisted account/evidence promotion they must not imply readiness.
func DeclaredProfiles() []Profile {
	return []Profile{
		{ID: ProfileCodexChatGPT, Provider: ProviderCodex, Model: "gpt-5.6", RuntimeKind: "codex-app-server", AuthModality: "chatgpt-subscription", Revision: "codex-app-server.v1", Status: StatusDisabled},
		{ID: ProfileClaudeCode, Provider: ProviderClaude, Model: "claude-code", RuntimeKind: "claude-code-cli", AuthModality: "account-login-or-api", Revision: "claude-code-cli.v1", Status: StatusDisabled},
		{ID: ProfileQwenGeneral, Provider: ProviderQwen, Model: "qwen-coder", RuntimeKind: "qwen-headless", AuthModality: "coding-plan-or-api", Revision: "qwen-headless.v1", Status: StatusDisabled},
		{ID: ProfileQwenLocalPD, Provider: ProviderQwen, Model: "qwen-local", RuntimeKind: "local-compatible", AuthModality: "local-no-auth", LocalOnly: true, Revision: "qwen-local-pd.v1", Status: StatusDisabled},
		{ID: ProfileKimiCode, Provider: ProviderKimi, Model: "kimi-code", RuntimeKind: "kimi-acp", AuthModality: "membership-oauth-or-api", Revision: "kimi-acp.v1", Status: StatusDisabled},
		{ID: ProfileDeepSeekAPI, Provider: ProviderDeepSeek, Model: "deepseek-chat", RuntimeKind: "deepseek-api", AuthModality: "api-key", Revision: "deepseek-api.v1", Status: StatusDisabled},
	}
}

// PinnedMappings returns synthetic mechanics mappings only. testdata contains
// event-name fixtures, not provider compatibility transcripts; these mappings
// can exercise OfflineMeshToolTransport but can never enable mesh_spawn.
func PinnedMappings() ([]Mapping, error) {
	definitions := []struct {
		provider Provider
		profile  string
		runtime  string
		protocol string
		fixture  string
		events   []OperationMapping
	}{
		{ProviderCodex, ProfileCodexChatGPT, "synthetic/codex-app-server-fixture.v1", "synthetic/app-server-thread.v1", "codex.json", eventSet("thread.tool_call", "thread.tool_result", "thread.cancel")},
		{ProviderClaude, ProfileClaudeCode, "synthetic/claude-code-fixture.v1", "synthetic/stream-json-mcp.v1", "claude.json", eventSet("sdk.tool_request", "sdk.tool_result", "sdk.interrupt")},
		{ProviderQwen, ProfileQwenGeneral, "synthetic/qwen-code-fixture.v1", "synthetic/stream-json-mcp.v1", "qwen-general.json", eventSet("stream.tool_call", "stream.tool_result", "stream.cancel")},
		{ProviderQwen, ProfileQwenLocalPD, "synthetic/qwen-local-fixture.v1", "synthetic/local-mcp.v1", "qwen-local-pd.json", eventSet("local.tool_call", "local.tool_result", "local.cancel")},
		{ProviderKimi, ProfileKimiCode, "synthetic/kimi-code-fixture.v1", "synthetic/acp-mcp.v1", "kimi.json", eventSet("acp.tool_request", "acp.tool_result", "acp.interrupt")},
		{ProviderDeepSeek, ProfileDeepSeekAPI, "synthetic/deepseek-api-fixture.v1", "synthetic/tool-calling.v1", "deepseek.json", eventSet("api.tool_call", "api.tool_result", "api.cancel")},
	}
	out := make([]Mapping, 0, len(definitions))
	for _, definition := range definitions {
		identity, _ := definitionFor(definition.profile)
		operationsDigest, err := digest(definition.events)
		if err != nil {
			return nil, fmt.Errorf("fixture operations %s: %w", definition.profile, err)
		}
		record := CompatibilityRecord{SchemaVersion: CompatibilityRecordV1, Maturity: CompatibilitySynthetic, Provider: definition.provider, ProfileID: definition.profile, ProfileRevision: identity.Revision, Model: identity.Model, AuthModality: identity.AuthModality, RuntimeVersion: definition.runtime, ProtocolVersion: definition.protocol, RuntimeArtifactDigest: fixedDigest(struct{ Runtime string }{definition.runtime}), ProtocolSchemaDigest: fixedDigest(struct{ Protocol string }{definition.protocol}), MeshToolSchemaDigest: fixedDigest(struct{ Schema string }{"mesh-tools.v1"}), TranscriptDigest: operationsDigest, Operations: definition.events, Handshake: "unavailable", Start: "unavailable", Stream: "unavailable", Cancel: "unavailable", Teardown: "unavailable", Health: "unavailable", GeneratorVersion: "synthetic-mechanics-fixture.v1", GeneratedAt: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC), SourceReferences: []CompatibilitySource{{Reference: "internal/providerbridge/testdata/" + definition.fixture, Digest: operationsDigest}}}
		if err := record.Seal(); err != nil {
			return nil, fmt.Errorf("seal synthetic record %s: %w", definition.profile, err)
		}
		mapping, err := MappingFromCompatibility(record)
		if err != nil {
			return nil, fmt.Errorf("seal %s: %w", definition.profile, err)
		}
		out = append(out, mapping)
	}
	return out, nil
}

func eventSet(request, result, cancel string) []OperationMapping {
	operations := []string{"listProfiles", "spawn", "spawnBatch", "send", "steer", "wait", "collect", "cancel", "list", "status", "result"}
	out := make([]OperationMapping, 0, len(operations))
	for _, operation := range operations {
		out = append(out, OperationMapping{Operation: operation, RequestEvent: request + "." + operation, ResultEvent: result + "." + operation, CancelEvent: cancel})
	}
	return out
}

func fixedDigest(value any) string {
	d, _ := digest(value)
	return d
}
