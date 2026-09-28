// Package releasecatalog is the single closed ManifestV2 artifact catalog.
// It has no installer or admission dependency so packaging and installation
// consume the same fixed source-to-destination authority.
package releasecatalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strings"
)

// InactiveProviderRoot is directly below the trusted SystemRoot. It is not
// below the writable controller home, so an unprivileged controller process
// cannot replace an otherwise root-owned provider policy directory through a
// writable ancestor.
const InactiveProviderRoot = "providers/inactive"

const (
	// ProviderBundleMaxBytes and ProviderTrustMaxBytes mirror the Controller
	// reader bounds. Keeping them in the shared catalog means a release cannot
	// be signed with payloads the installed reader would later reject.
	ProviderBundleMaxBytes      int64 = 512 << 10
	ProviderTrustMaxBytes       int64 = 32 << 10
	ProviderDescriptorMaxBytes  int64 = 32 << 10
	ProviderTopologyMaxBytes    int64 = 32 << 10
	ProviderHostRuntimeMaxBytes int64 = 512 << 20
	ProviderHostClosureMaxBytes int64 = 512 << 20
	// ProviderDaemonMaxBytes bounds an optional disabled binary independently
	// from descriptor metadata. A catalog entry does not create listener or
	// launchd authority.
	ProviderDaemonMaxBytes int64 = 64 << 20

	// PluginMetadataSchema identifies a non-operational provider-plugin
	// declaration. It is intentionally distinct from the runtime transport
	// descriptor schema: plugin metadata has no socket, command, key, URL,
	// account, evidence, or activation surface.
	PluginMetadataSchema   = "openduck.provider-plugin-metadata.v1"
	ProviderTopologySchema = "openduck.provider-topology.v1"
)

var ErrInvalid = errors.New("invalid release artifact catalog")

// Artifact is the neutral projection used to validate ManifestV2 fields.
type Artifact struct {
	Type            string
	Path            string
	Platform        string
	Arch            string
	Version         string
	ActivationGroup string
	Required        bool
}

// Output is a fixed SystemRoot-relative destination. Release is substituted
// only in closed base-artifact templates; optional provider metadata has no
// release-scoped executable destination and always remains inactive.
type Output struct {
	TargetTemplate string
	Mode           string
	Owner          string
	Group          string
}

// Entry is one exact staged leaf. Optional groups are all-or-none. No entry
// authorizes a lifecycle operation, private key, native plugin mount, or
// provider runtime start.
type Entry struct {
	Path            string
	Type            string
	ActivationGroup string
	Required        bool
	Mandatory       bool
	Executable      bool
	// Provider, ProfileID, and ProfileRevision are populated only for optional
	// provider runtime/plugin descriptors. They bind an opaque path to one
	// known disabled provider identity without adding new ManifestV2 fields.
	Provider        string
	ProfileID       string
	ProfileRevision string
	// MaxBytes is a catalog-specific upper bound. A zero value means the
	// package-wide artifact bound applies (the base executable catalog).
	MaxBytes int64
	Outputs  []Output
}

// PluginMetadata is the closed canonical format for provider_plugin leaves.
// It is metadata only and carries no authority to run, mount, authenticate, or
// enable a provider. The manifest signature remains its distribution authority.
type PluginMetadata struct {
	SchemaVersion   string `json:"schema_version"`
	Provider        string `json:"provider"`
	ProfileID       string `json:"profile_id"`
	ProfileRevision string `json:"profile_revision"`
	Disabled        bool   `json:"disabled"`
	Digest          string `json:"digest"`
}

// ProviderTopology is a signed expected deployment identity, not observed
// host state.  In particular Provisioned must remain false and
// ActivationState must remain inactive in a release catalog.  Creating the
// declared principal, channel, launchd job or listener requires a later P7
// lifecycle authority which is deliberately not representable here.
type ProviderTopology struct {
	SchemaVersion                 string `json:"schema_version"`
	Provider                      string `json:"provider"`
	ProfileID                     string `json:"profile_id"`
	ProfileRevision               string `json:"profile_revision"`
	ExpectedDaemonLeaf            string `json:"expected_daemon_leaf"`
	ExpectedRuntimeDescriptorLeaf string `json:"expected_runtime_descriptor_leaf"`
	ExpectedHostExecutableLeaf    string `json:"expected_host_executable_leaf,omitempty"`
	ExpectedHostIdentityLeaf      string `json:"expected_host_identity_leaf,omitempty"`
	ExpectedHostTeamID            string `json:"expected_host_team_id,omitempty"`
	ExpectedJobLabel              string `json:"expected_job_label"`
	ExpectedServiceUser           string `json:"expected_service_user"`
	ExpectedServiceGroup          string `json:"expected_service_group"`
	ExpectedChannelGroup          string `json:"expected_channel_group"`
	ActivationState               string `json:"activation_state"`
	Provisioned                   bool   `json:"provisioned"`
	Digest                        string `json:"digest"`
}

type ProviderHostIdentity struct {
	Schema, Provider, TeamID, ArtifactDigest, ImageIdentity string
}

func DecodeProviderHostIdentity(raw []byte) (ProviderHostIdentity, error) {
	if len(raw) == 0 || len(raw) > 4<<10 || !json.Valid(raw) || duplicateJSONKeys(raw) {
		return ProviderHostIdentity{}, ErrInvalid
	}
	var wire struct {
		Schema         string `json:"schema"`
		Provider       string `json:"provider"`
		TeamID         string `json:"team_id"`
		ArtifactDigest string `json:"artifact_digest"`
		ImageIdentity  string `json:"image_identity"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil || d.Decode(&struct{}{}) != io.EOF || wire.Schema != "openduck.provider-host-identity.v1" || !safeID(wire.Provider) || !safeID(wire.TeamID) || !prefixedDigest(wire.ArtifactDigest) || !prefixedDigest(wire.ImageIdentity) {
		return ProviderHostIdentity{}, ErrInvalid
	}
	canonical, _ := json.Marshal(wire)
	if !bytes.Equal(raw, canonical) {
		return ProviderHostIdentity{}, ErrInvalid
	}
	return ProviderHostIdentity{wire.Schema, wire.Provider, wire.TeamID, wire.ArtifactDigest, wire.ImageIdentity}, nil
}

// Entries returns a detached deterministic catalog. Callers must not retain
// mutable catalog state as authority.
func Entries() []Entry {
	out := make([]Entry, len(entries))
	for i, entry := range entries {
		out[i] = entry
		out[i].Outputs = append([]Output(nil), entry.Outputs...)
	}
	return out
}

// EntryFor resolves one exact, case-sensitive staged path.
func EntryFor(stagePath string) (Entry, bool) {
	entry, ok := byPath[stagePath]
	if !ok {
		return Entry{}, false
	}
	entry.Outputs = append([]Output(nil), entry.Outputs...)
	return entry, true
}

// Resolve returns the sole output mapping for a correctly typed manifest
// artifact. It does not accept a caller-provided destination.
func Resolve(artifact Artifact, release string) ([]Output, bool) {
	entry, ok := EntryFor(artifact.Path)
	if !ok || entry.Type != artifact.Type || entry.ActivationGroup != artifact.ActivationGroup || entry.Required != artifact.Required {
		return nil, false
	}
	return resolveEntry(entry, release)
}

// ResolveSource is the PlanV2 validation projection. Plan operations do not
// carry activation-group or required fields, so the caller must validate the
// full ManifestV2 with Validate before using this narrower path/type lookup.
// It still never accepts a caller-selected destination.
func ResolveSource(stagePath, artifactType, release string) ([]Output, bool) {
	entry, ok := EntryFor(stagePath)
	if !ok || entry.Type != artifactType {
		return nil, false
	}
	return resolveEntry(entry, release)
}

func resolveEntry(entry Entry, release string) ([]Output, bool) {
	if !safeID(release) {
		return nil, false
	}
	outputs := make([]Output, len(entry.Outputs))
	for i, output := range entry.Outputs {
		outputs[i] = output
		outputs[i].TargetTemplate = strings.ReplaceAll(output.TargetTemplate, "{release}", release)
		if !safeRelative(outputs[i].TargetTemplate) {
			return nil, false
		}
	}
	return outputs, true
}

// Validate rejects unknown paths/types/groups, duplicates, non-canonical
// order, absent base leaves, and partial optional groups. Platform, arch and
// version are exact cross-field inputs supplied by the signed manifest.
func Validate(artifacts []Artifact, platform, arch, version string) error {
	if !safeID(platform) || !safeID(arch) || !validVersion(version) || len(artifacts) == 0 || len(artifacts) > len(entries) {
		return ErrInvalid
	}
	seen := make(map[string]bool, len(artifacts))
	presentGroups := make(map[string]int)
	last := ""
	for _, artifact := range artifacts {
		entry, ok := byPath[artifact.Path]
		if !ok || artifact.Path <= last || seen[artifact.Path] || artifact.Type != entry.Type || artifact.ActivationGroup != entry.ActivationGroup || artifact.Required != entry.Required || artifact.Platform != platform || artifact.Arch != arch || artifact.Version != version {
			return ErrInvalid
		}
		seen[artifact.Path] = true
		presentGroups[entry.ActivationGroup]++
		last = artifact.Path
	}
	for _, entry := range entries {
		if entry.Mandatory && !seen[entry.Path] {
			return ErrInvalid
		}
	}
	for group, total := range groupSizes {
		if total != 0 && presentGroups[group] != 0 && presentGroups[group] != total {
			return ErrInvalid
		}
	}
	if !validOptionalGroupClosure(presentGroups) {
		return ErrInvalid
	}
	return nil
}

// SelectedEntries derives exact enabled-by-package groups from the caller's
// descriptor-safe existence check. Base entries are mandatory; an optional
// group appears only as an exact complete set.
func SelectedEntries(exists func(string) (bool, error)) ([]Entry, error) {
	if exists == nil {
		return nil, ErrInvalid
	}
	selected := make(map[string]bool, len(entries))
	for _, entry := range entries {
		present, err := exists(entry.Path)
		if err != nil {
			return nil, ErrInvalid
		}
		if entry.Mandatory && !present {
			return nil, ErrInvalid
		}
		if present {
			selected[entry.Path] = true
		}
	}
	for group, total := range groupSizes {
		count := 0
		for _, entry := range entries {
			if entry.ActivationGroup == group && selected[entry.Path] {
				count++
			}
		}
		if count != 0 && count != total {
			return nil, ErrInvalid
		}
	}
	presentGroups := make(map[string]int, len(groupSizes))
	for _, entry := range entries {
		if selected[entry.Path] && !entry.Mandatory {
			presentGroups[entry.ActivationGroup]++
		}
	}
	if !validOptionalGroupClosure(presentGroups) {
		return nil, ErrInvalid
	}
	out := make([]Entry, 0, len(selected))
	for _, entry := range entries {
		if selected[entry.Path] {
			entry.Outputs = append([]Output(nil), entry.Outputs...)
			out = append(out, entry)
		}
	}
	return out, nil
}

// validOptionalGroupClosure makes the signed policy and descriptor inventory
// one atomic disabled package. A policy without a known provider descriptor
// would be orphaned authority; a descriptor without the matching policy/trust
// bundle cannot be loaded. Base-only migration remains valid.
func validOptionalGroupClosure(present map[string]int) bool {
	policyCount, policyTotal := present["provider-policy"], groupSizes["provider-policy"]
	providerGroups := 0
	for group, total := range groupSizes {
		if group == "provider-policy" || total == 0 {
			continue
		}
		if present[group] == total {
			providerGroups++
		}
	}
	return (policyCount == policyTotal) == (providerGroups > 0)
}

// ExpectedChildren returns the exact children allowed in each catalog-derived
// directory for selected leaves. It intentionally does not walk arbitrary
// subtrees.
func ExpectedChildren(selected []Entry) map[string]map[string]bool {
	children := map[string]map[string]bool{".": {}}
	for _, entry := range selected {
		parts := strings.Split(entry.Path, "/")
		parent := "."
		for i, part := range parts {
			children[parent][part] = true
			if i == len(parts)-1 {
				break
			}
			if parent == "." {
				parent = part
			} else {
				parent += "/" + part
			}
			if children[parent] == nil {
				children[parent] = map[string]bool{}
			}
		}
	}
	return children
}

// IsExecutable is exact catalog policy; packaging checks it against staged
// mode bits before hashing the file.
func IsExecutable(stagePath string) (bool, bool) {
	entry, ok := byPath[stagePath]
	return entry.Executable, ok
}

// CanonicalPluginMetadata returns the sole allowed metadata shape for one
// optional provider_plugin catalog entry. It is useful for external package
// builders and synthetic tests; it never creates a runtime artifact.
func CanonicalPluginMetadata(entry Entry) ([]byte, error) {
	if entry.Mandatory || entry.Type != "provider_plugin" || entry.Provider == "" || entry.ProfileID == "" || entry.ProfileRevision == "" {
		return nil, ErrInvalid
	}
	metadata := PluginMetadata{SchemaVersion: PluginMetadataSchema, Provider: entry.Provider, ProfileID: entry.ProfileID, ProfileRevision: entry.ProfileRevision, Disabled: true}
	if err := metadata.Seal(); err != nil {
		return nil, err
	}
	return json.Marshal(metadata)
}

// DecodePluginMetadata accepts only exact canonical disabled metadata. The
// caller must separately compare it with the catalog entry for its fixed path.
func DecodePluginMetadata(raw []byte) (PluginMetadata, error) {
	if len(raw) == 0 || int64(len(raw)) > ProviderDescriptorMaxBytes || !json.Valid(raw) || duplicateJSONKeys(raw) {
		return PluginMetadata{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var metadata PluginMetadata
	if err := decoder.Decode(&metadata); err != nil || decoder.Decode(&struct{}{}) != io.EOF || metadata.Validate() != nil {
		return PluginMetadata{}, ErrInvalid
	}
	canonical, err := json.Marshal(metadata)
	if err != nil || !bytes.Equal(canonical, raw) {
		return PluginMetadata{}, ErrInvalid
	}
	return metadata, nil
}

// CanonicalProviderTopology returns the sole inactive topology declaration
// for one provider_topology catalog leaf.
func CanonicalProviderTopology(entry Entry) ([]byte, error) {
	if entry.Mandatory || entry.Type != "provider_topology" || entry.Provider == "" || entry.ProfileID == "" || entry.ProfileRevision == "" {
		return nil, ErrInvalid
	}
	runtimeLeaf := "runtime-descriptor.json"
	hostLeaf := entry.Provider
	hostTeam := map[string]string{"codex": "2DC432GLL2", "claude": "Q6L2SF6YDW", "kimi": "2J9472RW75", "qwen": "HX7739G8FX"}[entry.Provider]
	if entry.Provider == "deepseek" {
		runtimeLeaf = "dsh-adapter-descriptor.json"
		hostLeaf = ""
	} else if entry.Provider == "kimi" {
		hostLeaf = "kimi-code"
	} else if entry.Provider == "qwen" {
		hostLeaf = "node"
	}
	topology := ProviderTopology{
		SchemaVersion: ProviderTopologySchema,
		Provider:      entry.Provider, ProfileID: entry.ProfileID, ProfileRevision: entry.ProfileRevision,
		ExpectedDaemonLeaf:            "openduck-provider-" + entry.Provider,
		ExpectedRuntimeDescriptorLeaf: runtimeLeaf,
		ExpectedHostExecutableLeaf:    hostLeaf,
		ExpectedHostIdentityLeaf:      map[bool]string{true: "", false: "host-identity.json"}[entry.Provider == "deepseek"],
		ExpectedHostTeamID:            hostTeam,
		ExpectedJobLabel:              "com.openduck.provider." + entry.Provider,
		ExpectedServiceUser:           "_openduck_provider_" + entry.Provider,
		ExpectedServiceGroup:          "_openduck_provider_" + entry.Provider,
		ExpectedChannelGroup:          "_openduck_provider_" + entry.Provider + "_channel",
		ActivationState:               "inactive", Provisioned: false,
	}
	if err := topology.Seal(); err != nil {
		return nil, err
	}
	return json.Marshal(topology)
}

// CanonicalProviderTopologyFromIdentity is the importer-facing variant of the
// inactive topology constructor.  A host identity is an importer assertion,
// not something the release packager can reconstruct (notably, macOS CDHash
// is not derivable from arbitrary bytes).  DeepSeek is API-only and therefore
// requires nil.  Other providers require an exact provider and pinned Team ID
// before their symbolic, still-disabled topology is emitted.
func CanonicalProviderTopologyFromIdentity(entry Entry, identity *ProviderHostIdentity) ([]byte, error) {
	if entry.Mandatory || entry.Type != "provider_topology" {
		return nil, ErrInvalid
	}
	if entry.Provider == "deepseek" {
		if identity != nil {
			return nil, ErrInvalid
		}
		return CanonicalProviderTopology(entry)
	}
	if identity == nil || identity.Provider != entry.Provider || identity.TeamID != map[string]string{"codex": "2DC432GLL2", "claude": "Q6L2SF6YDW", "kimi": "2J9472RW75", "qwen": "HX7739G8FX"}[entry.Provider] || !prefixedDigest(identity.ArtifactDigest) || !prefixedDigest(identity.ImageIdentity) {
		return nil, ErrInvalid
	}
	return CanonicalProviderTopology(entry)
}

func DecodeProviderTopology(raw []byte) (ProviderTopology, error) {
	if len(raw) == 0 || int64(len(raw)) > ProviderTopologyMaxBytes || !json.Valid(raw) || duplicateJSONKeys(raw) {
		return ProviderTopology{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var topology ProviderTopology
	if err := decoder.Decode(&topology); err != nil || decoder.Decode(&struct{}{}) != io.EOF || topology.Validate() != nil {
		return ProviderTopology{}, ErrInvalid
	}
	canonical, err := json.Marshal(topology)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ProviderTopology{}, ErrInvalid
	}
	return topology, nil
}

func (topology *ProviderTopology) Seal() error {
	if topology == nil {
		return ErrInvalid
	}
	topology.Digest = ""
	if topology.SchemaVersion == "" {
		topology.SchemaVersion = ProviderTopologySchema
	}
	if topology.ValidateUnsigned() != nil {
		return ErrInvalid
	}
	topology.Digest = providerTopologyDigest(*topology)
	return topology.Validate()
}

func (topology ProviderTopology) ValidateUnsigned() error {
	if topology.SchemaVersion != ProviderTopologySchema || !safeID(topology.Provider) || !safeID(topology.ProfileID) || !safeID(topology.ProfileRevision) || !safeLeaf(topology.ExpectedDaemonLeaf) || !safeLeaf(topology.ExpectedRuntimeDescriptorLeaf) || (topology.Provider == "deepseek" && (topology.ExpectedHostExecutableLeaf != "" || topology.ExpectedHostIdentityLeaf != "" || topology.ExpectedHostTeamID != "")) || (topology.Provider != "deepseek" && (!safeLeaf(topology.ExpectedHostExecutableLeaf) || topology.ExpectedHostIdentityLeaf != "host-identity.json" || !safeID(topology.ExpectedHostTeamID))) || !safeID(topology.ExpectedJobLabel) || !safeID(topology.ExpectedServiceUser) || !safeID(topology.ExpectedServiceGroup) || !safeID(topology.ExpectedChannelGroup) || topology.ActivationState != "inactive" || topology.Provisioned {
		return ErrInvalid
	}
	return nil
}

func (topology ProviderTopology) Validate() error {
	if topology.ValidateUnsigned() != nil || !prefixedDigest(topology.Digest) || topology.Digest != providerTopologyDigest(topology) {
		return ErrInvalid
	}
	return nil
}

func providerTopologyDigest(topology ProviderTopology) string {
	topology.Digest = ""
	raw, err := json.Marshal(topology)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func safeLeaf(value string) bool {
	return safeID(value) && path.Base(value) == value && value != "." && value != ".."
}

// Seal computes the metadata's non-secret, canonical content address.
func (metadata *PluginMetadata) Seal() error {
	if metadata == nil {
		return ErrInvalid
	}
	metadata.Digest = ""
	if metadata.SchemaVersion == "" {
		metadata.SchemaVersion = PluginMetadataSchema
	}
	if metadata.SchemaVersion != PluginMetadataSchema || !safeID(metadata.Provider) || !safeID(metadata.ProfileID) || !safeID(metadata.ProfileRevision) || !metadata.Disabled {
		return ErrInvalid
	}
	metadata.Digest = pluginMetadataDigest(*metadata)
	return metadata.Validate()
}

// Validate ensures that the descriptor is disabled and self-consistent. Its
// path-to-provider/profile binding is deliberately left to the release catalog
// consumer because the schema itself is reusable for the closed leaf set.
func (metadata PluginMetadata) Validate() error {
	if metadata.SchemaVersion != PluginMetadataSchema || !safeID(metadata.Provider) || !safeID(metadata.ProfileID) || !safeID(metadata.ProfileRevision) || !metadata.Disabled || !prefixedDigest(metadata.Digest) {
		return ErrInvalid
	}
	if metadata.Digest != pluginMetadataDigest(metadata) {
		return ErrInvalid
	}
	return nil
}

func pluginMetadataDigest(metadata PluginMetadata) string {
	metadata.Digest = ""
	raw, err := json.Marshal(metadata)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func prefixedDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil
}

func duplicateJSONKeys(raw []byte) bool {
	var scan func(*json.Decoder) bool
	scan = func(decoder *json.Decoder) bool {
		token, err := decoder.Token()
		if err != nil {
			return true
		}
		switch delimiter := token.(type) {
		case json.Delim:
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					key, keyErr := decoder.Token()
					name, ok := key.(string)
					if keyErr != nil || !ok || seen[name] {
						return true
					}
					seen[name] = true
					if scan(decoder) {
						return true
					}
				}
				_, err = decoder.Token()
				return err != nil
			case '[':
				for decoder.More() {
					if scan(decoder) {
						return true
					}
				}
				_, err = decoder.Token()
				return err != nil
			}
		}
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if scan(decoder) {
		return true
	}
	_, err := decoder.Token()
	return err != io.EOF
}

func safeRelative(value string) bool {
	return value != "" && path.Clean(value) == value && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "../") && value != "." && !strings.Contains(value, "//")
}

func safeID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func validVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 9 || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func base(path, typ string, executable bool, outputs ...Output) Entry {
	// "default" is the canonical mandatory activation group already bound by
	// ManifestV2 migration fixtures. Optional provider groups are separate and
	// remain inactive until a later owner lifecycle operation.
	return Entry{Path: path, Type: typ, ActivationGroup: "default", Required: true, Mandatory: true, Executable: executable, Outputs: outputs}
}

func optional(path, typ, group string, outputs ...Output) Entry {
	return Entry{Path: path, Type: typ, ActivationGroup: group, Required: true, Executable: false, Outputs: outputs}
}

func optionalPolicy(path string, maxBytes int64, outputs ...Output) Entry {
	return Entry{Path: path, Type: "policy", ActivationGroup: "provider-policy", Required: true, Executable: false, MaxBytes: maxBytes, Outputs: outputs}
}

func optionalProvider(path, typ, group, provider, profileID, profileRevision string, outputs ...Output) Entry {
	return Entry{Path: path, Type: typ, ActivationGroup: group, Required: true, Executable: false, Provider: provider, ProfileID: profileID, ProfileRevision: profileRevision, MaxBytes: ProviderDescriptorMaxBytes, Outputs: outputs}
}

func optionalProviderDaemon(path, group, provider, profileID, profileRevision string, outputs ...Output) Entry {
	return Entry{Path: path, Type: "provider_daemon", ActivationGroup: group, Required: true, Executable: true, Provider: provider, ProfileID: profileID, ProfileRevision: profileRevision, MaxBytes: ProviderDaemonMaxBytes, Outputs: outputs}
}

// optionalProviderHostRuntime declares an exact, signed executable from an
// official provider distribution. It is installed into the inactive provider
// tree and therefore cannot create a process, principal, listener, or egress
// capability during a base deployment.
func optionalProviderHostRuntime(path, group, provider, profileID, profileRevision string, outputs ...Output) Entry {
	return Entry{Path: path, Type: "provider_host_runtime", ActivationGroup: group, Required: true, Executable: true, Provider: provider, ProfileID: profileID, ProfileRevision: profileRevision, MaxBytes: ProviderHostRuntimeMaxBytes, Outputs: outputs}
}

func optionalProviderHostClosure(path, group, provider, profileID, profileRevision string, maxBytes int64, outputs ...Output) Entry {
	return Entry{Path: path, Type: "provider_host_closure", ActivationGroup: group, Required: true, Provider: provider, ProfileID: profileID, ProfileRevision: profileRevision, MaxBytes: maxBytes, Outputs: outputs}
}

func optionalProviderHostIdentity(path, group, provider, profileID, profileRevision string, outputs ...Output) Entry {
	return Entry{Path: path, Type: "provider_host_identity", ActivationGroup: group, Required: true, Provider: provider, ProfileID: profileID, ProfileRevision: profileRevision, MaxBytes: 4 << 10, Outputs: outputs}
}

func optionalProviderTopology(path, group, provider, profileID, profileRevision string, outputs ...Output) Entry {
	return Entry{Path: path, Type: "provider_topology", ActivationGroup: group, Required: true, Executable: false, Provider: provider, ProfileID: profileID, ProfileRevision: profileRevision, MaxBytes: ProviderTopologyMaxBytes, Outputs: outputs}
}

var entries = []Entry{
	base("bin/codex", "core", true, Output{"home/runtime/bin/codex", "0700", "root", "wheel"}, Output{"releases/codex/{release}/codex", "0755", "root", "wheel"}),
	base("bin/openduck-anchor", "core", true, Output{"releases/anchor/{release}/openduck-anchor", "0550", "root", "_openduck_anchor"}, Output{"releases/anchor-checkpoint/{release}/openduck-anchor", "0550", "root", "_openduck_checkpoint"}, Output{"releases/anchor-installer/{release}/openduck-anchor", "0550", "root", "wheel"}),
	base("bin/openduck-checkpoint", "core", true, Output{"releases/checkpoint/{release}/openduck-checkpoint", "0550", "root", "_openduck_checkpoint"}, Output{"releases/checkpoint-installer/{release}/openduck-checkpoint", "0550", "root", "wheel"}),
	base("bin/openduck-codex-broker", "provider_plugin", true, Output{"releases/broker/{release}/openduck-codex-broker", "0550", "root", "_openduck_broker"}),
	base("bin/openduck-codex-login", "helper", true, Output{"home/controller/bin/openduck-codex-login", "0700", "root", "wheel"}),
	base("bin/openduck-codex-runtime", "provider_runtime", true, Output{"releases/runtime/{release}/openduck-codex-runtime", "0550", "root", "_openduck_codex"}),
	base("bin/openduck-controller", "core", true, Output{"releases/controller/{release}/openduck-controller", "0550", "root", "_openduck"}),
	base("bin/openduck-egress", "core", true, Output{"releases/egress/{release}/openduck-egress", "0550", "root", "_openduck_egress"}),
	base("bin/openduck-installer", "helper", true, Output{".openduck-installer", "0700", "root", "wheel"}, Output{".openduck-service-login", "0700", "root", "wheel"}, Output{"releases/installer-checkpoint/{release}/openduck-installer", "0550", "root", "wheel"}, Output{"releases/installer-anchor/{release}/openduck-installer", "0550", "root", "wheel"}),
	base("bin/openduck-native-mcp", "helper", true, Output{".openduck-native-mcp", "0755", "root", "wheel"}),
	base("bin/openduck-owner-grant", "helper", true, Output{"operator/openduck-owner-grant", "0700", "root", "wheel"}),
	base("bin/openduck-provider-attestor", "helper", true, Output{".openduck-provider-attestor", "0700", "root", "wheel"}),
	base("bin/openduck-readiness", "helper", true, Output{".openduck-readiness", "0700", "root", "wheel"}),

	optionalPolicy("provider-bundle.json", ProviderBundleMaxBytes, Output{InactiveProviderRoot + "/provider-bundle.json", "0440", "root", "_openduck"}),
	optionalPolicy("provider-trust.json", ProviderTrustMaxBytes, Output{InactiveProviderRoot + "/provider-trust.json", "0440", "root", "_openduck"}),
	optionalProvider("providers/claude/plugin-descriptor.json", "provider_plugin", "provider-claude", "claude", "claude.code.cli", "claude-code-cli.v1", Output{InactiveProviderRoot + "/claude/plugin-descriptor.json", "0440", "root", "_openduck"}),
	optionalProvider("providers/claude/runtime-descriptor.json", "provider_runtime", "provider-claude", "claude", "claude.code.cli", "claude-code-cli.v1", Output{InactiveProviderRoot + "/claude/runtime-descriptor.json", "0440", "root", "_openduck"}),
	optionalProviderDaemon("bin/openduck-provider-claude", "provider-claude", "claude", "claude.code.cli", "claude-code-cli.v1", Output{InactiveProviderRoot + "/claude/openduck-provider-claude", "0500", "root", "_openduck"}),
	optionalProviderTopology("providers/claude/topology.json", "provider-claude", "claude", "claude.code.cli", "claude-code-cli.v1", Output{InactiveProviderRoot + "/claude/topology.json", "0440", "root", "_openduck"}),
	optionalProviderHostRuntime("providers/claude/host/claude", "provider-claude", "claude", "claude.code.cli", "claude-code-cli.v1", Output{InactiveProviderRoot + "/claude/host/claude", "0550", "root", "_openduck"}),
	optionalProviderHostIdentity("providers/claude/host/host-identity.json", "provider-claude", "claude", "claude.code.cli", "claude-code-cli.v1", Output{InactiveProviderRoot + "/claude/host/host-identity.json", "0440", "root", "_openduck"}),
	optionalProvider("providers/codex/plugin-descriptor.json", "provider_plugin", "provider-codex", "codex", "codex.chatgpt.app-server", "codex-app-server.v1", Output{InactiveProviderRoot + "/codex/plugin-descriptor.json", "0440", "root", "_openduck"}),
	optionalProvider("providers/codex/runtime-descriptor.json", "provider_runtime", "provider-codex", "codex", "codex.chatgpt.app-server", "codex-app-server.v1", Output{InactiveProviderRoot + "/codex/runtime-descriptor.json", "0440", "root", "_openduck"}),
	optionalProviderDaemon("bin/openduck-provider-codex", "provider-codex", "codex", "codex.chatgpt.app-server", "codex-app-server.v1", Output{InactiveProviderRoot + "/codex/openduck-provider-codex", "0500", "root", "_openduck"}),
	optionalProviderTopology("providers/codex/topology.json", "provider-codex", "codex", "codex.chatgpt.app-server", "codex-app-server.v1", Output{InactiveProviderRoot + "/codex/topology.json", "0440", "root", "_openduck"}),
	optionalProviderHostRuntime("providers/codex/host/codex", "provider-codex", "codex", "codex.chatgpt.app-server", "codex-app-server.v1", Output{InactiveProviderRoot + "/codex/host/codex", "0550", "root", "_openduck"}),
	optionalProviderHostIdentity("providers/codex/host/host-identity.json", "provider-codex", "codex", "codex.chatgpt.app-server", "codex-app-server.v1", Output{InactiveProviderRoot + "/codex/host/host-identity.json", "0440", "root", "_openduck"}),
	// DeepSeek is a single API/DSH adapter transport descriptor. It is not a
	// native plugin and there is deliberately no subscription leaf.
	optionalProvider("providers/deepseek/dsh-adapter-descriptor.json", "provider_runtime", "provider-deepseek", "deepseek", "deepseek.api", "deepseek-api.v1", Output{InactiveProviderRoot + "/deepseek/dsh-adapter-descriptor.json", "0440", "root", "_openduck"}),
	optionalProviderDaemon("bin/openduck-provider-deepseek", "provider-deepseek", "deepseek", "deepseek.api", "deepseek-api.v1", Output{InactiveProviderRoot + "/deepseek/openduck-provider-deepseek", "0500", "root", "_openduck"}),
	optionalProviderTopology("providers/deepseek/topology.json", "provider-deepseek", "deepseek", "deepseek.api", "deepseek-api.v1", Output{InactiveProviderRoot + "/deepseek/topology.json", "0440", "root", "_openduck"}),
	optionalProvider("providers/kimi/plugin-descriptor.json", "provider_plugin", "provider-kimi", "kimi", "kimi.code.acp", "kimi-acp.v1", Output{InactiveProviderRoot + "/kimi/plugin-descriptor.json", "0440", "root", "_openduck"}),
	optionalProvider("providers/kimi/runtime-descriptor.json", "provider_runtime", "provider-kimi", "kimi", "kimi.code.acp", "kimi-acp.v1", Output{InactiveProviderRoot + "/kimi/runtime-descriptor.json", "0440", "root", "_openduck"}),
	optionalProviderDaemon("bin/openduck-provider-kimi", "provider-kimi", "kimi", "kimi.code.acp", "kimi-acp.v1", Output{InactiveProviderRoot + "/kimi/openduck-provider-kimi", "0500", "root", "_openduck"}),
	optionalProviderTopology("providers/kimi/topology.json", "provider-kimi", "kimi", "kimi.code.acp", "kimi-acp.v1", Output{InactiveProviderRoot + "/kimi/topology.json", "0440", "root", "_openduck"}),
	optionalProviderHostRuntime("providers/kimi/host/kimi-code", "provider-kimi", "kimi", "kimi.code.acp", "kimi-acp.v1", Output{InactiveProviderRoot + "/kimi/host/kimi-code", "0550", "root", "_openduck"}),
	optionalProviderHostIdentity("providers/kimi/host/host-identity.json", "provider-kimi", "kimi", "kimi.code.acp", "kimi-acp.v1", Output{InactiveProviderRoot + "/kimi/host/host-identity.json", "0440", "root", "_openduck"}),
	optionalProvider("providers/qwen/plugin-descriptor.json", "provider_plugin", "provider-qwen", "qwen", "qwen.general.headless", "qwen-headless.v1", Output{InactiveProviderRoot + "/qwen/plugin-descriptor.json", "0440", "root", "_openduck"}),
	optionalProvider("providers/qwen/runtime-descriptor.json", "provider_runtime", "provider-qwen", "qwen", "qwen.general.headless", "qwen-headless.v1", Output{InactiveProviderRoot + "/qwen/runtime-descriptor.json", "0440", "root", "_openduck"}),
	optionalProviderDaemon("bin/openduck-provider-qwen", "provider-qwen", "qwen", "qwen.general.headless", "qwen-headless.v1", Output{InactiveProviderRoot + "/qwen/openduck-provider-qwen", "0500", "root", "_openduck"}),
	optionalProviderTopology("providers/qwen/topology.json", "provider-qwen", "qwen", "qwen.general.headless", "qwen-headless.v1", Output{InactiveProviderRoot + "/qwen/topology.json", "0440", "root", "_openduck"}),
	optionalProviderHostRuntime("providers/qwen/host/node", "provider-qwen", "qwen", "qwen.general.headless", "qwen-headless.v1", Output{InactiveProviderRoot + "/qwen/host/node", "0550", "root", "_openduck"}),
	optionalProviderHostIdentity("providers/qwen/host/host-identity.json", "provider-qwen", "qwen", "qwen.general.headless", "qwen-headless.v1", Output{InactiveProviderRoot + "/qwen/host/host-identity.json", "0440", "root", "_openduck"}),
	optionalProviderHostClosure("providers/qwen/host/qwen-code-darwin-arm64.tar.gz", "provider-qwen", "qwen", "qwen.general.headless", "qwen-headless.v1", ProviderHostClosureMaxBytes, Output{InactiveProviderRoot + "/qwen/host/qwen-code-darwin-arm64.tar.gz", "0440", "root", "_openduck"}),
	optionalProviderHostClosure("providers/qwen/host/qwen-closure.sha256", "provider-qwen", "qwen", "qwen.general.headless", "qwen-headless.v1", 2<<20, Output{InactiveProviderRoot + "/qwen/host/qwen-closure.sha256", "0440", "root", "_openduck"}),
}

var byPath map[string]Entry
var groupSizes map[string]int

func init() {
	byPath = make(map[string]Entry, len(entries))
	groupSizes = make(map[string]int)
	outputOwners := make(map[string]string)
	for _, entry := range entries {
		if !safeRelative(entry.Path) || !safeID(entry.Type) || !safeID(entry.ActivationGroup) || byPath[entry.Path].Path != "" {
			panic("invalid closed release catalog")
		}
		if entry.MaxBytes < 0 {
			panic("invalid release catalog size bound")
		}
		if !entry.Mandatory && (entry.Type == "provider_runtime" || entry.Type == "provider_plugin" || entry.Type == "provider_daemon" || entry.Type == "provider_topology" || entry.Type == "provider_host_runtime" || entry.Type == "provider_host_closure" || entry.Type == "provider_host_identity") && (!safeID(entry.Provider) || !safeID(entry.ProfileID) || !safeID(entry.ProfileRevision) || entry.MaxBytes == 0) {
			panic("invalid closed provider descriptor catalog")
		}
		if !entry.Mandatory && entry.Type == "policy" && (entry.Provider != "" || entry.ProfileID != "" || entry.ProfileRevision != "" || entry.MaxBytes == 0) {
			panic("invalid closed provider policy catalog")
		}
		if entry.Mandatory && (entry.Provider != "" || entry.ProfileID != "" || entry.ProfileRevision != "") {
			panic("mandatory catalog entry has provider identity")
		}
		if len(entry.Outputs) == 0 {
			panic("release catalog entry without output")
		}
		for _, output := range entry.Outputs {
			if !safeRelative(output.TargetTemplate) || output.Mode == "" || output.Owner == "" || output.Group == "" {
				panic("invalid release catalog output")
			}
			if prior, exists := outputOwners[output.TargetTemplate]; exists && prior != entry.Path {
				panic("colliding release catalog output")
			}
			outputOwners[output.TargetTemplate] = entry.Path
		}
		byPath[entry.Path] = entry
		if !entry.Mandatory {
			groupSizes[entry.ActivationGroup]++
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
}
