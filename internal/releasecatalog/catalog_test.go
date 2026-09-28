package releasecatalog

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const (
	testPlatform = "darwin"
	testArch     = "arm64"
	testVersion  = "1.2.3"
	testRelease  = "release-20260826"
)

func TestCatalogAcceptsBaseAndClosedOptionalGroups(t *testing.T) {
	base := catalogArtifacts(t, func(entry Entry) bool { return entry.Mandatory })
	policy := catalogArtifacts(t, func(entry Entry) bool { return entry.ActivationGroup == "provider-policy" })
	if err := Validate(base, testPlatform, testArch, testVersion); err != nil {
		t.Fatalf("base-only migration rejected: %v", err)
	}
	for _, group := range optionalGroups(t) {
		if group == "provider-policy" {
			continue
		}
		artifacts := append([]Artifact(nil), base...)
		artifacts = append(artifacts, catalogArtifacts(t, func(entry Entry) bool { return entry.ActivationGroup == "provider-policy" })...)
		artifacts = append(artifacts, catalogArtifacts(t, func(entry Entry) bool { return entry.ActivationGroup == group })...)
		sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
		if err := Validate(artifacts, testPlatform, testArch, testVersion); err != nil {
			t.Fatalf("valid optional group %q rejected: %v", group, err)
		}
	}

	policyOnly := append(append([]Artifact(nil), base...), policy...)
	sort.Slice(policyOnly, func(i, j int) bool { return policyOnly[i].Path < policyOnly[j].Path })
	if err := Validate(policyOnly, testPlatform, testArch, testVersion); err == nil {
		t.Fatal("orphan provider policy accepted")
	}
	for _, group := range optionalGroups(t) {
		if group == "provider-policy" {
			continue
		}
		providerOnly := append(append([]Artifact(nil), base...), catalogArtifacts(t, func(entry Entry) bool { return entry.ActivationGroup == group })...)
		sort.Slice(providerOnly, func(i, j int) bool { return providerOnly[i].Path < providerOnly[j].Path })
		if err := Validate(providerOnly, testPlatform, testArch, testVersion); err == nil {
			t.Fatalf("provider group %q without policy accepted", group)
		}
	}

	all := catalogArtifacts(t, func(Entry) bool { return true })
	if err := Validate(all, testPlatform, testArch, testVersion); err != nil {
		t.Fatalf("complete catalog rejected: %v", err)
	}
}

func TestCatalogRejectsPartialUnknownAndBindingDrift(t *testing.T) {
	base := catalogArtifacts(t, func(entry Entry) bool { return entry.Mandatory })
	policy := catalogArtifacts(t, func(entry Entry) bool { return entry.ActivationGroup == "provider-policy" })
	if len(policy) != 2 {
		t.Fatalf("provider policy group = %d, want 2", len(policy))
	}
	partial := append(append([]Artifact(nil), base...), policy[0])
	sort.Slice(partial, func(i, j int) bool { return partial[i].Path < partial[j].Path })
	if err := Validate(partial, testPlatform, testArch, testVersion); err == nil {
		t.Fatal("partial optional group accepted")
	}

	for _, tc := range []struct {
		name string
		edit func([]Artifact)
	}{
		{"unknown path", func(values []Artifact) { values[0].Path = "providers/unknown/descriptor.json" }},
		{"case alias", func(values []Artifact) { values[0].Path = strings.ToUpper(values[0].Path) }},
		{"traversal", func(values []Artifact) { values[0].Path = "../" + values[0].Path }},
		{"type", func(values []Artifact) { values[0].Type = "policy" }},
		{"group", func(values []Artifact) { values[0].ActivationGroup = "provider-policy" }},
		{"required", func(values []Artifact) { values[0].Required = false }},
		{"platform", func(values []Artifact) { values[0].Platform = "linux" }},
		{"arch", func(values []Artifact) { values[0].Arch = "amd64" }},
		{"version", func(values []Artifact) { values[0].Version = "9.9.9" }},
		{"duplicate", func(values []Artifact) { values[1] = values[0] }},
		{"order", func(values []Artifact) { values[0], values[1] = values[1], values[0] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := append([]Artifact(nil), base...)
			tc.edit(values)
			if err := Validate(values, testPlatform, testArch, testVersion); err == nil {
				t.Fatal("invalid catalog projection accepted")
			}
		})
	}
}

func TestCatalogSelectionInventoryAndNoLifecycleAuthorization(t *testing.T) {
	present := map[string]bool{}
	for _, entry := range Entries() {
		if entry.Mandatory || entry.ActivationGroup == "provider-policy" || entry.ActivationGroup == "provider-deepseek" {
			present[entry.Path] = true
		}
	}
	selected, err := SelectedEntries(func(stagePath string) (bool, error) { return present[stagePath], nil })
	if err != nil {
		t.Fatalf("closed selected groups rejected: %v", err)
	}
	children := ExpectedChildren(selected)
	if !reflect.DeepEqual(sortedChildren(children["."]), []string{"bin", "provider-bundle.json", "provider-trust.json", "providers"}) {
		t.Fatalf("root inventory=%v", sortedChildren(children["."]))
	}
	if !reflect.DeepEqual(sortedChildren(children["providers/deepseek"]), []string{"dsh-adapter-descriptor.json", "topology.json"}) {
		t.Fatalf("deepseek inventory=%v", sortedChildren(children["providers/deepseek"]))
	}
	for _, forbidden := range []string{"provider-lifecycle-operation.json", "controller-owner-ed25519.json", "providers/deepseek/subscription.json"} {
		if _, ok := EntryFor(forbidden); ok {
			t.Fatalf("forbidden standing authorization catalogued: %s", forbidden)
		}
	}

	policy, ok := ResolveSource("provider-bundle.json", "policy", testRelease)
	if !ok || len(policy) != 1 || policy[0] != (Output{TargetTemplate: InactiveProviderRoot + "/provider-bundle.json", Mode: "0440", Owner: "root", Group: "_openduck"}) {
		t.Fatalf("provider policy resolution=%+v ok=%v", policy, ok)
	}
	if _, ok := ResolveSource("provider-bundle.json", "provider_plugin", testRelease); ok {
		t.Fatal("wrong provider artifact type resolved")
	}
}

func TestCanonicalProviderTopologyIsInactiveAndExactlyBound(t *testing.T) {
	for _, provider := range []string{"codex", "claude", "qwen", "kimi", "deepseek"} {
		entry, found := EntryFor("providers/" + provider + "/topology.json")
		if !found || entry.Type != "provider_topology" {
			t.Fatalf("missing topology entry for %s", provider)
		}
		raw, err := CanonicalProviderTopology(entry)
		if err != nil {
			t.Fatal(err)
		}
		topology, err := DecodeProviderTopology(raw)
		if err != nil || topology.Provider != provider || topology.ProfileID != entry.ProfileID || topology.ProfileRevision != entry.ProfileRevision || topology.ActivationState != "inactive" || topology.Provisioned || topology.ExpectedDaemonLeaf != "openduck-provider-"+provider || topology.ExpectedJobLabel != "com.openduck.provider."+provider {
			t.Fatalf("invalid canonical topology for %s: %+v err=%v", provider, topology, err)
		}
		expectedHost := provider
		if provider == "kimi" {
			expectedHost = "kimi-code"
		}
		if provider == "qwen" {
			expectedHost = "node"
		}
		if provider == "deepseek" {
			expectedHost = ""
		}
		if topology.ExpectedHostExecutableLeaf != expectedHost {
			t.Fatalf("wrong host executable for %s: %q", provider, topology.ExpectedHostExecutableLeaf)
		}
		tampered := topology
		tampered.ActivationState = "active"
		if _, err = json.Marshal(tampered); err != nil {
			t.Fatal(err)
		}
		if tampered.Validate() == nil {
			t.Fatal("active topology accepted")
		}
	}
}

func TestDisabledProviderDaemonsAreExactGroupMembersAndDeepSeekRemainsAPIOnly(t *testing.T) {
	for _, tc := range []struct {
		group, path, provider, profile string
	}{
		{"provider-codex", "bin/openduck-provider-codex", "codex", "codex.chatgpt.app-server"},
		{"provider-claude", "bin/openduck-provider-claude", "claude", "claude.code.cli"},
		{"provider-qwen", "bin/openduck-provider-qwen", "qwen", "qwen.general.headless"},
		{"provider-kimi", "bin/openduck-provider-kimi", "kimi", "kimi.code.acp"},
		{"provider-deepseek", "bin/openduck-provider-deepseek", "deepseek", "deepseek.api"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			entry, found := EntryFor(tc.path)
			if !found || entry.Type != "provider_daemon" || !entry.Executable || entry.ActivationGroup != tc.group || entry.Provider != tc.provider || entry.ProfileID != tc.profile || entry.MaxBytes != ProviderDaemonMaxBytes {
				t.Fatalf("closed disabled daemon entry drift: %+v found=%t", entry, found)
			}
			group := catalogArtifacts(t, func(v Entry) bool {
				return v.Mandatory || v.ActivationGroup == "provider-policy" || v.ActivationGroup == tc.group
			})
			sort.Slice(group, func(i, j int) bool { return group[i].Path < group[j].Path })
			if err := Validate(group, testPlatform, testArch, testVersion); err != nil {
				t.Fatalf("complete daemon group rejected: %v", err)
			}
			withoutDaemon := make([]Artifact, 0, len(group)-1)
			for _, artifact := range group {
				if artifact.Path != tc.path {
					withoutDaemon = append(withoutDaemon, artifact)
				}
			}
			if err := Validate(withoutDaemon, testPlatform, testArch, testVersion); err == nil {
				t.Fatal("descriptor group without its disabled daemon was accepted")
			}
		})
	}
	for _, forbidden := range []string{"bin/openduck-provider-deepseek-subscription", "providers/deepseek/subscription.json"} {
		if _, found := EntryFor(forbidden); found {
			t.Fatalf("DeepSeek subscription path was catalogued: %s", forbidden)
		}
	}
}

func catalogArtifacts(t *testing.T, include func(Entry) bool) []Artifact {
	t.Helper()
	values := make([]Artifact, 0)
	for _, entry := range Entries() {
		if include(entry) {
			values = append(values, Artifact{Type: entry.Type, Path: entry.Path, Platform: testPlatform, Arch: testArch, Version: testVersion, ActivationGroup: entry.ActivationGroup, Required: entry.Required})
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Path < values[j].Path })
	return values
}

func optionalGroups(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, entry := range Entries() {
		if !entry.Mandatory {
			seen[entry.ActivationGroup] = true
		}
	}
	groups := make([]string, 0, len(seen))
	for group := range seen {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	return groups
}

func sortedChildren(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
