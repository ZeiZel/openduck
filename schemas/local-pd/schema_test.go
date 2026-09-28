package localpd_schema

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"openduck/internal/localpd"
)

const fixtureDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type schemaDoc struct {
	Schema    string                    `json:"$schema"`
	Authority string                    `json:"x-openduck-authority"`
	Defs      map[string]map[string]any `json:"$defs"`
}

func loadSchema(t *testing.T) schemaDoc {
	t.Helper()
	b, err := os.ReadFile("contracts.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc schemaDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func contractTypes() map[string]reflect.Type {
	return map[string]reflect.Type{
		"gate": reflect.TypeOf(localpd.IngressGateState{}), "binding": reflect.TypeOf(localpd.PDSessionBinding{}), "view": reflect.TypeOf(localpd.LocalPDViewBinding{}), "runtime": reflect.TypeOf(localpd.QwenRuntimeAttestation{}), "config": reflect.TypeOf(localpd.QwenConfigAttestation{}), "provenance": reflect.TypeOf(localpd.NativeInputProvenance{}), "decision": reflect.TypeOf(localpd.DeclassificationDecision{}), "erasure": reflect.TypeOf(localpd.ErasureReceipt{}), "postscan": reflect.TypeOf(localpd.PostscanAttestation{}), "reconciliation": reflect.TypeOf(localpd.ReconciliationBinding{}),
	}
}

func TestContractsSchemaHasExactGoFieldParity(t *testing.T) {
	doc := loadSchema(t)
	if doc.Schema != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("unexpected schema: %q", doc.Schema)
	}
	if doc.Authority != "go-validate-required" {
		t.Fatalf("schema does not declare structural-only authority boundary")
	}
	for name, typ := range contractTypes() {
		def, ok := doc.Defs[name]
		if !ok {
			t.Fatalf("missing definition %s", name)
		}
		if def["additionalProperties"] != false {
			t.Fatalf("%s permits additional properties", name)
		}
		if def["x-openduck-authority"] != "go-validate-required" {
			t.Fatalf("%s lacks authority boundary", name)
		}
		props := def["properties"].(map[string]any)
		required := stringSet(def["required"].([]any))
		fields := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			fields[strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]] = true
		}
		if !reflect.DeepEqual(sortedKeys(fields), sortedKeysMap(props)) {
			t.Fatalf("%s properties differ: go=%v schema=%v", name, sortedKeys(fields), sortedKeysMap(props))
		}
		if !reflect.DeepEqual(sortedKeys(fields), sortedKeys(required)) {
			t.Fatalf("%s required differs: go=%v required=%v", name, sortedKeys(fields), sortedKeys(required))
		}
	}
}

func stringSet(values []any) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		out[v.(string)] = true
	}
	return out
}
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func sortedKeysMap(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fixtures() map[string]any {
	a := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	b := a.Add(30 * time.Minute)
	return map[string]any{
		"gate":           localpd.IngressGateState{SchemaVersion: localpd.IngressGateStateV1, GateID: "gate-1", State: "local_only", StateVersion: 1, HighWater: 1, SourceCursorDigest: fixtureDigest, PolicyDigest: fixtureDigest, ControllerAttestationDigest: fixtureDigest, Nonce: "n", IssuedAt: a, ExpiresAt: b, Digest: fixtureDigest, ConversationScope: "scope", SourceSequence: 1, SourceVersion: 1, IngestOrdinal: 1, ScannedThrough: 1, PriorComplete: true, ChainHeadDigest: fixtureDigest, GapRanges: []string{}, PendingParts: []string{}, Mode: "pd", PolicyVersion: "p1", PolicyUpdatedAt: a.Add(-time.Minute), ControllerSignature: fixtureDigest},
		"binding":        localpd.PDSessionBinding{SchemaVersion: localpd.PDSessionBindingV1, SessionID: "s", BindingVersion: 1, HighWater: 1, IngressGateDigest: fixtureDigest, LocalPDViewDigest: fixtureDigest, QwenRuntimeDigest: fixtureDigest, QwenConfigDigest: fixtureDigest, Nonce: "n", IssuedAt: a, ExpiresAt: b, ControllerSignature: fixtureDigest, Digest: fixtureDigest, ConversationScope: "scope", SourceSequence: 1, SourceVersion: 1, ClassHighWater: "L2", ClassHighWaterVersion: 1, Sticky: true},
		"view":           localpd.LocalPDViewBinding{SchemaVersion: localpd.LocalPDViewBindingV1, ViewID: "v", BindingVersion: 1, HighWater: 1, SourceVersion: 1, SourceDigest: fixtureDigest, RedactionDigest: fixtureDigest, AllowedFields: []string{"summary"}, IssuedAt: a, ExpiresAt: b, Nonce: "n", Digest: fixtureDigest, ControllerSignature: fixtureDigest},
		"runtime":        localpd.QwenRuntimeAttestation{SchemaVersion: localpd.QwenRuntimeAttestationV1, RuntimeID: "r", ProcessDigest: fixtureDigest, BinaryDigest: fixtureDigest, Model: "qwen3:8b", EndpointDigest: fixtureDigest, NetworkPolicy: "none", ToolsPolicy: "none", AttestedAt: a, ExpiresAt: b, Nonce: "n", Digest: fixtureDigest, ControllerSignature: fixtureDigest},
		"config":         localpd.QwenConfigAttestation{SchemaVersion: localpd.QwenConfigAttestationV1, ConfigID: "c", ConfigDigest: fixtureDigest, Model: "qwen3:8b", NumCtx: 40960, ContextTokens: 32768, Thinking: "medium", NetworkPolicy: "none", ToolsPolicy: "none", ConfigVersion: 1, IssuedAt: a, ExpiresAt: b, Nonce: "n", Digest: fixtureDigest, ControllerSignature: fixtureDigest},
		"provenance":     localpd.NativeInputProvenance{SchemaVersion: localpd.NativeInputProvenanceV1, ProvenanceID: "p", SourceKind: "telegram", SourceAccountDigest: fixtureDigest, ContainerDigest: fixtureDigest, EventDigest: fixtureDigest, CaptureRevision: 1, HighWater: 1, SourceVersion: 1, ObservedAt: a, ExpiresAt: b, ControllerAttestationDigest: fixtureDigest, Digest: fixtureDigest, ControllerSignature: fixtureDigest},
		"decision":       localpd.DeclassificationDecision{SchemaVersion: localpd.DeclassificationDecisionV1, DecisionID: "d", SessionBindingDigest: fixtureDigest, FromClass: "L2", TargetClass: "L0", Decision: "allow", AllowedFields: []string{"summary"}, RationaleDigest: fixtureDigest, PolicyDigest: fixtureDigest, IssuedAt: a, ExpiresAt: b, Nonce: "n", ControllerSignature: fixtureDigest, Digest: fixtureDigest, InputDigest: fixtureDigest, CandidateDigest: fixtureDigest, ReleasedDigest: fixtureDigest, SourceOrigin: "owner_manual_blank_editor", CandidateOrigin: "owner_manual_blank_editor", PostscanAttestationDigest: fixtureDigest, DestinationRoute: "local", ProviderDigest: fixtureDigest, AuthContextDigest: fixtureDigest, RetentionPolicyDigest: fixtureDigest, PurposeDigest: fixtureDigest, ApproverID: "owner", RecentAuthProofDigest: fixtureDigest, RecentAuthAt: a.Add(time.Minute), RequestedAt: a, ApprovedAt: a.Add(2 * time.Minute), LifecycleState: "approved", MaxUses: 1, UseNonce: "use-1", CASBindingDigest: fixtureDigest},
		"erasure":        localpd.ErasureReceipt{SchemaVersion: localpd.ErasureReceiptV1, ReceiptID: "e", SessionBindingDigest: fixtureDigest, TargetDigest: fixtureDigest, ErasureScope: "payload", ErasureVersion: 1, HighWater: 1, ObservedTargetVersion: 1, ObservedTargetHighWater: 1, DeletedThroughHighWater: 1, DeletionStatus: "deleted", VerificationMethod: "authoritative_store_absence", CoverageComplete: true, ErasedAt: a, ExpiresAt: b, DeletionEvidenceDigest: fixtureDigest, CoverageDigest: fixtureDigest, VerificationDigest: fixtureDigest, ControllerSignature: fixtureDigest, Digest: fixtureDigest},
		"postscan":       localpd.PostscanAttestation{SchemaVersion: localpd.PostscanAttestationV1, AttestationID: "ps", ReleasedDigest: fixtureDigest, PolicyDigest: fixtureDigest, ScannerDigest: fixtureDigest, PolicyVersion: 1, ScannerVersion: 1, MaxClass: "L0", MatchedRuleIDs: []string{}, Decision: "allow", IssuedAt: a, ExpiresAt: b, Nonce: "n", ControllerSignature: fixtureDigest, Digest: fixtureDigest},
		"reconciliation": localpd.ReconciliationBinding{SchemaVersion: localpd.ReconciliationBindingV1, ReconciliationID: "rec", GateID: "gate", PriorQuarantineDigest: fixtureDigest, NextGateDigest: fixtureDigest, CompleteCoverageDigest: fixtureDigest, GapClosureDigest: fixtureDigest, HighWater: 1, PolicyDigest: fixtureDigest, PolicyVersion: "p1", TargetMode: "pd", CompleteCoverage: true, GapsClosed: true, IssuedAt: a, ExpiresAt: b, Nonce: "n", ControllerSignature: fixtureDigest, Digest: fixtureDigest},
	}
}

func TestSchemaCompilerAcceptsPositiveFixtures(t *testing.T) {
	doc := loadSchema(t)
	for name, fixture := range fixtures() {
		b, err := json.Marshal(fixture)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(b, &value); err != nil {
			t.Fatal(err)
		}
		if err := validateSchema(value, doc.Defs[name], doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestSchemaCompilerRejectsMissingUnknownNullTimeDecisionAndOrigin(t *testing.T) {
	doc := loadSchema(t)
	b, _ := json.Marshal(fixtures()["decision"])
	var base map[string]any
	_ = json.Unmarshal(b, &base)
	cases := []func(map[string]any){
		func(v map[string]any) { delete(v, "approved_at") },
		func(v map[string]any) { v["unknown"] = true },
		func(v map[string]any) { v["approved_at"] = nil },
		func(v map[string]any) { v["approved_at"] = "2026-08-19 10:02:00" },
		func(v map[string]any) { v["decision"] = "deny" },
		func(v map[string]any) { v["source_origin"] = "qwen" },
	}
	for i, mutate := range cases {
		v := cloneMap(base)
		mutate(v)
		if err := validateSchema(v, doc.Defs["decision"], doc); err == nil {
			t.Fatalf("negative %d accepted", i)
		}
	}
}

func TestSchemaEncodesFeasibleGateModeRelations(t *testing.T) {
	doc := loadSchema(t)
	b, _ := json.Marshal(fixtures()["gate"])
	var gate map[string]any
	_ = json.Unmarshal(b, &gate)
	gate["mode"], gate["state"] = "pd", "open"
	if err := validateSchema(gate, doc.Defs["gate"], doc); err == nil {
		t.Fatal("schema accepted encodable gate mode/state mismatch")
	}
}

func TestGoValidationRejectsTimeOrderAndContextRelations(t *testing.T) {
	fx := fixtures()
	d := fx["decision"].(localpd.DeclassificationDecision)
	d.RequestedAt = d.IssuedAt.Add(-time.Second)
	if err := d.Validate(); err == nil {
		t.Fatal("accepted invalid chronology")
	}
	g := fx["gate"].(localpd.IngressGateState)
	g.SourceSequence = g.HighWater + 1
	if err := g.Validate(); err == nil {
		t.Fatal("accepted invalid gate high-water relation")
	}
	s := fx["binding"].(localpd.PDSessionBinding)
	s.ClassHighWaterVersion = 0
	if err := s.Validate(); err == nil {
		t.Fatal("accepted invalid session class context")
	}
}

func TestSchemaIsStructuralOnlyForCrossFieldInvariants(t *testing.T) {
	doc := loadSchema(t)
	fx := fixtures()
	tests := []struct {
		name, def  string
		value      any
		goValidate func() error
	}{
		{"gate-order", "gate", func() any { x := fx["gate"].(localpd.IngressGateState); x.SourceSequence = x.HighWater + 1; return x }(), func() error {
			x := fx["gate"].(localpd.IngressGateState)
			x.SourceSequence = x.HighWater + 1
			return x.Validate()
		}},
		{"session-order", "binding", func() any {
			x := fx["binding"].(localpd.PDSessionBinding)
			x.SourceSequence = x.HighWater + 1
			return x
		}(), func() error {
			x := fx["binding"].(localpd.PDSessionBinding)
			x.SourceSequence = x.HighWater + 1
			return x.Validate()
		}},
		{"view-window", "view", func() any {
			x := fx["view"].(localpd.LocalPDViewBinding)
			x.ExpiresAt = x.IssuedAt.Add(-time.Second)
			return x
		}(), func() error {
			x := fx["view"].(localpd.LocalPDViewBinding)
			x.ExpiresAt = x.IssuedAt.Add(-time.Second)
			return x.Validate()
		}},
		{"runtime-window", "runtime", func() any {
			x := fx["runtime"].(localpd.QwenRuntimeAttestation)
			x.ExpiresAt = x.AttestedAt.Add(-time.Second)
			return x
		}(), func() error {
			x := fx["runtime"].(localpd.QwenRuntimeAttestation)
			x.ExpiresAt = x.AttestedAt.Add(-time.Second)
			return x.Validate()
		}},
		{"config-budget", "config", func() any {
			x := fx["config"].(localpd.QwenConfigAttestation)
			x.ContextTokens = x.NumCtx + 1
			return x
		}(), func() error {
			x := fx["config"].(localpd.QwenConfigAttestation)
			x.ContextTokens = x.NumCtx + 1
			return x.Validate()
		}},
		{"provenance-window", "provenance", func() any {
			x := fx["provenance"].(localpd.NativeInputProvenance)
			x.ExpiresAt = x.ObservedAt.Add(-time.Second)
			return x
		}(), func() error {
			x := fx["provenance"].(localpd.NativeInputProvenance)
			x.ExpiresAt = x.ObservedAt.Add(-time.Second)
			return x.Validate()
		}},
		{"decision-time", "decision", func() any {
			x := fx["decision"].(localpd.DeclassificationDecision)
			x.RequestedAt = x.IssuedAt.Add(-time.Second)
			return x
		}(), func() error {
			x := fx["decision"].(localpd.DeclassificationDecision)
			x.RequestedAt = x.IssuedAt.Add(-time.Second)
			return x.Validate()
		}},
		{"erasure-coverage", "erasure", func() any { x := fx["erasure"].(localpd.ErasureReceipt); x.DeletedThroughHighWater++; return x }(), func() error {
			x := fx["erasure"].(localpd.ErasureReceipt)
			x.DeletedThroughHighWater++
			return x.Validate()
		}},
		{"postscan-window", "postscan", func() any {
			x := fx["postscan"].(localpd.PostscanAttestation)
			x.ExpiresAt = x.IssuedAt.Add(-time.Second)
			return x
		}(), func() error {
			x := fx["postscan"].(localpd.PostscanAttestation)
			x.ExpiresAt = x.IssuedAt.Add(-time.Second)
			return x.Validate()
		}},
		{"reconciliation-window", "reconciliation", func() any {
			x := fx["reconciliation"].(localpd.ReconciliationBinding)
			x.ExpiresAt = x.IssuedAt.Add(-time.Second)
			return x
		}(), func() error {
			x := fx["reconciliation"].(localpd.ReconciliationBinding)
			x.ExpiresAt = x.IssuedAt.Add(-time.Second)
			return x.Validate()
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(tc.value)
			var value any
			_ = json.Unmarshal(b, &value)
			if err := validateSchema(value, doc.Defs[tc.def], doc); err != nil {
				t.Fatalf("fixture must be schema-valid: %v", err)
			}
			if tc.goValidate() == nil {
				t.Fatal("fixture unexpectedly Go-valid")
			}
			if err := validateForAuthority(value, doc.Defs[tc.def], doc, nil); err == nil {
				t.Fatal("schema-only authority accepted")
			}
			if err := validateForAuthority(value, doc.Defs[tc.def], doc, tc.goValidate); err == nil {
				t.Fatal("authority accepted Go-invalid fixture")
			}
		})
	}
}

func validateForAuthority(value any, schema map[string]any, doc schemaDoc, goValidate func() error) error {
	if err := validateSchema(value, schema, doc); err != nil {
		return err
	}
	if schema["x-openduck-authority"] == "go-validate-required" && goValidate == nil {
		return fmt.Errorf("Go Validate required")
	}
	if goValidate == nil {
		return fmt.Errorf("authority validator absent")
	}
	return goValidate()
}

func cloneMap(in map[string]any) map[string]any {
	b, _ := json.Marshal(in)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func validateSchema(value any, schema map[string]any, doc schemaDoc) error {
	if ref, ok := schema["$ref"].(string); ok {
		const prefix = "#/$defs/"
		if !strings.HasPrefix(ref, prefix) {
			return fmt.Errorf("unsupported ref %q", ref)
		}
		return validateSchema(value, doc.Defs[strings.TrimPrefix(ref, prefix)], doc)
	}
	if clauses, ok := schema["allOf"].([]any); ok {
		for _, raw := range clauses {
			clause := raw.(map[string]any)
			if condition, ok := clause["if"].(map[string]any); ok {
				if validateSchema(value, condition, doc) == nil {
					if then, ok := clause["then"].(map[string]any); ok {
						if err := validateSchema(value, then, doc); err != nil {
							return err
						}
					}
				}
			} else if err := validateSchema(value, clause, doc); err != nil {
				return err
			}
		}
	}
	if want, ok := schema["const"]; ok && !reflect.DeepEqual(value, want) {
		return fmt.Errorf("const mismatch")
	}
	if raw, ok := schema["enum"].([]any); ok {
		found := false
		for _, want := range raw {
			if reflect.DeepEqual(value, want) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("enum mismatch")
		}
	}
	typ, _ := schema["type"].(string)
	if typ == "" {
		if _, ok := schema["properties"]; ok {
			typ = "object"
		}
	}
	switch typ {
	case "object":
		obj, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("not object")
		}
		props, _ := schema["properties"].(map[string]any)
		required, _ := schema["required"].([]any)
		for _, raw := range required {
			if _, ok := obj[raw.(string)]; !ok {
				return fmt.Errorf("missing %s", raw)
			}
		}
		for key, raw := range props {
			child, ok := obj[key]
			if !ok {
				continue
			}
			if err := validateSchema(child, raw.(map[string]any), doc); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
		if schema["additionalProperties"] == false {
			for key := range obj {
				if _, ok := props[key]; !ok {
					return fmt.Errorf("unknown %s", key)
				}
			}
		}
	case "array":
		arr, ok := value.([]any)
		if !ok {
			return fmt.Errorf("not array")
		}
		if n, ok := number(schema["minItems"]); ok && len(arr) < n {
			return fmt.Errorf("too few items")
		}
		if n, ok := number(schema["maxItems"]); ok && len(arr) > n {
			return fmt.Errorf("too many items")
		}
		if schema["uniqueItems"] == true {
			seen := map[string]bool{}
			for _, item := range arr {
				b, _ := json.Marshal(item)
				if seen[string(b)] {
					return fmt.Errorf("duplicate item")
				}
				seen[string(b)] = true
			}
		}
		if child, ok := schema["items"].(map[string]any); ok {
			for _, item := range arr {
				if err := validateSchema(item, child, doc); err != nil {
					return err
				}
			}
		}
	case "string":
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("not string")
		}
		if pattern, ok := schema["pattern"].(string); ok {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return err
			}
			if !re.MatchString(s) {
				return fmt.Errorf("pattern mismatch")
			}
		}
		if schema["format"] == "date-time" {
			parsed, err := time.Parse(time.RFC3339, s)
			if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond() != 0 {
				return fmt.Errorf("bad date-time")
			}
		}
	case "integer":
		n, ok := value.(float64)
		if !ok || n != float64(int64(n)) {
			return fmt.Errorf("not integer")
		}
		if min, ok := schema["minimum"].(float64); ok && n < min {
			return fmt.Errorf("below minimum")
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("not boolean")
		}
	case "":
		if value == nil {
			return fmt.Errorf("null")
		}
	default:
		return fmt.Errorf("unsupported type %q", typ)
	}
	return nil
}

func number(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case json.Number:
		i, e := strconv.Atoi(n.String())
		return i, e == nil
	}
	return 0, false
}
