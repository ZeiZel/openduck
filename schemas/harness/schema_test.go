package harness

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSchemasAreStrictJSONSchemaDocuments(t *testing.T) {
	for _, name := range []string{"contracts.v1.json", "runtime-interactions.v1.json", "worker-result.v1.json"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if doc["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
			t.Fatalf("%s has no 2020-12 schema", name)
		}
		if name == "worker-result.v1.json" {
			if doc["additionalProperties"] != false {
				t.Fatalf("%s permits unknown properties", name)
			}
			continue
		}
		defs, ok := doc["$defs"].(map[string]any)
		if !ok || len(defs) == 0 {
			t.Fatalf("%s has no contracts", name)
		}
		for contract, raw := range defs {
			m, ok := raw.(map[string]any)
			if !ok || contract == "d" || contract == "digest" {
				continue
			}
			if m["additionalProperties"] != false {
				t.Fatalf("%s/%s permits unknown properties", name, contract)
			}
		}
	}
}
