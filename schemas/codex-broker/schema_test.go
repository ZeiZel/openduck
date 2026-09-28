package codexbroker_schema

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOwnerRuntimeSchemaLoads(t *testing.T) {
	raw, err := os.ReadFile("owner-runtime-broker.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatal("unexpected schema dialect")
	}
}
