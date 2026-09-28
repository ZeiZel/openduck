package dshbridge_schema

import (
	"encoding/json"
	"os"
	"testing"
)

func TestContractsAreStrictAndVersioned(t *testing.T) {
	b, err := os.ReadFile("contracts.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema      string                     `json:"$schema"`
		Definitions map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema=%q", doc.Schema)
	}
	for _, name := range []string{"safeProjection", "uiChannelSession", "composerCloud", "composerLocalPD", "inboxEnvelope", "calendarEnvelope", "workgraphEnvelope", "tasksEnvelope", "timeEnvelope", "reviewsEnvelope", "memoryEnvelope", "healthEnvelope", "inbox", "calendar", "workgraph", "tasks", "time", "reviews", "memory", "health"} {
		var def struct {
			AdditionalProperties bool                       `json:"additionalProperties"`
			Required             []string                   `json:"required"`
			Properties           map[string]json.RawMessage `json:"properties"`
			AllOf                []json.RawMessage          `json:"allOf"`
		}
		if err := json.Unmarshal(doc.Definitions[name], &def); err != nil {
			t.Fatal(err)
		}
		if def.AdditionalProperties || (len(def.Required) == 0 && len(def.AllOf) == 0) || (len(def.Properties) == 0 && len(def.AllOf) == 0) {
			t.Fatalf("definition %s is not strict", name)
		}
	}
}
