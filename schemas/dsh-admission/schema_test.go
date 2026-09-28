package admission_schema

import (
	"encoding/json"
	"os"
	"testing"
)

func TestContractsSchemaIsStrictAndVersioned(t *testing.T) {
	b, err := os.ReadFile("contracts.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Schema      string                     `json:"$schema"`
		Definitions map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(b, &document); err != nil {
		t.Fatal(err)
	}
	if document.Schema != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("unexpected schema: %q", document.Schema)
	}
	for _, name := range []string{"sourceEvent", "snapshot", "highWater", "privacyDecision", "safeCapsule", "cloudPrompt", "localPD", "cloudConsumption", "cloudReceipt", "egressReservation", "dshAttestation", "uiSession"} {
		var definition struct {
			AdditionalProperties bool                       `json:"additionalProperties"`
			Required             []string                   `json:"required"`
			Properties           map[string]json.RawMessage `json:"properties"`
		}
		raw, ok := document.Definitions[name]
		if !ok {
			t.Fatalf("missing definition %s", name)
		}
		if err := json.Unmarshal(raw, &definition); err != nil {
			t.Fatal(err)
		}
		if definition.AdditionalProperties {
			t.Fatalf("%s permits unknown fields", name)
		}
		if len(definition.Required) == 0 || len(definition.Properties) == 0 {
			t.Fatalf("%s is not strict/complete", name)
		}
	}
}
