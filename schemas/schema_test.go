package schemas

import (
	"encoding/json"
	"os"
	"testing"
)

func TestLocalSchemasParseAndCandidateSourceIsInline(t *testing.T) {
	for _, name := range []string{"inbound-event.v1.json", "candidate.v1.json", "safe-envelope.v1.json"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var v map[string]any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	b, _ := os.ReadFile("candidate.v1.json")
	var v map[string]any
	_ = json.Unmarshal(b, &v)
	props := v["properties"].(map[string]any)
	if _, ok := props["source"].(map[string]any)["$ref"]; ok {
		t.Fatal("candidate source must not depend on unresolved external $defs")
	}
}
