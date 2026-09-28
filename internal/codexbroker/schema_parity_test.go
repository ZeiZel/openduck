package codexbroker

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// schemaAccept is a deliberately narrow executable Draft-2020 evaluator for
// the keywords used by owner-runtime-broker.v1.json. It evaluates the loaded
// document, never a duplicated protocol oracle.
func schemaAccept(root map[string]any, v any) bool { return evalSchema(root, root, v) }
func evalSchema(root, s map[string]any, v any) bool {
	if ref, ok := s["$ref"].(string); ok {
		if !strings.HasPrefix(ref, "#/$defs/") {
			return false
		}
		d, _ := root["$defs"].(map[string]any)
		x, _ := d[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
		return evalSchema(root, x, v)
	}
	if a, ok := s["allOf"].([]any); ok {
		for _, x := range a {
			if !evalSchema(root, x.(map[string]any), v) {
				return false
			}
		}
	}
	if a, ok := s["anyOf"].([]any); ok {
		good := false
		for _, x := range a {
			if evalSchema(root, x.(map[string]any), v) {
				good = true
			}
		}
		if !good {
			return false
		}
	}
	if a, ok := s["oneOf"].([]any); ok {
		n := 0
		for _, x := range a {
			if evalSchema(root, x.(map[string]any), v) {
				n++
			}
		}
		if n != 1 {
			return false
		}
	}
	if i, ok := s["if"].(map[string]any); ok {
		if evalSchema(root, i, v) {
			if t, ok := s["then"].(map[string]any); ok && !evalSchema(root, t, v) {
				return false
			}
		}
	}
	if n, ok := s["not"].(map[string]any); ok && evalSchema(root, n, v) {
		return false
	}
	if c, ok := s["const"]; ok && !sameJSON(c, v) {
		return false
	}
	if e, ok := s["enum"].([]any); ok {
		good := false
		for _, x := range e {
			if sameJSON(x, v) {
				good = true
			}
		}
		if !good {
			return false
		}
	}
	if typ, ok := s["type"].(string); ok && !jsonType(typ, v) {
		return false
	}
	if req, ok := s["required"].([]any); ok {
		m, _ := v.(map[string]any)
		for _, k := range req {
			if _, yes := m[k.(string)]; !yes {
				return false
			}
		}
	}
	if m, ok := v.(map[string]any); ok {
		if n, ok := s["maxProperties"].(float64); ok && float64(len(m)) > n {
			return false
		}
		if ap, ok := s["additionalProperties"].(bool); ok && !ap {
			if p, _ := s["properties"].(map[string]any); p != nil {
				for k := range m {
					if _, yes := p[k]; !yes {
						return false
					}
				}
			}
		}
		if p, ok := s["properties"].(map[string]any); ok {
			for k, x := range p {
				if val, yes := m[k]; yes && !evalSchema(root, x.(map[string]any), val) {
					return false
				}
			}
		}
	}
	if a, ok := v.([]any); ok {
		if n, ok := s["maxItems"].(float64); ok && float64(len(a)) > n {
			return false
		}
	}
	if str, ok := v.(string); ok {
		n := float64(utf8.RuneCountInString(str))
		if x, ok := s["x-maxBytes"].(float64); ok && float64(len([]byte(str))) > x {
			return false
		}
		if x, ok := s["minLength"].(float64); ok && n < x {
			return false
		}
		if x, ok := s["maxLength"].(float64); ok && n > x {
			return false
		}
		if p, ok := s["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(str) {
			return false
		}
		if f, ok := s["format"].(string); ok && f == "date-time" {
			if _, err := time.Parse(time.RFC3339, str); err != nil {
				return false
			}
		}
	}
	if n, ok := v.(float64); ok {
		if x, yes := s["minimum"].(float64); yes && n < x {
			return false
		}
		if x, yes := s["maximum"].(float64); yes && n > x {
			return false
		}
	}
	return true
}
func jsonType(t string, v any) bool {
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "integer":
		n, ok := v.(float64)
		return ok && n == float64(int64(n))
	case "boolean":
		_, ok := v.(bool)
		return ok
	}
	return false
}
func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func TestLoadedSchemaParityAndMutation(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/codex-broker/owner-runtime-broker.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if json.Unmarshal(raw, &root) != nil {
		t.Fatal("schema JSON")
	}
	empty := map[string]any{}
	frame := func(d, k string, ok bool, p any) wireFrame {
		b, _ := json.Marshal(p)
		return wireFrame{SchemaVersion: ProtocolV1, Direction: d, Sequence: 1, RequestID: "r_1", Kind: k, OK: ok, Payload: b}
	}
	fixtures := []wireFrame{frame("request", "attestation", false, empty), frame("request", "inventory", false, empty), frame("request", "close", false, empty), frame("request", "login.start", false, LoginStart{AccountType: "chatgpt"}), frame("request", "login.completed", false, map[string]any{"login_id": "l"}), frame("request", "turn", false, Turn{SessionID: "s", TurnID: "t", Prompt: "p", Classification: "L0", MaxOutputBytes: 1}), frame("request", "turn", false, Turn{SessionID: "сессия", TurnID: "ход", Prompt: "привет мир", Classification: "L0", MaxOutputBytes: 1}), frame("request", "cancel", false, Cancel{SessionID: "s", TurnID: "t"}), frame("response", "attestation", true, fixtureAttestation()), frame("response", "inventory", true, fixtureInventory()), frame("response", "login.start", true, LoginStarted{LoginID: "l", AuthorizationURL: "https://x"}), frame("response", "login.start", true, LoginStarted{LoginID: "l", AuthorizationURL: "https://пример.test/путь"}), frame("response", "login.completed", true, LoginCompleted{LoginID: "l", Success: true}), frame("response", "turn", true, TurnResult{SessionID: "s", TurnID: "t", State: "completed", Answer: "a"}), frame("response", "cancel", true, empty), frame("response", "close", true, empty)}
	fixtures = append(fixtures,
		frame("response", "login.start", true, LoginStarted{LoginID: "l", AuthorizationURL: "https://" + strings.Repeat("é", 1020)}),
		frame("response", "login.start", true, LoginStarted{LoginID: "l", UserCode: strings.Repeat("界", 42) + "aa"}),
		frame("request", "turn", false, Turn{SessionID: "s", TurnID: "t", Prompt: strings.Repeat("界", 21845) + "a", Classification: "L0", MaxOutputBytes: 1}),
	)
	for _, f := range fixtures {
		raw, _ := json.Marshal(f)
		var v map[string]any
		json.Unmarshal(raw, &v)
		schema := schemaAccept(root, v)
		runtime := validateWirePayload(f) == nil
		if schema != runtime {
			t.Fatalf("parity mismatch kind=%s dir=%s ok=%v schema=%v runtime=%v", f.Kind, f.Direction, f.OK, schema, runtime)
		}
	}
	negatives := []wireFrame{
		// Every request operation has a typed payload (or the exact empty
		// object); these deliberately exercise each of the seven operation
		// branches rather than relying on one representative failure.
		frame("request", "attestation", false, map[string]any{"extra": true}),
		frame("request", "inventory", false, map[string]any{"extra": true}),
		frame("request", "close", false, map[string]any{"covert": true}),
		frame("request", "login.start", false, LoginStart{AccountType: "other"}),
		frame("request", "login.start", false, map[string]any{"account_type": "chatgpt", "extra": true}),
		frame("response", "login.completed", true, LoginCompleted{LoginID: "l", Success: false}),
		frame("response", "attestation", true, map[string]any{"extra": true}),
		frame("response", "inventory", true, map[string]any{"extra": true}),
		frame("response", "inventory", true, map[string]any{"schema_version": ProtocolV1, "account_state": "chatgpt", "runtime_version": "v1", "runtime_digest": Digest("runtime"), "model_only": true, "mcp": []any{}, "plugins": []any{}, "hooks": []any{}}),
		frame("response", "login.start", true, map[string]any{"login_id": "l"}),
		frame("response", "login.start", true, map[string]any{"login_id": "l", "authorization_url": nil, "user_code": "code"}),
		frame("response", "login.start", true, map[string]any{"login_id": "l", "authorization_url": "", "user_code": "code"}),
		frame("response", "login.start", true, map[string]any{"login_id": "l", "authorization_url": "https://"}),
		frame("response", "login.start", true, map[string]any{"login_id": "l", "authorization_url": "https://x\r\nforged"}),
		frame("response", "login.completed", true, map[string]any{"login_id": "l", "error_code": "protocol"}),
		frame("response", "turn", true, TurnResult{SessionID: "s", TurnID: "t", State: "completed", ErrorCode: "protocol"}),
		frame("response", "turn", true, TurnResult{SessionID: "s", TurnID: "t", State: "failed", Answer: "wrong"}),
		frame("response", "cancel", true, map[string]any{"extra": true}),
		frame("response", "close", true, map[string]any{"extra": true}),
	}
	largeUnicodeAnswer := strings.Repeat("界", MaxAnswerBytes/len([]byte("界"))+1)
	negatives = append(negatives, frame("response", "turn", true, TurnResult{SessionID: "s", TurnID: "t", State: "completed", Answer: largeUnicodeAnswer}))
	negatives = append(negatives,
		frame("response", "login.start", true, LoginStarted{LoginID: "l", AuthorizationURL: "https://" + strings.Repeat("é", 1021)}),
		frame("response", "login.start", true, LoginStarted{LoginID: "l", UserCode: strings.Repeat("界", 43)}),
		frame("request", "turn", false, Turn{SessionID: "s", TurnID: "t", Prompt: strings.Repeat("界", 21846), Classification: "L0", MaxOutputBytes: 1}),
	)
	// Error responses are payload-free and every operation must reject an
	// error response carrying a covert typed payload. This covers the error
	// branch independently from the success branch above.
	for _, kind := range []string{"attestation", "inventory", "login.start", "login.completed", "turn", "cancel", "close"} {
		f := frame("response", kind, false, map[string]any{"covert": true})
		f.ErrorCode = "protocol"
		negatives = append(negatives, f)
	}
	badAtt := frame("response", "attestation", true, fixtureAttestation())
	badRaw, _ := json.Marshal(map[string]any{"schema_version": ProtocolV1, "runtime_id": "runtime_1", "peer_id": "peer_1", "runtime_binary_digest": Digest("runtime"), "policy_digest": Digest("policy"), "issued_at": "not-a-date", "peer_uid": 1000, "peer_gid": 1000, "epoch": 1, "broker_socket_digest": Digest("socket"), "broker_release_digest": Digest("release"), "expected_egress_uid": 1002, "expected_egress_gid": 1003, "expected_egress_release_digest": Digest("egress-release"), "expected_egress_socket_digest": Digest("egress-socket"), "signature": Digest("signature")})
	badAtt.Payload = badRaw
	negatives = append(negatives, badAtt)
	for _, f := range negatives {
		raw, _ := json.Marshal(f)
		var v map[string]any
		json.Unmarshal(raw, &v)
		if schemaAccept(root, v) != (validateWirePayload(f) == nil) {
			t.Fatalf("negative parity mismatch kind=%s", f.Kind)
		}
	}
	mut := map[string]any{}
	b, _ := json.Marshal(root)
	json.Unmarshal(b, &mut)
	props := mut["properties"].(map[string]any)
	props["kind"].(map[string]any)["enum"] = []any{"close"}
	f := fixtures[0]
	raw, _ = json.Marshal(f)
	var v map[string]any
	json.Unmarshal(raw, &v)
	if schemaAccept(mut, v) {
		t.Fatal("schema mutation was not observed")
	}
	mut2 := map[string]any{}
	b, _ = json.Marshal(root)
	json.Unmarshal(b, &mut2)
	defs := mut2["$defs"].(map[string]any)
	turnDef := defs["turn"].(map[string]any)
	turnDef["required"] = []any{"session_id", "prompt", "classification", "max_output_bytes"}
	f2 := frame("request", "turn", false, map[string]any{"session_id": "s", "prompt": "p", "classification": "L0", "max_output_bytes": 1})
	raw, _ = json.Marshal(f2)
	json.Unmarshal(raw, &v)
	if !schemaAccept(mut2, v) {
		t.Fatal("required-key schema mutation was not observed")
	}
	if validateWirePayload(f2) == nil {
		t.Fatal("runtime accepted missing turn_id")
	}
}
