package synthetic

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
)

// FlatReadAdapter translates the bridge's authenticated {route,data} wire
// envelope into the Command Center's exact flat read-model schema. It is
// intentionally transport-only; authentication and validation remain in the
// underlying bridge handler.
func FlatReadAdapter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/v1/read/") {
			next.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			copyResponse(w, rec)
			return
		}
		var envelope struct {
			Route string          `json:"route"`
			Data  json.RawMessage `json:"data"`
		}
		if json.Unmarshal(rec.Body.Bytes(), &envelope) != nil || envelope.Route == "" || len(envelope.Data) == 0 {
			copyResponse(w, rec)
			return
		}
		// The bridge has already verified the attestation. The Command Center
		// schema is a deliberately narrower view and does not render proof data.
		var flat map[string]json.RawMessage
		if json.Unmarshal(envelope.Data, &flat) == nil {
			delete(flat, "projection")
			if data, err := json.Marshal(flat); err == nil {
				envelope.Data = data
			}
		}
		copyHeaders(w.Header(), rec.Header())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.TrimSpace(envelope.Data))
	})
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		dst[key] = append([]string(nil), values...)
	}
}
func copyResponse(w http.ResponseWriter, rec *httptest.ResponseRecorder) {
	copyHeaders(w.Header(), rec.Header())
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}
