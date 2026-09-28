package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"openduck/internal/core"
)

type Server struct {
	Queue         core.Queue
	Pseudonymizer core.Pseudonymizer
	Mode          string
}

// Purge composes queue and pseudonym mapping deletion; callers must invoke it
// only after the owner-approved retention decision.
func (s *Server) Purge(ctx context.Context, scope string) error {
	if s.Pseudonymizer == nil {
		return errors.New("pseudonymizer unavailable")
	}
	return core.Purge(ctx, s.Queue, s.Pseudonymizer, scope)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/v1/manual/events", s.manual)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if h, ok := s.Queue.(interface{ Health() core.Health }); ok {
		health := h.Health()
		if health.Mode == "" {
			health.Mode = s.Mode
		}
		_ = json.NewEncoder(w).Encode(health)
		return
	}
	json.NewEncoder(w).Encode(core.Health{Status: "ok", Mode: s.Mode, QueueDepth: s.Queue.Depth()})
}
func (s *Server) manual(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var e core.InboundEvent
	if err := dec.Decode(&e); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := e.Validate(); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	authoritative := core.DLP{}.Classify(e.Text)
	if e.Classification != authoritative {
		http.Error(w, "classification mismatch", http.StatusBadRequest)
		return
	}
	classification, modelErr := core.ClassifyWithModel(r.Context(), e.Text, core.DLP{}, core.DisabledModel{})
	degraded := modelErr != nil
	note, _ := core.Watch(e, s.Mode, false, degraded)
	added, err := s.Queue.Enqueue(r.Context(), e)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"accepted": true, "deduplicated": !added, "classification": classification, "degraded": degraded, "notification": note})
}
