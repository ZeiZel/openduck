package harnesshttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"openduck/internal/harness"
	"slices"
	"strings"
)

const StatusSchemaVersion = "controller-status.v1"

type Snapshotter interface {
	Snapshot(context.Context) (harness.ControllerSnapshot, error)
}

type Status struct {
	SchemaVersion         string         `json:"schema_version"`
	Mode                  string         `json:"mode"`
	DeliveryState         string         `json:"delivery_state"`
	ExternalEffects       bool           `json:"external_effects"`
	OwnerDecisionCallback bool           `json:"owner_decision_callback"`
	TaskCounts            map[string]int `json:"task_counts"`
}

// TaskSummary is the complete read-only task projection intentionally exposed
// to the Codex-facing plugin. It excludes signals, specs, WorkOrder text,
// previews, callback handles and decision proofs.
type TaskSummary struct {
	ID            string `json:"id"`
	State         string `json:"state"`
	Version       uint64 `json:"version"`
	HasWorkOrder  bool   `json:"has_work_order"`
	HasEvidence   bool   `json:"has_evidence"`
	HasReview     bool   `json:"has_review"`
	DecisionCount int    `json:"decision_count"`
}

type TaskList struct {
	SchemaVersion string        `json:"schema_version"`
	Mode          string        `json:"mode"`
	Tasks         []TaskSummary `json:"tasks"`
}

type Server struct {
	Controller         Snapshotter
	CallbackController CallbackController
	OwnerAuthenticator OwnerAuthenticator
	callback           CallbackConfig
}

// ConfigureCallback returns a copy of the server with callback transport
// settings. It is intentionally opt-in; the zero value keeps all callback
// routes undiscoverable.
func (s *Server) ConfigureCallback(cfg CallbackConfig) error {
	if err := validateCallbackConfig(cfg); err != nil {
		return err
	}
	s.callback = cfg
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/readyz", s.ready)
	mux.HandleFunc("/v1/controller/status", s.status)
	mux.HandleFunc("/v1/controller/tasks", s.tasks)
	transport := &callbackTransport{server: s}
	mux.HandleFunc(originProbePath, transport.serveOriginProbe)
	mux.HandleFunc(callbackOriginPath, transport.serve)
	mux.HandleFunc(callbackRenderPath, transport.serve)
	mux.HandleFunc(callbackDecisionPath, transport.serve)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) tasks(w http.ResponseWriter, r *http.Request) {
	if !methodGET(w, r) {
		return
	}
	if s.Controller == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	snap, err := s.Controller.Snapshot(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	out := make([]TaskSummary, 0, len(snap.Tasks))
	for _, task := range snap.Tasks {
		out = append(out, TaskSummary{ID: task.ID, State: string(task.State), Version: task.Version, HasWorkOrder: task.WorkOrder != nil, HasEvidence: task.Evidence != nil, HasReview: task.Review != nil, DecisionCount: len(task.Decisions)})
	}
	// Stable ordering prevents the plugin/card from treating map iteration as a
	// task lifecycle event.
	slices.SortFunc(out, func(a, b TaskSummary) int { return strings.Compare(a.ID, b.ID) })
	writeJSON(w, http.StatusOK, TaskList{SchemaVersion: "controller-task-list.v1", Mode: "synthetic", Tasks: out})
}

func methodGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	w.Header().Set("Allow", http.MethodGet)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if !methodGET(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if !methodGET(w, r) {
		return
	}
	if s.Controller == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	if _, err := s.Controller.Snapshot(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if !methodGET(w, r) {
		return
	}
	if s.Controller == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	snap, err := s.Controller.Snapshot(r.Context())
	if err != nil {
		if errors.Is(err, harness.ErrControllerPoisoned) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	counts := map[string]int{
		string(harness.Observed): 0, string(harness.SignalReady): 0, string(harness.SpecDraft): 0,
		string(harness.SpecFrozen): 0, string(harness.Dispatched): 0, string(harness.WorkRunning): 0,
		string(harness.EvidenceReady): 0, string(harness.Reviewing): 0, string(harness.Accepted): 0,
		string(harness.Blocked): 0, string(harness.Cancelled): 0,
	}
	for _, task := range snap.Tasks {
		counts[string(task.State)]++
	}
	writeJSON(w, http.StatusOK, Status{SchemaVersion: StatusSchemaVersion, Mode: "synthetic", DeliveryState: "UI_DELIVERY_BLOCKED", ExternalEffects: false, OwnerDecisionCallback: false, TaskCounts: counts})
}
func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
