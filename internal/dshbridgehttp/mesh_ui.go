package dshbridgehttp

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"openduck/internal/meshui"
)

var meshProposalKinds = map[string]bool{
	"selection-revision": true, "mesh-spawn": true, "mesh-spawnBatch": true, "mesh-send": true, "mesh-steer": true, "mesh-wait": true, "mesh-collect": true, "mesh-cancel": true, "mesh-list": true, "mesh-status": true, "mesh-result": true, "mesh-listProfiles": true,
	"provider-directory": true, "ui-session-graph": true, "run-compare": true, "run-synthesis": true, "run-templates": true, "policy-approval-inspector": true, "provider-diagnostics": true, "deployment-diagnostics": true, "plugin-lifecycle": true,
}

func (s *Server) meshUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/plugin-reads/mesh" {
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.ContentLength != 0 || r.Header.Get("Content-Type") != "" {
			http.Error(w, "mesh read rejected", http.StatusBadRequest)
			return
		}
		projection := s.MeshUI.Projection(r.Context())
		if err := projection.Validate(); err != nil {
			s.cors(w)
			writeMeshUIUnavailable(w, http.StatusBadGateway)
			return
		}
		s.cors(w)
		writeJSON(w, http.StatusOK, projection)
		return
	}
	kind := strings.TrimPrefix(r.URL.Path, "/v1/plugin-proposals/")
	if !meshProposalKinds[kind] || strings.Contains(kind, "/") {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "mesh proposal rejected", http.StatusBadRequest)
		return
	}
	if r.ContentLength < 1 || r.ContentLength > 64<<10 {
		http.Error(w, "mesh proposal rejected", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil || int64(len(body)) != r.ContentLength {
		http.Error(w, "mesh proposal rejected", http.StatusBadRequest)
		return
	}
	var result meshui.MeshUIResponse
	if kind == "selection-revision" {
		result, err = s.MeshUI.Select(r.Context(), body)
	} else {
		result, err = s.MeshUI.Propose(r.Context(), kind, body)
	}
	if errors.Is(err, meshui.ErrInvalid) {
		http.Error(w, "mesh proposal rejected", http.StatusBadRequest)
		return
	}
	if errors.Is(err, meshui.ErrUnavailable) {
		s.cors(w)
		writeMeshUIUnavailable(w, http.StatusConflict)
		return
	}
	if errors.Is(err, meshui.ErrInvalidOutput) {
		s.cors(w)
		writeMeshUIUnavailable(w, http.StatusBadGateway)
		return
	}
	if err != nil {
		http.Error(w, "mesh proposal unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := result.Validate(kind); err != nil {
		s.cors(w)
		writeMeshUIUnavailable(w, http.StatusBadGateway)
		return
	}
	s.cors(w)
	writeJSON(w, http.StatusOK, result)
}

func writeMeshUIUnavailable(w http.ResponseWriter, status int) {
	response := meshui.UnavailableError()
	if response.Validate() != nil {
		http.Error(w, "mesh proposal unavailable", http.StatusBadGateway)
		return
	}
	writeJSON(w, status, response)
}
