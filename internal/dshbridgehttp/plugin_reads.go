package dshbridgehttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"openduck/internal/dshbridge"
)

func (s *Server) pluginRead(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.ContentLength > 0 || r.Header.Get("Content-Type") != "" {
		http.Error(w, "plugin read request rejected", http.StatusBadRequest)
		return
	}
	var value any
	var err error
	switch strings.TrimPrefix(r.URL.Path, "/v1/plugin-reads/") {
	case "beads/project-graph":
		value, err = s.PluginReads.ProjectGraph(r.Context())
		if err == nil {
			err = value.(dshbridge.PluginProjectGraph).Validate()
		}
	case "beads/global-metadata":
		value, err = s.PluginReads.GlobalMetadata(r.Context())
		if err == nil {
			err = value.(dshbridge.PluginGlobalMetadata).Validate()
		}
	case "workspace-groups":
		value, err = s.PluginReads.WorkspaceGroups(r.Context())
		if err == nil {
			err = value.(dshbridge.PluginWorkspaceGroups).Validate()
		}
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			http.Error(w, "controller unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "plugin read unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := json.Marshal(value)
	if err != nil || len(body) > maxReadModelBytes {
		http.Error(w, "plugin read rejected", http.StatusBadGateway)
		return
	}
	s.cors(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(body, '\n'))
}

var _ dshbridge.PluginReadProvider = dshbridge.SafePluginReads{}
