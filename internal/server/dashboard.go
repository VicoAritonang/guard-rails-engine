package server

import (
	"embed"
	"net/http"
)

// The console is embedded rather than served from disk so that the binary is
// the whole deployment artefact. A container that needs a sidecar volume to
// render its own operator page is a container that will eventually be deployed
// without one.
//
//go:embed assets/*
var assets embed.FS

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	page, err := assets.ReadFile("assets/index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "console unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The console runs entirely from this response: no CDN, no inline eval.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page)
}
