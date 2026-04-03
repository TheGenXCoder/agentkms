package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/*
var staticFiles embed.FS

// RegisterHandlers registers the UI handlers on the given mux.
func RegisterHandlers(mux *http.ServeMux, h *Handlers) {
	// Static files
	sub, _ := fs.Sub(staticFiles, "static")
	mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("GET /ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusMovedPermanently)
	})

	// UI API endpoints (internal for the UI, not part of the public API)
	mux.HandleFunc("GET /ui/api/keys", h.HandleListKeys)
	mux.HandleFunc("GET /ui/api/audit", h.HandleListAudit)
	mux.HandleFunc("GET /ui/api/policy", h.HandleGetPolicy)
	mux.HandleFunc("PUT /ui/api/policy", h.HandleUpdatePolicy)
}
