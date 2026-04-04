package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/*
var staticFiles embed.FS

// RegisterHandlers registers the UI handlers on the given mux.
// authMw is used to protect the API endpoints.
func RegisterHandlers(mux *http.ServeMux, h *Handlers, authMw func(http.HandlerFunc) http.HandlerFunc) {
	// Static files
	sub, _ := fs.Sub(staticFiles, "static")
	mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("GET /ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusMovedPermanently)
	})

	// UI API endpoints (protected)
	mux.HandleFunc("GET /ui/api/keys", authMw(h.HandleListKeys))
	mux.HandleFunc("GET /ui/api/audit", authMw(h.HandleListAudit))
	mux.HandleFunc("GET /ui/api/policy", authMw(h.HandleGetPolicy))
	mux.HandleFunc("PUT /ui/api/policy", authMw(h.HandleUpdatePolicy))
}
