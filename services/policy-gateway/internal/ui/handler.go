package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var uiAssets embed.FS

type Handler struct {
	dist fs.FS
}

func NewHandler() *Handler {
	dist, err := fs.Sub(uiAssets, "dist")
	if err != nil {
		panic(err)
	}
	return &Handler{dist: dist}
}

func (h *Handler) Register(mux *http.ServeMux) {
	fileServer := http.FileServer(http.FS(h.dist))
	mux.HandleFunc("GET /ui", h.serveIndex)
	mux.Handle("GET /ui/", http.StripPrefix("/ui/", h.spaHandler(fileServer)))
}

func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ui" {
		http.NotFound(w, r)
		return
	}
	h.serveFile(w, r, "index.html")
}

func (h *Handler) spaHandler(fileServer http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			h.serveFile(w, r, "index.html")
			return
		}
		if _, err := fs.Stat(h.dist, path); err != nil {
			h.serveFile(w, r, "index.html")
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

func (h *Handler) serveFile(w http.ResponseWriter, r *http.Request, name string) {
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFileFS(w, r, h.dist, name)
}
