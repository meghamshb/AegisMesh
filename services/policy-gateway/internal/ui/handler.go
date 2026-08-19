package ui

import (
	_ "embed"
	"net/http"
)

//go:embed inbox.html
var inboxHTML []byte

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui", h.handleInbox)
	mux.HandleFunc("GET /ui/", h.handleInbox)
}

func (h *Handler) handleInbox(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(inboxHTML)
}
