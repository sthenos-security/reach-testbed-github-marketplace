package handlers

import (
	"context"
	"net/http"
	"os/exec"
	"time"

	"github.com/reachable/reach-testbed-github-marketplace/internal/safety"
)

const pingTimeout = 5 * time.Second

func DiagnosticPing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !safety.AllowedHostname(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), pingTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ping", "-c", "1", host).CombinedOutput()
	if err != nil {
		writeClientError(w, r, http.StatusBadGateway, "bad gateway", err, "run diagnostic ping")
		return
	}

	_, _ = w.Write(out)
}

func SafeDiagnosticPing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !safety.AllowedHostname(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), pingTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ping", "-c", "1", host).CombinedOutput()
	if err != nil {
		writeClientError(w, r, http.StatusBadGateway, "bad gateway", err, "run safe diagnostic ping")
		return
	}

	_, _ = w.Write(out)
}
