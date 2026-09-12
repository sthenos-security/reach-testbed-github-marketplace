package handlers

import (
	"net/http"
	"os/exec"

	"github.com/reachable/reach-testbed-github-marketplace/internal/safety"
)

func DiagnosticPing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !safety.AllowedHostname(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	out, err := exec.CommandContext(r.Context(), "ping", "-c", "1", host).CombinedOutput()
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

	out, err := exec.CommandContext(r.Context(), "ping", "-c", "1", host).CombinedOutput()
	if err != nil {
		writeClientError(w, r, http.StatusBadGateway, "bad gateway", err, "run safe diagnostic ping")
		return
	}

	_, _ = w.Write(out)
}
