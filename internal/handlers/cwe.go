package handlers

import (
	"log"
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

	out, err := exec.Command("ping", "-c", "1", host).CombinedOutput()
	if err != nil {
		log.Printf("DiagnosticPing failed for host %q: %v", host, err)
		_ = out
		http.Error(w, "ping failed", http.StatusBadGateway)
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

	out, err := exec.Command("ping", "-c", "1", host).CombinedOutput()
	if err != nil {
		log.Printf("SafeDiagnosticPing failed for host %q: %v", host, err)
		_ = out
		http.Error(w, "ping failed", http.StatusBadGateway)
		return
	}

	_, _ = w.Write(out)
}
