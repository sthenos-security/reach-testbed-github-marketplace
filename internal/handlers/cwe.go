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
		log.Printf("diagnostic ping failed for host %q: %v", host, err)
		http.Error(w, "diagnostic failed", http.StatusBadGateway)
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
		http.Error(w, string(out), http.StatusBadGateway)
		return
	}

	_, _ = w.Write(out)
}
