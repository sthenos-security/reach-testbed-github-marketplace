package handlers

import (
	"errors"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/reachable/reach-testbed-github-marketplace/internal/safety"
)

var resolvePingPath = trustedPingPath

func DiagnosticPing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !safety.AllowedHostname(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	pingPath, err := resolvePingPath()
	if err != nil {
		log.Printf("diagnostic ping unavailable: %v", err)
		http.Error(w, "diagnostic failed", http.StatusBadGateway)
		return
	}

	out, err := exec.CommandContext(r.Context(), pingPath, "-c", "1", host).CombinedOutput()
	if err != nil {
		log.Printf("diagnostic ping failed: %v", err)
		http.Error(w, "diagnostic failed", http.StatusBadGateway)
		return
	}

	_, _ = w.Write(out)
}

func trustedPingPath() (string, error) {
	for _, path := range []string{"/bin/ping", "/usr/bin/ping"} {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path, nil
		}
	}

	return "", errors.New("trusted ping executable not found")
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
