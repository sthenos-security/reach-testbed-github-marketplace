package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiagnosticPingRejectsInvalidHost(t *testing.T) {
	query := url.Values{}
	query.Set("host", "127.0.0.1;whoami")

	req := httptest.NewRequest(http.MethodGet, "/diagnostics/ping?"+query.Encode(), nil)
	rr := httptest.NewRecorder()

	DiagnosticPing(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestDiagnosticPingAcceptsValidHost(t *testing.T) {
	tempDir := t.TempDir()
	pingPath := filepath.Join(tempDir, "ping")
	pingScript := "#!/bin/sh\nif [ \"$1\" = \"-c\" ] && [ \"$2\" = \"1\" ] && [ \"$3\" = \"example.com\" ]; then\n  echo \"pong\"\n  exit 0\nfi\necho \"unexpected args\" >&2\nexit 2\n"
	if err := os.WriteFile(pingPath, []byte(pingScript), 0o755); err != nil {
		t.Fatalf("failed to write ping stub: %v", err)
	}

	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	query := url.Values{}
	query.Set("host", "example.com")

	req := httptest.NewRequest(http.MethodGet, "/diagnostics/ping?"+query.Encode(), nil)
	rr := httptest.NewRecorder()

	DiagnosticPing(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d, body=%q", http.StatusOK, rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "pong") {
		t.Fatalf("expected response to contain pong, got %q", rr.Body.String())
	}
}
