package handlers

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSupportExportRedactsPIIInLogAndAnalyticsPayload(t *testing.T) {
	originalPost := supportExportPost
	defer func() {
		supportExportPost = originalPost
	}()

	var (
		logs     bytes.Buffer
		postURL  string
		postType string
		postBody []byte
	)
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(originalWriter)

	supportExportPost = func(url, contentType string, body io.Reader) (*http.Response, error) {
		var err error
		postBody, err = io.ReadAll(body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		postURL = url
		postType = contentType
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/support/export", nil)
	rec := httptest.NewRecorder()

	SupportExport(rec, req)

	if postURL != "https://analytics.example.com/track" {
		t.Fatalf("unexpected analytics URL: %q", postURL)
	}
	if postType != "application/json" {
		t.Fatalf("unexpected analytics content type: %q", postType)
	}

	for _, raw := range []string{
		"123-45-6789",
		"1978-04-23",
		"avery@example.invalid",
		"+1-415-555-0199",
		"4111111111111111",
	} {
		if strings.Contains(logs.String(), raw) {
			t.Fatalf("log output leaked raw PII %q: %s", raw, logs.String())
		}
		if strings.Contains(string(postBody), raw) {
			t.Fatalf("analytics payload leaked raw PII %q: %s", raw, string(postBody))
		}
	}
	if !strings.Contains(logs.String(), "support export") {
		t.Fatalf("expected audit log entry, got %q", logs.String())
	}
	if !bytes.Contains(postBody, []byte(`"event":"support_export_generated"`)) {
		t.Fatalf("expected redacted analytics event payload, got %s", string(postBody))
	}
}

func TestSupportExportPreservesCSVResponse(t *testing.T) {
	originalPost := supportExportPost
	defer func() {
		supportExportPost = originalPost
	}()
	supportExportPost = func(string, string, io.Reader) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/support/export", nil)
	rec := httptest.NewRecorder()

	SupportExport(rec, req)

	if got := rec.Header().Get("Content-Type"); got != "text/csv" {
		t.Fatalf("unexpected content type: %q", got)
	}
	const want = "name,email,ssn,phone,card_number,last4\n" +
		"Avery Example,avery@example.invalid,123-45-6789,+1-415-555-0199,4111111111111111,4242\n"
	if got := rec.Body.String(); got != want {
		t.Fatalf("unexpected CSV response:\nwant %q\ngot  %q", want, got)
	}
}
