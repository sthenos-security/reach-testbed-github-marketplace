package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestParseLanguageAllowsConfiguredTag(t *testing.T) {
	query := url.Values{"tag": {"en-US"}}
	req := httptest.NewRequest(http.MethodPost, "/parse-language?"+query.Encode(), nil)
	rec := httptest.NewRecorder()

	ParseLanguage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if body := rec.Body.String(); body != "en-US\n" {
		t.Fatalf("expected normalized tag, got %q", body)
	}
}

func TestParseLanguageRejectsUnsupportedTag(t *testing.T) {
	query := url.Values{"tag": {"de-DE"}}
	req := httptest.NewRequest(http.MethodPost, "/parse-language?"+query.Encode(), nil)
	rec := httptest.NewRecorder()

	ParseLanguage(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	if body := rec.Body.String(); !strings.Contains(body, "unsupported language tag") {
		t.Fatalf("expected unsupported tag error, got %q", body)
	}
}
