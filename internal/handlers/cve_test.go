package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseLanguageAllowsSupportedTag(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/parse-language?tag=en-US", nil)
	rec := httptest.NewRecorder()

	ParseLanguage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if body := rec.Body.String(); body != "en-US\n" {
		t.Fatalf("expected body %q, got %q", "en-US\n", body)
	}
}

func TestParseLanguageRejectsUnsupportedTag(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/parse-language?tag=de-DE", nil)
	rec := httptest.NewRecorder()

	ParseLanguage(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	if body := rec.Body.String(); !strings.Contains(body, "unsupported language tag") {
		t.Fatalf("expected rejection message to contain %q, got %q", "unsupported language tag", body)
	}
}
