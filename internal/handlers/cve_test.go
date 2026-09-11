package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseLanguage_AllowsExpectedTag(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/parse-language?tag=en-US", nil)
	rec := httptest.NewRecorder()

	ParseLanguage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if rec.Body.String() != "en-US\n" {
		t.Fatalf("expected body %q, got %q", "en-US\n", rec.Body.String())
	}
}

func TestParseLanguage_RejectsUnsupportedTag(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/parse-language?tag=zh", nil)
	rec := httptest.NewRecorder()

	ParseLanguage(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	if rec.Body.String() != "unsupported language tag\n" {
		t.Fatalf("expected body %q, got %q", "unsupported language tag\n", rec.Body.String())
	}
}

func TestParseLanguage_RejectsMalformedTag(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/parse-language?tag=en%0AUS", nil)
	rec := httptest.NewRecorder()

	ParseLanguage(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	if rec.Body.String() != "unsupported language tag\n" {
		t.Fatalf("expected body %q, got %q", "unsupported language tag\n", rec.Body.String())
	}
}
