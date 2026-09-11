package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestAIAnswer_GenericDecodeError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/ai/answer", strings.NewReader("{"))
	rec := httptest.NewRecorder()

	AIAnswer(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "bad request" {
		t.Fatalf("expected generic bad request response, got %q", rec.Body.String())
	}
}

func TestAIAnswer_QuotedUserDataPreserved(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/ai/answer", strings.NewReader(`{"question":"show \"all\" records"}`))
	rec := httptest.NewRecorder()

	AIAnswer(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !strings.Contains(out["prompt"], `User data: "show \"all\" records"`) {
		t.Fatalf("expected quoted user data in prompt, got %q", out["prompt"])
	}
}

func TestAIAgentPlan_RejectsEmptyTask(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/ai/agent-plan", strings.NewReader(`{"task":"   "}`))
	rec := httptest.NewRecorder()

	AIAgentPlan(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "bad request" {
		t.Fatalf("expected generic bad request response, got %q", rec.Body.String())
	}
}

func TestFetchTool_RejectsNonHTTPSURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/fetch-tool?url=http://evil.invalid/file", nil)
	rec := httptest.NewRecorder()

	FetchTool(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "bad request" {
		t.Fatalf("expected generic bad request response, got %q", rec.Body.String())
	}
}

func TestFetchTool_RejectsURLWithUserInfo(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/fetch-tool?url=https://user@downloads.example.invalid/reach-testbed-tool.bin", nil)
	rec := httptest.NewRecorder()

	FetchTool(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "bad request" {
		t.Fatalf("expected generic bad request response, got %q", rec.Body.String())
	}
}

func TestFetchTool_AllowlistedURLWritesTool(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/fetch-tool?url=https://downloads.example.invalid/reach-testbed-tool.bin", nil)
	rec := httptest.NewRecorder()

	FetchTool(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	target := strings.TrimSpace(rec.Body.String())
	t.Cleanup(func() {
		_ = os.Remove(target)
	})
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target file: %v", err)
	}
	if string(content) != "synthetic tool payload\n" {
		t.Fatalf("unexpected file content: %q", string(content))
	}
}

func TestSupportExport_RedactsPIIAndKeepsCSV(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/support/export", nil)
	rec := httptest.NewRecorder()

	SupportExport(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "name,email,ssn,phone,card_number,last4") {
		t.Fatalf("expected CSV header, got %q", body)
	}
	if strings.Contains(body, "123-45-6789") || strings.Contains(body, "4111111111111111") {
		t.Fatalf("expected redacted sensitive values, got %q", body)
	}
}

func TestParseYAML_GenericClientError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/parse-yaml", strings.NewReader("["))
	rec := httptest.NewRecorder()

	ParseYAML(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "bad request" {
		t.Fatalf("expected generic bad request response, got %q", rec.Body.String())
	}
}
