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

func TestFetchTool_RejectsDisallowedURLVariants(t *testing.T) {
	cases := []string{
		"/admin/fetch-tool?url=https://downloads.example.invalid/reach-testbed-tool.bin?extra=1",
		"/admin/fetch-tool?url=https://downloads.example.invalid:444/reach-testbed-tool.bin",
		"/admin/fetch-tool?url=https://downloads.example.invalid/wrong-path.bin",
	}
	for _, target := range cases {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		FetchTool(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected status %d for %q, got %d", http.StatusBadRequest, target, rec.Code)
		}
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
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode 0600, got %o", info.Mode().Perm())
	}
	if string(content) != "synthetic tool payload\n" {
		t.Fatalf("unexpected file content: %q", string(content))
	}
}

func TestFetchTool_AllowlistedURLUsesUniqueFiles(t *testing.T) {
	req1 := httptest.NewRequest(http.MethodGet, "/admin/fetch-tool?url=https://downloads.example.invalid/reach-testbed-tool.bin", nil)
	rec1 := httptest.NewRecorder()
	FetchTool(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/admin/fetch-tool?url=https://downloads.example.invalid/reach-testbed-tool.bin", nil)
	rec2 := httptest.NewRecorder()
	FetchTool(rec2, req2)

	if rec1.Code != http.StatusOK || rec2.Code != http.StatusOK {
		t.Fatalf("expected both responses to be 200, got %d and %d", rec1.Code, rec2.Code)
	}
	target1 := strings.TrimSpace(rec1.Body.String())
	target2 := strings.TrimSpace(rec2.Body.String())
	t.Cleanup(func() {
		_ = os.Remove(target1)
		_ = os.Remove(target2)
	})
	if target1 == target2 {
		t.Fatalf("expected unique tool file paths, got %q", target1)
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
	if !strings.Contains(body, "************4242,4242") {
		t.Fatalf("expected consistent card redaction and last4, got %q", body)
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
