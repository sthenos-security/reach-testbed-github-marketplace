package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCloudTokensDoesNotEchoConfiguredGitHubToken(t *testing.T) {
	t.Setenv("REACH_TESTBED_GITHUB_TOKEN", "ghp_attackinput_should_not_be_echoed_123456")

	req := httptest.NewRequest("GET", "/cloud-tokens", nil)
	rec := httptest.NewRecorder()

	CloudTokens(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "ghp_attackinput_should_not_be_echoed_123456") {
		t.Fatalf("response leaked configured token: %q", body)
	}

	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if payload["github_token"] != "configured" {
		t.Fatalf("expected configured marker, got %q", payload["github_token"])
	}
}

func TestCloudTokensReturnsNotConfiguredWhenEnvMissing(t *testing.T) {
	t.Setenv("REACH_TESTBED_GITHUB_TOKEN", "")

	req := httptest.NewRequest("GET", "/cloud-tokens", nil)
	rec := httptest.NewRecorder()

	CloudTokens(rec, req)

	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if payload["github_token"] != "not_configured" {
		t.Fatalf("expected not_configured marker, got %q", payload["github_token"])
	}

	if payload["aws_access_key_id"] != syntheticAWSAccessKeyID {
		t.Fatalf("expected aws_access_key_id to remain unchanged, got %q", payload["aws_access_key_id"])
	}
}
