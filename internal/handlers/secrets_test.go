package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCloudTokensNotConfigured(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("REACH_TESTBED_GITHUB_TOKEN", "")

	req := httptest.NewRequest("GET", "/cloud-tokens", nil)
	w := httptest.NewRecorder()

	CloudTokens(w, req)

	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if got["aws_access_key_id"] != "not_configured" {
		t.Fatalf("aws_access_key_id = %q, want %q", got["aws_access_key_id"], "not_configured")
	}
	if got["github_token"] != "not_configured" {
		t.Fatalf("github_token = %q, want %q", got["github_token"], "not_configured")
	}
}

func TestCloudTokensConfiguredNoSecretEcho(t *testing.T) {
	awsKey := "AKIAIOSFODNN7EXAMPLE"
	githubToken := "ghp_reachtestbedsynthetic000000000000000000"

	t.Setenv("AWS_ACCESS_KEY_ID", awsKey)
	t.Setenv("REACH_TESTBED_GITHUB_TOKEN", githubToken)

	req := httptest.NewRequest("GET", "/cloud-tokens", nil)
	w := httptest.NewRecorder()

	CloudTokens(w, req)

	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if got["aws_access_key_id"] != "configured" {
		t.Fatalf("aws_access_key_id = %q, want %q", got["aws_access_key_id"], "configured")
	}
	if got["github_token"] != "configured" {
		t.Fatalf("github_token = %q, want %q", got["github_token"], "configured")
	}

	body := w.Body.String()
	if strings.Contains(body, awsKey) {
		t.Fatalf("response unexpectedly echoed aws key")
	}
	if strings.Contains(body, githubToken) {
		t.Fatalf("response unexpectedly echoed github token")
	}
}
