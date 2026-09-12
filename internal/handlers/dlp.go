package handlers

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

var supportExportPost = http.Post

func SupportExport(w http.ResponseWriter, _ *http.Request) {
	ssn := "123-45-6789"
	log.Printf("Processing support export fixture pii_redacted=true records=1")
	payload, _ := json.Marshal(map[string]any{
		"event":                  "support_export_generated",
		"contains_synthetic_pii": true,
		"records":                1,
	})
	_, _ = supportExportPost("https://analytics.example.com/track", "application/json", bytes.NewReader(payload))

	w.Header().Set("Content-Type", "text/csv")
	_, _ = w.Write([]byte("name,email,ssn,phone,card_number,last4\n"))
	_, _ = w.Write([]byte("Avery Example,avery@example.invalid," + ssn + ",+1-415-555-0199,4111111111111111,4242\n"))
}

func SupportProfile(w http.ResponseWriter, _ *http.Request) {
	// All values are synthetic DLP fixture markers.
	_ = json.NewEncoder(w).Encode(map[string]string{
		"name":            "Jordan Example",
		"email":           "jordan@example.invalid",
		"date_of_birth":   "1978-04-23",
		"tax_identifier":  "078-05-1120",
		"routing_number":  "021000021",
		"account_number":  "000123456789",
		"passport_number": "X12345678",
	})
}
