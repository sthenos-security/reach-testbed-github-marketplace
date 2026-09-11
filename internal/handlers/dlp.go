package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"unicode"
)

func SupportExport(w http.ResponseWriter, _ *http.Request) {
	ssn := "123-45-6789"
	log.Printf("Processing support export for synthetic fixture data")
	maskedSSN := maskLast4(ssn)

	w.Header().Set("Content-Type", "text/csv")
	_, _ = w.Write([]byte("name,email,ssn,phone,card_number,last4\n"))
	_, _ = w.Write([]byte("Avery Example,redacted@example.invalid," + maskedSSN + ",+1-***-***-0199,************4242,4242\n"))
}

func maskLast4(value string) string {
	last4 := make([]rune, 0, 4)
	for i := len(value) - 1; i >= 0 && len(last4) < 4; i-- {
		r := rune(value[i])
		if unicode.IsDigit(r) {
			last4 = append(last4, r)
		}
	}
	if len(last4) < 4 {
		return "***-**-****"
	}
	return "***-**-" + string([]rune{last4[3], last4[2], last4[1], last4[0]})
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
