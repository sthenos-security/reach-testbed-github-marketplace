package handlers

import (
	"log"
	"net/http"
)

func writeClientError(w http.ResponseWriter, r *http.Request, status int, clientMessage string, err error, operation string) {
	requestID := r.Header.Get("X-Request-ID")
	correlationID := r.Header.Get("X-Correlation-ID")
	log.Printf("%s failed: method=%s path=%s request_id=%q correlation_id=%q err=%v", operation, r.Method, r.URL.Path, requestID, correlationID, err)
	http.Error(w, clientMessage, status)
}
