package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

type promptRequest struct {
	Question string `json:"question"`
}

type agentRequest struct {
	Task string `json:"task"`
}

func AIAnswer(w http.ResponseWriter, r *http.Request) {
	var req promptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("AIAnswer decode failed: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	_ = req.Question
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

func AIAgentPlan(w http.ResponseWriter, r *http.Request) {
	var req agentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("AIAgentPlan decode failed: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	_ = req.Task
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "planned",
	})
}

func SafeAIAnswer(w http.ResponseWriter, r *http.Request) {
	var req promptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("SafeAIAnswer decode failed: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.Contains(strings.ToLower(req.Question), "ignore previous") {
		http.Error(w, "unsafe instruction", http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}
