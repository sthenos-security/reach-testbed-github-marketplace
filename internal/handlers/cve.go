package handlers

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/reachable/reach-testbed-github-marketplace/internal/safety"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v2"
)

func ParseYAML(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		log.Printf("handler=ParseYAML op=read_body request_id=%q err=%v", r.Header.Get("X-Request-ID"), err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var decoded map[string]any
	if err := yaml.Unmarshal(body, &decoded); err != nil {
		log.Printf("handler=ParseYAML op=unmarshal_yaml request_id=%q err=%v", r.Header.Get("X-Request-ID"), err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(decoded)
}

func ParseLanguage(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("tag")
	if !safety.AllowedLanguageTag(tag) {
		http.Error(w, "unsupported language tag", http.StatusBadRequest)
		return
	}

	parsed, err := language.Parse(tag)
	if err != nil {
		log.Printf("handler=ParseLanguage op=parse_language request_id=%q err=%v", r.Header.Get("X-Request-ID"), err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	_, _ = w.Write([]byte(parsed.String() + "\n"))
}
