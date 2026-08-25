package httpapi

import (
	"bridgewatch/internal/assessment"
	"net/http"
)

func (s *Server) routes() {
	s.Mux.HandleFunc("/", s.index)
	s.Mux.HandleFunc("/static/app.js", s.js)
	s.Mux.HandleFunc("/static/style.css", s.css)
	s.Mux.HandleFunc("/api/alerts", s.alerts)
	s.Mux.HandleFunc("/api/alerts/batches/", s.batchAction)
	s.Mux.HandleFunc("/api/cases", s.cases)
	s.Mux.HandleFunc("/api/cases/", s.caseAction)
	s.Mux.HandleFunc("/api/thresholds", s.thresholds)
}

func (s *Server) thresholds(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		write(w, map[string]string{"error": "method not allowed"}, http.StatusMethodNotAllowed)
		return
	}
	write(w, map[string]any{"default_version": assessment.DefaultThreshold(), "items": assessment.ThresholdCatalog()}, http.StatusOK)
}
