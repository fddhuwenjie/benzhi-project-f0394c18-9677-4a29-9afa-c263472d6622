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
	if r.Method == http.MethodGet {
		write(w, map[string]any{"default_version": assessment.DefaultThreshold(), "items": assessment.ThresholdCatalog()}, http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		write(w, map[string]string{"error": "method not allowed"}, http.StatusMethodNotAllowed)
		return
	}
	var q struct {
		Version string `json:"version"`
		Status  string `json:"status"`
		Default string `json:"default"`
	}
	if decode(r, &q) != nil {
		write(w, map[string]string{"error": "请求无效"}, http.StatusBadRequest)
		return
	}
	if q.Version != "" && q.Status != "" {
		if err := assessment.SetThresholdStatus(q.Version, q.Status); err != nil {
			write(w, map[string]string{"error": err.Error()}, http.StatusBadRequest)
			return
		}
		write(w, map[string]any{"version": q.Version, "status": q.Status}, http.StatusOK)
		return
	}
	if q.Default != "" {
		if err := assessment.SetDefaultThreshold(q.Default); err != nil {
			write(w, map[string]string{"error": err.Error()}, http.StatusBadRequest)
			return
		}
		write(w, map[string]any{"default_version": assessment.DefaultThreshold()}, http.StatusOK)
		return
	}
	write(w, map[string]string{"error": "缺少version/status或default参数"}, http.StatusBadRequest)
}
