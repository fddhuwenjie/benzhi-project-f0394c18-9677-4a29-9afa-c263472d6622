package store

import "time"

type Batch struct {
	BatchID      string      `json:"batch_id"`
	CreatedAt    time.Time   `json:"created_at"`
	Items        []BatchItem `json:"items"`
	SuccessCount int         `json:"success_count"`
	FailureCount int         `json:"failure_count"`
	Total        int         `json:"total"`
}

type BatchItem struct {
	Index         int    `json:"index"`
	RequestID     string `json:"request_id"`
	Fingerprint   string `json:"fingerprint"`
	Alert         Alert  `json:"alert"`
	Status        string `json:"status"`
	CaseID        string `json:"case_id,omitempty"`
	Error         string `json:"error,omitempty"`
	Attempts      int    `json:"attempts"`
	RiskLevel     string `json:"risk_level,omitempty"`
	QualityScore  int    `json:"quality_score,omitempty"`
	NeedsReReview bool   `json:"needs_re_review,omitempty"`
}
