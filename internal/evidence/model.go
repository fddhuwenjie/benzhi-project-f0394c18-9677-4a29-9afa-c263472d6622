package evidence

import (
	"bridgewatch/internal/assessment"
	"errors"
	"time"
)

var ErrInvalid = errors.New("证据不完整")

type Input struct {
	Checkpoint     string            `json:"checkpoint"`
	ArrivedAt      time.Time         `json:"arrived_at"`
	PhotoRefs      []string          `json:"photo_refs"`
	Resample       assessment.Signal `json:"resample"`
	Notes          string            `json:"notes"`
	SubmittedBy    string            `json:"submitted_by"`
	Version        int               `json:"version,omitempty"`
	ConflictReason string            `json:"conflict_reason,omitempty"`
	ConfirmReuseBy string            `json:"confirm_reuse_by,omitempty"`
	SubmittedAt    time.Time         `json:"submitted_at,omitempty"`
	LateReason     string            `json:"late_reason,omitempty"`
}
