package assessment

import "time"

type Signal struct {
	PeakAmplitude     float64 `json:"peak_amplitude"`
	DominantFrequency float64 `json:"dominant_frequency"`
	DurationMS        int     `json:"duration_ms"`
	RawDigest         string  `json:"raw_digest"`
}

type Quality struct {
	Valid  bool   `json:"valid"`
	Score  int    `json:"score"`
	Reason string `json:"reason"`
}

type Risk string

const (
	Low    Risk = "low"
	Medium Risk = "medium"
	High   Risk = "high"
	Noise  Risk = "noise"
)

type Result struct {
	Quality          Quality   `json:"quality"`
	Risk             Risk      `json:"risk"`
	Explanation      string    `json:"explanation"`
	Factors          []string  `json:"factors,omitempty"`
	ThresholdVersion string    `json:"threshold_version"`
	CalculatedAt     time.Time `json:"calculated_at"`
}
