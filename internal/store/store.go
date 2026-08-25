package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Alert struct {
	AlertID           string    `json:"alert_id"`
	BridgeID          string    `json:"bridge_id"`
	SensorID          string    `json:"sensor_id"`
	CapturedAt        time.Time `json:"captured_at"`
	PeakAmplitude     float64   `json:"peak_amplitude"`
	DominantFrequency float64   `json:"dominant_frequency"`
	DurationMS        int       `json:"duration_ms"`
	RawDigest         string    `json:"raw_digest"`
	ReceivedAt        time.Time `json:"received_at,omitempty"`
	TimeQuality       string    `json:"time_quality,omitempty"`
	DriftSeconds      float64   `json:"drift_seconds,omitempty"`
}
type Case struct {
	CaseID                   string               `json:"case_id"`
	AlertID                  string               `json:"alert_id"`
	Status                   string               `json:"status"`
	RiskLevel                string               `json:"risk_level"`
	Reviewer                 string               `json:"reviewer"`
	Assignee                 string               `json:"assignee"`
	Revision                 int                  `json:"revision"`
	OpenedAt                 *time.Time           `json:"opened_at"`
	ClosedAt                 *time.Time           `json:"closed_at,omitempty"`
	BeforePeak               float64              `json:"before_peak"`
	EvidenceID               string               `json:"evidence_id"`
	DecisionID               string               `json:"decision_id"`
	ThresholdVersion         string               `json:"threshold_version"`
	RiskExplanation          string               `json:"risk_explanation"`
	RiskFactors              []string             `json:"risk_factors,omitempty"`
	QualityScore             int                  `json:"quality_score"`
	QualityReason            string               `json:"quality_reason"`
	RiskCalculatedAt         *time.Time           `json:"risk_calculated_at"`
	TaskID                   string               `json:"task_id"`
	ReceivedAt               time.Time            `json:"received_at"`
	ReviewCount              int                  `json:"review_count"`
	NextReviewAt             *time.Time           `json:"next_review_at"`
	MergeCount               int                  `json:"merge_count"`
	SourceBridgeID           string               `json:"source_bridge_id"`
	SourceSensorID           string               `json:"source_sensor_id"`
	SourceCapturedAt         *time.Time           `json:"source_captured_at"`
	CurrentBridgeID          string               `json:"current_bridge_id,omitempty"`
	CurrentSensorID          string               `json:"current_sensor_id,omitempty"`
	CurrentCapturedAt        *time.Time           `json:"current_captured_at,omitempty"`
	NoiseReviewCount         int                  `json:"noise_review_count"`
	NoiseReclassifiedCount   int                  `json:"noise_reclassified_count"`
	ThresholdCompareVersion  string               `json:"threshold_compare_version"`
	ThresholdCompareRisk     string               `json:"threshold_compare_risk"`
	ThresholdCompareQuality  int                  `json:"threshold_compare_quality"`
	ThresholdSuggestion      string               `json:"threshold_suggestion,omitempty"`
	ArchiveHash              string               `json:"archive_hash,omitempty"`
	ArchiveStatus            string               `json:"archive_status,omitempty"`
	AuditCount               int                  `json:"audit_count"`
	AssociatedAlerts         []AlertRef           `json:"associated_alerts,omitempty"`
	ThresholdConfirmToken    string               `json:"-"`
	ThresholdConfirmedBy     string               `json:"threshold_confirmed_by,omitempty"`
	ThresholdConfirmedAt     *time.Time           `json:"threshold_confirmed_at,omitempty"`
	ThresholdConfirmedReason string               `json:"threshold_confirmed_reason,omitempty"`
	RetestPlanDueAt          *time.Time           `json:"retest_plan_due_at,omitempty"`
	RetestPassRate           float64              `json:"retest_pass_rate,omitempty"`
	RetestConsecutivePasses  int                  `json:"retest_consecutive_passes,omitempty"`
	RetestStability          string               `json:"retest_stability,omitempty"`
	RiskQualityScore         int                  `json:"risk_quality_score,omitempty"`
	RiskAlertCount           int                  `json:"risk_alert_count,omitempty"`
	NeedsReReview            bool                 `json:"needs_re_review,omitempty"`
	RiskHistory              []RiskSnapshot       `json:"risk_history,omitempty"`
	ReviewSnapshots          []ReviewSnapshot     `json:"review_snapshots,omitempty"`
	Checkins                 []Checkin            `json:"checkins,omitempty"`
	RetestTrend              string               `json:"retest_trend,omitempty"`
	RetestRecommendation     string               `json:"retest_recommendation,omitempty"`
	ThresholdSnapshot        any                  `json:"threshold_snapshot,omitempty"`
	Claim                    *CaseClaim           `json:"claim,omitempty"`
	RequiredCheckpoints      []CheckpointProgress `json:"required_checkpoints,omitempty"`
	ArchiveManifest          *ArchiveManifest     `json:"archive_manifest,omitempty"`
	TimeQuality              string               `json:"time_quality,omitempty"`
	DriftSeconds             float64              `json:"drift_seconds,omitempty"`
	FirstDriftAt             *time.Time           `json:"first_drift_at,omitempty"`
	LastDriftAt              *time.Time           `json:"last_drift_at,omitempty"`
	MaxDriftSeconds          float64              `json:"max_drift_seconds,omitempty"`
	DensityCount             int                  `json:"density_count,omitempty"`
	DensityWindow            string               `json:"density_window,omitempty"`
	DensityReason            string               `json:"density_reason,omitempty"`
	DensityTriggerAlertID    string               `json:"density_trigger_alert_id,omitempty"`
	ReviewAttempts           []ReviewAttempt      `json:"review_attempts,omitempty"`
	IndependentGate          string               `json:"independent_gate,omitempty"`
	IndependentReviewer      string               `json:"independent_reviewer,omitempty"`
	IndependentDigest        string               `json:"independent_digest,omitempty"`
	PendingCorrection        *CheckinCorrection   `json:"pending_correction,omitempty"`
	ReopenCount              int                  `json:"reopen_count,omitempty"`
	ReopenReason             string               `json:"reopen_reason,omitempty"`
	RetestFailureCount       int                  `json:"retest_failure_count,omitempty"`
}
type CaseClaim struct {
	Token       string    `json:"token"`
	Holder      string    `json:"holder"`
	ClaimedAt   time.Time `json:"claimed_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	LockVersion int       `json:"lock_version"`
	LastHolder  string    `json:"last_holder,omitempty"`
}
type CheckpointProgress struct {
	ID              string     `json:"id"`
	ArrivedAt       *time.Time `json:"arrived_at,omitempty"`
	EvidenceVersion int        `json:"evidence_version,omitempty"`
	Missing         []string   `json:"missing,omitempty"`
}
type ArchiveManifest struct {
	Fingerprint  string   `json:"fingerprint"`
	AlertDigest  string   `json:"alert_digest"`
	EvidenceHash string   `json:"evidence_hash"`
	DecisionIDs  []string `json:"decision_ids"`
	RetestCount  int      `json:"retest_count"`
	AuditCount   int      `json:"audit_count"`
	ChainHead    string   `json:"chain_head"`
	Status       string   `json:"status"`
	Anomalies    []string `json:"anomalies,omitempty"`
}
type RiskSnapshot struct {
	At                time.Time `json:"at"`
	AlertCount        int       `json:"alert_count"`
	PeakAmplitude     float64   `json:"peak_amplitude"`
	DominantFrequency float64   `json:"dominant_frequency"`
	DurationMS        int       `json:"duration_ms"`
	RiskLevel         string    `json:"risk_level"`
	QualityScore      int       `json:"quality_score"`
	ThresholdVersion  string    `json:"threshold_version"`
	TriggerAlertID    string    `json:"trigger_alert_id"`
	DensityCount      int       `json:"density_count,omitempty"`
	DensityWindow     string    `json:"density_window,omitempty"`
	DensityReason     string    `json:"density_reason,omitempty"`
}
type ReviewSnapshot struct {
	ID               string    `json:"id"`
	Revision         int       `json:"revision"`
	Digest           string    `json:"digest"`
	ThresholdVersion string    `json:"threshold_version"`
	QualityScore     int       `json:"quality_score"`
	RiskFactors      []string  `json:"risk_factors,omitempty"`
	Operator         string    `json:"operator"`
	Preview          bool      `json:"preview"`
	Adopted          bool      `json:"adopted"`
	Success          bool      `json:"success"`
	At               time.Time `json:"at"`
	Error            string    `json:"error,omitempty"`
}
type ReviewAttempt struct {
	Attempt      int        `json:"attempt"`
	At           time.Time  `json:"at"`
	Operator     string     `json:"operator"`
	Digest       string     `json:"digest"`
	Category     string     `json:"category"`
	Action       string     `json:"action"`
	NextReviewAt *time.Time `json:"next_review_at,omitempty"`
	Success      bool       `json:"success"`
}
type CheckinCorrection struct {
	Checkpoint     string     `json:"checkpoint"`
	OriginalAt     time.Time  `json:"original_at"`
	OriginalPerson string     `json:"original_person"`
	RequestedAt    time.Time  `json:"requested_at"`
	RequestedBy    string     `json:"requested_by"`
	Reason         string     `json:"reason"`
	IdempotencyKey string     `json:"idempotency_key,omitempty"`
	Status         string     `json:"status"`
	ApprovedBy     string     `json:"approved_by,omitempty"`
	DecisionAt     *time.Time `json:"decision_at,omitempty"`
}
type Checkin struct {
	ID             string    `json:"id"`
	At             time.Time `json:"at"`
	SubmittedAt    time.Time `json:"submitted_at"`
	Person         string    `json:"person"`
	Checkpoint     string    `json:"checkpoint"`
	Reason         string    `json:"reason,omitempty"`
	Kind           string    `json:"kind"`
	IdempotencyKey string    `json:"idempotency_key,omitempty"`
	Valid          bool      `json:"valid"`
}
type AlertRef struct {
	AlertID           string    `json:"alert_id"`
	SensorID          string    `json:"sensor_id"`
	BridgeID          string    `json:"bridge_id"`
	CapturedAt        time.Time `json:"captured_at"`
	PeakAmplitude     float64   `json:"peak_amplitude"`
	DominantFrequency float64   `json:"dominant_frequency"`
	DurationMS        int       `json:"duration_ms"`
	RawDigest         string    `json:"raw_digest"`
}
type Evidence struct {
	EvidenceID        string            `json:"evidence_id"`
	CaseID            string            `json:"case_id"`
	Checkpoint        string            `json:"checkpoint"`
	Hash              string            `json:"hash"`
	ArrivedAt         time.Time         `json:"arrived_at"`
	PhotoRefs         []string          `json:"photo_refs"`
	ResamplePeak      float64           `json:"resample_peak"`
	ResampleFrequency float64           `json:"resample_frequency"`
	ResampleDuration  int               `json:"resample_duration"`
	ResampleDigest    string            `json:"resample_digest"`
	Notes             string            `json:"notes"`
	SubmittedBy       string            `json:"submitted_by"`
	Version           int               `json:"version"`
	History           []EvidenceVersion `json:"history,omitempty"`
	DueState          string            `json:"due_state,omitempty"`
	LateMinutes       int               `json:"late_minutes,omitempty"`
	LateReason        string            `json:"late_reason,omitempty"`
	LateConfirmedBy   string            `json:"late_confirmed_by,omitempty"`
	LateConfirmedAt   *time.Time        `json:"late_confirmed_at,omitempty"`
	SubmittedAt       time.Time         `json:"submitted_at,omitempty"`
}
type EvidenceVersion struct {
	Version           int       `json:"version"`
	Hash              string    `json:"hash"`
	At                time.Time `json:"at"`
	SubmittedBy       string    `json:"submitted_by"`
	Change            string    `json:"change,omitempty"`
	Checkpoint        string    `json:"checkpoint,omitempty"`
	PhotoRefs         []string  `json:"photo_refs,omitempty"`
	ResamplePeak      float64   `json:"resample_peak,omitempty"`
	ResampleFrequency float64   `json:"resample_frequency,omitempty"`
	ResampleDuration  int       `json:"resample_duration,omitempty"`
	ResampleDigest    string    `json:"resample_digest,omitempty"`
	Notes             string    `json:"notes,omitempty"`
	PrevHash          string    `json:"prev_hash,omitempty"`
}
type Decision struct {
	DecisionID          string          `json:"decision_id"`
	CaseID              string          `json:"case_id"`
	Action              string          `json:"action"`
	MonitoringWindow    string          `json:"monitoring_window"`
	ApprovedBy          string          `json:"approved_by"`
	Reason              string          `json:"reason"`
	ApprovedAt          time.Time       `json:"approved_at"`
	TemplateVersion     string          `json:"template_version"`
	NextReviewAt        string          `json:"next_review_at,omitempty"`
	WithdrawnAt         *time.Time      `json:"withdrawn_at,omitempty"`
	Checklist           map[string]bool `json:"checklist,omitempty"`
	ConfirmedBy         string          `json:"confirmed_by,omitempty"`
	ConfirmedAt         *time.Time      `json:"confirmed_at,omitempty"`
	ConfirmedReason     string          `json:"confirmed_reason,omitempty"`
	Status              string          `json:"status,omitempty"`
	Supersedes          string          `json:"supersedes,omitempty"`
	SupersededAt        *time.Time      `json:"superseded_at,omitempty"`
	RuleVersion         string          `json:"rule_version,omitempty"`
	RuleSummary         string          `json:"rule_summary,omitempty"`
	MonitoringFrequency string          `json:"monitoring_frequency,omitempty"`
	SiteIsolation       string          `json:"site_isolation,omitempty"`
}
type Task struct {
	TaskID                 string     `json:"task_id"`
	CaseID                 string     `json:"case_id"`
	Assignee               string     `json:"assignee"`
	TargetCheckpoint       string     `json:"target_checkpoint"`
	Status                 string     `json:"status"`
	DueAt                  *time.Time `json:"due_at"`
	FirstArrivedAt         *time.Time `json:"first_arrived_at,omitempty"`
	Late                   bool       `json:"late"`
	ArrivalReason          string     `json:"arrival_reason,omitempty"`
	ReassignedBy           string     `json:"reassigned_by,omitempty"`
	ReassignReason         string     `json:"reassign_reason,omitempty"`
	LateMinutes            int        `json:"late_minutes"`
	DueState               string     `json:"due_state,omitempty"`
	EscalationLevel        string     `json:"escalation_level,omitempty"`
	LastEscalationAt       *time.Time `json:"last_escalation_at,omitempty"`
	EscalationAcknowledged bool       `json:"escalation_acknowledged,omitempty"`
	EscalationReason       string     `json:"escalation_reason,omitempty"`
	CorrectionPending      bool       `json:"correction_pending,omitempty"`
}
type Retest struct {
	ID                string    `json:"id"`
	CaseID            string    `json:"case_id"`
	At                time.Time `json:"at"`
	PeakAmplitude     float64   `json:"peak_amplitude"`
	DominantFrequency float64   `json:"dominant_frequency"`
	DurationMS        int       `json:"duration_ms"`
	Passed            bool      `json:"passed"`
	Explanation       string    `json:"explanation"`
	ChangeRate        float64   `json:"change_rate"`
	Revision          int       `json:"revision"`
	BaselineOK        bool      `json:"baseline_ok"`
	BaselineReason    string    `json:"baseline_reason,omitempty"`
	EvidenceBaseline  string    `json:"evidence_baseline,omitempty"`
}
type Event struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	CaseID    string         `json:"case_id"`
	RequestID string         `json:"request_id,omitempty"`
	At        time.Time      `json:"at"`
	Data      map[string]any `json:"data,omitempty"`
	PrevHash  string         `json:"prev_hash,omitempty"`
	Hash      string         `json:"hash,omitempty"`
}
type Store struct {
	mu   sync.RWMutex
	data Snapshot
	path string
	seen map[string]any
}

func New(path string) *Store {
	s := &Store{path: path, seen: map[string]any{}, data: Snapshot{Alerts: map[string]Alert{}, Cases: map[string]Case{}, Evidence: map[string]Evidence{}, Decisions: map[string]Decision{}, Tasks: map[string]Task{}, Retests: map[string]Retest{}, Batches: map[string]Batch{}, Idempotency: map[string]any{}}}
	if path != "" {
		s.load()
	}
	return s
}
func (s *Store) load() {
	b, e := os.ReadFile(s.path)
	if e != nil {
		return
	}
	var d Snapshot
	if json.Unmarshal(b, &d) == nil {
		if d.Alerts == nil {
			d.Alerts = map[string]Alert{}
		}
		if d.Cases == nil {
			d.Cases = map[string]Case{}
		}
		if d.Evidence == nil {
			d.Evidence = map[string]Evidence{}
		}
		if d.Decisions == nil {
			d.Decisions = map[string]Decision{}
		}
		if d.Tasks == nil {
			d.Tasks = map[string]Task{}
		}
		if d.Retests == nil {
			d.Retests = map[string]Retest{}
		}
		if d.Batches == nil {
			d.Batches = map[string]Batch{}
		}
		if d.Idempotency == nil {
			d.Idempotency = map[string]any{}
		}
		// Backfill hash fields for snapshots written before audit chaining.
		last := map[string]string{}
		for i := range d.Events {
			e := &d.Events[i]
			if e.Hash != "" {
				last[e.CaseID] = e.Hash
				continue
			}
			prev := last[e.CaseID]
			if prev == "" {
				prev = e.CaseID
			}
			b, _ := json.Marshal(struct {
				Type   string         `json:"type"`
				CaseID string         `json:"case_id"`
				At     time.Time      `json:"at"`
				Data   map[string]any `json:"data,omitempty"`
			}{e.Type, e.CaseID, e.At, e.Data})
			h := sha256.Sum256(append([]byte(prev+"|"), b...))
			e.PrevHash = prev
			e.Hash = hex.EncodeToString(h[:])
			last[e.CaseID] = e.Hash
		}
		s.data = d
		s.seen = d.Idempotency
	}
}
func (s *Store) persist() {
	if s.path == "" {
		return
	}
	b, _ := json.MarshalIndent(s.data, "", "  ")
	tmp := s.path + ".tmp"
	_ = os.MkdirAll(filepath.Dir(s.path), 0755)
	if os.WriteFile(tmp, b, 0644) == nil {
		_ = os.Rename(tmp, s.path)
	}
}
func (s *Store) Event(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := ""
	for i := len(s.data.Events) - 1; i >= 0; i-- {
		if s.data.Events[i].CaseID == e.CaseID {
			prev = s.data.Events[i].Hash
			break
		}
	}
	if prev == "" {
		prev = e.CaseID
	}
	e.PrevHash = prev
	b, _ := json.Marshal(struct {
		Type   string         `json:"type"`
		CaseID string         `json:"case_id"`
		At     time.Time      `json:"at"`
		Data   map[string]any `json:"data,omitempty"`
	}{e.Type, e.CaseID, e.At, e.Data})
	h := sha256.Sum256(append([]byte(prev+"|"), b...))
	e.Hash = hex.EncodeToString(h[:])
	s.data.Events = append(s.data.Events, e)
	if c, ok := s.data.Cases[e.CaseID]; ok {
		c.AuditCount = len(s.eventsForCaseLocked(e.CaseID))
		s.data.Cases[e.CaseID] = c
	}
	s.persist()
}
func (s *Store) eventsForCaseLocked(id string) []Event {
	out := []Event{}
	for _, e := range s.data.Events {
		if e.CaseID == id {
			out = append(out, e)
		}
	}
	return out
}
func (s *Store) VerifyEventChain(id string) (bool, string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var prev string
	count := 0
	for _, e := range s.data.Events {
		if e.CaseID != id {
			continue
		}
		count++
		p := prev
		if p == "" {
			p = id
		}
		b, _ := json.Marshal(struct {
			Type   string         `json:"type"`
			CaseID string         `json:"case_id"`
			At     time.Time      `json:"at"`
			Data   map[string]any `json:"data,omitempty"`
		}{e.Type, e.CaseID, e.At, e.Data})
		h := sha256.Sum256(append([]byte(p+"|"), b...))
		if e.PrevHash != p || e.Hash != hex.EncodeToString(h[:]) {
			return false, e.ID, "审计哈希链异常"
		}
		prev = e.Hash
	}
	return true, "", ""
}
func (s *Store) RepairEventChain(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := id
	found := false
	for i := range s.data.Events {
		e := &s.data.Events[i]
		if e.CaseID != id {
			continue
		}
		found = true
		b, _ := json.Marshal(struct {
			Type   string         `json:"type"`
			CaseID string         `json:"case_id"`
			At     time.Time      `json:"at"`
			Data   map[string]any `json:"data,omitempty"`
		}{e.Type, e.CaseID, e.At, e.Data})
		h := sha256.Sum256(append([]byte(prev+"|"), b...))
		e.PrevHash = prev
		e.Hash = hex.EncodeToString(h[:])
		prev = e.Hash
	}
	if found {
		s.persist()
	}
	return nil
}
func (s *Store) PutAlert(a Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Alerts[a.AlertID] = a
	s.persist()
}
func (s *Store) GetAlert(id string) (Alert, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.data.Alerts[id]
	return a, ok
}
func (s *Store) ListAlertsBySource(bridgeID, sensorID string, from, to time.Time) []Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Alert{}
	for _, a := range s.data.Alerts {
		if bridgeID != "" && a.BridgeID != bridgeID {
			continue
		}
		if sensorID != "" && a.SensorID != sensorID {
			continue
		}
		if !from.IsZero() && a.CapturedAt.Before(from) {
			continue
		}
		if !to.IsZero() && a.CapturedAt.After(to) {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CapturedAt.Before(out[j].CapturedAt) })
	return out
}
func (s *Store) PutCase(c Case) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Cases[c.CaseID] = c
	s.persist()
}
func (s *Store) GetCase(id string) (Case, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.data.Cases[id]
	return c, ok
}
func (s *Store) ListCases() []Case {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Case, 0, len(s.data.Cases))
	for _, c := range s.data.Cases {
		out = append(out, c)
	}
	return out
}
func (s *Store) FindCaseByAlert(id string) (Case, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.data.Cases {
		if c.AlertID == id {
			return c, true
		}
	}
	return Case{}, false
}
func (s *Store) FindSimilarAlert(alertID, sensorID string, captured time.Time, window time.Duration) (Case, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.data.Cases {
		if alertID != "" && c.AlertID == alertID {
			return c, true
		}
		a, ok := s.data.Alerts[c.AlertID]
		if !ok || a.SensorID != sensorID {
			continue
		}
		if captured.Sub(a.CapturedAt) < 0 {
			if a.CapturedAt.Sub(captured) <= window {
				return c, true
			}
		} else if captured.Sub(a.CapturedAt) <= window {
			return c, true
		}
	}
	return Case{}, false
}

// FindSimilarAlertBySource also treats a bridge-local sensor change as the same
// short-window incident so source migration remains auditable on one case.
func (s *Store) FindSimilarAlertBySource(alertID, bridgeID, sensorID string, captured time.Time, window time.Duration) (Case, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.data.Cases {
		if alertID != "" && c.AlertID == alertID {
			return c, true
		}
		a, ok := s.data.Alerts[c.AlertID]
		if !ok || bridgeID == "" || a.BridgeID != bridgeID {
			continue
		}
		delta := captured.Sub(a.CapturedAt)
		if delta < 0 {
			delta = -delta
		}
		if delta <= window {
			return c, true
		}
	}
	return Case{}, false
}
func (s *Store) EventsForCase(id string) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Event{}
	for _, e := range s.data.Events {
		if e.CaseID == id {
			out = append(out, e)
		}
	}
	return out
}
func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}
func (s *Store) SetThresholdCatalog(v []any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.ThresholdCatalog = v
	s.persist()
}
func (s *Store) ThresholdCatalog() []any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]any(nil), s.data.ThresholdCatalog...)
}
func (s *Store) PutTask(t Task) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Tasks[t.TaskID] = t
	s.persist()
}
func (s *Store) GetTask(id string) (Task, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.data.Tasks[id]
	return t, ok
}
func (s *Store) GetTaskByCase(id string) (Task, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.data.Tasks {
		if t.CaseID == id {
			return t, true
		}
	}
	return Task{}, false
}
func (s *Store) PutRetest(r Retest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Retests[r.ID] = r
	s.persist()
}
func (s *Store) PutBatch(b Batch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Batches == nil {
		s.data.Batches = map[string]Batch{}
	}
	s.data.Batches[b.BatchID] = b
	s.persist()
}
func (s *Store) GetBatch(id string) (Batch, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.data.Batches[id]
	return b, ok
}
func (s *Store) ListBatches() []Batch {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Batch, 0, len(s.data.Batches))
	for _, b := range s.data.Batches {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
func (s *Store) ListRetests(id string) []Retest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Retest{}
	for _, r := range s.data.Retests {
		if r.CaseID == id {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}
func (s *Store) CountEvents(id string) int { return len(s.EventsForCase(id)) }
func (s *Store) PutEvidence(e Evidence) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Evidence[e.EvidenceID] = e
	s.persist()
}
func (s *Store) GetEvidenceByCase(id string) (Evidence, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.data.Evidence {
		if e.CaseID == id {
			return e, true
		}
	}
	return Evidence{}, false
}
func (s *Store) FindEvidenceConflict(caseID string, refs []string, fingerprint string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	wanted := map[string]bool{}
	for _, r := range refs {
		wanted[r] = true
	}
	for _, e := range s.data.Evidence {
		if e.CaseID == caseID {
			continue
		}
		owner := false
		for _, r := range e.PhotoRefs {
			if wanted[r] {
				owner = true
			}
		}
		if owner {
			return e.CaseID, true
		}
		if fingerprint != "" { // compare stored resample identity
			f := fmt.Sprintf("%.4f|%.4f|%d|%s", e.ResamplePeak, e.ResampleFrequency, e.ResampleDuration, e.ResampleDigest)
			if strings.Contains(f, fingerprint) {
				return e.CaseID, true
			}
		}
	}
	return "", false
}
func (s *Store) PutDecision(d Decision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Decisions[d.DecisionID] = d
	s.persist()
}
func (s *Store) GetDecision(id string) (Decision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.data.Decisions[id]
	return d, ok
}
func (s *Store) Once(key string) (bool, any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.seen[key]
	return ok, v
}
func (s *Store) Mark(key string, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[key] = v
	s.data.Idempotency[key] = v
	s.persist()
}

var ErrNotFound = errors.New("not found")
