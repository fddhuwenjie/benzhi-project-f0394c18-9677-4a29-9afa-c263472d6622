package workflow

import (
	"bridgewatch/internal/assessment"
	"bridgewatch/internal/evidence"
	"bridgewatch/internal/store"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

func New(st *store.Store) *Service {
	cat := make([]any, 0)
	for _, x := range assessment.ThresholdCatalog() {
		cat = append(cat, x)
	}
	if len(st.ThresholdCatalog()) == 0 {
		st.SetThresholdCatalog(cat)
	}
	s := &Service{Store: st, AssociationWindow: 5 * time.Minute}
	for _, c := range st.ListCases() {
		if c.Claim != nil && time.Now().After(c.Claim.ExpiresAt) {
			old := c.Claim.Holder
			c.Claim = nil
			st.PutCase(c)
			st.Event(store.Event{ID: newID(), Type: "case_claim_expired", CaseID: c.CaseID, At: time.Now(), Data: map[string]any{"holder": old, "recovered": true}})
		}
	}
	return s
}
func newID() string { b := make([]byte, 12); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func appendUniqueAlertRef(refs []store.AlertRef, in AlertInput) []store.AlertRef {
	for _, r := range refs {
		if r.AlertID == in.AlertID && in.AlertID != "" {
			return refs
		}
	}
	return append(refs, store.AlertRef{AlertID: in.AlertID, SensorID: in.SensorID, BridgeID: in.BridgeID, CapturedAt: in.CapturedAt, PeakAmplitude: in.PeakAmplitude, DominantFrequency: in.DominantFrequency, DurationMS: in.DurationMS, RawDigest: in.RawDigest})
}

func (s *Service) enrichAlertCase(c *store.Case, in AlertInput, received time.Time) {
	tc := assessment.CheckTime(in.CapturedAt, received, in.DriftTolerance)
	c.TimeQuality, c.DriftSeconds = tc.Quality, tc.DriftSeconds
	if tc.Quality != "trusted" {
		now := received
		if c.FirstDriftAt == nil {
			c.FirstDriftAt = &now
		}
		c.LastDriftAt = &now
		if math.Abs(tc.DriftSeconds) > math.Abs(c.MaxDriftSeconds) {
			c.MaxDriftSeconds = tc.DriftSeconds
		}
		s.Store.Event(store.Event{ID: newID(), Type: "sensor_time_drift", CaseID: c.CaseID, At: received, Data: map[string]any{"quality": tc.Quality, "drift_seconds": tc.DriftSeconds, "reason": tc.Reason}})
	}
	window := in.DensityWindow
	if window <= 0 {
		window = 15 * time.Minute
	}
	alerts := s.Store.ListAlertsBySource(in.BridgeID, in.SensorID, in.CapturedAt.Add(-window), in.CapturedAt.Add(window))
	times := make([]time.Time, 0, len(alerts))
	for _, a := range alerts {
		if assessment.Check(assessment.Signal{PeakAmplitude: a.PeakAmplitude, DominantFrequency: a.DominantFrequency, DurationMS: a.DurationMS, RawDigest: a.RawDigest}).Valid {
			times = append(times, a.CapturedAt)
		}
	}
	d := assessment.AssessDensity(times, assessment.Risk(c.RiskLevel), window, in.AlertID)
	c.DensityCount, c.DensityWindow, c.DensityReason, c.DensityTriggerAlertID = d.Count, window.String(), d.Reason, d.TriggerAlertID
	if d.Upgrade && c.Status == "pending_review" && tc.Quality != "severe_drift" {
		old := c.RiskLevel
		c.RiskLevel = string(d.Risk)
		c.RiskFactors = append(c.RiskFactors, "密度因子: "+d.Reason)
		c.RiskHistory = append(c.RiskHistory, store.RiskSnapshot{At: received, AlertCount: d.Count, RiskLevel: c.RiskLevel, QualityScore: c.QualityScore, ThresholdVersion: c.ThresholdVersion, TriggerAlertID: in.AlertID, DensityCount: d.Count, DensityWindow: window.String(), DensityReason: d.Reason})
		if old != c.RiskLevel {
			s.Store.Event(store.Event{ID: newID(), Type: "density_risk_upgraded", CaseID: c.CaseID, At: received, Data: map[string]any{"old_risk": old, "new_risk": c.RiskLevel, "count": d.Count, "window": window.String(), "trigger_alert_id": in.AlertID}})
		}
	}
	if tc.Quality == "severe_drift" {
		c.Status = "pending_time_review"
		c.RiskLevel = "unassessed"
		c.QualityReason = tc.Reason
	}
}

// recomputeAggregatedRisk recalculates a case from all valid associated alerts.
// It deliberately keeps confirmed conclusions immutable after field inspection.
func (s *Service) recomputeAggregatedRisk(c *store.Case, trigger string) {
	if len(c.AssociatedAlerts) == 0 {
		return
	}
	latest := c.AssociatedAlerts[len(c.AssociatedAlerts)-1]
	peak, freq, dur := latest.PeakAmplitude, latest.DominantFrequency, latest.DurationMS
	for _, a := range c.AssociatedAlerts {
		if a.PeakAmplitude > peak {
			peak = a.PeakAmplitude
		}
		if a.CapturedAt.After(latest.CapturedAt) {
			latest = a
			freq, dur = a.DominantFrequency, a.DurationMS
		}
	}
	sig := assessment.Signal{PeakAmplitude: peak, DominantFrequency: freq, DurationMS: dur, RawDigest: ""}
	q := assessment.Check(sig)
	if !q.Valid {
		s.Store.Event(store.Event{ID: newID(), Type: "risk_recompute_failed", CaseID: c.CaseID, At: time.Now(), Data: map[string]any{"reason": q.Reason, "alert_id": trigger}})
		return
	}
	ar := assessment.AssessVersion(sig, c.ThresholdVersion)
	if ar.ThresholdVersion == "" || !assessment.ValidThresholdVersion(ar.ThresholdVersion) {
		ar = assessment.Assess(sig)
	}
	old := c.RiskLevel
	c.RiskAlertCount = len(c.AssociatedAlerts)
	c.RiskQualityScore = ar.Quality.Score
	c.RiskHistory = append(c.RiskHistory, store.RiskSnapshot{At: time.Now(), AlertCount: len(c.AssociatedAlerts), PeakAmplitude: peak, DominantFrequency: freq, DurationMS: dur, RiskLevel: string(ar.Risk), QualityScore: ar.Quality.Score, ThresholdVersion: ar.ThresholdVersion, TriggerAlertID: trigger})
	if c.Status == "pending_review" {
		c.RiskLevel = string(ar.Risk)
		c.QualityScore, c.QualityReason = ar.Quality.Score, ar.Quality.Reason
		c.RiskExplanation, c.RiskFactors = ar.Explanation, ar.Factors
		now := ar.CalculatedAt
		c.RiskCalculatedAt = &now
		if old != c.RiskLevel {
			c.Revision++
			s.Store.Event(store.Event{ID: newID(), Type: "risk_diff", CaseID: c.CaseID, At: time.Now(), Data: map[string]any{"old_risk": old, "new_risk": c.RiskLevel, "alert_count": len(c.AssociatedAlerts), "trigger_alert_id": trigger, "threshold_version": ar.ThresholdVersion, "quality_score": ar.Quality.Score}})
		} else {
			c.Revision++
		}
		s.Store.PutCase(*c)
	} else if old != string(ar.Risk) {
		c.NeedsReReview = true
		s.Store.Event(store.Event{ID: newID(), Type: "risk_re_review_required", CaseID: c.CaseID, At: time.Now(), Data: map[string]any{"old_risk": old, "new_risk": ar.Risk, "trigger_alert_id": trigger, "alert_count": len(c.AssociatedAlerts)}})
		s.Store.PutCase(*c)
	}
}

func thresholdToken(caseID string, rev int, sig assessment.Signal, primary, compare string, ar assessment.Result, cmp *assessment.Result) string {
	cmpRisk := ""
	cmpQuality := 0
	if cmp != nil {
		cmpRisk, cmpQuality = string(cmp.Risk), cmp.Quality.Score
	}
	s := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%d|%s|%d", caseID, rev, assessment.Digest(sig), primary, compare, ar.Risk, ar.Quality.Score, cmpRisk, cmpQuality)
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func (s *Service) Receive(in AlertInput, req string) (store.Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(in.BridgeID) == "" {
		return store.Case{}, errors.New("bridge_id不能为空")
	}
	if strings.TrimSpace(in.SensorID) == "" {
		return store.Case{}, errors.New("sensor_id不能为空")
	}
	if in.CapturedAt.IsZero() {
		return store.Case{}, errors.New("captured_at不能为空")
	}
	received := in.ReceivedAt
	if received.IsZero() {
		received = time.Now()
	}
	if in.DurationMS <= 0 || in.DurationMS > 86400000 {
		return store.Case{}, errors.New("duration_ms必须在1到86400000之间")
	}
	if math.IsNaN(in.PeakAmplitude) || math.IsInf(in.PeakAmplitude, 0) || math.IsNaN(in.DominantFrequency) || math.IsInf(in.DominantFrequency, 0) || in.PeakAmplitude < 0 || in.PeakAmplitude > 100 || in.DominantFrequency <= 0 {
		return store.Case{}, errors.New("幅值或频率无效")
	}
	quality := assessment.Check(in.Signal)
	if req != "" {
		if ok, v := s.Store.Once("alert:" + req); ok {
			if c, ok := v.(store.Case); ok {
				return c, nil
			}
		}
	}
	if quality.Valid && in.AlertID != "" {
		if c, ok := s.Store.FindCaseByAlert(in.AlertID); ok {
			if existing, okA := s.Store.GetAlert(c.AlertID); okA && existing.BridgeID != "" && existing.BridgeID != in.BridgeID {
				// Same identifier from another bridge is a conflicting source, never merge.
				s.Store.Event(store.Event{ID: newID(), Type: "alert_association_rejected", CaseID: c.CaseID, RequestID: req, At: time.Now(), Data: map[string]any{"reason": "bridge_id冲突", "bridge_id": in.BridgeID}})
			} else {
				oldCaptured := c.CurrentCapturedAt
				s.Store.PutAlert(store.Alert{AlertID: in.AlertID, BridgeID: in.BridgeID, SensorID: in.SensorID, CapturedAt: in.CapturedAt, PeakAmplitude: in.PeakAmplitude, DominantFrequency: in.DominantFrequency, DurationMS: in.DurationMS, RawDigest: in.RawDigest, ReceivedAt: received, TimeQuality: assessment.CheckTime(in.CapturedAt, received, in.DriftTolerance).Quality, DriftSeconds: assessment.CheckTime(in.CapturedAt, received, in.DriftTolerance).DriftSeconds})
				oldBridge, oldSensor := c.CurrentBridgeID, c.CurrentSensorID
				if oldBridge == "" || oldSensor == "" {
					if old, ok := s.Store.GetAlert(c.AlertID); ok {
						oldBridge, oldSensor = old.BridgeID, old.SensorID
					}
				}
				if oldSensor != in.SensorID || oldBridge != in.BridgeID {
					s.Store.Event(store.Event{ID: newID(), Type: "alert_source_changed", CaseID: c.CaseID, RequestID: req, At: time.Now(), Data: map[string]any{"from_sensor": oldSensor, "to_sensor": in.SensorID, "from_bridge": oldBridge, "to_bridge": in.BridgeID}})
				}
				c.CurrentBridgeID, c.CurrentSensorID, c.CurrentCapturedAt = in.BridgeID, in.SensorID, &in.CapturedAt
				c.MergeCount++
				c.AssociatedAlerts = appendUniqueAlertRef(c.AssociatedAlerts, in)
				c.Revision++
				s.enrichAlertCase(&c, in, received)
				s.Store.PutCase(c)
				s.recomputeAggregatedRisk(&c, in.AlertID)
				delta := int64(0)
				if oldCaptured != nil {
					delta = int64(in.CapturedAt.Sub(*oldCaptured) / time.Millisecond)
					if delta < 0 {
						delta = -delta
					}
				}
				s.Store.Event(store.Event{ID: newID(), Type: "alert_associated", CaseID: c.CaseID, RequestID: req, At: time.Now(), Data: map[string]any{"merge_count": c.MergeCount, "alert_id": in.AlertID, "sensor_id": in.SensorID, "bridge_id": in.BridgeID, "delta_ms": delta, "peak_amplitude": in.PeakAmplitude, "dominant_frequency": in.DominantFrequency, "duration_ms": in.DurationMS}})
				if req != "" {
					s.Store.Mark("alert:"+req, c)
				}
				return c, nil
			}
		}
	}
	if quality.Valid {
		window := s.AssociationWindow
		if window <= 0 {
			window = 5 * time.Minute
		}
		if c, ok := s.Store.FindSimilarAlertBySource(in.AlertID, in.BridgeID, in.SensorID, in.CapturedAt, window); ok {
			oldCaptured := c.CurrentCapturedAt
			s.Store.PutAlert(store.Alert{AlertID: in.AlertID, BridgeID: in.BridgeID, SensorID: in.SensorID, CapturedAt: in.CapturedAt, PeakAmplitude: in.PeakAmplitude, DominantFrequency: in.DominantFrequency, DurationMS: in.DurationMS, RawDigest: in.RawDigest, ReceivedAt: received, TimeQuality: assessment.CheckTime(in.CapturedAt, received, in.DriftTolerance).Quality, DriftSeconds: assessment.CheckTime(in.CapturedAt, received, in.DriftTolerance).DriftSeconds})
			oldBridge, oldSensor := c.CurrentBridgeID, c.CurrentSensorID
			if oldBridge == "" || oldSensor == "" {
				if old, ok := s.Store.GetAlert(c.AlertID); ok {
					oldBridge, oldSensor = old.BridgeID, old.SensorID
				}
			}
			if oldSensor != in.SensorID || oldBridge != in.BridgeID {
				s.Store.Event(store.Event{ID: newID(), Type: "alert_source_changed", CaseID: c.CaseID, RequestID: req, At: time.Now(), Data: map[string]any{"from_sensor": oldSensor, "to_sensor": in.SensorID, "from_bridge": oldBridge, "to_bridge": in.BridgeID}})
			}
			c.CurrentBridgeID, c.CurrentSensorID, c.CurrentCapturedAt = in.BridgeID, in.SensorID, &in.CapturedAt
			c.MergeCount++
			c.AssociatedAlerts = appendUniqueAlertRef(c.AssociatedAlerts, in)
			c.Revision++
			s.enrichAlertCase(&c, in, received)
			s.Store.PutCase(c)
			s.recomputeAggregatedRisk(&c, in.AlertID)
			delta := int64(0)
			if oldCaptured != nil {
				delta = int64(in.CapturedAt.Sub(*oldCaptured) / time.Millisecond)
				if delta < 0 {
					delta = -delta
				}
			}
			s.Store.Event(store.Event{ID: newID(), Type: "alert_associated", CaseID: c.CaseID, RequestID: req, At: time.Now(), Data: map[string]any{"merge_count": c.MergeCount, "window": window.String(), "sensor_id": in.SensorID, "bridge_id": in.BridgeID, "delta_ms": delta, "peak_amplitude": in.PeakAmplitude, "dominant_frequency": in.DominantFrequency, "duration_ms": in.DurationMS}})
			if req != "" {
				s.Store.Mark("alert:"+req, c)
			}
			return c, nil
		}
	}
	if in.AlertID == "" {
		in.AlertID = newID()
	}
	tc := assessment.CheckTime(in.CapturedAt, received, in.DriftTolerance)
	a := store.Alert{AlertID: in.AlertID, BridgeID: in.BridgeID, SensorID: in.SensorID, CapturedAt: in.CapturedAt, PeakAmplitude: in.PeakAmplitude, DominantFrequency: in.DominantFrequency, DurationMS: in.DurationMS, RawDigest: in.RawDigest, ReceivedAt: received, TimeQuality: tc.Quality, DriftSeconds: tc.DriftSeconds}
	ar := assessment.Assess(in.Signal)
	status := "pending_review"
	if ar.Risk == assessment.Noise {
		status = "noise"
	}
	if tc.Quality == "severe_drift" {
		status = "pending_time_review"
		ar.Risk = assessment.Noise
		ar.Quality.Valid = false
		ar.Quality.Reason = tc.Reason
	}
	now := time.Now()
	ts, _ := assessment.ThresholdSnapshot(ar.ThresholdVersion)
	c := store.Case{CaseID: newID(), AlertID: in.AlertID, Status: status, RiskLevel: string(ar.Risk), Revision: 1, OpenedAt: &now, ReceivedAt: now, BeforePeak: in.PeakAmplitude, ThresholdVersion: ar.ThresholdVersion, ThresholdSnapshot: ts, RiskExplanation: ar.Explanation, RiskFactors: ar.Factors, QualityScore: ar.Quality.Score, QualityReason: ar.Quality.Reason, RiskCalculatedAt: &ar.CalculatedAt, MergeCount: 1, SourceBridgeID: in.BridgeID, SourceSensorID: in.SensorID, SourceCapturedAt: &in.CapturedAt, CurrentBridgeID: in.BridgeID, CurrentSensorID: in.SensorID, CurrentCapturedAt: &in.CapturedAt, TimeQuality: tc.Quality, DriftSeconds: tc.DriftSeconds, AssociatedAlerts: []store.AlertRef{{AlertID: in.AlertID, SensorID: in.SensorID, BridgeID: in.BridgeID, CapturedAt: in.CapturedAt, PeakAmplitude: in.PeakAmplitude, DominantFrequency: in.DominantFrequency, DurationMS: in.DurationMS, RawDigest: in.RawDigest}}}
	s.Store.PutAlert(a)
	s.Store.PutCase(c)
	s.enrichAlertCase(&c, in, received)
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "alert_received", CaseID: c.CaseID, RequestID: req, At: now})
	if !quality.Valid {
		s.Store.Event(store.Event{ID: newID(), Type: "alert_association_rejected", CaseID: c.CaseID, RequestID: req, At: now, Data: map[string]any{"reason": "摘要无效: " + quality.Reason}})
	}
	if req != "" {
		s.Store.Mark("alert:"+req, c)
	}
	return c, nil
}

// SplitAlert removes one associated alert from a pending case and creates a
// new independent case for it. Both snapshots are updated together while the
// workflow mutex is held; failures leave the original association untouched.
func (s *Service) SplitAlert(id, alertID string, rev int, operator, idem string) (store.Case, store.Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idem != "" {
		if ok, v := s.Store.Once("split:" + idem); ok {
			if x, ok := v.([2]store.Case); ok {
				return x[0], x[1], nil
			}
		}
	}
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.Case{}, store.ErrNotFound
	}
	if c.Revision != rev {
		return c, store.Case{}, ErrConflict
	}
	if c.Status != "pending_review" {
		return c, store.Case{}, ErrInvalidTransition
	}
	if len(c.AssociatedAlerts) <= 1 {
		return c, store.Case{}, errors.New("不能拆分唯一告警")
	}
	idx := -1
	var ar store.AlertRef
	for i, a := range c.AssociatedAlerts {
		if a.AlertID == alertID {
			idx = i
			ar = a
			break
		}
	}
	if idx < 0 {
		return c, store.Case{}, errors.New("告警不属于案件")
	}
	refs := append([]store.AlertRef(nil), c.AssociatedAlerts...)
	c.AssociatedAlerts = append(refs[:idx], refs[idx+1:]...)
	c.MergeCount = len(c.AssociatedAlerts)
	c.RiskAlertCount = len(c.AssociatedAlerts)
	c.Revision++
	s.recomputeAggregatedRisk(&c, "split:"+alertID)
	now := time.Now()
	sig := assessment.Signal{PeakAmplitude: ar.PeakAmplitude, DominantFrequency: ar.DominantFrequency, DurationMS: ar.DurationMS, RawDigest: ar.RawDigest}
	rr := assessment.AssessVersion(sig, c.ThresholdVersion)
	status := "pending_review"
	if rr.Risk == assessment.Noise {
		status = "noise"
	}
	nc := store.Case{CaseID: newID(), AlertID: ar.AlertID, Status: status, RiskLevel: string(rr.Risk), Revision: 1, OpenedAt: &now, ReceivedAt: now, BeforePeak: ar.PeakAmplitude, ThresholdVersion: rr.ThresholdVersion, ThresholdSnapshot: func() any { x, _ := assessment.ThresholdSnapshot(rr.ThresholdVersion); return x }(), RiskExplanation: rr.Explanation, RiskFactors: rr.Factors, QualityScore: rr.Quality.Score, QualityReason: rr.Quality.Reason, RiskCalculatedAt: &rr.CalculatedAt, MergeCount: 1, SourceBridgeID: ar.BridgeID, SourceSensorID: ar.SensorID, SourceCapturedAt: &ar.CapturedAt, CurrentBridgeID: ar.BridgeID, CurrentSensorID: ar.SensorID, CurrentCapturedAt: &ar.CapturedAt, AssociatedAlerts: []store.AlertRef{ar}}
	s.Store.PutCase(c)
	s.Store.PutCase(nc)
	s.Store.Event(store.Event{ID: newID(), Type: "alert_split", CaseID: id, At: now, Data: map[string]any{"new_case_id": nc.CaseID, "alert_id": alertID, "operator": operator}})
	s.Store.Event(store.Event{ID: newID(), Type: "alert_split_created", CaseID: nc.CaseID, At: now, Data: map[string]any{"original_case_id": id, "alert_id": alertID, "operator": operator}})
	if idem != "" {
		s.Store.Mark("split:"+idem, [2]store.Case{c, nc})
	}
	return c, nc, nil
}

func AlertFingerprint(in AlertInput) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%.6f|%.6f|%d|%s", in.AlertID, in.BridgeID, in.SensorID, in.CapturedAt.UTC().Format(time.RFC3339Nano), in.PeakAmplitude, in.DominantFrequency, in.DurationMS, in.RawDigest)))
	return hex.EncodeToString(h[:])
}

func (s *Service) ReplayBatch(batchID string, indexes []int, inputs []AlertInput) (store.Batch, error) {
	b, ok := s.Store.GetBatch(batchID)
	if !ok {
		return store.Batch{}, store.ErrNotFound
	}
	if len(indexes) != len(inputs) {
		return b, errors.New("重放项数量不匹配")
	}
	for i, idx := range indexes {
		if idx < 0 || idx >= len(b.Items) {
			return b, errors.New("批次项索引无效")
		}
		fp := AlertFingerprint(inputs[i])
		if fp != b.Items[idx].Fingerprint {
			return b, fmt.Errorf("批次项%d指纹冲突", idx)
		}
		if b.Items[idx].Status != "failed" {
			continue
		}
		c, e := s.Receive(inputs[i], b.Items[idx].RequestID)
		b.Items[idx].Attempts++
		if e != nil {
			b.Items[idx].Error = e.Error()
		} else {
			b.Items[idx].Status = "success"
			b.Items[idx].CaseID = c.CaseID
			b.Items[idx].RiskLevel, b.Items[idx].QualityScore, b.Items[idx].NeedsReReview = c.RiskLevel, c.QualityScore, c.NeedsReReview
			b.Items[idx].Error = ""
			b.FailureCount--
			b.SuccessCount++
		}
	}
	s.Store.PutBatch(b)
	s.Store.Event(store.Event{ID: newID(), Type: "alert_batch_replayed", RequestID: batchID, At: time.Now(), Data: map[string]any{"batch_id": batchID, "items": indexes}})
	return b, nil
}

type ReviewOptions struct {
	Reviewer, ThresholdVersion, CompareVersion, Reason string
	Summary                                            *assessment.Signal
	TargetCheckpoint                                   string
	Preview                                            bool
	IdempotencyKey                                     string
	ConfirmToken                                       string
	ConfirmedBy                                        string
	ClaimToken                                         string
	IndependentReview                                  bool
	Arbitration                                        bool
	ArbitrationBy, ArbitrationReason                   string
}

func (s *Service) ClaimCase(id, holder string, ttl time.Duration) (store.Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if c.Status != "pending_review" {
		return c, ErrInvalidTransition
	}
	if strings.TrimSpace(holder) == "" {
		return c, errors.New("holder不能为空")
	}
	now := time.Now()
	if c.Claim != nil && now.Before(c.Claim.ExpiresAt) {
		return c, ErrClaimRequired
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		ttl = 30 * time.Minute
	}
	token := newID()
	prev := ""
	if c.Claim != nil {
		prev = c.Claim.Holder
	}
	c.Claim = &store.CaseClaim{Token: token, Holder: holder, ClaimedAt: now, ExpiresAt: now.Add(ttl), LockVersion: c.Revision, LastHolder: prev}
	c.Revision++
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "case_claimed", CaseID: id, At: now, Data: map[string]any{"holder": holder, "expires_at": c.Claim.ExpiresAt, "lock_version": c.Claim.LockVersion}})
	return c, nil
}
func (s *Service) ReleaseCase(id, holder, token string) (store.Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if c.Claim == nil {
		return c, nil
	}
	if c.Claim.Holder != holder || (token != "" && c.Claim.Token != token) {
		return c, ErrClaimRequired
	}
	old := c.Claim.Holder
	c.Claim = nil
	c.Revision++
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "case_claim_released", CaseID: id, At: time.Now(), Data: map[string]any{"holder": old}})
	return c, nil
}
func (s *Service) RepairAuditChain(id, by, reason string) error {
	c, ok := s.Store.GetCase(id)
	if !ok {
		return store.ErrNotFound
	}
	if c.Status == "closed" {
		return errors.New("已关闭案件禁止修复审计链")
	}
	if strings.TrimSpace(reason) == "" {
		return errors.New("修复说明不能为空")
	}
	if err := s.Store.RepairEventChain(id); err != nil {
		return err
	}
	s.Store.Event(store.Event{ID: newID(), Type: "audit_chain_repaired", CaseID: id, At: time.Now(), Data: map[string]any{"by": by, "reason": reason}})
	return nil
}
func (s *Service) ClaimStatus(c store.Case) map[string]any {
	if c.Claim == nil {
		return map[string]any{"status": "available"}
	}
	now := time.Now()
	if now.After(c.Claim.ExpiresAt) {
		return map[string]any{"status": "expired", "holder": c.Claim.Holder, "remaining_seconds": 0}
	}
	return map[string]any{"status": "claimed", "holder": c.Claim.Holder, "remaining_seconds": int(time.Until(c.Claim.ExpiresAt).Seconds()), "lock_version": c.Claim.LockVersion}
}

// Diagnose performs the same pure waveform assessment used by review without
// changing the case or appending timeline events.
func (s *Service) Diagnose(id string, rev int, o ReviewOptions) (assessment.Result, *assessment.Result, error) {
	c, ok := s.Store.GetCase(id)
	if !ok {
		return assessment.Result{}, nil, store.ErrNotFound
	}
	if c.Revision != rev {
		return assessment.Result{}, nil, ErrConflict
	}
	if o.Summary == nil {
		return assessment.Result{}, nil, errors.New("preview需要summary")
	}
	v := o.ThresholdVersion
	if v == "" {
		v = assessment.DefaultThreshold()
	}
	ar, cmp, err := assessment.Compare(*o.Summary, v, o.CompareVersion)
	if err == nil {
		digest := assessment.Digest(*o.Summary)
		duplicate := false
		for _, snap := range c.ReviewSnapshots {
			if snap.Revision == rev && snap.Digest == digest {
				duplicate = true
				break
			}
		}
		if !duplicate {
			c.ReviewSnapshots = append(c.ReviewSnapshots, store.ReviewSnapshot{ID: newID(), Revision: rev, Digest: digest, ThresholdVersion: ar.ThresholdVersion, QualityScore: ar.Quality.Score, RiskFactors: ar.Factors, Operator: o.Reviewer, Preview: true, Success: ar.Quality.Valid, At: time.Now()})
			s.Store.Event(store.Event{ID: newID(), Type: "review_snapshot_preview", CaseID: id, At: time.Now(), Data: map[string]any{"digest": digest, "revision": rev}})
		}
		c.ThresholdConfirmToken = thresholdToken(id, rev, *o.Summary, v, o.CompareVersion, ar, cmp)
		s.Store.PutCase(c)
	} else {
		c.ReviewSnapshots = append(c.ReviewSnapshots, store.ReviewSnapshot{ID: newID(), Revision: rev, Digest: assessment.Digest(*o.Summary), ThresholdVersion: v, Operator: o.Reviewer, Preview: true, Success: false, Error: err.Error(), At: time.Now()})
		s.Store.PutCase(c)
		s.Store.Event(store.Event{ID: newID(), Type: "review_snapshot_failed", CaseID: id, At: time.Now(), Data: map[string]any{"reason": err.Error()}})
	}
	return ar, cmp, err
}

func (s *Service) Review(id string, rev int, reviewer string, versions ...string) (store.Case, error) {
	o := ReviewOptions{Reviewer: reviewer}
	if len(versions) > 0 {
		o.ThresholdVersion = versions[0]
	}
	if len(versions) > 1 {
		o.TargetCheckpoint = versions[1]
	}
	if len(versions) > 2 {
		o.Reason = versions[2]
	}
	return s.ReviewWithOptions(id, rev, o)
}
func (s *Service) ReleaseTimeGate(id string, rev int, by, reason string) (store.Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if c.Revision != rev {
		return c, ErrConflict
	}
	if c.Status != "pending_time_review" {
		return c, ErrInvalidTransition
	}
	if strings.TrimSpace(by) == "" || strings.TrimSpace(reason) == "" {
		return c, errors.New("时间放行需要人员和理由")
	}
	c.Status = "pending_review"
	c.RiskLevel = "unassessed"
	c.Revision++
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "sensor_time_released", CaseID: id, At: time.Now(), Data: map[string]any{"by": by, "reason": reason}})
	return c, nil
}
func (s *Service) ReviewWithOptions(id string, rev int, o ReviewOptions) (store.Case, error) {
	reviewer := o.Reviewer
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if o.Preview {
		return c, errors.New("preview应通过Diagnose调用")
	}
	if o.IdempotencyKey != "" {
		if ok, v := s.Store.Once("review:" + o.IdempotencyKey); ok {
			if old, ok := v.(store.Case); ok {
				return old, nil
			}
		}
	}
	if c.Revision != rev {
		return c, ErrConflict
	}
	if c.Status == "pending_time_review" {
		if strings.TrimSpace(o.Reason) == "" {
			return c, errors.New("严重时间漂移案件需要人工放行理由")
		}
		c.Status = "pending_review"
		c.RiskLevel = string(assessment.AssessVersion(assessment.Signal{PeakAmplitude: c.BeforePeak, DominantFrequency: func() float64 { a, _ := s.Store.GetAlert(c.AlertID); return a.DominantFrequency }(), DurationMS: func() int { a, _ := s.Store.GetAlert(c.AlertID); return a.DurationMS }()}, c.ThresholdVersion).Risk)
		c.Revision++
		s.Store.PutCase(c)
		s.Store.Event(store.Event{ID: newID(), Type: "sensor_time_released", CaseID: id, At: time.Now(), Data: map[string]any{"by": reviewer, "reason": o.Reason}})
	}
	if c.Claim != nil {
		if time.Now().After(c.Claim.ExpiresAt) {
			old := c.Claim.Holder
			c.Claim = nil
			c.Revision++
			s.Store.PutCase(c)
			s.Store.Event(store.Event{ID: newID(), Type: "case_claim_expired", CaseID: id, At: time.Now(), Data: map[string]any{"holder": old}})
			return c, ErrConflict
		}
		if c.Claim.Holder != reviewer || (o.ClaimToken != "" && o.ClaimToken != c.Claim.Token) {
			return c, ErrClaimRequired
		}
	}
	oldRisk, oldQuality, oldThreshold := c.RiskLevel, c.QualityScore, c.ThresholdVersion
	if strings.TrimSpace(reviewer) == "" {
		return c, errors.New("reviewer不能为空")
	}
	if c.NextReviewAt != nil && time.Now().Before(*c.NextReviewAt) {
		return c, fmt.Errorf("下一次复核时间未到，还需等待%d秒", int(time.Until(*c.NextReviewAt).Seconds()))
	}
	if c.Status == "noise" {
		if strings.TrimSpace(o.Reason) == "" {
			return c, errors.New("噪声复核理由不能为空")
		}
		if o.Summary != nil {
			q := assessment.Check(*o.Summary)
			if !q.Valid {
				c.NoiseReviewCount++
				c.ReviewCount++
				c.QualityReason = q.Reason
				c.Revision++
				s.Store.PutCase(c)
				s.Store.Event(store.Event{ID: newID(), Type: "review_failed", CaseID: id, At: time.Now(), Data: map[string]any{"reason": q.Reason, "review_count": c.NoiseReviewCount}})
				return c, errors.New(q.Reason)
			}
			version := o.ThresholdVersion
			if version == "" {
				version = assessment.DefaultThreshold()
			}
			ar, cmp, ce := assessment.Compare(*o.Summary, version, o.CompareVersion)
			if ce != nil {
				return c, ce
			}
			if !ar.Quality.Valid || ar.Risk == assessment.Noise {
				c.NoiseReviewCount++
				c.ReviewCount++
				c.QualityScore, c.QualityReason = ar.Quality.Score, ar.Quality.Reason
				c.Revision++
				s.Store.PutCase(c)
				s.Store.Event(store.Event{ID: newID(), Type: "review_failed", CaseID: id, At: time.Now(), Data: map[string]any{"reason": ar.Quality.Reason, "review_count": c.NoiseReviewCount}})
				return c, errors.New(ar.Quality.Reason)
			}
			c.Status = "pending_inspection"
			c.RiskLevel = string(ar.Risk)
			c.ThresholdVersion = ar.ThresholdVersion
			if cmp != nil {
				c.ThresholdCompareVersion = cmp.ThresholdVersion
				c.ThresholdCompareRisk = string(cmp.Risk)
				c.ThresholdCompareQuality = cmp.Quality.Score
				if cmp.Risk != ar.Risk {
					c.ThresholdSuggestion = "建议结合对比版本复核升级"
				}
			}
			c.RiskExplanation, c.RiskFactors = ar.Explanation, ar.Factors
			c.QualityScore, c.QualityReason = ar.Quality.Score, ar.Quality.Reason
			c.RiskCalculatedAt = &ar.CalculatedAt
			c.NoiseReclassifiedCount++
			c.Revision++
			c.Reviewer = reviewer
			s.Store.PutCase(c)
			if c.Claim != nil {
				holder := c.Claim.Holder
				c.Claim = nil
				s.Store.PutCase(c)
				s.Store.Event(store.Event{ID: newID(), Type: "case_claim_released", CaseID: id, At: time.Now(), Data: map[string]any{"holder": holder, "reason": "review_completed"}})
			}
			s.Store.Event(store.Event{ID: newID(), Type: "noise_reclassified", CaseID: id, At: time.Now(), Data: map[string]any{"reason": o.Reason}})
			due := time.Now().Add(24 * time.Hour)
			if ar.Risk == assessment.High {
				due = time.Now().Add(4 * time.Hour)
			} else if ar.Risk == assessment.Medium {
				due = time.Now().Add(12 * time.Hour)
			}
			t := store.Task{TaskID: newID(), CaseID: id, Assignee: reviewer, TargetCheckpoint: "P1", Status: "open", DueAt: &due}
			s.Store.PutTask(t)
			c.TaskID, c.Assignee = t.TaskID, reviewer
			s.Store.PutCase(c)
			return c, nil
		}
		c.Reviewer = reviewer
		c.Revision++
		c.NoiseReviewCount++
		s.Store.PutCase(c)
		if c.Claim != nil {
			holder := c.Claim.Holder
			c.Claim = nil
			s.Store.PutCase(c)
			s.Store.Event(store.Event{ID: newID(), Type: "case_claim_released", CaseID: id, At: time.Now(), Data: map[string]any{"holder": holder, "reason": "noise_review"}})
		}
		s.Store.Event(store.Event{ID: newID(), Type: "noise_confirmed", CaseID: id, At: time.Now(), Data: map[string]any{"reviewer": reviewer, "reason": o.Reason}})
		return c, nil
	}
	if c.Status != "pending_review" && c.Status != "awaiting_independent_review" && c.Status != "awaiting_arbitration" {
		return c, ErrInvalidTransition
	}
	if c.Status == "awaiting_independent_review" && !o.IndependentReview {
		return c, errors.New("案件等待独立复核")
	}
	if c.Status == "awaiting_arbitration" {
		if !o.Arbitration || strings.TrimSpace(o.ArbitrationBy) == "" || strings.TrimSpace(o.ArbitrationReason) == "" {
			return c, errors.New("独立复核差异需要负责人裁决")
		}
		c.IndependentGate = "approved"
		c.Status = "pending_review"
		c.Reviewer = o.ArbitrationBy
		c.Revision++
		s.Store.PutCase(c)
		s.Store.Event(store.Event{ID: newID(), Type: "independent_review_arbitrated", CaseID: id, At: time.Now(), Data: map[string]any{"by": o.ArbitrationBy, "reason": o.ArbitrationReason}})
	}
	a, _ := s.Store.GetAlert(c.AlertID)
	v := assessment.DefaultThreshold()
	if o.ThresholdVersion != "" {
		v = o.ThresholdVersion
	}
	if c.ThresholdVersion != "" && v != c.ThresholdVersion && strings.TrimSpace(o.Reason) == "" {
		s.Store.Event(store.Event{ID: newID(), Type: "threshold_version_difference", CaseID: id, At: time.Now(), Data: map[string]any{"case_version": c.ThresholdVersion, "requested_version": v}})
		return c, fmt.Errorf("阈值版本与案件既有版本不一致，需要确认理由")
	}
	signal := assessment.Signal{PeakAmplitude: a.PeakAmplitude, DominantFrequency: a.DominantFrequency, DurationMS: a.DurationMS, RawDigest: a.RawDigest}
	if o.Summary != nil {
		signal = *o.Summary
	}
	r, cmp, ce := assessment.Compare(signal, v, o.CompareVersion)
	if ce != nil {
		failure := assessment.ClassifyReviewFailure(ce.Error())
		c.ReviewAttempts = append(c.ReviewAttempts, store.ReviewAttempt{Attempt: len(c.ReviewAttempts) + 1, At: time.Now(), Operator: reviewer, Digest: assessment.Digest(signal), Category: failure.Category, Action: failure.Action, Success: false})
		c.ReviewSnapshots = append(c.ReviewSnapshots, store.ReviewSnapshot{ID: newID(), Revision: rev, Digest: assessment.Digest(signal), ThresholdVersion: v, Operator: reviewer, Success: false, Error: ce.Error(), At: time.Now()})
		s.Store.PutCase(c)
		s.Store.Event(store.Event{ID: newID(), Type: "review_failed", CaseID: id, At: time.Now(), Data: map[string]any{"reason": ce.Error(), "threshold_version": v, "compare_version": o.CompareVersion}})
		if o.IdempotencyKey != "" {
			s.Store.Mark("review:"+o.IdempotencyKey, c)
		}
		return c, ce
	}
	if r.Quality.Valid {
		digest := assessment.Digest(signal)
		found := false
		for _, snap := range c.ReviewSnapshots {
			if snap.Revision == rev && snap.Digest == digest && snap.Adopted {
				found = true
				break
			}
		}
		if !found {
			c.ReviewSnapshots = append(c.ReviewSnapshots, store.ReviewSnapshot{ID: newID(), Revision: rev, Digest: digest, ThresholdVersion: r.ThresholdVersion, QualityScore: r.Quality.Score, RiskFactors: r.Factors, Operator: reviewer, Adopted: true, Success: true, At: time.Now()})
		}
	}
	if cmp != nil && cmp.Risk != r.Risk {
		expected := thresholdToken(id, rev, signal, v, o.CompareVersion, r, cmp)
		if strings.TrimSpace(o.ConfirmToken) == "" || o.ConfirmToken != expected || strings.TrimSpace(o.Reason) == "" {
			s.Store.Event(store.Event{ID: newID(), Type: "threshold_confirmation_required", CaseID: id, At: time.Now(), Data: map[string]any{"primary_risk": r.Risk, "compare_risk": cmp.Risk}})
			return c, errors.New("阈值版本结论不一致，需要提交有效差异令牌和解释理由")
		}
		c.ThresholdConfirmedBy, c.ThresholdConfirmedReason = o.ConfirmedBy, o.Reason
		now := time.Now()
		c.ThresholdConfirmedAt = &now
	}
	if !r.Quality.Valid {
		failure := assessment.ClassifyReviewFailure(r.Quality.Reason)
		attempt := len(c.ReviewAttempts) + 1
		next := time.Now().Add(time.Duration(attempt) * time.Minute)
		c.ReviewAttempts = append(c.ReviewAttempts, store.ReviewAttempt{Attempt: attempt, At: time.Now(), Operator: reviewer, Digest: assessment.Digest(signal), Category: failure.Category, Action: failure.Action, NextReviewAt: &next, Success: false})
		c.NextReviewAt = &next
		c.ReviewSnapshots = append(c.ReviewSnapshots, store.ReviewSnapshot{ID: newID(), Revision: rev, Digest: assessment.Digest(signal), ThresholdVersion: v, QualityScore: r.Quality.Score, RiskFactors: r.Factors, Operator: reviewer, Success: false, Error: r.Quality.Reason, At: time.Now()})
		c.Status = "noise"
		c.RiskLevel = string(assessment.Noise)
		c.QualityScore, c.QualityReason = r.Quality.Score, r.Quality.Reason
		c.NoiseReviewCount++
		c.ReviewCount++
		c.Revision++
		s.Store.PutCase(c)
		s.Store.Event(store.Event{ID: newID(), Type: "review_failed", CaseID: id, At: time.Now(), Data: map[string]any{"reason": r.Quality.Reason}})
		if o.IdempotencyKey != "" {
			s.Store.Mark("review:"+o.IdempotencyKey, c)
		}
		return c, errors.New(r.Quality.Reason)
	}
	if len(c.ReviewAttempts) > 0 && c.NextReviewAt != nil && time.Now().Before(*c.NextReviewAt) {
		return c, fmt.Errorf("下一次复核时间未到，还需等待%d秒", int(time.Until(*c.NextReviewAt).Seconds()))
	}
	if c.IndependentGate == "awaiting" && o.IndependentReview {
		if reviewer == c.Reviewer {
			return c, errors.New("独立复核人必须与首位工程师不同")
		}
		if r.Risk != assessment.High || int(math.Abs(float64(r.Quality.Score-c.QualityScore))) > 20 {
			c.IndependentGate = "disputed"
			c.Status = "awaiting_arbitration"
			c.Revision++
			s.Store.PutCase(c)
			return c, errors.New("独立复核结论不一致，需要负责人裁决")
		}
		c.IndependentReviewer, c.IndependentDigest, c.IndependentGate = reviewer, assessment.Digest(signal), "approved"
	} else if r.Risk == assessment.High && o.IndependentReview {
		if c.IndependentGate == "awaiting" {
			if reviewer == c.Reviewer {
				return c, errors.New("独立复核人必须与首位工程师不同")
			}
			if r.Risk != assessment.High {
				c.IndependentGate = "disputed"
				c.Status = "awaiting_arbitration"
				c.Revision++
				s.Store.PutCase(c)
				return c, errors.New("独立复核结论不一致，需要负责人裁决")
			}
			c.IndependentReviewer, c.IndependentDigest, c.IndependentGate = reviewer, assessment.Digest(signal), "approved"
		} else {
			c.IndependentGate, c.IndependentReviewer, c.IndependentDigest = "awaiting", reviewer, assessment.Digest(signal)
			c.Status = "awaiting_independent_review"
			c.Reviewer = reviewer
			c.RiskLevel = string(r.Risk)
			c.Revision++
			s.Store.PutCase(c)
			s.Store.Event(store.Event{ID: newID(), Type: "independent_review_required", CaseID: id, At: time.Now(), Data: map[string]any{"reviewer": reviewer, "risk": r.Risk}})
			return c, nil
		}
	}
	c.RiskLevel = string(r.Risk)
	c.Reviewer = reviewer
	c.Status = "pending_inspection"
	c.Revision++
	c.ThresholdVersion = v
	if ts, ok := assessment.ThresholdSnapshot(v); ok {
		c.ThresholdSnapshot = ts
	}
	c.RiskExplanation = r.Explanation
	c.RiskFactors = r.Factors
	c.QualityScore = r.Quality.Score
	c.QualityReason = r.Quality.Reason
	c.RiskCalculatedAt = &r.CalculatedAt
	c.ReviewCount++
	if cmp != nil {
		c.ThresholdCompareVersion = cmp.ThresholdVersion
		c.ThresholdCompareRisk = string(cmp.Risk)
		c.ThresholdCompareQuality = cmp.Quality.Score
		if cmp.Risk != r.Risk {
			c.ThresholdSuggestion = "建议结合对比版本复核升级"
			if c.ThresholdConfirmedAt != nil {
				s.Store.Event(store.Event{ID: newID(), Type: "threshold_difference_confirmed", CaseID: id, At: *c.ThresholdConfirmedAt, Data: map[string]any{"primary_version": v, "compare_version": o.CompareVersion, "confirmed_by": o.ConfirmedBy, "reason": o.Reason}})
			}
		}
	}
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "reviewed", CaseID: id, At: time.Now(), Data: map[string]any{"risk": r.Risk}})
	if ts, ok := assessment.ThresholdSnapshot(v); ok {
		s.Store.Event(store.Event{ID: newID(), Type: "threshold_selected", CaseID: id, At: time.Now(), Data: map[string]any{"version": v, "released_at": ts.ReleasedAt, "parameters": ts}})
	}
	if oldRisk != c.RiskLevel || oldQuality != c.QualityScore || oldThreshold != c.ThresholdVersion {
		s.Store.Event(store.Event{ID: newID(), Type: "risk_diff", CaseID: id, At: time.Now(), Data: map[string]any{"old_risk": oldRisk, "new_risk": c.RiskLevel, "old_quality": oldQuality, "new_quality": c.QualityScore, "old_threshold_version": oldThreshold, "new_threshold_version": c.ThresholdVersion, "reviewer": reviewer, "reason": o.Reason, "factors": c.RiskFactors}})
	}
	due := time.Now().Add(24 * time.Hour)
	if r.Risk == assessment.High {
		due = time.Now().Add(4 * time.Hour)
	} else if r.Risk == assessment.Medium {
		due = time.Now().Add(12 * time.Hour)
	}
	checkpoint := "P1"
	if strings.TrimSpace(o.TargetCheckpoint) != "" {
		checkpoint = strings.TrimSpace(o.TargetCheckpoint)
	}
	checkpoints := []store.CheckpointProgress{}
	for _, cp := range strings.Split(checkpoint, ",") {
		cp = strings.TrimSpace(cp)
		if cp != "" {
			checkpoints = append(checkpoints, store.CheckpointProgress{ID: cp})
		}
	}
	t := store.Task{TaskID: newID(), CaseID: id, Assignee: reviewer, TargetCheckpoint: checkpoint, Status: "open", DueAt: &due}
	c.RequiredCheckpoints = checkpoints
	if c.Claim != nil {
		holder := c.Claim.Holder
		c.Claim = nil
		s.Store.Event(store.Event{ID: newID(), Type: "case_claim_released", CaseID: id, At: time.Now(), Data: map[string]any{"holder": holder, "reason": "review_completed"}})
	}
	s.Store.PutTask(t)
	c.TaskID = t.TaskID
	s.Store.PutCase(c)
	if o.IdempotencyKey != "" {
		s.Store.Mark("review:"+o.IdempotencyKey, c)
	}
	return c, nil
}
func (s *Service) SubmitEvidence(id string, rev int, in evidence.Input, submitted string) (store.Case, error) {
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if c.Revision != rev {
		return c, ErrConflict
	}
	if c.Status != "pending_inspection" && c.Status != "evidence_submitted" && c.Status != "pending_reinspection" {
		return c, ErrInvalidTransition
	}
	if c.PendingCorrection != nil && c.PendingCorrection.Status == "pending" {
		return c, errors.New("签到更正待负责人审批")
	}
	t, taskOK := s.Store.GetTaskByCase(id)
	if !taskOK {
		return c, errors.New("核验任务不存在")
	}
	a, _ := s.Store.GetAlert(c.AlertID)
	if len(in.PhotoRefs) > 0 {
		norm := evidence.PhotoFingerprint(in.PhotoRefs)
		if len(norm) != len(in.PhotoRefs) {
			return c, errors.New("同一证据包包含重复照片引用")
		}
	}
	if t.FirstArrivedAt != nil && !in.ArrivedAt.IsZero() && in.ArrivedAt.Equal(*t.FirstArrivedAt) {
		return c, nil
	}
	if !in.ArrivedAt.IsZero() && in.ArrivedAt.After(time.Now().Add(5*time.Minute)) {
		return c, errors.New("arrived_at超出允许的时钟偏差")
	}
	if _, exists := s.Store.GetEvidenceByCase(id); !exists && !in.ArrivedAt.IsZero() && in.ArrivedAt.Before(a.CapturedAt) {
		return c, errors.New("arrived_at不能早于告警采集时间")
	}
	if old, exists := s.Store.GetEvidenceByCase(id); exists {
		if in.Version > 0 && in.Version != old.Version {
			return c, fmt.Errorf("证据版本冲突，当前版本为%d", old.Version)
		}
		if in.Version == old.Version && in.Version > 0 && evidence.ResampleFingerprint(in) == evidence.ResampleFingerprint(evidence.Input{Checkpoint: old.Checkpoint, Resample: assessment.Signal{PeakAmplitude: old.ResamplePeak, DominantFrequency: old.ResampleFrequency, DurationMS: old.ResampleDuration, RawDigest: old.ResampleDigest}}) && len(in.PhotoRefs) == len(old.PhotoRefs) {
			return c, nil
		}
		in.PhotoRefs = append(old.PhotoRefs, in.PhotoRefs...)
		if in.Notes == "" {
			in.Notes = old.Notes
		}
		if in.SubmittedBy == "" {
			in.SubmittedBy = old.SubmittedBy
		}
		if in.Checkpoint == "" {
			in.Checkpoint = old.Checkpoint
		}
		if in.ArrivedAt.IsZero() {
			in.ArrivedAt = old.ArrivedAt
		}
		if in.ArrivedAt.Before(a.CapturedAt) {
			return c, errors.New("arrived_at不能早于告警采集时间")
		}
		if in.Resample.DurationMS == 0 {
			in.Resample = assessment.Signal{PeakAmplitude: old.ResamplePeak, DominantFrequency: old.ResampleFrequency, DurationMS: old.ResampleDuration, RawDigest: old.ResampleDigest}
		}
	}
	allowed := false
	for _, cp := range c.RequiredCheckpoints {
		if cp.ID == in.Checkpoint {
			allowed = true
		}
	}
	if len(c.RequiredCheckpoints) == 0 {
		allowed = in.Checkpoint == t.TargetCheckpoint
	}
	if !allowed {
		return c, errors.New("测点不在核验任务范围")
	}
	if len(in.PhotoRefs) > 0 {
		refs := evidence.PhotoFingerprint(in.PhotoRefs)
		fp := evidence.ResampleFingerprint(in)
		if owner, conflict := s.Store.FindEvidenceConflict(id, refs, fp); conflict {
			role := strings.ToLower(strings.TrimSpace(in.ConfirmReuseBy))
			if len([]rune(strings.TrimSpace(in.ConflictReason))) < 4 || strings.TrimSpace(in.ConfirmReuseBy) == "" || !(strings.Contains(role, "lead") || strings.Contains(role, "manager") || strings.Contains(role, "负责人") || strings.Contains(role, "主管")) {
				return c, fmt.Errorf("证据引用已被案件%s占用，需要负责人确认理由", owner)
			}
			s.Store.Event(store.Event{ID: newID(), Type: "evidence_conflict_confirmed", CaseID: id, At: time.Now(), Data: map[string]any{"owner_case_id": owner, "reason": in.ConflictReason, "by": in.ConfirmReuseBy}})
		}
	}
	// merge incremental photo references without duplicating the existing package
	if len(in.PhotoRefs) > 0 {
		uniq := map[string]bool{}
		out := []string{}
		for _, p := range in.PhotoRefs {
			n := strings.ToLower(strings.TrimSpace(p))
			if !uniq[n] {
				uniq[n] = true
				out = append(out, n)
			}
		}
		in.PhotoRefs = out
	}
	eid := c.EvidenceID
	if eid == "" {
		eid = newID()
	}
	if _, err := evidence.SaveIncremental(s.Store, id, eid, in); err != nil {
		return c, err
	}
	if ev, ok := s.Store.GetEvidenceByCase(id); ok {
		ev.SubmittedAt = in.SubmittedAt
		if ev.SubmittedAt.IsZero() {
			ev.SubmittedAt = time.Now()
		}
		if t.DueAt != nil {
			if ev.SubmittedAt.After(*t.DueAt) || ev.ArrivedAt.After(*t.DueAt) {
				ev.DueState = "late"
				lateAt := ev.SubmittedAt
				if ev.ArrivedAt.After(lateAt) {
					lateAt = ev.ArrivedAt
				}
				ev.LateMinutes = int(lateAt.Sub(*t.DueAt).Minutes())
				ev.LateReason = in.LateReason
			} else if ev.SubmittedAt.After(t.DueAt.Add(-time.Hour)) {
				ev.DueState = "critical"
			} else {
				ev.DueState = "on_time"
			}
		}
		s.Store.PutEvidence(ev)
	}
	wasReinspection := c.Status == "pending_reinspection"
	c.EvidenceID = eid
	c.Assignee = submitted
	c.Status = "evidence_submitted"
	if wasReinspection {
		c.Status = "mitigation"
	}
	c.Revision++
	for i := range c.RequiredCheckpoints {
		if c.RequiredCheckpoints[i].ID == in.Checkpoint {
			now := in.ArrivedAt
			c.RequiredCheckpoints[i].ArrivedAt = &now
			ev, _ := s.Store.GetEvidenceByCase(id)
			c.RequiredCheckpoints[i].EvidenceVersion = ev.Version
			c.RequiredCheckpoints[i].Missing = evidence.Missing(ev)
		}
	}
	if t.FirstArrivedAt == nil {
		t.FirstArrivedAt = &in.ArrivedAt
		t.Late = in.ArrivedAt.After(*t.DueAt)
		if t.Late {
			t.LateMinutes = int(in.ArrivedAt.Sub(*t.DueAt).Minutes())
			s.Store.Event(store.Event{ID: newID(), Type: "task_overdue_escalated", CaseID: id, At: time.Now(), Data: map[string]any{"late_minutes": t.LateMinutes, "reason": in.Notes, "assignee": t.Assignee}})
		}
		t.ArrivalReason = in.Notes
		t.Status = "completed"
		t.EscalationAcknowledged = true
		t.EscalationAcknowledged = true
		s.Store.PutTask(t)
	}
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "evidence_submitted", CaseID: id, At: time.Now()})
	return c, nil
}

func (s *Service) RollbackEvidence(id string, rev, version int, by, reason string, expected ...int) (store.Case, error) {
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if c.Revision != rev {
		return c, ErrConflict
	}
	if c.Status == "mitigation" || c.Status == "closed" {
		return c, errors.New("当前案件状态不允许回滚证据")
	}
	cur, ok := s.Store.GetEvidenceByCase(id)
	if !ok {
		return c, errors.New("证据版本不存在")
	}
	if len(expected) > 0 && expected[0] > 0 && cur.Version != expected[0] {
		return c, fmt.Errorf("证据版本冲突，当前版本为%d", cur.Version)
	}
	if version <= 0 || version >= cur.Version {
		return c, fmt.Errorf("只能回滚到历史版本，当前版本为%d", cur.Version)
	}
	var h store.EvidenceVersion
	found := false
	for _, v := range cur.History {
		if v.Version == version {
			h = v
			found = true
			break
		}
	}
	if !found {
		return c, errors.New("指定证据版本不存在")
	}
	in := evidence.Input{Checkpoint: h.Checkpoint, ArrivedAt: h.At, PhotoRefs: h.PhotoRefs, Resample: assessment.Signal{PeakAmplitude: h.ResamplePeak, DominantFrequency: h.ResampleFrequency, DurationMS: h.ResampleDuration, RawDigest: h.ResampleDigest}, Notes: h.Notes, SubmittedBy: by}
	if err := evidence.Validate(in); err != nil {
		return c, err
	}
	if strings.TrimSpace(reason) == "" {
		return c, errors.New("回滚原因不能为空")
	}
	if _, err := evidence.SaveIncremental(s.Store, id, cur.EvidenceID, in); err != nil {
		return c, err
	}
	c.EvidenceID = cur.EvidenceID
	c.Revision++
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "evidence_rolled_back", CaseID: id, At: time.Now(), Data: map[string]any{"from_version": cur.Version, "to_version": version, "reason": reason, "by": by}})
	return c, nil
}

func (s *Service) RepairEvidenceChain(id string, rev int, by, reason string) (store.Case, error) {
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if c.Revision != rev {
		return c, ErrConflict
	}
	if c.Status == "mitigation" || c.Status == "closed" {
		return c, errors.New("当前状态禁止修复证据链")
	}
	if strings.TrimSpace(reason) == "" {
		return c, errors.New("修复说明不能为空")
	}
	ev, ok := s.Store.GetEvidenceByCase(id)
	if !ok {
		return c, errors.New("证据不存在")
	}
	in := evidence.Input{Checkpoint: ev.Checkpoint, ArrivedAt: ev.ArrivedAt, PhotoRefs: ev.PhotoRefs, Resample: assessment.Signal{PeakAmplitude: ev.ResamplePeak, DominantFrequency: ev.ResampleFrequency, DurationMS: ev.ResampleDuration, RawDigest: ev.ResampleDigest}, Notes: ev.Notes, SubmittedBy: by}
	if _, e := evidence.SaveIncremental(s.Store, id, ev.EvidenceID, in); e != nil {
		return c, e
	}
	fixed, _ := s.Store.GetEvidenceByCase(id)
	prev := ""
	for i := range fixed.History {
		h := &fixed.History[i]
		hi := evidence.Input{Checkpoint: h.Checkpoint, ArrivedAt: h.At, PhotoRefs: h.PhotoRefs, Resample: assessment.Signal{PeakAmplitude: h.ResamplePeak, DominantFrequency: h.ResampleFrequency, DurationMS: h.ResampleDuration, RawDigest: h.ResampleDigest}, Notes: h.Notes, SubmittedBy: h.SubmittedBy}
		h.Hash = evidence.HashWithPrev(prev, evidence.Hash(hi))
		prev = h.Hash
	}
	ci := evidence.Input{Checkpoint: fixed.Checkpoint, ArrivedAt: fixed.ArrivedAt, PhotoRefs: fixed.PhotoRefs, Resample: assessment.Signal{PeakAmplitude: fixed.ResamplePeak, DominantFrequency: fixed.ResampleFrequency, DurationMS: fixed.ResampleDuration, RawDigest: fixed.ResampleDigest}, Notes: fixed.Notes, SubmittedBy: fixed.SubmittedBy}
	fixed.Hash = evidence.HashWithPrev(prev, evidence.Hash(ci))
	s.Store.PutEvidence(fixed)
	c.Revision++
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "evidence_chain_repaired", CaseID: id, At: time.Now(), Data: map[string]any{"by": by, "reason": reason}})
	return c, nil
}
func (s *Service) Approve(id string, rev int, action, window, by, reason string, req ...string) (store.Case, error) {
	return s.ApproveWithOptions(id, rev, ApprovalOptions{Action: action, Window: window, ApprovedBy: by, Reason: reason, IdempotencyKey: first(req), Checklist: map[string]bool{"load_scope": true, "monitoring_frequency": true, "site_isolation": true}, ConfirmedBy: "legacy-reviewer", ConfirmedReason: "兼容既有流程"})
}
func first(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}

type ApprovalOptions struct {
	Action, Window, ApprovedBy, Reason string
	ConfirmedBy, ConfirmedReason       string
	Checklist                          map[string]bool
	IdempotencyKey                     string
	ChangeOfDecision                   bool
	OriginalDecisionID                 string
	MonitoringFrequency                string
	SiteIsolation                      string
	LateConfirmedBy                    string
	LateReason                         string
}

func (s *Service) ApproveWithOptions(id string, rev int, o ApprovalOptions) (store.Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if o.IdempotencyKey != "" {
		if ok, v := s.Store.Once("approve:" + o.IdempotencyKey); ok {
			if old, ok := v.(store.Case); ok {
				return old, nil
			}
		}
	}
	if c.Revision != rev {
		return c, ErrConflict
	}
	if c.Status != "evidence_submitted" && !(o.ChangeOfDecision && c.Status == "mitigation") {
		return c, ErrInvalidTransition
	}
	if c.PendingCorrection != nil && c.PendingCorrection.Status == "pending" {
		return c, errors.New("签到更正待负责人审批")
	}
	if o.ChangeOfDecision {
		if len(s.Store.ListRetests(id)) > 0 {
			return c, errors.New("已有复测记录，不能变更方案")
		}
		if o.OriginalDecisionID == "" || o.OriginalDecisionID != c.DecisionID {
			return c, errors.New("原decision_id不匹配")
		}
	}
	action, window, by, reason := o.Action, o.Window, o.ApprovedBy, o.Reason
	if action != "限载" && action != "持续观测" {
		return c, errors.New("仅支持限载或持续观测")
	}
	m := regexp.MustCompile(`^([1-9][0-9]*)(h|d)$`).FindStringSubmatch(strings.TrimSpace(window))
	if len(m) != 3 {
		return c, errors.New("观测窗口必须为正数小时或天")
	}
	var n int
	fmt.Sscanf(m[1], "%d", &n)
	if (m[2] == "h" && n > 720) || (m[2] == "d" && n > 30) {
		return c, errors.New("观测窗口超过配置上限30天")
	}
	role := strings.ToLower(strings.TrimSpace(by))
	if role == "" || role == "eng" || strings.Contains(role, "engineer") || strings.Contains(by, "工程师") || !(strings.Contains(role, "lead") || strings.Contains(role, "manager") || strings.Contains(role, "supervisor") || strings.Contains(by, "负责人") || strings.Contains(by, "主管")) {
		return c, errors.New("approved_by必须具备负责人角色")
	}
	if len([]rune(strings.TrimSpace(reason))) < 4 {
		return c, errors.New("审批理由至少4个字")
	}
	frequency, isolation := o.MonitoringFrequency, o.SiteIsolation
	if frequency == "" && o.Checklist["monitoring_frequency"] {
		frequency = "checklist-confirmed"
	}
	if isolation == "" && o.Checklist["site_isolation"] {
		isolation = "checklist-confirmed"
	}
	match := assessment.ValidateAction(assessment.Risk(c.RiskLevel), action, window, frequency, isolation, reason)
	if !match.Valid {
		return c, fmt.Errorf("%s: %s", match.Reason, strings.Join(match.Missing, ","))
	}
	if ev, ok := s.Store.GetEvidenceByCase(id); !ok || !evidence.Verify(ev) || func() bool { good, _, _ := evidence.VerifyChain(ev); return !good }() {
		return c, errors.New("证据包不完整")
	}
	if ev, ok := s.Store.GetEvidenceByCase(id); ok && ev.DueState == "late" && ev.LateConfirmedBy == "" {
		if strings.TrimSpace(o.LateConfirmedBy) == "" || strings.TrimSpace(o.LateReason) == "" {
			return c, errors.New("迟交证据需要负责人确认和理由")
		}
		now := time.Now()
		ev.LateConfirmedBy = o.LateConfirmedBy
		ev.LateReason = o.LateReason
		ev.LateConfirmedAt = &now
		s.Store.PutEvidence(ev)
	}
	if c.RiskLevel == string(assessment.High) {
		required := []string{"load_scope", "monitoring_frequency", "site_isolation"}
		for _, k := range required {
			if !o.Checklist[k] {
				return c, fmt.Errorf("高风险审批清单缺少%s", k)
			}
		}
		if strings.TrimSpace(o.ConfirmedBy) == "" || strings.EqualFold(strings.TrimSpace(o.ConfirmedBy), strings.TrimSpace(by)) {
			return c, errors.New("高风险审批需要不同的复核确认人")
		}
		if len([]rune(strings.TrimSpace(o.ConfirmedReason))) < 4 {
			return c, errors.New("复核确认理由至少4个字")
		}
	}
	if len(c.RequiredCheckpoints) > 0 {
		missing := []string{}
		for _, cp := range c.RequiredCheckpoints {
			if cp.ArrivedAt == nil || cp.EvidenceVersion == 0 {
				missing = append(missing, cp.ID)
			}
		}
		if len(missing) > 0 {
			return c, fmt.Errorf("必检点覆盖不足，缺少%s", strings.Join(missing, ","))
		}
	}
	now := time.Now()
	d := store.Decision{DecisionID: newID(), CaseID: id, Action: action, MonitoringWindow: window, ApprovedBy: by, ApprovedAt: now, Reason: reason, TemplateVersion: "v1", Checklist: o.Checklist, ConfirmedBy: o.ConfirmedBy, ConfirmedReason: o.ConfirmedReason, Status: "active", Supersedes: c.DecisionID, RuleVersion: match.RuleVersion, RuleSummary: match.Reason, MonitoringFrequency: frequency, SiteIsolation: isolation}
	if o.ConfirmedBy != "" {
		d.ConfirmedAt = &now
	}
	if strings.Contains(action, "持续") {
		n := d.ApprovedAt.Add(parseWindowDuration(window))
		d.NextReviewAt = n.Format(time.RFC3339)
		c.NextReviewAt = &n
		c.RetestPlanDueAt = &n
	}
	s.Store.PutDecision(d)
	if o.ChangeOfDecision {
		if old, ok := s.Store.GetDecision(c.DecisionID); ok {
			old.Status = "superseded"
			old.SupersededAt = &now
			s.Store.PutDecision(old)
		}
	}
	c.DecisionID = d.DecisionID
	c.Status = "mitigation"
	c.Revision++
	s.Store.PutCase(c)
	evType := "mitigation_approved"
	if o.ChangeOfDecision {
		evType = "decision_renewed"
	}
	s.Store.Event(store.Event{ID: newID(), Type: evType, CaseID: id, At: time.Now(), Data: map[string]any{"decision_id": d.DecisionID, "supersedes": d.Supersedes, "window": window}})
	if o.IdempotencyKey != "" {
		s.Store.Mark("approve:"+o.IdempotencyKey, c)
	}
	return c, nil
}

func parseWindowDuration(window string) time.Duration {
	m := regexp.MustCompile(`^([1-9][0-9]*)(h|d)$`).FindStringSubmatch(strings.TrimSpace(window))
	if len(m) != 3 {
		return 24 * time.Hour
	}
	var n int
	_, _ = fmt.Sscanf(m[1], "%d", &n)
	if m[2] == "d" {
		return time.Duration(n) * 24 * time.Hour
	}
	return time.Duration(n) * time.Hour
}

func (s *Service) archiveManifestForCase(fingerprint, alertDigest, evidenceHash, chainHead string, decisionIDs []string, retestCount, auditCount int) *store.ArchiveManifest {
	if s.archiveManifest == nil {
		s.archiveManifest = &store.ArchiveManifest{}
	}
	m := s.archiveManifest
	m.Fingerprint = fingerprint
	m.AlertDigest = alertDigest
	m.EvidenceHash = evidenceHash
	m.DecisionIDs = append(m.DecisionIDs[:0], decisionIDs...)
	m.RetestCount = retestCount
	m.AuditCount = auditCount
	m.ChainHead = chainHead
	m.Status = "verified"
	m.Anomalies = nil
	return m
}

func (s *Service) ReassignTask(id string, rev int, assignee, by, reason string) (store.Case, error) {
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if c.Revision != rev {
		return c, ErrConflict
	}
	if c.Status != "pending_inspection" {
		return c, ErrInvalidTransition
	}
	t, ok := s.Store.GetTaskByCase(id)
	if !ok {
		return c, errors.New("核验任务不存在")
	}
	if t.Status != "open" {
		return c, errors.New("任务已完成，不能改派")
	}
	if strings.TrimSpace(assignee) == "" || strings.TrimSpace(reason) == "" {
		return c, errors.New("改派人员和原因不能为空")
	}
	t.ReassignedBy = by
	t.ReassignReason = reason
	t.Assignee = assignee
	s.Store.PutTask(t)
	c.Assignee = assignee
	c.Revision++
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "task_reassigned", CaseID: id, At: time.Now(), Data: map[string]any{"assignee": assignee, "reason": reason, "by": by}})
	return c, nil
}

func (s *Service) CheckinTask(id string, rev int, at time.Time, person, checkpoint, kind, reason, idem string) (store.Case, error) {
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if c.Revision != rev {
		return c, ErrConflict
	}
	t, ok := s.Store.GetTaskByCase(id)
	if !ok {
		return c, errors.New("核验任务不存在")
	}
	if strings.TrimSpace(person) == "" || strings.TrimSpace(checkpoint) == "" {
		return c, errors.New("签到人员和测点不能为空")
	}
	if len(c.RequiredCheckpoints) > 0 {
		okcp := false
		for _, cp := range c.RequiredCheckpoints {
			if cp.ID == checkpoint {
				okcp = true
			}
		}
		if !okcp {
			return c, errors.New("测点不在核验任务范围")
		}
	}
	if kind == "" {
		kind = "checkin"
	}
	if kind == "correction" && strings.TrimSpace(reason) == "" {
		return c, errors.New("更正签到必须提供理由")
	}
	if kind == "correction" {
		if c.PendingCorrection != nil && c.PendingCorrection.IdempotencyKey == idem && idem != "" {
			return c, nil
		}
		var original store.Checkin
		found := false
		for _, x := range c.Checkins {
			if x.Checkpoint == checkpoint && x.Valid {
				original = x
				found = true
				break
			}
		}
		if !found {
			return c, errors.New("没有可更正的原签到")
		}
		c.PendingCorrection = &store.CheckinCorrection{Checkpoint: checkpoint, OriginalAt: original.At, OriginalPerson: original.Person, RequestedAt: time.Now(), RequestedBy: person, Reason: reason, IdempotencyKey: idem, Status: "pending"}
		t.CorrectionPending = true
		s.Store.PutTask(t)
		c.Revision++
		s.Store.PutCase(c)
		s.Store.Event(store.Event{ID: newID(), Type: "checkin_correction_requested", CaseID: id, At: time.Now(), Data: map[string]any{"checkpoint": checkpoint, "original_at": original.At, "reason": reason, "by": person}})
		return c, nil
	}
	a, _ := s.Store.GetAlert(c.AlertID)
	if at.IsZero() {
		at = time.Now()
	}
	if at.Before(a.CapturedAt) {
		return c, errors.New("签到时间不能早于告警采集时间")
	}
	if at.After(time.Now().Add(5 * time.Minute)) {
		return c, errors.New("签到时间超出允许的时钟偏差")
	}
	for _, x := range c.Checkins {
		if idem != "" && x.IdempotencyKey == idem {
			return c, nil
		}
	}
	ch := store.Checkin{ID: newID(), At: at, SubmittedAt: time.Now(), Person: person, Checkpoint: checkpoint, Reason: reason, Kind: kind, IdempotencyKey: idem, Valid: true}
	c.Checkins = append(c.Checkins, ch)
	for i := range c.RequiredCheckpoints {
		if c.RequiredCheckpoints[i].ID == checkpoint {
			atCopy := at
			c.RequiredCheckpoints[i].ArrivedAt = &atCopy
		}
	}
	t.FirstArrivedAt = &at
	t.Late = t.DueAt != nil && at.After(*t.DueAt)
	if t.Late && t.DueAt != nil {
		t.LateMinutes = int(at.Sub(*t.DueAt).Minutes())
	}
	s.Store.PutTask(t)
	c.Revision++
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "task_checkin", CaseID: id, At: time.Now(), Data: map[string]any{"kind": kind, "person": person, "checkpoint": checkpoint, "at": at, "reason": reason}})
	return c, nil
}

func (s *Service) ApproveCheckinCorrection(id string, rev int, approve bool, by, reason string) (store.Case, error) {
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if c.Revision != rev {
		return c, ErrConflict
	}
	if c.PendingCorrection == nil {
		return c, errors.New("没有待审批签到更正")
	}
	if strings.TrimSpace(by) == "" || strings.TrimSpace(reason) == "" {
		return c, errors.New("审批人和理由不能为空")
	}
	p := c.PendingCorrection
	now := time.Now()
	p.DecisionAt = &now
	p.ApprovedBy = by
	if approve {
		p.Status = "approved"
		for i := range c.Checkins {
			if c.Checkins[i].Checkpoint == p.Checkpoint && c.Checkins[i].Valid {
				c.Checkins[i].Valid = false
			}
		}
		c.Checkins = append(c.Checkins, store.Checkin{ID: newID(), At: p.RequestedAt, SubmittedAt: now, Person: p.RequestedBy, Checkpoint: p.Checkpoint, Reason: p.Reason, Kind: "correction_approved", Valid: true})
		if t, ok := s.Store.GetTaskByCase(id); ok {
			t.CorrectionPending = false
			t.FirstArrivedAt = &p.RequestedAt
			t.Late = t.DueAt != nil && p.RequestedAt.After(*t.DueAt)
			if t.Late {
				t.LateMinutes = int(p.RequestedAt.Sub(*t.DueAt).Minutes())
			}
			s.Store.PutTask(t)
		}
		for i := range c.RequiredCheckpoints {
			if c.RequiredCheckpoints[i].ID == p.Checkpoint {
				at := p.RequestedAt
				c.RequiredCheckpoints[i].ArrivedAt = &at
			}
		}
	} else {
		p.Status = "rejected"
		s.Store.Event(store.Event{ID: newID(), Type: "checkin_correction_rejected", CaseID: id, At: now, Data: map[string]any{"by": by, "reason": reason}})
	}
	c.PendingCorrection = p
	c.Revision++
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "checkin_correction_decided", CaseID: id, At: now, Data: map[string]any{"approved": approve, "by": by, "reason": reason}})
	return c, nil
}

// RefreshTaskDue computes the externally visible due state and emits one
// escalation event for an uncompleted task that crosses its deadline.
func (s *Service) RefreshTaskDue(id string) (store.Task, error) {
	t, ok := s.Store.GetTaskByCase(id)
	if !ok {
		return store.Task{}, store.ErrNotFound
	}
	c, _ := s.Store.GetCase(id)
	now := time.Now()
	state := "pending"
	if t.Status == "completed" || t.FirstArrivedAt != nil {
		state = "completed"
	} else if t.DueAt != nil {
		if now.After(*t.DueAt) {
			state = "overdue"
		} else if now.Add(time.Hour).After(*t.DueAt) {
			state = "due"
		}
	}
	t.DueState = state
	if state == "overdue" && t.Status != "completed" && t.LastEscalationAt == nil {
		mins := 0
		if t.DueAt != nil {
			mins = int(now.Sub(*t.DueAt).Minutes())
		}
		level := "提醒"
		if c.RiskLevel == string(assessment.High) || mins >= 24*60 {
			level = "升级"
		} else if mins >= 60 {
			level = "加急"
		}
		t.EscalationLevel, t.LastEscalationAt, t.Late, t.LateMinutes = level, &now, true, mins
		s.Store.PutTask(t)
		s.Store.Event(store.Event{ID: newID(), Type: "task_overdue_escalated", CaseID: id, At: now, Data: map[string]any{"level": level, "late_minutes": mins}})
	} else {
		s.Store.PutTask(t)
	}
	return t, nil
}

func (s *Service) AcknowledgeEscalation(id string, rev int, by, reason, assignee string) (store.Case, error) {
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if c.Revision != rev {
		return c, ErrConflict
	}
	t, ok := s.Store.GetTaskByCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if strings.TrimSpace(reason) == "" {
		return c, errors.New("催办确认理由不能为空")
	}
	t.EscalationAcknowledged = true
	t.EscalationReason = reason
	if assignee != "" {
		t.Assignee = assignee
		c.Assignee = assignee
	}
	s.Store.PutTask(t)
	c.Revision++
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "task_escalation_acknowledged", CaseID: id, At: time.Now(), Data: map[string]any{"by": by, "reason": reason}})
	return c, nil
}
func (s *Service) WithdrawApproval(id string, rev int, by string) (store.Case, error) {
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if c.Revision != rev {
		return c, ErrConflict
	}
	if c.Status != "mitigation" {
		return c, ErrInvalidTransition
	}
	ev, eok := s.Store.GetEvidenceByCase(id)
	if !eok || !evidence.Verify(ev) {
		return c, errors.New("归档完整性校验失败：证据哈希或字段缺失")
	}
	if _, dok := s.Store.GetDecision(c.DecisionID); !dok {
		return c, errors.New("归档缺少批准决定")
	}
	if len(s.Store.ListRetests(id)) > 0 {
		return c, errors.New("已有复测记录，不能撤回")
	}
	d, ok := s.Store.GetDecision(c.DecisionID)
	if !ok {
		return c, errors.New("批准决定不存在")
	}
	now := time.Now()
	d.WithdrawnAt = &now
	s.Store.PutDecision(d)
	c.Status = "evidence_submitted"
	c.Revision++
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "mitigation_withdrawn", CaseID: id, At: now, Data: map[string]any{"by": by}})
	return c, nil
}
func (s *Service) Close(id string, rev int, after assessment.Signal) (store.Case, error) {
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if c.Revision != rev {
		return c, ErrConflict
	}
	if c.Status != "mitigation" && c.Status != "pending_reinspection" {
		return c, ErrInvalidTransition
	}
	if c.RetestPlanDueAt != nil && time.Now().After(*c.RetestPlanDueAt) {
		return c, errors.New("处置决定已到期，需要负责人续期")
	}
	if ok, bad, why := s.Store.VerifyEventChain(id); !ok {
		return c, fmt.Errorf("审计链校验失败(%s): %s", bad, why)
	}
	qualitySignal := after
	a, _ := s.Store.GetAlert(c.AlertID)
	if qualitySignal.DominantFrequency <= 0 {
		qualitySignal.DominantFrequency = a.DominantFrequency
		qualitySignal.RawDigest = ""
		after.DominantFrequency = qualitySignal.DominantFrequency
	}
	if q := assessment.Check(qualitySignal); !q.Valid {
		return c, errors.New(q.Reason)
	}
	d, _ := s.Store.GetDecision(c.DecisionID)
	if c.RiskLevel == string(assessment.High) && d.Action == "限载" {
		missing := []string{}
		for _, k := range []string{"load_scope", "monitoring_frequency", "site_isolation"} {
			if !d.Checklist[k] {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			return c, fmt.Errorf("执行清单未完成: %s", strings.Join(missing, ","))
		}
	}
	ev, evOK := s.Store.GetEvidenceByCase(id)
	if !evOK || !evidence.Verify(ev) || func() bool { good, _, _ := evidence.VerifyChain(ev); return !good }() {
		return c, errors.New("证据包不完整或哈希校验失败")
	}
	if d.DecisionID == "" {
		return c, errors.New("批准决定不存在")
	}
	for _, rt := range s.Store.ListRetests(id) {
		if rt.Revision == rev {
			return c, errors.New("同一revision已提交相同复测")
		}
	}
	baseOK, baseReason := assessment.BaselineCheck(assessment.Signal{DominantFrequency: a.DominantFrequency, DurationMS: a.DurationMS}, assessment.Signal{DominantFrequency: ev.ResampleFrequency, DurationMS: ev.ResampleDuration, RawDigest: ev.ResampleDigest}, qualitySignal)
	if !baseOK {
		s.Store.Event(store.Event{ID: newID(), Type: "retest_baseline_failed", CaseID: id, At: time.Now(), Data: map[string]any{"reason": baseReason}})
		return c, errors.New("复测基线异常: " + baseReason)
	}
	if d.Action == "持续观测" && d.MonitoringWindow != "" {
		hours := 0
		if strings.HasSuffix(d.MonitoringWindow, "d") {
			var days int
			fmt.Sscanf(d.MonitoringWindow, "%dd", &days)
			hours = days * 24
		} else {
			fmt.Sscanf(d.MonitoringWindow, "%dh", &hours)
		}
		if hours > 0 {
			if time.Now().Before(d.ApprovedAt.Add(time.Duration(hours) * time.Hour)) {
				next := d.ApprovedAt.Add(time.Duration(hours) * time.Hour)
				c.NextReviewAt = &next
				s.Store.PutCase(c)
				return c, fmt.Errorf("观测窗口尚未结束，可于%s后复测", next.Format(time.RFC3339))
			}
		}
	}
	good, why := assessment.Recovery(assessment.Signal{PeakAmplitude: a.PeakAmplitude, DurationMS: a.DurationMS}, after)
	rate := 0.0
	if a.PeakAmplitude > 0 {
		rate = (a.PeakAmplitude - after.PeakAmplitude) / a.PeakAmplitude
	}
	previous := s.Store.ListRetests(id)
	s.Store.PutRetest(store.Retest{ID: newID(), CaseID: id, At: time.Now(), PeakAmplitude: after.PeakAmplitude, DominantFrequency: after.DominantFrequency, DurationMS: after.DurationMS, Passed: good, Explanation: why, ChangeRate: rate, Revision: rev, BaselineOK: true, BaselineReason: baseReason})
	trendWarning := false
	if len(previous) > 0 && previous[len(previous)-1].PeakAmplitude > 0 && after.PeakAmplitude >= previous[len(previous)-1].PeakAmplitude*1.2 {
		trendWarning = true
	}
	if !good && len(previous) > 0 && !previous[len(previous)-1].Passed {
		trendWarning = true
	}
	if trendWarning {
		c.ReviewCount++
		s.Store.Event(store.Event{ID: newID(), Type: "retest_trend_warning", CaseID: id, At: time.Now(), Data: map[string]any{"failure_count": len(previous) + 1, "recommendation": "重新处置", "peak": after.PeakAmplitude}})
	}
	if !good {
		c.ReviewCount++
		c.RetestFailureCount++
		if c.RetestFailureCount >= 2 || trendWarning {
			c.Status = "pending_reinspection"
			c.NeedsReReview = true
			c.ReopenCount++
			c.ReopenReason = why
			due := time.Now().Add(4 * time.Hour)
			nt := store.Task{TaskID: newID(), CaseID: id, Assignee: c.Assignee, TargetCheckpoint: "P1", Status: "open", DueAt: &due}
			s.Store.PutTask(nt)
			c.TaskID = nt.TaskID
			c.Revision++
			s.Store.Event(store.Event{ID: newID(), Type: "retest_reopened", CaseID: id, At: time.Now(), Data: map[string]any{"reason": why, "reopen_count": c.ReopenCount, "task_id": nt.TaskID}})
			s.Store.PutCase(c)
			return c, fmt.Errorf("复测失败，已重新安排核验任务")
		}
		c.Revision++
		s.Store.PutCase(c)
		s.Store.Event(store.Event{ID: newID(), Type: "retest_failed", CaseID: id, At: time.Now(), Data: map[string]any{"explanation": why, "attempt": c.ReviewCount}})
		return c, fmt.Errorf("复测未达到关闭阈值")
	}
	retests := s.Store.ListRetests(id)
	passed := 0
	for _, rt := range retests {
		if rt.Passed {
			passed++
		}
	}
	c.RetestPassRate = float64(passed) / float64(len(retests))
	if len(retests) >= 2 {
		prev := retests[len(retests)-2]
		latest := retests[len(retests)-1]
		change := 0.0
		if prev.PeakAmplitude > 0 {
			change = math.Abs(latest.PeakAmplitude-prev.PeakAmplitude) / prev.PeakAmplitude
		}
		freqShift := math.Abs(latest.DominantFrequency - prev.DominantFrequency)
		switch {
		case change > 0.2 || (!latest.Passed && !prev.Passed):
			c.RetestTrend = "恶化"
			c.RetestRecommendation = "重新处置并提高监测频率"
		case change > 0.1 || freqShift > 1:
			c.RetestTrend = "波动"
			c.RetestRecommendation = "保持观测，建议在下一窗口复测"
		default:
			c.RetestTrend = "稳定"
			c.RetestRecommendation = "按计划完成观测窗口"
		}
	}
	c.RetestConsecutivePasses = 0
	for i := len(retests) - 1; i >= 0 && retests[i].Passed; i-- {
		c.RetestConsecutivePasses++
	}
	if c.RetestConsecutivePasses >= 2 {
		c.RetestStability = "通过"
	} else {
		c.RetestStability = "观察中"
	}
	doc, _ := s.Store.GetDecision(c.DecisionID)
	consecutive := len(retests) >= 2 && retests[len(retests)-1].Passed && retests[len(retests)-2].Passed
	stable := consecutive
	if len(retests) >= 2 {
		stable = stable && retests[len(retests)-1].PeakAmplitude <= retests[len(retests)-2].PeakAmplitude
	}
	if doc.Action == "持续观测" && !stable {
		next := time.Now().Add(parseWindowDuration(doc.MonitoringWindow))
		c.RetestPlanDueAt = &next
		c.NextReviewAt = &next
		c.ReviewCount++
		c.Revision++
		s.Store.PutCase(c)
		return c, fmt.Errorf("需要连续两次达标复测")
	}
	if c.RetestTrend == "波动" {
		next := time.Now().Add(parseWindowDuration(doc.MonitoringWindow))
		c.RetestPlanDueAt = &next
		c.NextReviewAt = &next
		c.ReviewCount++
		c.Revision++
		s.Store.PutCase(c)
		s.Store.Event(store.Event{ID: newID(), Type: "retest_trend_warning", CaseID: id, At: time.Now(), Data: map[string]any{"trend": c.RetestTrend, "recommendation": c.RetestRecommendation}})
		return c, errors.New("复测趋势波动，继续观测")
	}
	now := time.Now()
	c.Status = "closed"
	c.ClosedAt = &now
	c.Revision++
	c.ArchiveStatus = "verified"
	archiveInput := assessment.Signal{PeakAmplitude: c.BeforePeak, DominantFrequency: after.DominantFrequency, DurationMS: len(s.Store.EventsForCase(id)) + len(s.Store.ListRetests(id))}
	c.ArchiveHash = assessment.Digest(archiveInput)
	c.AuditCount = s.Store.CountEvents(id) + 1
	chainHead := ""
	if evs := s.Store.EventsForCase(id); len(evs) > 0 {
		chainHead = evs[len(evs)-1].Hash
	}
	dIDs := []string{}
	for _, dd := range s.Store.Snapshot().Decisions {
		if dd.CaseID == id {
			dIDs = append(dIDs, dd.DecisionID)
		}
	}
	c.ArchiveManifest = s.archiveManifestForCase(
		c.ArchiveHash,
		assessment.Digest(assessment.Signal{PeakAmplitude: c.BeforePeak, DominantFrequency: a.DominantFrequency, DurationMS: a.DurationMS}),
		ev.Hash,
		chainHead,
		dIDs,
		len(s.Store.ListRetests(id)),
		c.AuditCount,
	)
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "case_closed", CaseID: id, At: now})
	return c, nil
}

func (s *Service) UpdateChecklist(id string, rev int, item string, done bool, by, note string) (store.Case, error) {
	c, ok := s.Store.GetCase(id)
	if !ok {
		return c, store.ErrNotFound
	}
	if c.Revision != rev {
		return c, ErrConflict
	}
	if c.Status != "mitigation" {
		return c, ErrInvalidTransition
	}
	d, ok := s.Store.GetDecision(c.DecisionID)
	if !ok {
		return c, errors.New("批准决定不存在")
	}
	if d.Checklist == nil {
		d.Checklist = map[string]bool{}
	}
	if strings.TrimSpace(item) == "" {
		return c, errors.New("清单项不能为空")
	}
	d.Checklist[item] = done
	s.Store.PutDecision(d)
	c.Revision++
	s.Store.PutCase(c)
	s.Store.Event(store.Event{ID: newID(), Type: "checklist_updated", CaseID: id, At: time.Now(), Data: map[string]any{"item": item, "done": done, "by": by, "note": note}})
	return c, nil
}
