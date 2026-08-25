package httpapi

import (
	"bridgewatch/internal/assessment"
	"bridgewatch/internal/evidence"
	"bridgewatch/internal/store"
	"bridgewatch/internal/workflow"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Server struct {
	WF  *workflow.Service
	Mux *http.ServeMux
}

func New(wf *workflow.Service) *Server {
	s := &Server{WF: wf, Mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) batchAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		write(w, map[string]string{"error": "路径错误"}, 404)
		return
	}
	id := parts[3]
	b, ok := s.WF.Store.GetBatch(id)
	if !ok {
		write(w, map[string]string{"error": "batch_id不存在"}, 404)
		return
	}
	if !b.CreatedAt.IsZero() && time.Since(b.CreatedAt) > 30*24*time.Hour {
		write(w, map[string]string{"error": "batch_id已过期"}, 404)
		return
	}
	if r.Method == "GET" {
		write(w, b, 200)
		return
	}
	if r.Method != "POST" || len(parts) < 5 || parts[4] != "replay" {
		write(w, map[string]string{"error": "method not allowed"}, 405)
		return
	}
	var q struct {
		Items []struct {
			Index int      `json:"index"`
			Alert alertReq `json:"alert"`
		} `json:"items"`
	}
	if decode(r, &q) != nil {
		write(w, map[string]string{"error": "请求无效"}, 400)
		return
	}
	idx := make([]int, 0, len(q.Items))
	ins := make([]workflow.AlertInput, 0, len(q.Items))
	for _, x := range q.Items {
		idx = append(idx, x.Index)
		ins = append(ins, workflow.AlertInput{AlertID: x.Alert.AlertID, BridgeID: x.Alert.BridgeID, SensorID: x.Alert.SensorID, CapturedAt: x.Alert.CapturedAt, Signal: assessment.Signal{PeakAmplitude: x.Alert.PeakAmplitude, DominantFrequency: x.Alert.DominantFrequency, DurationMS: x.Alert.DurationMS, RawDigest: x.Alert.RawDigest}})
	}
	out, e := s.WF.ReplayBatch(id, idx, ins)
	if e != nil {
		code := 400
		if errors.Is(e, store.ErrNotFound) {
			code = 404
		}
		write(w, map[string]string{"error": e.Error()}, code)
		return
	}
	write(w, out, 200)
}

type alertReq struct {
	AlertID               string    `json:"alert_id"`
	BridgeID              string    `json:"bridge_id"`
	SensorID              string    `json:"sensor_id"`
	CapturedAt            time.Time `json:"captured_at"`
	PeakAmplitude         float64   `json:"peak_amplitude"`
	DominantFrequency     float64   `json:"dominant_frequency"`
	DurationMS            int       `json:"duration_ms"`
	RawDigest             string    `json:"raw_digest"`
	ReceivedAt            time.Time `json:"received_at,omitempty"`
	DriftToleranceSec     int       `json:"drift_tolerance_seconds,omitempty"`
	ClockSkewToleranceSec int       `json:"clock_skew_tolerance_seconds,omitempty"`
	DensityWindowSec      int       `json:"density_window_seconds,omitempty"`
}

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		write(w, map[string]string{"error": "method not allowed"}, 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	body, e := io.ReadAll(r.Body)
	if e != nil {
		write(w, map[string]string{"error": "请求体过大"}, 413)
		return
	}
	var envelope struct {
		BatchID  string     `json:"batch_id"`
		Alerts   []alertReq `json:"alerts"`
		Action   string     `json:"action"`
		CaseID   string     `json:"case_id"`
		AlertID  string     `json:"alert_id"`
		Revision int        `json:"revision"`
		Operator string     `json:"operator"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		write(w, map[string]string{"error": "请求无效"}, 400)
		return
	}
	if envelope.Action == "split" {
		if envelope.CaseID == "" || envelope.AlertID == "" || envelope.Revision <= 0 {
			write(w, map[string]string{"error": "拆分参数不完整"}, 400)
			return
		}
		old, nc, er := s.WF.SplitAlert(envelope.CaseID, envelope.AlertID, envelope.Revision, envelope.Operator, r.Header.Get("Idempotency-Key"))
		if er != nil {
			code := 400
			if errors.Is(er, workflow.ErrConflict) {
				code = 409
			}
			write(w, map[string]string{"error": er.Error()}, code)
			return
		}
		write(w, map[string]any{"case": old, "new_case": nc}, 200)
		return
	}
	if len(envelope.Alerts) > 0 || envelope.BatchID != "" {
		if len(envelope.Alerts) == 0 {
			write(w, map[string]string{"error": "alerts不能为空"}, 400)
			return
		}
		if len(envelope.Alerts) > 100 {
			write(w, map[string]string{"error": "单批最多100条告警"}, 400)
			return
		}
		batchID := strings.TrimSpace(envelope.BatchID)
		if batchID == "" {
			batchID = r.Header.Get("Idempotency-Key")
			if batchID == "" {
				batchID = strconv.FormatInt(time.Now().UnixNano(), 10)
			}
		}
		if old, exists := s.WF.Store.GetBatch(batchID); exists {
			write(w, map[string]any{"batch_id": batchID, "success_count": old.SuccessCount, "failure_count": old.FailureCount, "total": old.Total, "items": old.Items}, 200)
			return
		}
		items := make([]map[string]any, 0, len(envelope.Alerts))
		batchItems := make([]store.BatchItem, 0, len(envelope.Alerts))
		seenAlerts := map[string]bool{}
		success, failed := 0, 0
		for i, a := range envelope.Alerts {
			if a.AlertID != "" && seenAlerts[a.AlertID] {
				items = append(items, map[string]any{"item": i, "ok": false, "error": "批次内重复告警标识"})
				batchItems = append(batchItems, store.BatchItem{Index: i, RequestID: fmt.Sprintf("batch:%s:%d", batchID, i), Fingerprint: workflow.AlertFingerprint(workflow.AlertInput{AlertID: a.AlertID, BridgeID: a.BridgeID, SensorID: a.SensorID, CapturedAt: a.CapturedAt, Signal: assessment.Signal{PeakAmplitude: a.PeakAmplitude, DominantFrequency: a.DominantFrequency, DurationMS: a.DurationMS, RawDigest: a.RawDigest}}), Alert: store.Alert{AlertID: a.AlertID, BridgeID: a.BridgeID, SensorID: a.SensorID, CapturedAt: a.CapturedAt, PeakAmplitude: a.PeakAmplitude, DominantFrequency: a.DominantFrequency, DurationMS: a.DurationMS, RawDigest: a.RawDigest}, Status: "failed", Error: "批次内重复告警标识"})
				failed++
				continue
			}
			if a.AlertID != "" {
				seenAlerts[a.AlertID] = true
			}
			reqID := fmt.Sprintf("batch:%s:%d", batchID, i)
			if a.AlertID != "" {
				reqID = "batch:" + batchID + ":" + a.AlertID
			}
			if a.RawDigest == "" {
				items = append(items, map[string]any{"item": i, "ok": false, "error": "raw_digest不能为空"})
				batchItems = append(batchItems, store.BatchItem{Index: i, RequestID: reqID, Fingerprint: workflow.AlertFingerprint(workflow.AlertInput{AlertID: a.AlertID, BridgeID: a.BridgeID, SensorID: a.SensorID, CapturedAt: a.CapturedAt, Signal: assessment.Signal{PeakAmplitude: a.PeakAmplitude, DominantFrequency: a.DominantFrequency, DurationMS: a.DurationMS, RawDigest: a.RawDigest}}), Alert: store.Alert{AlertID: a.AlertID, BridgeID: a.BridgeID, SensorID: a.SensorID, CapturedAt: a.CapturedAt, PeakAmplitude: a.PeakAmplitude, DominantFrequency: a.DominantFrequency, DurationMS: a.DurationMS, RawDigest: a.RawDigest}, Status: "failed", Error: "raw_digest不能为空"})
				failed++
				continue
			}
			tol := a.DriftToleranceSec
			if tol == 0 {
				tol = a.ClockSkewToleranceSec
			}
			c, err := s.WF.Receive(workflow.AlertInput{AlertID: a.AlertID, BridgeID: a.BridgeID, SensorID: a.SensorID, CapturedAt: a.CapturedAt, ReceivedAt: a.ReceivedAt, DriftTolerance: time.Duration(tol) * time.Second, DensityWindow: time.Duration(a.DensityWindowSec) * time.Second, Signal: assessment.Signal{PeakAmplitude: a.PeakAmplitude, DominantFrequency: a.DominantFrequency, DurationMS: a.DurationMS, RawDigest: a.RawDigest}}, reqID)
			if err != nil {
				items = append(items, map[string]any{"item": i, "ok": false, "error": err.Error()})
				batchItems = append(batchItems, store.BatchItem{Index: i, RequestID: reqID, Fingerprint: workflow.AlertFingerprint(workflow.AlertInput{AlertID: a.AlertID, BridgeID: a.BridgeID, SensorID: a.SensorID, CapturedAt: a.CapturedAt, Signal: assessment.Signal{PeakAmplitude: a.PeakAmplitude, DominantFrequency: a.DominantFrequency, DurationMS: a.DurationMS, RawDigest: a.RawDigest}}), Alert: store.Alert{AlertID: a.AlertID, BridgeID: a.BridgeID, SensorID: a.SensorID, CapturedAt: a.CapturedAt, PeakAmplitude: a.PeakAmplitude, DominantFrequency: a.DominantFrequency, DurationMS: a.DurationMS, RawDigest: a.RawDigest}, Status: "failed", Error: err.Error()})
				failed++
			} else {
				items = append(items, map[string]any{"item": i, "ok": true, "case_id": c.CaseID, "risk_level": c.RiskLevel, "quality_score": c.QualityScore, "needs_re_review": c.NeedsReReview, "risk_alert_count": c.RiskAlertCount})
				batchItems = append(batchItems, store.BatchItem{Index: i, RequestID: reqID, Fingerprint: workflow.AlertFingerprint(workflow.AlertInput{AlertID: a.AlertID, BridgeID: a.BridgeID, SensorID: a.SensorID, CapturedAt: a.CapturedAt, Signal: assessment.Signal{PeakAmplitude: a.PeakAmplitude, DominantFrequency: a.DominantFrequency, DurationMS: a.DurationMS, RawDigest: a.RawDigest}}), Alert: store.Alert{AlertID: a.AlertID, BridgeID: a.BridgeID, SensorID: a.SensorID, CapturedAt: a.CapturedAt, PeakAmplitude: a.PeakAmplitude, DominantFrequency: a.DominantFrequency, DurationMS: a.DurationMS, RawDigest: a.RawDigest}, Status: "success", CaseID: c.CaseID, RiskLevel: c.RiskLevel, QualityScore: c.QualityScore, NeedsReReview: c.NeedsReReview})
				success++
			}
		}
		if old, exists := s.WF.Store.GetBatch(batchID); exists {
			write(w, map[string]any{"batch_id": batchID, "success_count": old.SuccessCount, "failure_count": old.FailureCount, "total": old.Total, "items": old.Items}, 200)
			return
		}
		s.WF.Store.PutBatch(store.Batch{BatchID: batchID, CreatedAt: time.Now(), Items: batchItems, SuccessCount: success, FailureCount: failed, Total: len(envelope.Alerts)})
		st := s.WF.Store
		if seen, _ := st.Once("batch:event:" + batchID); !seen {
			st.Event(store.Event{ID: fmt.Sprintf("batch-%d", time.Now().UnixNano()), Type: "alert_batch_received", RequestID: batchID, At: time.Now(), Data: map[string]any{"batch_id": batchID, "success": success, "failed": failed}})
			st.Mark("batch:event:"+batchID, true)
		}
		code := 201
		if success == 0 {
			code = 400
		}
		write(w, map[string]any{"batch_id": batchID, "success_count": success, "failure_count": failed, "total": len(envelope.Alerts), "items": items}, code)
		return
	}
	var q alertReq
	if e := json.Unmarshal(body, &q); e != nil {
		write(w, map[string]string{"error": e.Error()}, 400)
		return
	}
	if q.RawDigest == "" {
		write(w, map[string]string{"error": "raw_digest不能为空"}, 400)
		return
	}
	tol := q.DriftToleranceSec
	if tol == 0 {
		tol = q.ClockSkewToleranceSec
	}
	c, e := s.WF.Receive(workflow.AlertInput{AlertID: q.AlertID, BridgeID: q.BridgeID, SensorID: q.SensorID, CapturedAt: q.CapturedAt, ReceivedAt: q.ReceivedAt, DriftTolerance: time.Duration(tol) * time.Second, DensityWindow: time.Duration(q.DensityWindowSec) * time.Second, Signal: assessment.Signal{PeakAmplitude: q.PeakAmplitude, DominantFrequency: q.DominantFrequency, DurationMS: q.DurationMS, RawDigest: q.RawDigest}}, r.Header.Get("Idempotency-Key"))
	if e != nil {
		write(w, map[string]string{"error": e.Error()}, 400)
		return
	}
	write(w, c, 201)
}
func (s *Server) cases(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		write(w, map[string]string{"error": "method not allowed"}, 405)
		return
	}
	all := s.WF.Store.ListCases()
	q := r.URL.Query()
	if rv := q.Get("risk_level"); rv != "" && rv != "low" && rv != "medium" && rv != "high" && rv != "noise" {
		write(w, map[string]string{"error": "risk_level参数无效"}, 400)
		return
	}
	from, to, errRange := parseTimeRange(q.Get("from"), q.Get("to"))
	if errRange != nil {
		write(w, map[string]string{"error": errRange.Error()}, 400)
		return
	}
	out := []store.Case{}
	for _, c := range all {
		if q.Get("bridge_id") != "" {
			a, _ := s.WF.Store.GetAlert(c.AlertID)
			bridge := c.CurrentBridgeID
			if bridge == "" {
				bridge = a.BridgeID
			}
			if bridge != q.Get("bridge_id") {
				continue
			}
		}
		if q.Get("status") != "" && c.Status != q.Get("status") {
			continue
		}
		if q.Get("risk_level") != "" && c.RiskLevel != q.Get("risk_level") {
			continue
		}
		if q.Get("time_quality") != "" && c.TimeQuality != q.Get("time_quality") {
			continue
		}
		if q.Get("density_min") != "" {
			n, _ := strconv.Atoi(q.Get("density_min"))
			if c.DensityCount < n {
				continue
			}
		}
		if q.Get("sensor_id") != "" {
			a, _ := s.WF.Store.GetAlert(c.AlertID)
			sensor := c.CurrentSensorID
			if sensor == "" {
				sensor = a.SensorID
			}
			if sensor != q.Get("sensor_id") {
				continue
			}
		}
		if q.Get("closed_from") != "" && (c.ClosedAt == nil || c.ClosedAt.Before(parseLooseTime(q.Get("closed_from")))) {
			continue
		}
		if q.Get("closed_to") != "" && (c.ClosedAt == nil || c.ClosedAt.After(parseLooseTime(q.Get("closed_to")))) {
			continue
		}
		if !from.IsZero() && c.ReceivedAt.Before(from) {
			continue
		}
		if !to.IsZero() && c.ReceivedAt.After(to) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Revision == out[j].Revision {
			return out[i].CaseID < out[j].CaseID
		}
		return out[i].Revision > out[j].Revision
	})
	total := len(out)
	statsCases := append([]store.Case(nil), out...)
	if p, _ := strconv.Atoi(q.Get("page")); p > 0 {
		size, _ := strconv.Atoi(q.Get("page_size"))
		if size <= 0 {
			size = 20
		}
		start := (p - 1) * size
		if start >= len(out) {
			out = []store.Case{}
		} else {
			end := start + size
			if end > len(out) {
				end = len(out)
			}
			out = out[start:end]
		}
	}
	if q.Get("stats") == "1" || q.Get("archive") == "1" || q.Get("archive_summary") == "1" {
		counts := map[string]int{}
		riskCounts := map[string]int{}
		var durationTotal time.Duration
		var durationN int
		unassigned := 0
		unclaimed, expiredClaims := 0, 0
		late := 0
		lateEvidence := 0
		lateMinutesTotal := 0
		noise := 0
		reclassified := 0
		for _, c := range statsCases {
			if c.Status == "pending_review" {
				if c.Claim == nil {
					unclaimed++
				} else if time.Now().After(c.Claim.ExpiresAt) {
					expiredClaims++
				}
			}
			_, _ = s.WF.RefreshTaskDue(c.CaseID)
			counts[c.Status]++
			riskCounts[c.RiskLevel]++
			if c.ClosedAt != nil {
				durationTotal += c.ClosedAt.Sub(c.ReceivedAt)
				durationN++
			}
			if t, ok := s.WF.Store.GetTaskByCase(c.CaseID); ok && t.Status == "open" && strings.TrimSpace(t.Assignee) == "" {
				unassigned++
			}
			if t, ok := s.WF.Store.GetTaskByCase(c.CaseID); ok && t.Late {
				late++
			}
			if ev, ok := s.WF.Store.GetEvidenceByCase(c.CaseID); ok && ev.DueState == "late" {
				lateEvidence++
				lateMinutesTotal += ev.LateMinutes
			}
			if c.RiskLevel == "noise" {
				noise++
			}
			reclassified += c.NoiseReclassifiedCount
		}
		avg := 0.0
		if durationN > 0 {
			avg = durationTotal.Hours() / float64(durationN)
		}
		falseRate := 0.0
		if len(statsCases) > 0 {
			falseRate = float64(noise) / float64(len(statsCases))
		}
		avgLate := 0.0
		if lateEvidence > 0 {
			avgLate = float64(lateMinutesTotal) / float64(lateEvidence)
		}
		stats := map[string]any{"by_status": counts, "by_risk": riskCounts, "average_handling_hours": avg, "unassigned_tasks": unassigned, "late_tasks": late, "late_evidence": lateEvidence, "average_late_minutes": avgLate, "noise_total": noise, "noise_reclassified": reclassified, "false_positive_rate": falseRate, "unclaimed_cases": unclaimed, "expired_claims": expiredClaims}
		if g := q.Get("group_by"); g != "" {
			if g != "bridge" && g != "sensor" {
				write(w, map[string]string{"error": "group_by仅支持bridge或sensor"}, 400)
				return
			}
			groups := map[string]map[string]any{}
			for _, c := range statsCases {
				key := c.CurrentBridgeID
				if g == "sensor" {
					key = c.CurrentSensorID
				}
				if key == "" {
					a, _ := s.WF.Store.GetAlert(c.AlertID)
					if g == "bridge" {
						key = a.BridgeID
					} else {
						key = a.SensorID
					}
				}
				x := groups[key]
				if x == nil {
					x = map[string]any{"total": 0, "by_risk": map[string]int{}, "quality_sum": 0, "noise": 0, "risk_upgrades": 0, "risk_downgrades": 0, "unreviewed": 0, "recent_alert_at": (*time.Time)(nil)}
					groups[key] = x
				}
				x["total"] = x["total"].(int) + 1
				br := x["by_risk"].(map[string]int)
				br[c.RiskLevel]++
				x["quality_sum"] = x["quality_sum"].(int) + c.QualityScore
				if c.RiskLevel == "noise" {
					x["noise"] = x["noise"].(int) + 1
				}
				if c.Status == "pending_review" || c.NeedsReReview {
					x["unreviewed"] = x["unreviewed"].(int) + 1
				}
				for _, ev := range s.WF.Store.EventsForCase(c.CaseID) {
					if ev.Type == "risk_diff" {
						if old, ok := ev.Data["old_risk"].(string); ok {
							if nr, ok := ev.Data["new_risk"].(string); ok {
								rank := func(v string) int {
									switch v {
									case "low":
										return 1
									case "medium":
										return 2
									case "high":
										return 3
									}
									return 0
								}
								if rank(nr) > rank(old) {
									x["risk_upgrades"] = x["risk_upgrades"].(int) + 1
								} else if rank(nr) < rank(old) {
									x["risk_downgrades"] = x["risk_downgrades"].(int) + 1
								}
							}
						}
					}
				}
				t := c.CurrentCapturedAt
				if t == nil {
					t = c.SourceCapturedAt
				}
				if t != nil && (x["recent_alert_at"].(*time.Time) == nil || t.After(*x["recent_alert_at"].(*time.Time))) {
					x["recent_alert_at"] = t
				}
			}
			for _, x := range groups {
				total := x["total"].(int)
				x["average_quality"] = float64(x["quality_sum"].(int)) / float64(total)
				x["noise_rate"] = float64(x["noise"].(int)) / float64(total)
				delete(x, "quality_sum")
				delete(x, "noise")
			}
			stats["groups"] = groups
		}
		if q.Get("archive") == "1" || q.Get("archive_summary") == "1" {
			summaries := make([]map[string]any, 0, len(statsCases))
			valid := 0
			anomalies := 0
			for _, c := range statsCases {
				ev, eok := s.WF.Store.GetEvidenceByCase(c.CaseID)
				_, dok := s.WF.Store.GetDecision(c.DecisionID)
				rts := s.WF.Store.ListRetests(c.CaseID)
				anomaly := ""
				if c.Status == "closed" {
					if !eok || !evidence.Verify(ev) {
						anomaly = "证据哈希异常"
					}
					if !dok {
						anomaly = "缺少批准决定"
					}
					if len(rts) == 0 {
						anomaly = "缺少复测"
					}
					if c.ArchiveHash == "" {
						anomaly = "缺少归档哈希"
					}
					if ok, bad, _ := s.WF.Store.VerifyEventChain(c.CaseID); !ok {
						anomaly = "审计链异常:" + bad
					}
					if c.ArchiveManifest == nil {
						anomaly = "缺少归档清单"
					}
				}
				if anomaly != "" {
					anomalies++
				} else if c.Status == "closed" {
					valid++
				}
				item := map[string]any{"case_id": c.CaseID, "archive_hash": c.ArchiveHash, "audit_event_count": len(s.WF.Store.EventsForCase(c.CaseID)), "evidence_hash_ok": eok && evidence.Verify(ev), "decision": dok, "last_retest": nil, "anomaly": anomaly}
				if len(rts) > 0 {
					item["last_retest"] = rts[len(rts)-1]
				}
				summaries = append(summaries, item)
			}
			rate := 0.0
			closed := 0
			for _, c := range statsCases {
				if c.Status == "closed" {
					closed++
				}
			}
			if closed > 0 {
				rate = float64(valid) / float64(closed)
			}
			stats["archive_summaries"] = summaries
			stats["verifiable_pass_rate"] = rate
			stats["archive_anomalies"] = anomalies
		}
		write(w, map[string]any{"items": out, "total": total, "stats": stats}, 200)
		return
	}
	if len(q) == 0 {
		write(w, out, 200)
		return
	}
	payload := map[string]any{"items": out, "total": total}
	if q.Get("thresholds") == "1" {
		payload["threshold_catalog"] = map[string]any{"default_version": assessment.DefaultThreshold(), "items": assessment.ThresholdCatalog()}
	}
	write(w, payload, 200)
}
func (s *Server) caseAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		write(w, map[string]string{"error": "路径错误"}, 404)
		return
	}
	id := parts[2]
	if len(parts) == 3 {
		if r.Method != "GET" {
			write(w, map[string]string{"error": "method not allowed"}, 405)
			return
		}
		c, ok := s.WF.Store.GetCase(id)
		if !ok {
			write(w, map[string]string{"error": "not found"}, 404)
			return
		}
		a, _ := s.WF.Store.GetAlert(c.AlertID)
		events := s.WF.Store.EventsForCase(id)
		sort.Slice(events, func(i, j int) bool { return events[i].At.Before(events[j].At) })
		payload := map[string]any{"case": c, "alert": a, "events": events}
		payload["claim"] = s.WF.ClaimStatus(c)
		chainOK, badEvent, chainErr := s.WF.Store.VerifyEventChain(id)
		payload["audit_chain"] = map[string]any{"ok": chainOK}
		if !chainOK {
			payload["audit_chain"].(map[string]any)["event_id"] = badEvent
			payload["audit_chain"].(map[string]any)["error"] = chainErr
		}
		if c.ArchiveManifest != nil {
			payload["archive_manifest"] = c.ArchiveManifest
		}
		payload["risk_history"] = c.RiskHistory
		payload["review_snapshots"] = c.ReviewSnapshots
		payload["checkins"] = c.Checkins
		riskChanges := make([]store.Event, 0)
		for _, ev := range events {
			if ev.Type == "risk_diff" {
				riskChanges = append(riskChanges, ev)
			}
		}
		payload["risk_changes"] = riskChanges
		sourceBridge, sourceSensor, sourceCaptured := c.SourceBridgeID, c.SourceSensorID, c.SourceCapturedAt
		if sourceBridge == "" {
			sourceBridge = a.BridgeID
		}
		if sourceSensor == "" {
			sourceSensor = a.SensorID
		}
		if sourceCaptured == nil {
			sourceCaptured = &a.CapturedAt
		}
		currentBridge, currentSensor, currentCaptured := c.CurrentBridgeID, c.CurrentSensorID, c.CurrentCapturedAt
		if currentBridge == "" {
			currentBridge = a.BridgeID
		}
		if currentSensor == "" {
			currentSensor = a.SensorID
		}
		if currentCaptured == nil {
			currentCaptured = &a.CapturedAt
		}
		payload["source"] = map[string]any{"bridge_id": sourceBridge, "sensor_id": sourceSensor, "captured_at": sourceCaptured, "current_bridge_id": currentBridge, "current_sensor_id": currentSensor, "current_captured_at": currentCaptured, "merge_count": c.MergeCount}
		payload["audit_event_count"] = len(events)
		if ev, ok := s.WF.Store.GetEvidenceByCase(id); ok {
			payload["evidence"] = ev
			chainOK, badVersion, chainErr := evidence.VerifyChain(ev)
			if !chainOK {
				payload["evidence_chain_error"] = map[string]any{"version": badVersion, "error": chainErr}
			}
			if !evidence.Verify(ev) || !chainOK {
				payload["evidence_anomaly"] = "证据哈希或字段校验失败"
			}
		} else {
			payload["evidence_anomaly"] = "缺少证据关联"
		}
		if d, ok := s.WF.Store.GetDecision(c.DecisionID); ok {
			payload["decision"] = d
			chain := []store.Decision{}
			for _, dd := range s.WF.Store.Snapshot().Decisions {
				if dd.CaseID == id {
					chain = append(chain, dd)
				}
			}
			sort.Slice(chain, func(i, j int) bool { return chain[i].ApprovedAt.Before(chain[j].ApprovedAt) })
			payload["decision_chain"] = chain
		} else if c.Status == "mitigation" || c.Status == "closed" {
			payload["decision_anomaly"] = "缺少批准关联"
		}
		payload["retests"] = s.WF.Store.ListRetests(id)
		if c.RetestPlanDueAt != nil {
			state := "pending"
			if c.Status == "closed" {
				state = "frozen"
			} else if time.Now().After(*c.RetestPlanDueAt) {
				state = "overdue"
			} else if time.Now().Add(time.Hour).After(*c.RetestPlanDueAt) {
				state = "due"
			}
			payload["retest_plan"] = map[string]any{"due_at": c.RetestPlanDueAt, "state": state, "pass_rate": c.RetestPassRate, "consecutive_passes": c.RetestConsecutivePasses, "stability": c.RetestStability}
		}
		if c.Status == "closed" {
			if _, ok := payload["decision"]; !ok {
				payload["decision_anomaly"] = "缺少批准关联"
			}
			if _, ok := payload["evidence"]; !ok {
				payload["evidence_anomaly"] = "缺少证据关联"
			}
			if c.ArchiveHash == "" {
				payload["archive_anomaly"] = "缺少归档哈希"
			}
			if c.AuditCount != len(events) {
				payload["audit_anomaly"] = "审计计数不一致"
			}
			if c.ArchiveHash != "" {
				freq := a.DominantFrequency
				rts := s.WF.Store.ListRetests(id)
				if len(rts) > 0 && rts[len(rts)-1].DominantFrequency > 0 {
					freq = rts[len(rts)-1].DominantFrequency
				}
				archiveSignal := assessment.Signal{PeakAmplitude: c.BeforePeak, DominantFrequency: freq, DurationMS: len(events) - 1 + len(rts)}
				if c.ArchiveHash != assessment.Digest(archiveSignal) {
					payload["archive_anomaly"] = "归档哈希校验失败"
				}
			}
			if c.ArchiveManifest != nil {
				if evm, ok := payload["evidence"].(store.Evidence); ok && c.ArchiveManifest.EvidenceHash != evm.Hash {
					payload["archive_anomaly"] = "归档清单证据哈希不一致"
				}
				if ok, bad, _ := s.WF.Store.VerifyEventChain(id); !ok {
					payload["archive_anomaly"] = "归档审计链异常:" + bad
				}
			}
		}
		write(w, payload, 200)
		return
	}
	action := parts[3]
	if action == "claim" || action == "release" {
		if r.Method != "POST" {
			write(w, map[string]string{"error": "method not allowed"}, 405)
			return
		}
		var q struct {
			Holder string `json:"holder"`
			Token  string `json:"lock_token"`
			TTL    int    `json:"ttl_seconds"`
		}
		if decode(r, &q) != nil {
			write(w, map[string]string{"error": "请求无效"}, 400)
			return
		}
		var c store.Case
		var e error
		if action == "claim" {
			c, e = s.WF.ClaimCase(id, q.Holder, time.Duration(q.TTL)*time.Second)
		} else {
			c, e = s.WF.ReleaseCase(id, q.Holder, q.Token)
		}
		if e != nil {
			code := 400
			if errors.Is(e, workflow.ErrClaimRequired) {
				code = 409
			}
			write(w, map[string]string{"error": e.Error()}, code)
			return
		}
		write(w, c, 200)
		return
	}
	if action == "split" {
		if r.Method != "POST" {
			write(w, map[string]string{"error": "method not allowed"}, 405)
			return
		}
		rev, e := parseRev(r)
		if e != nil {
			write(w, map[string]string{"error": "需要 If-Match revision"}, 400)
			return
		}
		var q struct {
			AlertID  string `json:"alert_id"`
			Operator string `json:"operator"`
		}
		if decode(r, &q) != nil {
			write(w, map[string]string{"error": "请求无效"}, 400)
			return
		}
		old, nc, e := s.WF.SplitAlert(id, q.AlertID, rev, q.Operator, r.Header.Get("Idempotency-Key"))
		if e != nil {
			code := 400
			if errors.Is(e, workflow.ErrConflict) {
				code = 409
			}
			write(w, map[string]string{"error": e.Error()}, code)
			return
		}
		write(w, map[string]any{"case": old, "new_case": nc}, 200)
		return
	}
	if action == "time-release" {
		if r.Method != "POST" {
			write(w, map[string]string{"error": "method not allowed"}, 405)
			return
		}
		rev, e := parseRev(r)
		if e != nil {
			write(w, map[string]string{"error": "需要 If-Match revision"}, 400)
			return
		}
		var q struct {
			By     string `json:"by"`
			Reason string `json:"reason"`
		}
		if decode(r, &q) != nil {
			write(w, map[string]string{"error": "请求无效"}, 400)
			return
		}
		c, e := s.WF.ReleaseTimeGate(id, rev, q.By, q.Reason)
		if e != nil {
			code := 400
			if errors.Is(e, workflow.ErrConflict) {
				code = 409
			}
			write(w, map[string]string{"error": e.Error()}, code)
			return
		}
		write(w, c, 200)
		return
	}
	if action == "evidence" && r.Method == "GET" {
		ev, ok := s.WF.Store.GetEvidenceByCase(id)
		if !ok {
			write(w, map[string]any{"status": "incomplete", "missing": []string{"evidence"}}, 200)
			return
		}
		missing := evidence.Missing(ev)
		status := "complete"
		if len(missing) > 0 {
			status = "incomplete"
		}
		versions := append([]store.EvidenceVersion(nil), ev.History...)
		versions = append(versions, store.EvidenceVersion{Version: ev.Version, Hash: ev.Hash, At: ev.ArrivedAt, SubmittedBy: ev.SubmittedBy, Checkpoint: ev.Checkpoint, PhotoRefs: ev.PhotoRefs, ResamplePeak: ev.ResamplePeak, ResampleFrequency: ev.ResampleFrequency, ResampleDuration: ev.ResampleDuration, ResampleDigest: ev.ResampleDigest, Notes: ev.Notes})
		sort.Slice(versions, func(i, j int) bool { return versions[i].Version < versions[j].Version })
		chainOK, badVersion, chainErr := evidence.VerifyChain(ev)
		payload := map[string]any{"evidence": ev, "versions": versions, "status": status, "missing": missing, "chain_ok": chainOK}
		if owner, conflict := s.WF.Store.FindEvidenceConflict(id, evidence.PhotoFingerprint(ev.PhotoRefs), evidence.ResampleFingerprint(evidence.Input{Checkpoint: ev.Checkpoint, Resample: assessment.Signal{PeakAmplitude: ev.ResamplePeak, DominantFrequency: ev.ResampleFrequency, DurationMS: ev.ResampleDuration, RawDigest: ev.ResampleDigest}})); conflict {
			payload["conflict"] = map[string]any{"owner_case_id": owner, "status": "occupied"}
		} else {
			payload["conflict"] = map[string]any{"status": "none"}
		}
		if !chainOK {
			payload["chain_error"] = map[string]any{"version": badVersion, "error": chainErr}
		}
		write(w, payload, 200)
		return
	}
	if action == "task" && r.Method == "GET" {
		t, err := s.WF.RefreshTaskDue(id)
		ok := err == nil
		if !ok {
			write(w, map[string]string{"error": "not found"}, 404)
			return
		}
		dueState := t.DueState
		if dueState == "" {
			dueState = "pending"
		}
		cc, _ := s.WF.Store.GetCase(id)
		payload := map[string]any{"task": t, "due_state": dueState, "escalated": t.LastEscalationAt != nil && !t.EscalationAcknowledged, "escalation": t.EscalationLevel, "checkins": cc.Checkins}
		payload["pending_correction"] = cc.PendingCorrection
		covered := 0
		for _, cp := range cc.RequiredCheckpoints {
			if cp.ArrivedAt != nil && cp.EvidenceVersion > 0 {
				covered++
			}
		}
		rate := 1.0
		if len(cc.RequiredCheckpoints) > 0 {
			rate = float64(covered) / float64(len(cc.RequiredCheckpoints))
		}
		payload["coverage_rate"] = rate
		payload["missing_checkpoints"] = func() []string {
			m := []string{}
			for _, cp := range cc.RequiredCheckpoints {
				if cp.ArrivedAt == nil || cp.EvidenceVersion == 0 {
					m = append(m, cp.ID)
				}
			}
			return m
		}()
		if t.Late && strings.TrimSpace(t.ReassignReason) == "" {
			payload["pending_confirmation"] = true
		}
		write(w, payload, 200)
		return
	}
	if action == "task" && r.Method == "PUT" {
		rev, e := parseRev(r)
		if e != nil {
			write(w, map[string]string{"error": "需要 If-Match revision"}, 400)
			return
		}
		var q struct {
			Assignee, By, Reason string
			Acknowledge          bool      `json:"acknowledge"`
			Checkin              bool      `json:"checkin"`
			Correction           bool      `json:"correction"`
			At                   time.Time `json:"at"`
			Checkpoint           string    `json:"checkpoint"`
			ApproveCorrection    bool      `json:"approve_correction"`
			RejectCorrection     bool      `json:"reject_correction"`
			Approver             string    `json:"approver"`
		}
		if decode(r, &q) != nil {
			write(w, map[string]string{"error": "请求无效"}, 400)
			return
		}
		var c store.Case
		if q.ApproveCorrection || q.RejectCorrection {
			c, e = s.WF.ApproveCheckinCorrection(id, rev, q.ApproveCorrection, q.Approver, q.Reason)
		} else if q.Checkin || q.Correction {
			kind := "checkin"
			if q.Correction {
				kind = "correction"
			}
			c, e = s.WF.CheckinTask(id, rev, q.At, q.By, q.Checkpoint, kind, q.Reason, r.Header.Get("Idempotency-Key"))
		} else if q.Acknowledge {
			c, e = s.WF.AcknowledgeEscalation(id, rev, q.By, q.Reason, q.Assignee)
		} else {
			c, e = s.WF.ReassignTask(id, rev, q.Assignee, q.By, q.Reason)
		}
		if e != nil {
			code := 400
			if errors.Is(e, workflow.ErrConflict) {
				code = 409
			}
			write(w, map[string]string{"error": e.Error()}, code)
			return
		}
		write(w, c, 200)
		return
	}
	if action == "checklist" && r.Method == "PUT" {
		rev, e := parseRev(r)
		if e != nil {
			write(w, map[string]string{"error": "需要 If-Match revision"}, 400)
			return
		}
		var q struct {
			Item string `json:"item"`
			Done bool   `json:"done"`
			By   string `json:"by"`
			Note string `json:"note"`
		}
		if decode(r, &q) != nil {
			write(w, map[string]string{"error": "请求无效"}, 400)
			return
		}
		c, e := s.WF.UpdateChecklist(id, rev, q.Item, q.Done, q.By, q.Note)
		if e != nil {
			code := 400
			if errors.Is(e, workflow.ErrConflict) {
				code = 409
			}
			write(w, map[string]string{"error": e.Error()}, code)
			return
		}
		write(w, c, 200)
		return
	}
	if action == "timeline" {
		if r.Method == "POST" {
			var q struct {
				By     string `json:"by"`
				Reason string `json:"reason"`
			}
			if decode(r, &q) != nil {
				write(w, map[string]string{"error": "请求无效"}, 400)
				return
			}
			if er := s.WF.RepairAuditChain(id, q.By, q.Reason); er != nil {
				code := 400
				if errors.Is(er, store.ErrNotFound) {
					code = 404
				}
				write(w, map[string]string{"error": er.Error()}, code)
				return
			}
			write(w, map[string]string{"status": "repaired"}, 200)
			return
		}
		if r.Method != "GET" {
			write(w, map[string]string{"error": "method not allowed"}, 405)
			return
		}
		c, ok := s.WF.Store.GetCase(id)
		if !ok {
			write(w, map[string]string{"error": "not found"}, 404)
			return
		}
		ev := s.WF.Store.EventsForCase(id)
		sort.Slice(ev, func(i, j int) bool { return ev[i].At.Before(ev[j].At) })
		q := r.URL.Query()
		typ := q.Get("type")
		from, _ := time.Parse(time.RFC3339, q.Get("from"))
		to, _ := time.Parse(time.RFC3339, q.Get("to"))
		filtered := make([]store.Event, 0, len(ev))
		for _, x := range ev {
			if typ != "" && x.Type != typ {
				continue
			}
			if !from.IsZero() && x.At.Before(from) {
				continue
			}
			if !to.IsZero() && x.At.After(to) {
				continue
			}
			filtered = append(filtered, x)
		}
		limit := 50
		if n, _ := strconv.Atoi(q.Get("limit")); n > 0 && n <= 200 {
			limit = n
		}
		start := 0
		if cur := q.Get("cursor"); cur != "" {
			parts := strings.Split(cur, "|")
			if len(parts) != 5 || parts[0] != id || parts[1] != typ || parts[2] != q.Get("from") || parts[3] != q.Get("to") {
				write(w, map[string]string{"error": "cursor与筛选条件不匹配"}, 400)
				return
			}
			start, _ = strconv.Atoi(parts[4])
			if start < 0 || start > len(filtered) {
				write(w, map[string]string{"error": "cursor已过期"}, 400)
				return
			}
		}
		end := start + limit
		if end > len(filtered) {
			end = len(filtered)
		}
		page := filtered[start:end]
		next := ""
		if end < len(filtered) {
			next = fmt.Sprintf("%s|%s|%s|%s|%d", id, typ, q.Get("from"), q.Get("to"), end)
		}
		integrity := true
		anomaly := ""
		chainOK, badID, chainErr := s.WF.Store.VerifyEventChain(id)
		if !chainOK {
			integrity = false
			anomaly = chainErr + ":" + badID
		}
		if c.AuditCount > 0 && c.AuditCount != len(ev) {
			integrity = false
			anomaly = "审计计数与事件数量不一致"
		}
		for i := 1; i < len(ev); i++ {
			if ev[i].At.Before(ev[i-1].At) {
				integrity = false
				anomaly = "事件时间顺序异常"
				break
			}
		}
		write(w, map[string]any{"case": c, "events": page, "total": len(filtered), "next_cursor": next, "integrity_ok": integrity, "integrity_error": anomaly}, 200)
		return
	}
	rev, e := parseRev(r)
	if e != nil {
		write(w, map[string]string{"error": "需要 If-Match revision"}, 400)
		return
	}
	var out store.Case
	switch action {
	case "review":
		var q struct {
			Reviewer          string             `json:"reviewer"`
			ThresholdVersion  string             `json:"threshold_version"`
			TargetCheckpoint  string             `json:"target_checkpoint"`
			Checkpoints       []string           `json:"checkpoints"`
			CompareVersion    string             `json:"compare_version"`
			Reason            string             `json:"reason"`
			Summary           *assessment.Signal `json:"summary"`
			Preview           bool               `json:"preview"`
			ConfirmToken      string             `json:"confirm_token"`
			ConfirmedBy       string             `json:"confirmed_by"`
			ClaimToken        string             `json:"lock_token"`
			IndependentReview bool               `json:"independent_review"`
			Arbitration       bool               `json:"arbitration"`
			ArbitrationBy     string             `json:"arbitration_by"`
			ArbitrationReason string             `json:"arbitration_reason"`
		}
		if decode(r, &q) != nil {
			write(w, map[string]string{"error": "请求无效"}, 400)
			return
		}
		if q.TargetCheckpoint == "" && len(q.Checkpoints) > 0 {
			q.TargetCheckpoint = strings.Join(q.Checkpoints, ",")
		}
		opts := workflow.ReviewOptions{Reviewer: q.Reviewer, ThresholdVersion: q.ThresholdVersion, CompareVersion: q.CompareVersion, Reason: q.Reason, Summary: q.Summary, TargetCheckpoint: q.TargetCheckpoint, IdempotencyKey: r.Header.Get("Idempotency-Key"), ConfirmToken: q.ConfirmToken, ConfirmedBy: q.ConfirmedBy, ClaimToken: q.ClaimToken, IndependentReview: q.IndependentReview, Arbitration: q.Arbitration, ArbitrationBy: q.ArbitrationBy, ArbitrationReason: q.ArbitrationReason}
		if q.Preview {
			ar, cmp, de := s.WF.Diagnose(id, rev, opts)
			if de != nil {
				e = de
			} else {
				if !ar.Quality.Valid {
					write(w, map[string]any{"error": ar.Quality.Reason, "quality": ar.Quality, "threshold_version": ar.ThresholdVersion}, 400)
					return
				}
				token := ""
				if cc, ok := s.WF.Store.GetCase(id); ok {
					token = cc.ThresholdConfirmToken
				}
				write(w, map[string]any{"preview": true, "quality": ar.Quality, "risk": ar.Risk, "explanation": ar.Explanation, "factors": ar.Factors, "threshold_version": ar.ThresholdVersion, "compare": cmp, "confirm_token": token}, 200)
				return
			}
		} else {
			out, e = s.WF.ReviewWithOptions(id, rev, opts)
		}
	case "evidence":
		var q struct {
			evidence.Input
			RollbackVersion int    `json:"rollback_version"`
			RollbackReason  string `json:"rollback_reason"`
			Repair          bool   `json:"repair"`
			RepairReason    string `json:"repair_reason"`
		}
		if decode(r, &q) != nil {
			write(w, map[string]string{"error": "请求无效"}, 400)
			return
		}
		if hv := r.Header.Get("If-Match-Evidence"); hv != "" {
			if n, er := strconv.Atoi(hv); er == nil {
				q.Version = n
			}
		}
		if q.Repair {
			out, e = s.WF.RepairEvidenceChain(id, rev, q.SubmittedBy, q.RepairReason)
		} else if q.RollbackVersion > 0 {
			out, e = s.WF.RollbackEvidence(id, rev, q.RollbackVersion, q.SubmittedBy, q.RollbackReason, q.Version)
		} else {
			out, e = s.WF.SubmitEvidence(id, rev, q.Input, q.SubmittedBy)
		}
	case "approve":
		var q struct {
			Action              string          `json:"action"`
			Window              string          `json:"window"`
			ApprovedBy          string          `json:"approved_by"`
			Reason              string          `json:"reason"`
			ConfirmedBy         string          `json:"confirmed_by"`
			ConfirmedReason     string          `json:"confirmed_reason"`
			Checklist           map[string]bool `json:"checklist"`
			ChangeOfDecision    bool            `json:"change_of_decision"`
			OriginalDecisionID  string          `json:"original_decision_id"`
			MonitoringFrequency string          `json:"monitoring_frequency"`
			SiteIsolation       string          `json:"site_isolation"`
			LateConfirmedBy     string          `json:"late_confirmed_by"`
			LateReason          string          `json:"late_reason"`
		}
		if decode(r, &q) != nil {
			write(w, map[string]string{"error": "请求无效"}, 400)
			return
		}
		out, e = s.WF.ApproveWithOptions(id, rev, workflow.ApprovalOptions{Action: q.Action, Window: q.Window, ApprovedBy: q.ApprovedBy, Reason: q.Reason, ConfirmedBy: q.ConfirmedBy, ConfirmedReason: q.ConfirmedReason, Checklist: q.Checklist, IdempotencyKey: r.Header.Get("Idempotency-Key"), ChangeOfDecision: q.ChangeOfDecision, OriginalDecisionID: q.OriginalDecisionID, MonitoringFrequency: q.MonitoringFrequency, SiteIsolation: q.SiteIsolation, LateConfirmedBy: q.LateConfirmedBy, LateReason: q.LateReason})
	case "withdraw":
		var q struct {
			By string `json:"by"`
		}
		_ = decode(r, &q)
		out, e = s.WF.WithdrawApproval(id, rev, q.By)
	case "close":
		var q assessment.Signal
		if decode(r, &q) != nil {
			write(w, map[string]string{"error": "请求无效"}, 400)
			return
		}
		if q.DominantFrequency <= 0 {
			if cc, ok := s.WF.Store.GetCase(id); ok {
				if aa, ok := s.WF.Store.GetAlert(cc.AlertID); ok {
					q.DominantFrequency = aa.DominantFrequency
				}
			}
		}
		if q.RawDigest == "" {
			q.RawDigest = assessment.Digest(q)
		}
		out, e = s.WF.Close(id, rev, q)
	default:
		write(w, map[string]string{"error": "未知操作"}, 404)
		return
	}
	if e != nil {
		code := 400
		if errors.Is(e, workflow.ErrConflict) {
			code = 409
		}
		if errors.Is(e, workflow.ErrClaimRequired) {
			code = 409
		}
		if errors.Is(e, store.ErrNotFound) {
			code = 404
		}
		body := map[string]any{"error": e.Error()}
		if strings.Contains(e.Error(), "阈值版本") {
			if cc, ok := s.WF.Store.GetCase(id); ok {
				body["threshold_difference"] = map[string]any{"case_version": cc.ThresholdVersion, "requested_version": cc.ThresholdVersion, "requires_confirmation": true}
			}
		}
		if ev, ok := s.WF.Store.GetEvidenceByCase(id); ok {
			body["current_evidence_version"] = ev.Version
			body["if_match_evidence"] = strconv.Itoa(ev.Version)
		}
		if cc, ok := s.WF.Store.GetCase(id); ok && cc.NextReviewAt != nil {
			body["next_review_at"] = cc.NextReviewAt
		}
		if cc, ok := s.WF.Store.GetCase(id); ok && len(cc.ReviewAttempts) > 0 {
			body["review_attempt"] = cc.ReviewAttempts[len(cc.ReviewAttempts)-1]
		}
		write(w, body, code)
		return
	}
	write(w, out, 200)
}
