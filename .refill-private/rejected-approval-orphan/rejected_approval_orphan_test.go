package rejected_approval_orphan_test

import (
	"bridgewatch/internal/assessment"
	"bridgewatch/internal/evidence"
	"bridgewatch/internal/httpapi"
	"bridgewatch/internal/store"
	"bridgewatch/internal/workflow"
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestRejectedApprovalDoesNotPersistOrphanDecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	st := store.New(path)
	caseID := "case-missing-checkpoint"
	st.PutCase(store.Case{
		CaseID:              caseID,
		Status:              "evidence_submitted",
		RiskLevel:           string(assessment.Low),
		Revision:            7,
		RequiredCheckpoints: []store.CheckpointProgress{{ID: "P2"}},
	})
	_, err := evidence.Save(st, caseID, "evidence-1", evidence.Input{
		Checkpoint:  "P1",
		ArrivedAt:   time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC),
		PhotoRefs:   []string{"photo://site/p1"},
		Resample:    assessment.Signal{PeakAmplitude: 1, DominantFrequency: 2, DurationMS: 500},
		Notes:       "现场证据完整，但尚未覆盖P2测点",
		SubmittedBy: "field-user",
	})
	if err != nil {
		t.Fatalf("准备证据失败: %v", err)
	}

	body := bytes.NewBufferString(`{"action":"限载","window":"24h","approved_by":"lead-manager","reason":"等待补齐必检点","checklist":{"load_scope":true,"monitoring_frequency":true,"site_isolation":true}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/cases/"+caseID+"/approve", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", "7")
	rec := httptest.NewRecorder()
	httpapi.New(workflow.New(st)).Mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺失必检点应返回400，实际为%d: %s", rec.Code, rec.Body.String())
	}
	reloaded := store.New(path)
	if got := len(reloaded.Snapshot().Decisions); got != 0 {
		t.Fatalf("TestRejectedApprovalDoesNotPersistOrphanDecision: 重启后仍恢复了%d条失败审批产生的孤立决定", got)
	}
}
