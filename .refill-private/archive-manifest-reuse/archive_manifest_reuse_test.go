package archive_manifest_reuse_test

import (
	"bridgewatch/internal/assessment"
	"bridgewatch/internal/evidence"
	"bridgewatch/internal/store"
	"bridgewatch/internal/workflow"
	"testing"
	"time"
)

func seedMitigationCase(t *testing.T, st *store.Store, suffix string) (store.Case, assessment.Signal, string) {
	t.Helper()
	now := time.Date(2026, 8, 25, 8, 0, 0, 0, time.UTC)
	alertID := "alert-" + suffix
	caseID := "case-" + suffix
	evidenceID := "evidence-" + suffix
	decisionID := "decision-" + suffix

	alert := store.Alert{
		AlertID: alertID, BridgeID: "bridge-" + suffix, SensorID: "sensor-" + suffix,
		CapturedAt: now, PeakAmplitude: 2, DominantFrequency: 1, DurationMS: 500,
	}
	input := evidence.Input{
		Checkpoint: "P1", ArrivedAt: now.Add(10 * time.Minute),
		PhotoRefs: []string{"photo://" + suffix},
		Resample:  assessment.Signal{PeakAmplitude: 1, DominantFrequency: 1, DurationMS: 400},
		Notes:     "现场复测指标正常", SubmittedBy: "field-" + suffix,
	}
	ev := store.Evidence{
		EvidenceID: evidenceID, CaseID: caseID, Checkpoint: input.Checkpoint,
		ArrivedAt: input.ArrivedAt, PhotoRefs: append([]string(nil), input.PhotoRefs...),
		ResamplePeak: input.Resample.PeakAmplitude, ResampleFrequency: input.Resample.DominantFrequency,
		ResampleDuration: input.Resample.DurationMS, Notes: input.Notes,
		SubmittedBy: input.SubmittedBy, Version: 1, Hash: evidence.Hash(input),
	}
	c := store.Case{
		CaseID: caseID, AlertID: alertID, Status: "mitigation", RiskLevel: "low",
		Revision: 4, OpenedAt: &now, BeforePeak: alert.PeakAmplitude,
		EvidenceID: evidenceID, DecisionID: decisionID,
	}

	st.PutAlert(alert)
	st.PutEvidence(ev)
	st.PutDecision(store.Decision{DecisionID: decisionID, CaseID: caseID, Action: "限载", MonitoringWindow: "1h", ApprovedAt: now})
	st.PutCase(c)
	return c, assessment.Signal{PeakAmplitude: 0.5, DominantFrequency: 1, DurationMS: 400}, ev.Hash
}

func TestArchiveManifestRemainsOwnedByClosedCase(t *testing.T) {
	st := store.New("")
	wf := workflow.New(st)
	first, firstRetest, firstEvidenceHash := seedMitigationCase(t, st, "first")
	second, secondRetest, _ := seedMitigationCase(t, st, "second")

	closedFirst, err := wf.Close(first.CaseID, first.Revision, firstRetest)
	if err != nil {
		t.Fatalf("close first case: %v", err)
	}
	if closedFirst.ArchiveManifest == nil {
		t.Fatal("first archive manifest is missing")
	}
	firstDecisionID := closedFirst.ArchiveManifest.DecisionIDs[0]

	if _, err := wf.Close(second.CaseID, second.Revision, secondRetest); err != nil {
		t.Fatalf("close second case: %v", err)
	}
	persistedFirst, ok := st.GetCase(first.CaseID)
	if !ok || persistedFirst.ArchiveManifest == nil {
		t.Fatal("persisted first archive manifest is missing")
	}
	if got := persistedFirst.ArchiveManifest.EvidenceHash; got != firstEvidenceHash {
		t.Fatalf("first case archive was overwritten after closing second case: evidence_hash=%s want=%s", got, firstEvidenceHash)
	}
	if got := persistedFirst.ArchiveManifest.DecisionIDs; len(got) != 1 || got[0] != firstDecisionID {
		t.Fatalf("first case decision manifest was overwritten: got=%v want=%s", got, firstDecisionID)
	}
}
