package restartidempotencyloss

import (
	"bridgewatch/internal/assessment"
	"bridgewatch/internal/store"
	"bridgewatch/internal/workflow"
	"testing"
	"time"
)

func TestIdempotencyKeySurvivesRestart(t *testing.T) {
	path := t.TempDir() + "/state.json"
	captured := time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC)
	in := workflow.AlertInput{
		AlertID:    "alert-restart-1",
		BridgeID:   "bridge-1",
		SensorID:   "sensor-1",
		CapturedAt: captured,
		ReceivedAt: captured.Add(time.Second),
		Signal: assessment.Signal{
			PeakAmplitude:     6,
			DominantFrequency: 4,
			DurationMS:        1000,
		},
	}
	in.RawDigest = assessment.Digest(in.Signal)
	const requestID = "idem-restart-1"

	first, err := workflow.New(store.New(path)).Receive(in, requestID)
	if err != nil {
		t.Fatalf("first receive: %v", err)
	}

	restartedStore := store.New(path)
	restarted := workflow.New(restartedStore)
	second, err := restarted.Receive(in, requestID)
	if err != nil {
		t.Fatalf("replayed receive: %v", err)
	}
	if second.CaseID != first.CaseID {
		t.Fatalf("expected idempotent case %q, got %q", first.CaseID, second.CaseID)
	}
	if second.MergeCount != first.MergeCount || second.Revision != first.Revision {
		t.Fatalf("idempotent replay mutated persisted case: first merge/revision=%d/%d, replay=%d/%d", first.MergeCount, first.Revision, second.MergeCount, second.Revision)
	}
}
