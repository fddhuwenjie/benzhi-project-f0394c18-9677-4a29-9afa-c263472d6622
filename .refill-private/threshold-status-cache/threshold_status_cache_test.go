package threshold_status_cache_test

import (
	"bridgewatch/internal/assessment"
	"bridgewatch/internal/store"
	"bridgewatch/internal/workflow"
	"testing"
)

func TestInactiveThresholdIsRejectedAfterCacheWarmup(t *testing.T) {
	st := store.New("")
	st.PutCase(store.Case{CaseID: "threshold-cache-case", Revision: 1})
	svc := workflow.New(st)
	signal := assessment.Signal{PeakAmplitude: 4.5, DominantFrequency: 3.8, DurationMS: 1000}

	if _, _, err := svc.Diagnose("threshold-cache-case", 1, workflow.ReviewOptions{
		Reviewer:         "engineer-a",
		ThresholdVersion: "v2",
		Summary:          &signal,
	}); err != nil {
		t.Fatalf("warm threshold cache: %v", err)
	}

	if err := assessment.SetThresholdStatus("v2", "inactive"); err != nil {
		t.Fatalf("deactivate threshold: %v", err)
	}
	t.Cleanup(func() {
		_ = assessment.SetThresholdStatus("v2", "active")
	})

	changedSignal := assessment.Signal{PeakAmplitude: 7, DominantFrequency: 5.5, DurationMS: 2000}
	if _, _, err := svc.Diagnose("threshold-cache-case", 1, workflow.ReviewOptions{
		Reviewer:         "engineer-b",
		ThresholdVersion: "v2",
		Summary:          &changedSignal,
	}); err == nil {
		t.Fatal("inactive threshold was accepted after the active cache was warmed")
	}
}
