package assessment

import "testing"

func TestAssessAndRecovery(t *testing.T) {
	s := Signal{PeakAmplitude: 6, DominantFrequency: 4, DurationMS: 1000}
	if Assess(s).Risk != High {
		t.Fatal("risk")
	}
	ok, _ := Recovery(s, Signal{PeakAmplitude: 2, DurationMS: 500})
	if !ok {
		t.Fatal("recovery")
	}
}
