package workflow

import (
	"bridgewatch/internal/assessment"
	"bridgewatch/internal/evidence"
	"bridgewatch/internal/store"
	"testing"
	"time"
)

func TestFullFlow(t *testing.T) {
	s := New(store.New(""))
	c, e := s.Receive(AlertInput{BridgeID: "B1", SensorID: "S1", CapturedAt: time.Now(), Signal: assessment.Signal{PeakAmplitude: 6, DominantFrequency: 4, DurationMS: 1000}}, "r1")
	if e != nil {
		t.Fatal(e)
	}
	var err error
	if c, err = s.Review(c.CaseID, c.Revision, "eng"); err != nil {
		t.Fatal(err)
	}
	if c, err = s.SubmitEvidence(c.CaseID, c.Revision, evidence.Input{Checkpoint: "P1", ArrivedAt: time.Now(), PhotoRefs: []string{"photo://1"}, Resample: assessment.Signal{PeakAmplitude: 2, DominantFrequency: 1, DurationMS: 500}, Notes: "无裂缝", SubmittedBy: "field"}, "field"); err != nil {
		t.Fatal(err)
	}
	if c, err = s.Approve(c.CaseID, c.Revision, "限载", "24h", "lead", "安全观察"); err != nil {
		t.Fatal(err)
	}
	if _, e = s.Close(c.CaseID, c.Revision, assessment.Signal{PeakAmplitude: 1, DurationMS: 400}); e != nil {
		t.Fatal(e)
	}
}
