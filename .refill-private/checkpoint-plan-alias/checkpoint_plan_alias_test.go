package checkpoint_plan_alias_test

import (
	"bridgewatch/internal/assessment"
	"bridgewatch/internal/store"
	"bridgewatch/internal/workflow"
	"testing"
	"time"
)

func TestCheckpointProgressIsIsolatedAcrossCases(t *testing.T) {
	service := workflow.New(store.New(""))
	captured := time.Now().Add(-time.Minute)
	create := func(alertID, bridgeID string) store.Case {
		t.Helper()
		c, err := service.Receive(workflow.AlertInput{
			AlertID:    alertID,
			BridgeID:   bridgeID,
			SensorID:   "sensor-1",
			CapturedAt: captured,
			Signal: assessment.Signal{
				PeakAmplitude:     3.5,
				DominantFrequency: 3.2,
				DurationMS:        1000,
			},
		}, "receive-"+alertID)
		if err != nil {
			t.Fatalf("创建案件失败: %v", err)
		}
		c, err = service.ReviewWithOptions(c.CaseID, c.Revision, workflow.ReviewOptions{
			Reviewer:         "engineer-1",
			TargetCheckpoint: "P1,P2",
		})
		if err != nil {
			t.Fatalf("研判案件失败: %v", err)
		}
		return c
	}

	caseA := create("alert-a", "bridge-a")
	caseB := create("alert-b", "bridge-b")
	if _, err := service.CheckinTask(caseA.CaseID, caseA.Revision, time.Now(), "field-a", "P1", "checkin", "到场核验", "checkin-a"); err != nil {
		t.Fatalf("案件 A 签到失败: %v", err)
	}

	untouched, ok := service.Store.GetCase(caseB.CaseID)
	if !ok {
		t.Fatal("案件 B 不存在")
	}
	if untouched.RequiredCheckpoints[0].ArrivedAt != nil {
		t.Fatalf("案件 B 未签到，但 P1 被案件 A 的签到污染: %s", untouched.RequiredCheckpoints[0].ArrivedAt.Format(time.RFC3339Nano))
	}
}
