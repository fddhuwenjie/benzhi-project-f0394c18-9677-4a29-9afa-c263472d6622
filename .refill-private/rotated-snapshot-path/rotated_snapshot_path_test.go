package rotatedsnapshotpath_test

import (
	"bridgewatch/internal/assessment"
	"bridgewatch/internal/httpapi"
	"bridgewatch/internal/store"
	"bridgewatch/internal/workflow"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotWritesFollowRotatedDataDirectory(t *testing.T) {
	root := t.TempDir()
	oldDir := filepath.Join(root, "volume-a")
	newDir := filepath.Join(root, "volume-b")
	if err := os.MkdirAll(oldDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(newDir, 0755); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "current")
	if err := os.Symlink(oldDir, current); err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(current, "snapshot.json")
	st := store.New(snapshotPath)
	wf := workflow.New(st)
	now := time.Now()
	first, err := wf.Receive(workflow.AlertInput{
		AlertID: "alert-before-rotation", BridgeID: "bridge-a", SensorID: "sensor-a",
		CapturedAt: now, ReceivedAt: now,
		Signal: assessment.Signal{PeakAmplitude: 3.2, DominantFrequency: 3.1, DurationMS: 1000},
	}, "request-before-rotation")
	if err != nil {
		t.Fatalf("目录切换前接收告警失败: %v", err)
	}
	if _, ok := st.GetCase(first.CaseID); !ok {
		t.Fatal("目录切换前案件未进入内存 Store")
	}

	persisted, err := os.ReadFile(filepath.Join(oldDir, "snapshot.json"))
	if err != nil {
		t.Fatalf("读取目录切换前快照失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "snapshot.json"), persisted, 0644); err != nil {
		t.Fatalf("准备新数据目录失败: %v", err)
	}
	if err := os.Remove(current); err != nil {
		t.Fatalf("移除旧数据目录链接失败: %v", err)
	}
	if err := os.Symlink(newDir, current); err != nil {
		t.Fatalf("切换数据目录链接失败: %v", err)
	}

	signal := assessment.Signal{PeakAmplitude: 4.2, DominantFrequency: 3.6, DurationMS: 1200}
	payload, err := json.Marshal(map[string]any{
		"alert_id": "alert-after-rotation", "bridge_id": "bridge-b", "sensor_id": "sensor-b",
		"captured_at": now, "received_at": now, "peak_amplitude": signal.PeakAmplitude,
		"dominant_frequency": signal.DominantFrequency, "duration_ms": signal.DurationMS,
		"raw_digest": assessment.Digest(signal),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/alerts", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "request-after-rotation")
	recorder := httptest.NewRecorder()
	httpapi.New(wf).Mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusCreated {
		response, _ := io.ReadAll(recorder.Result().Body)
		t.Fatalf("目录切换后的告警请求应成功，HTTP 状态=%d，响应=%s", recorder.Code, response)
	}
	if _, ok := st.FindCaseByAlert("alert-after-rotation"); !ok {
		t.Fatal("目录切换后的案件未进入运行中 Store")
	}

	restarted := store.New(snapshotPath)
	if _, ok := restarted.FindCaseByAlert("alert-after-rotation"); !ok {
		t.Fatal("HTTP 201 对应的案件在数据目录切换并重启后丢失")
	}
}
