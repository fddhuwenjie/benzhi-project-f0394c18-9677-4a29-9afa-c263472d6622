package versionedchainhashreuse_test

import (
	"bridgewatch/internal/assessment"
	"bridgewatch/internal/evidence"
	"bridgewatch/internal/store"
	"testing"
	"time"
)

func TestVersionedEvidenceChainVerificationIsRepeatable(t *testing.T) {
	st := store.New("")
	arrived := time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC)
	first := evidence.Input{
		Checkpoint: "P1",
		ArrivedAt:  arrived,
		PhotoRefs: []string{
			"photo://inspection/first",
		},
		Resample: assessment.Signal{
			PeakAmplitude:     2.4,
			DominantFrequency: 3.2,
			DurationMS:        1200,
		},
		Notes:       "首次现场复测记录",
		SubmittedBy: "field-a",
	}
	if _, err := evidence.SaveIncremental(st, "case-chain", "evidence-chain", first); err != nil {
		t.Fatalf("保存首版证据失败: %v", err)
	}

	second := first
	second.PhotoRefs = []string{"photo://inspection/second"}
	second.Notes = "补充复测记录"
	second.SubmittedBy = "field-b"
	if _, err := evidence.SaveIncremental(st, "case-chain", "evidence-chain", second); err != nil {
		t.Fatalf("保存第二版证据失败: %v", err)
	}

	got, ok := st.GetEvidenceByCase("case-chain")
	if !ok || got.Version != 2 {
		t.Fatalf("未取得第二版证据: ok=%v version=%d", ok, got.Version)
	}
	if valid, version, reason := evidence.VerifyChain(got); !valid {
		t.Fatalf("首次校验应通过: version=%d reason=%s", version, reason)
	}
	if valid, version, reason := evidence.VerifyChain(got); !valid {
		t.Fatalf("重复校验不应受上次校验状态污染: version=%d reason=%s", version, reason)
	}
}
