package evidence

import (
	"bridgewatch/internal/assessment"
	"bridgewatch/internal/store"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

func Validate(i Input) error {
	missing := []string{}
	if strings.TrimSpace(i.Checkpoint) == "" {
		missing = append(missing, "checkpoint")
	}
	if i.ArrivedAt.IsZero() {
		missing = append(missing, "arrived_at")
	}
	if len(i.PhotoRefs) == 0 {
		missing = append(missing, "photo_refs")
	}
	if strings.TrimSpace(i.Notes) == "" {
		missing = append(missing, "notes")
	}
	if strings.TrimSpace(i.SubmittedBy) == "" {
		missing = append(missing, "submitted_by")
	}
	if len(missing) > 0 {
		return fmt.Errorf("证据缺少字段: %s", strings.Join(missing, ","))
	}
	if len(i.PhotoRefs) > 12 {
		return fmt.Errorf("照片数量超过限制")
	}
	seen := map[string]bool{}
	for _, p := range i.PhotoRefs {
		p = normalizeRef(p)
		if len(p) > 512 {
			return fmt.Errorf("照片引用过长")
		}
		if p == "" {
			return fmt.Errorf("照片引用不能为空")
		}
		u, err := url.Parse(p)
		if err != nil || (u.Scheme != "photo" && u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("照片引用协议不支持")
		}
		if seen[p] {
			return fmt.Errorf("照片引用重复: %s", p)
		}
		seen[p] = true
	}
	if len([]rune(i.Notes)) > 2000 {
		return fmt.Errorf("说明超过2000字")
	}
	if !assessment.Check(i.Resample).Valid {
		return fmt.Errorf("复测波形无效")
	}
	return nil
}
func normalizeRef(p string) string { return strings.ToLower(strings.TrimSpace(p)) }
func PhotoFingerprint(refs []string) []string {
	out := make([]string, 0, len(refs))
	seen := map[string]bool{}
	for _, p := range refs {
		n := normalizeRef(p)
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}
func ResampleFingerprint(i Input) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%.4f|%.4f|%d|%s", normalizeRef(i.Checkpoint), i.Resample.PeakAmplitude, i.Resample.DominantFrequency, i.Resample.DurationMS, i.Resample.RawDigest)))
	return hex.EncodeToString(h[:])
}
func Save(st *store.Store, caseID, id string, i Input) (store.Evidence, error) {
	if err := Validate(i); err != nil {
		return store.Evidence{}, err
	}
	refs := make([]string, 0, len(i.PhotoRefs))
	seen := map[string]bool{}
	for _, p := range i.PhotoRefs {
		p = strings.TrimSpace(p)
		if !seen[p] {
			seen[p] = true
			refs = append(refs, p)
		}
	}
	i.PhotoRefs = refs
	e := store.Evidence{EvidenceID: id, CaseID: caseID, Checkpoint: i.Checkpoint, ArrivedAt: i.ArrivedAt, PhotoRefs: i.PhotoRefs, ResamplePeak: i.Resample.PeakAmplitude, ResampleFrequency: i.Resample.DominantFrequency, ResampleDuration: i.Resample.DurationMS, ResampleDigest: i.Resample.RawDigest, Notes: i.Notes, SubmittedBy: i.SubmittedBy, Version: 1}
	e.Hash = Hash(i)
	st.PutEvidence(e)
	return e, nil
}

// SaveIncremental保留分批补交场景；已提供字段仍按协议和波形规则校验，完整性由Missing/Verify判定。
func SaveIncremental(st *store.Store, caseID, id string, i Input) (store.Evidence, error) {
	if strings.TrimSpace(i.Checkpoint) == "" || i.ArrivedAt.IsZero() || len(i.PhotoRefs) == 0 || strings.TrimSpace(i.SubmittedBy) == "" {
		return store.Evidence{}, fmt.Errorf("证据缺少必要字段: checkpoint,arrived_at,photo_refs,submitted_by")
	}
	if len(i.PhotoRefs) > 12 {
		return store.Evidence{}, fmt.Errorf("照片数量超过限制")
	}
	for _, p := range i.PhotoRefs {
		u, err := url.Parse(strings.TrimSpace(p))
		if err != nil || u.Host == "" || (u.Scheme != "photo" && u.Scheme != "http" && u.Scheme != "https") {
			return store.Evidence{}, fmt.Errorf("照片引用协议不支持")
		}
	}
	if i.Resample.DurationMS > 0 {
		if q := assessment.Check(i.Resample); !q.Valid {
			return store.Evidence{}, fmt.Errorf("复测波形无效: %s", q.Reason)
		}
	}
	refs := []string{}
	seen := map[string]bool{}
	for _, p := range i.PhotoRefs {
		p = normalizeRef(p)
		if seen[p] {
			return store.Evidence{}, fmt.Errorf("照片引用重复: %s", p)
		}
		seen[p] = true
		refs = append(refs, p)
	}
	i.PhotoRefs = refs
	old, exists := st.GetEvidenceByCase(caseID)
	version := 1
	history := []store.EvidenceVersion{}
	if exists {
		version = old.Version + 1
		history = append(history, old.History...)
		history = append(history, store.EvidenceVersion{Version: old.Version, Hash: old.Hash, PrevHash: "", At: old.ArrivedAt, SubmittedBy: old.SubmittedBy, Change: "保留旧版本", Checkpoint: old.Checkpoint, PhotoRefs: append([]string(nil), old.PhotoRefs...), ResamplePeak: old.ResamplePeak, ResampleFrequency: old.ResampleFrequency, ResampleDuration: old.ResampleDuration, ResampleDigest: old.ResampleDigest, Notes: old.Notes})
	}
	e := store.Evidence{EvidenceID: id, CaseID: caseID, Checkpoint: i.Checkpoint, ArrivedAt: i.ArrivedAt, PhotoRefs: i.PhotoRefs, ResamplePeak: i.Resample.PeakAmplitude, ResampleFrequency: i.Resample.DominantFrequency, ResampleDuration: i.Resample.DurationMS, ResampleDigest: i.Resample.RawDigest, Notes: i.Notes, SubmittedBy: i.SubmittedBy, Version: version, History: history}
	prev := ""
	if exists {
		prev = old.Hash
	}
	e.Hash = HashWithPrev(prev, Hash(i))
	st.PutEvidence(e)
	return e, nil
}

func Missing(e store.Evidence) []string {
	missing := []string{}
	if strings.TrimSpace(e.Checkpoint) == "" {
		missing = append(missing, "checkpoint")
	}
	if e.ArrivedAt.IsZero() {
		missing = append(missing, "arrived_at")
	}
	if len(e.PhotoRefs) == 0 {
		missing = append(missing, "photo_refs")
	}
	if strings.TrimSpace(e.Notes) == "" {
		missing = append(missing, "notes")
	}
	if strings.TrimSpace(e.SubmittedBy) == "" {
		missing = append(missing, "submitted_by")
	}
	if !assessment.Check(assessment.Signal{PeakAmplitude: e.ResamplePeak, DominantFrequency: e.ResampleFrequency, DurationMS: e.ResampleDuration, RawDigest: e.ResampleDigest}).Valid {
		missing = append(missing, "resample")
	}
	if strings.TrimSpace(e.Hash) == "" {
		missing = append(missing, "hash")
	}
	return missing
}

func Verify(e store.Evidence) bool {
	if len(Missing(e)) > 0 {
		return false
	}
	i := Input{Checkpoint: e.Checkpoint, ArrivedAt: e.ArrivedAt, PhotoRefs: e.PhotoRefs, Resample: assessment.Signal{PeakAmplitude: e.ResamplePeak, DominantFrequency: e.ResampleFrequency, DurationMS: e.ResampleDuration, RawDigest: e.ResampleDigest}, Notes: e.Notes, SubmittedBy: e.SubmittedBy}
	if e.Version == 1 {
		return e.Hash == HashWithPrev("", Hash(i)) || e.Hash == Hash(i)
	}
	prev := ""
	for _, h := range e.History {
		if h.Version == e.Version-1 {
			prev = h.Hash
			break
		}
	}
	return prev != "" && e.Hash == HashWithPrev(prev, Hash(i))
}

func VerifyChain(e store.Evidence) (bool, int, string) {
	versions := append([]store.EvidenceVersion(nil), e.History...)
	versions = append(versions, store.EvidenceVersion{Version: e.Version, Hash: e.Hash, Checkpoint: e.Checkpoint, At: e.ArrivedAt, PhotoRefs: e.PhotoRefs, ResamplePeak: e.ResamplePeak, ResampleFrequency: e.ResampleFrequency, ResampleDuration: e.ResampleDuration, ResampleDigest: e.ResampleDigest, Notes: e.Notes, SubmittedBy: e.SubmittedBy})
	for i := 0; i < len(versions); i++ {
		v := versions[i]
		in := Input{Checkpoint: v.Checkpoint, ArrivedAt: v.At, PhotoRefs: v.PhotoRefs, Resample: assessment.Signal{PeakAmplitude: v.ResamplePeak, DominantFrequency: v.ResampleFrequency, DurationMS: v.ResampleDuration, RawDigest: v.ResampleDigest}, Notes: v.Notes, SubmittedBy: v.SubmittedBy}
		prev := ""
		if i > 0 {
			prev = versions[i-1].Hash
		}
		if v.Hash != HashWithPrev(prev, Hash(in)) && !(i == 0 && v.Hash == Hash(in)) {
			return false, v.Version, "证据链断裂"
		}
	}
	return true, 0, ""
}
