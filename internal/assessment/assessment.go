package assessment

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

type ActionValidation struct {
	Valid       bool     `json:"valid"`
	Missing     []string `json:"missing,omitempty"`
	Reason      string   `json:"reason"`
	RuleVersion string   `json:"rule_version"`
}

func ValidateAction(risk Risk, action, window, frequency, isolation, reason string) ActionValidation {
	v := ActionValidation{Valid: true, RuleVersion: "action-v1"}
	m := regexp.MustCompile(`^([1-9][0-9]*)(h|d)$`).FindStringSubmatch(strings.TrimSpace(window))
	if len(m) != 3 {
		v.Valid = false
		v.Missing = append(v.Missing, "window格式")
	} else {
		n := 0
		fmt.Sscanf(m[1], "%d", &n)
		max := 30
		if m[2] == "h" {
			max = 720
		}
		if n > max {
			v.Valid = false
			v.Missing = append(v.Missing, "window超出范围")
		}
	}
	if risk == High && action == "持续观测" && strings.TrimSpace(frequency) == "" {
		v.Valid = false
		v.Missing = append(v.Missing, "monitoring_frequency")
	}
	if risk == High && action == "持续观测" && strings.TrimSpace(isolation) == "" {
		v.Valid = false
		v.Missing = append(v.Missing, "site_isolation")
	}
	if risk == Low && action == "限载" && strings.TrimSpace(reason) == "" {
		v.Valid = false
		v.Missing = append(v.Missing, "reason")
	}
	if !v.Valid {
		v.Reason = "处置动作与风险等级不匹配"
	}
	return v
}

// ThresholdEntry is the read-only, versioned threshold catalog entry exposed
// to callers. Parameters are copied so historical cases remain immutable.
type ThresholdEntry struct {
	Version         string    `json:"version"`
	ReleasedAt      time.Time `json:"released_at"`
	Status          string    `json:"status"`
	MaxAmplitude    float64   `json:"max_amplitude"`
	HighAmplitude   float64   `json:"high_amplitude"`
	MediumAmplitude float64   `json:"medium_amplitude"`
	HighFrequency   float64   `json:"high_frequency"`
	MediumFrequency float64   `json:"medium_frequency"`
	HighDuration    int       `json:"high_duration_ms"`
	MediumDuration  int       `json:"medium_duration_ms"`
}

const DefaultThresholdVersion = "v1"

var thresholds = map[string]struct {
	MaxAmplitude, HighAmplitude, MediumAmplitude, HighFrequency, MediumFrequency float64
	HighDuration, MediumDuration                                                 int
}{
	"v1": {MaxAmplitude: 100, HighAmplitude: 5, MediumAmplitude: 3, HighFrequency: 4, MediumFrequency: 3, HighDuration: 120000, MediumDuration: 60000},
	"v2": {MaxAmplitude: 100, HighAmplitude: 6, MediumAmplitude: 4, HighFrequency: 5, MediumFrequency: 3.5, HighDuration: 180000, MediumDuration: 90000},
}

var thresholdMeta = map[string]struct {
	released time.Time
	status   string
}{
	"v1": {released: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), status: "active"},
	"v2": {released: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), status: "active"},
}
var defaultThresholdVersion = DefaultThresholdVersion

// compareCache avoids recalculating identical preview results in one process.
// The cache is intentionally kept package-local so callers cannot mutate it.
var compareCache = map[string]Result{}

func compareCacheKey(s Signal, primary string) string {
	return fmt.Sprintf("%s|%s|%s", Digest(s), primary, s.RawDigest)
}

func ThresholdCatalog() []ThresholdEntry {
	out := make([]ThresholdEntry, 0, len(thresholds))
	for v, t := range thresholds {
		m := thresholdMeta[v]
		out = append(out, ThresholdEntry{Version: v, ReleasedAt: m.released, Status: m.status, MaxAmplitude: t.MaxAmplitude, HighAmplitude: t.HighAmplitude, MediumAmplitude: t.MediumAmplitude, HighFrequency: t.HighFrequency, MediumFrequency: t.MediumFrequency, HighDuration: t.HighDuration, MediumDuration: t.MediumDuration})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out
}
func DefaultThreshold() string { return defaultThresholdVersion }
func SetDefaultThreshold(v string) error {
	if !ValidThresholdVersion(v) || thresholdMeta[v].status != "active" {
		return fmt.Errorf("阈值配置版本不存在或已停用: %s", v)
	}
	defaultThresholdVersion = v
	return nil
}
func SetThresholdStatus(v, status string) error {
	if _, ok := thresholds[v]; !ok {
		return fmt.Errorf("阈值配置版本不存在: %s", v)
	}
	if status != "active" && status != "inactive" {
		return fmt.Errorf("阈值状态无效")
	}
	if defaultThresholdVersion == v && status != "active" {
		return fmt.Errorf("不能停用默认阈值版本")
	}
	m := thresholdMeta[v]
	m.status = status
	thresholdMeta[v] = m
	return nil
}
func ThresholdSnapshot(v string) (ThresholdEntry, bool) {
	for _, x := range ThresholdCatalog() {
		if x.Version == v {
			return x, true
		}
	}
	return ThresholdEntry{}, false
}

func ValidThresholdVersion(v string) bool {
	_, ok := thresholds[v]
	return ok && thresholdMeta[v].status == "active"
}
func Compare(s Signal, primary, other string) (Result, *Result, error) {
	if !ValidThresholdVersion(primary) {
		return Result{}, nil, fmt.Errorf("阈值配置版本不存在: %s", primary)
	}
	key := compareCacheKey(s, primary)
	r, cached := compareCache[key]
	if !cached {
		r = AssessVersion(s, primary)
		compareCache[key] = r
	}
	if other == "" {
		return r, nil, nil
	}
	if !ValidThresholdVersion(other) {
		return Result{}, nil, fmt.Errorf("阈值配置版本不存在: %s", other)
	}
	compareKey := compareCacheKey(s, other)
	c, cached := compareCache[compareKey]
	if !cached {
		c = AssessVersion(s, other)
		compareCache[compareKey] = c
	}
	return r, &c, nil
}

func Digest(s Signal) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%.4f|%.4f|%d", s.PeakAmplitude, s.DominantFrequency, s.DurationMS)))
	return hex.EncodeToString(h[:])
}
func Check(s Signal) Quality {
	if s.DurationMS <= 0 {
		return Quality{false, 0, "duration_ms必须为正数"}
	}
	if s.DurationMS < 100 {
		return Quality{false, 0, "持续时间不足"}
	}
	if math.IsNaN(s.PeakAmplitude) || math.IsInf(s.PeakAmplitude, 0) || math.IsNaN(s.DominantFrequency) || math.IsInf(s.DominantFrequency, 0) || s.PeakAmplitude < 0 || s.DominantFrequency <= 0 {
		return Quality{false, 0, "幅值或频率无效"}
	}
	if s.RawDigest != "" {
		if len(s.RawDigest) != 64 {
			return Quality{false, 20, "波形摘要必须是64位十六进制"}
		}
		if _, err := hex.DecodeString(s.RawDigest); err != nil {
			return Quality{false, 0, "波形摘要格式无效"}
		}
		if !strings.EqualFold(s.RawDigest, Digest(s)) {
			return Quality{false, 0, "RawDigest与规范化波形摘要不匹配"}
		}
	}
	score := 100
	if s.DurationMS > 60000 {
		score -= 15
	}
	if s.PeakAmplitude > 5 {
		score -= 20
	}
	return Quality{true, score, "波形时长、幅值和主频完整"}
}
func Assess(s Signal) Result { return AssessVersion(s, defaultThresholdVersion) }

func AssessVersion(s Signal, version string) Result {
	q := Check(s)
	if !q.Valid {
		return Result{Quality: q, Risk: Noise, Explanation: "信号质量不通过，标记为噪声告警", ThresholdVersion: version, CalculatedAt: time.Now()}
	}
	t, ok := thresholds[version]
	if !ok {
		return Result{Quality: Quality{Valid: false, Reason: "阈值配置版本不存在"}, Risk: Noise, Explanation: "请使用有效阈值版本", ThresholdVersion: version, CalculatedAt: time.Now()}
	}
	if s.PeakAmplitude > t.MaxAmplitude {
		return Result{Quality: Quality{Valid: false, Reason: "幅值超出允许范围"}, Risk: Noise, Explanation: "幅值超出阈值配置范围", ThresholdVersion: version, CalculatedAt: time.Now()}
	}
	var r Risk = Low
	factors := []string{}
	if s.PeakAmplitude >= t.HighAmplitude {
		factors = append(factors, fmt.Sprintf("幅值%.2f达到高风险阈值", s.PeakAmplitude))
	} else if s.PeakAmplitude >= t.MediumAmplitude {
		factors = append(factors, fmt.Sprintf("幅值%.2f达到中风险阈值", s.PeakAmplitude))
	}
	if s.DominantFrequency >= t.HighFrequency {
		factors = append(factors, fmt.Sprintf("主频%.2fHz达到高风险阈值", s.DominantFrequency))
	} else if s.DominantFrequency >= t.MediumFrequency {
		factors = append(factors, fmt.Sprintf("主频%.2fHz达到中风险阈值", s.DominantFrequency))
	}
	if s.DurationMS >= t.HighDuration {
		factors = append(factors, "持续时间达到高风险阈值")
	} else if s.DurationMS >= t.MediumDuration {
		factors = append(factors, "持续时间达到中风险阈值")
	}
	if s.PeakAmplitude >= 8 || (s.PeakAmplitude >= t.HighAmplitude && s.DominantFrequency >= t.HighFrequency) || s.DurationMS >= t.HighDuration {
		r = High
	} else if s.PeakAmplitude >= t.MediumAmplitude || s.DominantFrequency >= t.MediumFrequency || s.DurationMS >= t.MediumDuration {
		r = Medium
	}
	return Result{Quality: q, Risk: r, Explanation: fmt.Sprintf("峰值 %.2f、主频 %.2fHz、持续 %dms", s.PeakAmplitude, s.DominantFrequency, s.DurationMS), Factors: factors, ThresholdVersion: version, CalculatedAt: time.Now()}
}
func Recovery(before, after Signal) (bool, string) {
	if after.PeakAmplitude < before.PeakAmplitude*0.6 && after.DurationMS <= before.DurationMS {
		return true, "复测峰值降至处置前60%以下"
	}
	return false, "复测指标未达到关闭阈值"
}

// BaselineCheck verifies that a retest refers to the same measurement point
// and waveform shape as the alert/evidence baseline before Recovery is run.
func BaselineCheck(alert, evidence, retest Signal) (bool, string) {
	if retest.DominantFrequency <= 0 || retest.DurationMS <= 0 {
		return false, "复测摘要缺少主频或持续时间"
	}
	if evidence.DominantFrequency > 0 {
		d := math.Abs(retest.DominantFrequency - evidence.DominantFrequency)
		if d > math.Max(3, evidence.DominantFrequency*0.1) {
			return false, "复测主频与证据测点基线不一致"
		}
	}
	if alert.DominantFrequency > 0 {
		d := math.Abs(retest.DominantFrequency - alert.DominantFrequency)
		if d > math.Max(3, alert.DominantFrequency*0.1) {
			return false, "复测主频与原始告警测点不一致"
		}
	}
	if evidence.DurationMS > 0 && retest.DurationMS < evidence.DurationMS/2 {
		return false, "复测持续时间异常缩短"
	}
	if q := Check(retest); !q.Valid {
		return false, q.Reason
	}
	return true, "复测与告警、证据基线一致"
}
