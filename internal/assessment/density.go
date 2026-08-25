package assessment

import (
	"sort"
	"time"
)

type DensityResult struct {
	Quality         string        `json:"quality"`
	Count           int           `json:"count"`
	Window          time.Duration `json:"window"`
	Upgrade         bool          `json:"upgrade"`
	Risk            Risk          `json:"risk"`
	Reason          string        `json:"reason"`
	TriggerAlertID  string        `json:"trigger_alert_id"`
	AverageInterval time.Duration `json:"average_interval"`
}

func AssessDensity(times []time.Time, original Risk, window time.Duration, trigger string) DensityResult {
	if window <= 0 {
		window = 15 * time.Minute
	}
	if len(times) < 2 {
		return DensityResult{Quality: "insufficient", Count: len(times), Window: window, Risk: original, Reason: "窗口内告警数量不足"}
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	for _, t := range times {
		if t.IsZero() {
			return DensityResult{Quality: "undetermined", Count: len(times), Window: window, Risk: original, Reason: "告警时间顺序异常"}
		}
	}
	if times[len(times)-1].Sub(times[0]) > window {
		return DensityResult{Quality: "insufficient", Count: len(times), Window: window, Risk: original, Reason: "告警不在同一滚动窗口"}
	}
	interval := time.Duration(0)
	for i := 1; i < len(times); i++ {
		interval += times[i].Sub(times[i-1])
	}
	risk := original
	upgrade := false
	if len(times) >= 4 {
		upgrade = true
		if original == Low {
			risk = Medium
		} else if original == Medium {
			risk = High
		}
	}
	reason := "密度未达到升级阈值"
	if upgrade {
		reason = "同源告警在窗口内达到密度升级阈值"
	}
	return DensityResult{Quality: "determined", Count: len(times), Window: window, Risk: risk, Upgrade: upgrade, Reason: reason, TriggerAlertID: trigger, AverageInterval: interval / time.Duration(len(times)-1)}
}

func CalculateDensity(times []time.Time, original Risk, window time.Duration, trigger string) DensityResult {
	return AssessDensity(times, original, window, trigger)
}
