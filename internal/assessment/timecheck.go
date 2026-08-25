package assessment

import (
	"math"
	"time"
)

type TimeConsistency struct {
	Quality      string  `json:"quality"`
	DriftSeconds float64 `json:"drift_seconds"`
	Reason       string  `json:"reason"`
}

func CheckTime(captured, received time.Time, tolerance time.Duration) TimeConsistency {
	if received.IsZero() {
		received = time.Now()
	}
	if tolerance <= 0 {
		tolerance = time.Minute
	}
	drift := received.Sub(captured).Seconds()
	if math.Abs(drift) <= tolerance.Seconds() {
		return TimeConsistency{"trusted", drift, "采集时间在允许偏差内"}
	}
	if math.Abs(drift) >= 300 {
		return TimeConsistency{"severe_drift", drift, "采集时间严重偏移，需人工确认"}
	}
	return TimeConsistency{"attention_drift", drift, "采集时间存在可关注偏差"}
}

func EvaluateTimeDrift(captured, received time.Time, tolerance time.Duration) TimeConsistency {
	return CheckTime(captured, received, tolerance)
}
