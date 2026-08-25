package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

func parseLooseTime(v string) time.Time {
	t, _ := time.Parse(time.RFC3339, v)
	return t
}

func parseTimeRange(from, to string) (time.Time, time.Time, error) {
	var f, t time.Time
	var err error
	if from != "" {
		f, err = time.Parse(time.RFC3339, from)
		if err != nil {
			return f, t, errors.New("from必须是RFC3339时间")
		}
	}
	if to != "" {
		t, err = time.Parse(time.RFC3339, to)
		if err != nil {
			return f, t, errors.New("to必须是RFC3339时间")
		}
	}
	if !f.IsZero() && !t.IsZero() && f.After(t) {
		return f, t, errors.New("时间范围无效")
	}
	return f, t, nil
}

func parseRev(r *http.Request) (int, error) {
	return strconv.Atoi(r.Header.Get("If-Match"))
}
