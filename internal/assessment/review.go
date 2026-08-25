package assessment

import "strings"

type ReviewFailure struct {
	Category string `json:"category"`
	Action   string `json:"action"`
}

func ClassifyReviewFailure(reason string) ReviewFailure {
	r := strings.ToLower(reason)
	if strings.Contains(r, "digest") || strings.Contains(reason, "摘要") {
		return ReviewFailure{"摘要不一致", "重新生成并提交波形摘要"}
	}
	if strings.Contains(r, "duration") || strings.Contains(reason, "时长") || strings.Contains(reason, "采样") {
		return ReviewFailure{"采样不足", "补采样后重试"}
	}
	if strings.Contains(r, "format") || strings.Contains(reason, "格式") {
		return ReviewFailure{"格式错误", "修正输入格式后重试"}
	}
	return ReviewFailure{"噪声确认", "转人工复核并保留噪声结论"}
}
