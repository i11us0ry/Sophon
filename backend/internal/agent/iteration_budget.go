package agent

const maxSegmentIterations = 24

// configuredSegmentLimit 返回单段 Eino 迭代窗口。
// 该值只控制上下文重建节奏，不是任务结束条件；普通对话达到窗口后会自动续段。
func configuredSegmentLimit(configured int) int {
	if configured <= 0 {
		return maxSegmentIterations
	}
	if configured > maxSegmentIterations {
		return maxSegmentIterations
	}
	return configured
}
