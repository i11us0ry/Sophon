package app

import (
	"context"
	"fmt"
	"log"

	"sophon/internal/database"
)

func recoverInterruptedAgentRuns(ctx context.Context, db *database.DB) {
	if db == nil {
		return
	}
	runs, err := db.MarkStaleAgentRunsInterrupted(
		ctx,
		"服务重启或部署导致任务中断",
	)
	if err != nil {
		log.Printf("agent run recovery: %v", err)
		return
	}
	for _, run := range runs {
		notice := fmt.Sprintf(
			"任务因服务重启或部署中断，未产生最终结论。\n已执行 %d 段，项目事实、测试结果和工具记录均已保留。\n点击“继续执行”可从当前状态恢复。",
			run.SegmentCount,
		)
		if err := db.MarkAssistantMessageInterrupted(
			ctx,
			run.AssistantMessageID,
			notice,
		); err != nil {
			log.Printf("agent run recovery: message=%s: %v", run.AssistantMessageID, err)
		}
	}
	if len(runs) > 0 {
		log.Printf("agent run recovery: 已标记 %d 个中断任务", len(runs))
	}
}
