//go:build linux

package toolrunner

import "testing"

func TestParseProcStat(t *testing.T) {
	raw := "1234 (python worker) S 1 1234 1234 0 -1 4194560 0 0 0 0 12 7 0 0 20 0 1 0 100 0 0"
	state, processGroup, userTicks, systemTicks, err := parseProcStat(raw)
	if err != nil {
		t.Fatalf("解析 proc stat 失败: %v", err)
	}
	if state != "S" || processGroup != 1234 || userTicks != 12 || systemTicks != 7 {
		t.Fatalf("proc stat 字段错误: state=%s pgid=%d utime=%d stime=%d",
			state, processGroup, userTicks, systemTicks)
	}
}
