package agent

import (
	"strings"
	"testing"
	"time"
)

func TestProjectSyncGraphToolCreatesSkeleton(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key": "目标IP", "value": "10.0.0.1",
	}); err != nil {
		t.Fatalf("记录事实失败: %v", err)
	}

	kinds := map[string]int{}
	deadline := time.Now().Add(3 * time.Second)
	for {
		nodes, err := service.db.ListProjectGraphNodes(ctx, "project-tools")
		if err != nil {
			t.Fatalf("读取攻击路径失败: %v", err)
		}
		kinds = map[string]int{}
		for _, node := range nodes {
			kinds[node.Kind]++
		}
		if kinds["begin"] > 0 && kinds["goal"] > 0 && kinds["fact"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("记录事实后应自动补出起点/目标/事实节点: %+v", kinds)
		}
		time.Sleep(20 * time.Millisecond)
	}

	out, err := invokeProjectTool(t, service, ctx, "project_sync_graph", map[string]interface{}{})
	if err != nil {
		t.Fatalf("补全攻击路径失败: %v", err)
	}
	if !strings.Contains(out, "攻击路径已补全") {
		t.Fatalf("补全结果异常: %q", out)
	}
	edges, err := service.db.ListProjectGraphEdges(ctx, "project-tools")
	if err != nil || len(edges) == 0 {
		t.Fatalf("补全后应存在连线: %d, err=%v", len(edges), err)
	}
}
