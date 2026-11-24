package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sophon/internal/database"
	"sophon/internal/intel"

	"github.com/cloudwego/eino/components/tool"
)

func TestIntelSearchImportsCurrentProjectAssets(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if err := service.db.SaveIntelSettings(context.Background(), database.IntelSettings{
		Enabled:   true,
		FOFAEmail: "user@example.com",
		FOFAKey:   "fofa-key",
	}); err != nil {
		t.Fatalf("保存测试情报设置失败: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{
			"error":false,
			"results":[["10.0.0.8","8443","https://oa.example.com:8443","oa.example.com","OA","Shanghai","nginx","https","Example Org"]]
		}`))
	}))
	t.Cleanup(server.Close)
	client := intel.NewClient(server.Client())
	client.FOFAEndpoint = server.URL
	runtime := &intelSearchRuntime{
		fixed: &client,
		fofa: &intelProviderRuntime{
			sem: make(chan struct{}, 1),
		},
		hunter: &intelProviderRuntime{
			sem: make(chan struct{}, 1),
		},
	}
	searchTool := newIntelSearchToolWithRuntime(service, runtime)
	invokable, ok := searchTool.(tool.InvokableTool)
	if !ok {
		t.Fatal("intel_search 未实现 InvokableTool")
	}
	args, _ := json.Marshal(map[string]interface{}{
		"query":       `domain="example.com"`,
		"provider":    "fofa",
		"page_size":   20,
		"save_assets": true,
	})
	output, err := invokable.InvokableRun(ctx, string(args))
	if err != nil {
		t.Fatalf("执行情报查询失败: %v", err)
	}
	if !strings.Contains(output, "created=1") {
		t.Fatalf("资产导入摘要异常: %q", output)
	}
	assets, err := service.db.ListProjectAssets(ctx, "project-tools", "user-1")
	if err != nil {
		t.Fatalf("读取项目资产失败: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("应导入一个资产，实际 %d", len(assets))
	}
	asset := assets[0]
	if asset.Kind != "url" ||
		asset.Value != "https://oa.example.com:8443" ||
		asset.Name != "OA" ||
		asset.Status != "unknown" ||
		asset.Criticality != "info" ||
		asset.RiskScore != 0 {
		t.Fatalf("情报资产映射不符合预期: %+v", asset)
	}

	output, err = invokable.InvokableRun(ctx, string(args))
	if err != nil {
		t.Fatalf("重复执行情报查询失败: %v", err)
	}
	if !strings.Contains(output, "existing=1") {
		t.Fatalf("重复资产应跳过: %q", output)
	}
}
