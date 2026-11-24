package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"sophon/internal/database"
	"sophon/internal/intel"
)

func TestServiceSearchIntelAndCapabilities(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if err := service.db.SaveIntelSettings(context.Background(), database.IntelSettings{
		Enabled:   true,
		FOFAEmail: "user@example.com",
		FOFAKey:   "fofa-key",
	}); err != nil {
		t.Fatalf("保存情报设置失败: %v", err)
	}
	capabilities, err := service.IntelCapabilities(ctx)
	if err != nil {
		t.Fatalf("读取情报能力失败: %v", err)
	}
	if !capabilities.Enabled || !capabilities.FOFAConfigured || capabilities.HunterConfigured {
		t.Fatalf("情报能力状态异常: %+v", capabilities)
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
	service.intelRuntimeMu.Lock()
	service.intelRuntime = &intelSearchRuntime{
		fixed: &client,
		fofa: &intelProviderRuntime{
			sem: make(chan struct{}, 1),
		},
		hunter: &intelProviderRuntime{
			sem: make(chan struct{}, 1),
		},
	}
	service.intelRuntimeMu.Unlock()
	results, providerErrors, err := service.SearchIntel(ctx, IntelSearchRequest{
		Provider: "fofa",
		Query:    `domain="example.com"`,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("Service 情报查询失败: %v", err)
	}
	if len(results) != 1 || len(providerErrors) != 0 {
		t.Fatalf("Service 情报查询结果异常: results=%+v errors=%v", results, providerErrors)
	}
}
