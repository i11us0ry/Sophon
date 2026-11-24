package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientParsesFOFAAndHunter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/fofa":
			_, _ = writer.Write([]byte(`{
				"error":false,
				"results":[["10.0.0.8","8443","https://oa.example.com:8443","oa.example.com","OA","Shanghai","nginx","https","Example Org"]]
			}`))
		case "/hunter":
			_, _ = writer.Write([]byte(`{
				"code":200,
				"message":"success",
				"data":{"arr":[{
					"url":"https://oa.example.com:8443",
					"ip":"10.0.0.8",
					"port":8443,
					"web_title":"OA",
					"domain":"oa.example.com",
					"protocol":"https",
					"company":"Example Org",
					"city":"Shanghai",
					"updated_at":"2026-11-20",
					"component":[{"name":"nginx","version":"1.26"}]
				}]}
			}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	client := Client{
		HTTP:           server.Client(),
		FOFAEndpoint:   server.URL + "/fofa",
		HunterEndpoint: server.URL + "/hunter",
	}
	options := SearchOptions{Page: 1, PageSize: 20}
	fofaResults, err := client.SearchFOFA(context.Background(), Settings{
		FOFAEmail: "user@example.com",
		FOFAKey:   "fofa-key",
	}, `domain="example.com"`, options)
	if err != nil {
		t.Fatalf("FOFA 查询失败: %v", err)
	}
	hunterResults, err := client.SearchHunter(context.Background(), Settings{
		HunterKey: "hunter-key",
	}, `domain="example.com"`, options)
	if err != nil {
		t.Fatalf("Hunter 查询失败: %v", err)
	}
	if len(fofaResults) != 1 || len(hunterResults) != 1 {
		t.Fatalf("解析结果数量错误: fofa=%d hunter=%d", len(fofaResults), len(hunterResults))
	}
	merged := Deduplicate(append(fofaResults, hunterResults...), 100)
	if len(merged) != 1 || merged[0].URL != "https://oa.example.com:8443" {
		t.Fatalf("跨来源去重失败: %+v", merged)
	}
	if len(merged[0].Sources) != 2 || merged[0].Components[0] != "nginx 1.26" {
		t.Fatalf("来源合并或组件解析失败: %+v", merged[0])
	}
}

func TestProviderErrorDoesNotEchoKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"error":true,"errmsg":"invalid key fofa-secret-key"}`))
	}))
	t.Cleanup(server.Close)
	client := Client{HTTP: server.Client(), FOFAEndpoint: server.URL}
	_, err := client.SearchFOFA(context.Background(), Settings{
		FOFAEmail: "user@example.com",
		FOFAKey:   "fofa-secret-key",
	}, `domain="example.com"`, SearchOptions{Page: 1, PageSize: 20})
	if err == nil {
		t.Fatal("错误响应应返回错误")
	}
	if strings.Contains(err.Error(), "fofa-secret-key") {
		t.Fatalf("错误信息不应包含 Key: %v", err)
	}
}
