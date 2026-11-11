package handler

import "testing"

func TestParseConversationBatchAssets(t *testing.T) {
	items, invalid, duplicate := parseConversationBatchAssets(
		"https://a.example.com\n" +
			"https://a.example.com\n" +
			"10.0.0.1\n" +
			"example.com:8443\n" +
			"not a target\n",
	)
	if invalid != 1 {
		t.Fatalf("无效项统计错误: %d", invalid)
	}
	if duplicate != 1 {
		t.Fatalf("重复项统计错误: %d", duplicate)
	}
	if len(items) != 3 {
		t.Fatalf("有效资产数量错误: %+v", items)
	}
	if items[0].Kind != "url" || items[0].Value != "https://a.example.com" {
		t.Fatalf("URL 规范化错误: %+v", items[0])
	}
	if items[1].Kind != "ip" || items[1].Value != "10.0.0.1" {
		t.Fatalf("IP 规范化错误: %+v", items[1])
	}
	if items[2].Kind != "domain" || items[2].Value != "example.com:8443" {
		t.Fatalf("域名端口规范化错误: %+v", items[2])
	}
}
