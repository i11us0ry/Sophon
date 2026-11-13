package middleware

import (
	"net/http"
	"testing"
)

func TestRoutePermissionForAttachments(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   string
	}{
		{http.MethodGet, "/api/conversations/conv-1/attachments", "chat:read"},
		{http.MethodPost, "/api/conversations/conv-1/attachments", "chat:write"},
		{http.MethodGet, "/api/attachments/att-1/content", "chat:read"},
		{http.MethodDelete, "/api/attachments/att-1", "chat:delete"},
		{http.MethodGet, "/api/projects/project-1/vulnerabilities", "vulnerability:read"},
		{http.MethodGet, "/api/projects/project-1/assets", "asset:read"},
		{http.MethodGet, "/api/projects/project-1/graph", "vulnerability:read"},
		{http.MethodPost, "/api/projects/project-1/graph/sync", "vulnerability:write"},
		{http.MethodGet, "/api/vulnerabilities/vuln-1/retests", "vulnerability:read"},
		{http.MethodPost, "/api/vulnerabilities/vuln-1/retest", "vulnerability:write"},
		{http.MethodGet, "/api/agent-roles", "agentRole:read"},
		{http.MethodPost, "/api/agent-roles", "agentRole:admin"},
		{http.MethodGet, "/api/zhizi/nodes", "zhizi:read"},
		{http.MethodPost, "/api/zhizi/nodes", "zhizi:write"},
		{http.MethodDelete, "/api/zhizi/nodes/node-1", "zhizi:delete"},
		{http.MethodPost, "/api/zhizi/nodes/delete", "zhizi:delete"},
		{http.MethodPost, "/api/zhizi/nodes/init", "zhizi:write"},
		{http.MethodPut, "/api/zhizi/conversations/conversation-1", "zhizi:execute"},
		{http.MethodPut, "/api/auth/profile", PermissionExempt},
		{http.MethodGet, "/api/projects/project-1", "project:read"},
		{http.MethodGet, "/api/settings/ai", "settings:read"},
		{http.MethodPut, "/api/settings/ai", "settings:write"},
		{http.MethodGet, "/api/settings/llm/keys", "settings:read"},
		{http.MethodPost, "/api/settings/llm/keys", "settings:write"},
		{http.MethodDelete, "/api/settings/llm/keys/key-1", "settings:write"},
		{http.MethodPost, "/api/settings/llm/keys/test", "settings:write"},
		{http.MethodGet, "/api/settings/storage", "settings:read"},
		{http.MethodPut, "/api/settings/storage", "settings:write"},
		{http.MethodPost, "/api/settings/storage/cleanup", "settings:write"},
		{http.MethodPost, "/api/settings/llm/models", "settings:write"},
		{http.MethodGet, "/api/intercept/rules", "settings:read"},
		{http.MethodPost, "/api/intercept/rules", "settings:write"},
		{http.MethodPut, "/api/intercept/rules/rule-1", "settings:write"},
		{http.MethodDelete, "/api/intercept/rules/rule-1", "settings:write"},
		{http.MethodPost, "/api/intercept/rules/test", "settings:write"},
		{http.MethodGet, "/api/context/metrics", "dashboard:read"},
		{http.MethodGet, "/api/context/compactions", "dashboard:read"},
		{http.MethodGet, "/api/conversation-batches/batch-1/status", "chat:read"},
		{http.MethodGet, "/api/conversation-batches/batch-1/frontier", "chat:read"},
		{http.MethodGet, "/api/conversation-batches/batch-1/verifications", "chat:read"},
		{http.MethodGet, "/api/conversation-batches/batch-1/links", "chat:read"},
		{http.MethodPost, "/api/conversation-batches/batch-1/priority/recompute", "chat:write"},
		{http.MethodGet, "/api/workspace/list", "settings:read"},
		{http.MethodGet, "/api/workspace/content", "settings:read"},
		{http.MethodPut, "/api/workspace/content", "settings:write"},
		{http.MethodGet, "/api/workspace/download", "settings:read"},
		{http.MethodDelete, "/api/workspace/delete", "settings:write"},
		{http.MethodPost, "/api/workspace/batch-delete", "settings:write"},
	}
	for _, item := range cases {
		if got := RoutePermission(item.method, item.path); got != item.want {
			t.Fatalf("%s %s 权限映射应为 %s，实际 %q", item.method, item.path, item.want, got)
		}
	}
}
