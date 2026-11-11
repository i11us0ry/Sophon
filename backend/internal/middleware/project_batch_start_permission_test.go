package middleware

import (
	"net/http"
	"testing"
)

func TestProjectBatchStartRequiresProjectWrite(t *testing.T) {
	if got := RoutePermission(http.MethodPost, "/api/projects/batch-start"); got != "project:write" {
		t.Fatalf("批量启动权限应为 project:write，实际 %q", got)
	}
}
