package middleware

import (
	"net/http"
	"testing"
)

func TestRoutePermissionForIntelDelete(t *testing.T) {
	if got := RoutePermission(http.MethodDelete, "/api/intel/searches/search-1"); got != "asset:delete" {
		t.Fatalf("删除信息收集记录权限=%q, want asset:delete", got)
	}
}
