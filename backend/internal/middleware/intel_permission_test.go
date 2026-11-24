package middleware

import (
	"net/http"
	"testing"
)

func TestRoutePermissionForIntelCollection(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   string
	}{
		{http.MethodGet, "/api/intel/capabilities", "asset:read"},
		{http.MethodGet, "/api/intel/searches", "asset:read"},
		{http.MethodGet, "/api/intel/searches/search-1", "asset:read"},
		{http.MethodPost, "/api/intel/searches", "asset:write"},
		{http.MethodPost, "/api/intel/searches/search-1/import", "asset:write"},
	}
	for _, item := range cases {
		if got := RoutePermission(item.method, item.path); got != item.want {
			t.Fatalf("%s %s permission=%q, want %q", item.method, item.path, got, item.want)
		}
	}
}
