package handler

import (
	"log"
	"net/http"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

const (
	projectBatchMaxAssets      = 500
	projectBatchMaxSourceBytes = 1 << 20
)

type projectBatchCreateRequest struct {
	Assets string `json:"assets"`
}

type projectBatchFailure struct {
	Asset   string `json:"asset"`
	Message string `json:"message"`
}

type projectBatchCreateResponse struct {
	Created   int                   `json:"created"`
	Duplicate int                   `json:"duplicate"`
	Invalid   int                   `json:"invalid"`
	Failed    int                   `json:"failed"`
	Items     []database.Project    `json:"items"`
	Failures  []projectBatchFailure `json:"failures,omitempty"`
}

// CreateProjectsBatch creates one active project per valid asset line and uses
// that line as the project's complete authorization scope.
func (h *BusinessHandler) CreateProjectsBatch(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}

	var request projectBatchCreateRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_request", "批量请求格式错误")
		return
	}
	rawAssets := strings.TrimSpace(request.Assets)
	if rawAssets == "" {
		badRequest(c, "assets_required", "资产列表不能为空")
		return
	}
	if len(rawAssets) > projectBatchMaxSourceBytes {
		badRequest(c, "assets_too_large", "资产列表不能超过 1 MB")
		return
	}

	assets, invalid, duplicate := parseProjectBatchAssets(rawAssets)
	if len(assets) == 0 {
		badRequest(c, "assets_invalid", "没有可识别的 URL、域名、IP 或 CIDR")
		return
	}
	if len(assets) > projectBatchMaxAssets {
		badRequest(c, "assets_limit", "单次最多创建 500 个项目")
		return
	}

	result := projectBatchCreateResponse{
		Duplicate: duplicate,
		Invalid:   invalid,
		Items:     make([]database.Project, 0, len(assets)),
		Failures:  make([]projectBatchFailure, 0),
	}
	for _, scope := range assets {
		now := time.Now().UTC()
		item := database.Project{
			ID:          randomID(),
			OwnerUserID: user.ID,
			Name:        truncateRunes(scope, 100),
			Scope:       scope,
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := h.db.CreateProject(c.Request.Context(), item); err != nil {
			log.Printf("batch create project failed: asset=%q err=%v", scope, err)
			result.Failed++
			result.Failures = append(result.Failures, projectBatchFailure{
				Asset:   scope,
				Message: "创建项目失败",
			})
			continue
		}
		if _, err := h.db.SyncProjectScopeAssets(
			c.Request.Context(),
			item.ID,
			user.ID,
			item.Scope,
		); err != nil {
			log.Printf(
				"batch sync project scope assets failed: project=%s asset=%q err=%v",
				item.ID,
				scope,
				err,
			)
		}
		if _, err := h.db.SyncProjectGraph(c.Request.Context(), item); err != nil {
			log.Printf("batch sync project graph failed: project=%s err=%v", item.ID, err)
		}
		result.Created++
		result.Items = append(result.Items, item)
	}

	if result.Created == 0 {
		internalError(c, "create_projects_failed", "批量创建项目失败")
		return
	}
	c.JSON(http.StatusCreated, result)
}

func parseProjectBatchAssets(raw string) ([]string, int, int) {
	assets := make([]string, 0)
	seen := make(map[string]bool)
	invalid := 0
	duplicate := 0
	for _, line := range strings.Split(raw, "\n") {
		scope := strings.TrimSpace(line)
		if scope == "" {
			continue
		}
		if len([]rune(scope)) > projectScopeMaxRunes ||
			len(database.ParseProjectScopeAssets(scope)) == 0 {
			invalid++
			continue
		}
		key := strings.ToLower(scope)
		if seen[key] {
			duplicate++
			continue
		}
		seen[key] = true
		assets = append(assets, scope)
	}
	return assets, invalid, duplicate
}
