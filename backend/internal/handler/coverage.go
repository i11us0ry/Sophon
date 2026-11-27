package handler

import (
	"net/http"
	"strings"

	"sophon/internal/database"
	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

// Coverage 返回项目覆盖率与未覆盖队列（只读，project:read 权限）。
func (h *ProjectHandler) Coverage(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	coverage, err := h.db.ProjectCoverage(c.Request.Context(), project.ID, user.ID)
	if err != nil {
		internalError(c, "project_coverage_failed", "读取项目覆盖率失败")
		return
	}
	c.JSON(http.StatusOK, coverage)
}

func (h *ProjectHandler) ListAssetOverview(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	items, total, err := h.db.ListProjectAssetOverview(
		c.Request.Context(),
		project.ID,
		user.ID,
		database.AssetOverviewFilter{
			State:              c.Query("state"),
			Kind:               c.Query("kind"),
			AuthorizationState: c.Query("authorizationState"),
			QualityStatus:      c.Query("qualityStatus"),
			Search:             c.Query("search"),
			Limit:              clampQueryInt(c.Query("limit"), 200, 1, 500),
			Offset:             clampQueryInt(c.Query("offset"), 0, 0, 1000000),
		},
	)
	if err != nil {
		internalError(c, "project_asset_overview_failed", "读取项目资产总览失败")
		return
	}
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	nextOffset := offset + len(items)
	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"total":      total,
		"hasMore":    len(items) > 0 && nextOffset < total,
		"nextOffset": nextOffset,
	})
}

func (h *ProjectHandler) ListEvidenceGaps(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	assetID := strings.TrimSpace(c.Query("assetId"))
	if assetID != "" {
		asset, err := h.db.GetAsset(c.Request.Context(), assetID, user.ID)
		if err != nil || asset == nil || asset.ProjectID != project.ID {
			badRequest(c, "invalid_asset", "资产不存在或不属于当前项目")
			return
		}
	}
	query := strings.TrimSpace(c.Query("query"))
	if len([]rune(query)) > 200 {
		badRequest(c, "invalid_evidence_gap_query", "证据缺口搜索内容过长")
		return
	}
	kind := strings.ToLower(strings.TrimSpace(c.Query("kind")))
	if kind != "" && kind != "fact" && kind != "finding" {
		badRequest(c, "invalid_evidence_gap_kind", "证据缺口类型只能是 fact 或 finding")
		return
	}
	status := strings.ToLower(strings.TrimSpace(c.Query("status")))
	if status != "" && status != "all" && status != "missing_evidence" {
		badRequest(c, "invalid_evidence_gap_status", "证据缺口状态不合法")
		return
	}
	limit := clampQueryInt(c.Query("limit"), 50, 1, 200)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	items, total, err := h.db.ListEvidenceGaps(
		c.Request.Context(),
		database.EvidenceGapFilter{
			ProjectID: project.ID,
			AssetID:   assetID,
			Kind:      kind,
			Status:    status,
			Query:     query,
			Limit:     limit,
			Offset:    offset,
		},
	)
	if err != nil {
		internalError(c, "project_evidence_gaps_failed", "读取项目证据缺口失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"total":      total,
		"hasMore":    offset+len(items) < total,
		"nextOffset": offset + len(items),
	})
}

func (h *ProjectHandler) ListAssetWork(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	items, err := h.db.ListProjectAssetWork(c.Request.Context(), project.ID, user.ID)
	if err != nil {
		internalError(c, "project_asset_work_failed", "读取资产工作队列失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
}

func (h *ProjectHandler) AssetCloseout(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	assetID := strings.TrimSpace(c.Param("assetId"))
	if assetID == "" {
		badRequest(c, "invalid_asset_id", "资产 id 不能为空")
		return
	}
	status, err := h.db.AssetCloseoutStatus(c.Request.Context(), project.ID, user.ID, assetID)
	if err != nil {
		internalError(c, "project_asset_closeout_failed", "读取资产关闭门禁失败")
		return
	}
	c.JSON(http.StatusOK, status)
}

func (h *ProjectHandler) ReopenAssetWork(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	assetID := strings.TrimSpace(c.Param("assetId"))
	if assetID == "" {
		badRequest(c, "invalid_asset_id", "资产 id 不能为空")
		return
	}
	if err := h.db.ReopenProjectAssetWork(
		c.Request.Context(),
		project.ID,
		user.ID,
		assetID,
		"用户手动重开资产",
	); err != nil {
		internalError(c, "project_asset_reopen_failed", "重开资产失败")
		return
	}
	h.auditProjectAction(
		c,
		"project_asset_work.reopen",
		"project_asset_work",
		assetID,
		"用户手动重开资产工作项",
	)
	c.JSON(http.StatusOK, gin.H{"reopened": true, "assetId": assetID})
}
