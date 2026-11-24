package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	agentpkg "sophon/internal/agent"
	"sophon/internal/database"
	"sophon/internal/intel"
	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

type intelCollectionService interface {
	SearchIntel(
		ctx context.Context,
		request agentpkg.IntelSearchRequest,
	) ([]intel.Result, []string, error)
	IntelCapabilities(ctx context.Context) (agentpkg.IntelCapabilities, error)
	ImportIntelAssets(
		ctx context.Context,
		userID string,
		projectID string,
		results []intel.Result,
	) (agentpkg.IntelAssetImportSummary, error)
}

type IntelCollectionHandler struct {
	db      *database.DB
	service intelCollectionService
}

func NewIntelCollectionHandler(
	db *database.DB,
	service intelCollectionService,
) *IntelCollectionHandler {
	return &IntelCollectionHandler{db: db, service: service}
}

func (h *IntelCollectionHandler) Capabilities(c *gin.Context) {
	if h == nil || h.service == nil {
		internalError(c, "intel_unavailable", "情报能力不可用")
		return
	}
	value, err := h.service.IntelCapabilities(c.Request.Context())
	if err != nil {
		internalError(c, "load_intel_capabilities_failed", "读取情报能力失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"enabled":          value.Enabled,
		"fofaConfigured":   value.FOFAConfigured,
		"hunterConfigured": value.HunterConfigured,
	})
}

func (h *IntelCollectionHandler) List(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil || h == nil || h.db == nil {
		unauthorized(c)
		return
	}
	limit := clampQueryInt(c.Query("limit"), 20, 1, 100)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	items, total, err := h.db.ListIntelSearches(
		c.Request.Context(),
		user.ID,
		c.Query("projectId"),
		limit,
		offset,
	)
	if err != nil {
		internalError(c, "list_intel_searches_failed", "读取信息收集记录失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      intelSearchSummaries(items),
		"total":      total,
		"hasMore":    offset+len(items) < total,
		"nextOffset": offset + len(items),
	})
}

func (h *IntelCollectionHandler) Create(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil || h == nil || h.db == nil || h.service == nil {
		unauthorized(c)
		return
	}
	var request struct {
		Provider  string `json:"provider"`
		Query     string `json:"query"`
		ProjectID string `json:"projectId"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
		StartTime string `json:"start_time"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_intel_search", "查询请求格式错误")
		return
	}
	projectID := strings.TrimSpace(request.ProjectID)
	if projectID != "" {
		if _, err := h.db.GetProject(c.Request.Context(), projectID, user.ID); err != nil {
			badRequest(c, "invalid_intel_search", "项目不存在或无权访问")
			return
		}
	}
	results, providerErrors, err := h.service.SearchIntel(c.Request.Context(), agentpkg.IntelSearchRequest{
		Provider:  request.Provider,
		Query:     request.Query,
		Page:      request.Page,
		PageSize:  request.PageSize,
		StartTime: request.StartTime,
	})
	if err != nil {
		badRequest(c, "intel_search_failed", err.Error())
		return
	}
	if len(results) == 0 && len(providerErrors) > 0 {
		c.JSON(http.StatusBadGateway, gin.H{
			"code":            "intel_search_failed",
			"message":         "情报查询失败",
			"provider_errors": providerErrors,
		})
		return
	}
	request.Query = strings.TrimSpace(request.Query)
	request.Provider = strings.ToLower(strings.TrimSpace(request.Provider))
	if request.Provider == "" {
		request.Provider = "all"
	}
	if request.Page <= 0 {
		request.Page = 1
	}
	if request.PageSize <= 0 {
		request.PageSize = 20
	}
	record := database.IntelSearchRecord{
		ID:          randomID(),
		OwnerUserID: user.ID,
		ProjectID:   projectID,
		Provider:    request.Provider,
		Query:       request.Query,
		Page:        request.Page,
		PageSize:    request.PageSize,
		StartTime:   strings.TrimSpace(request.StartTime),
		ResultCount: len(results),
		CreatedAt:   time.Now().UTC(),
	}
	resultsJSON, err := json.Marshal(results)
	if err != nil {
		respondIntelSearchPartial(c, record, results, providerErrors)
		return
	}
	errorsJSON, err := json.Marshal(providerErrors)
	if err != nil {
		respondIntelSearchPartial(c, record, results, providerErrors)
		return
	}
	record.ResultsJSON = string(resultsJSON)
	record.ProviderErrorsJSON = string(errorsJSON)
	if err := h.db.CreateIntelSearch(c.Request.Context(), record); err != nil {
		respondIntelSearchPartial(c, record, results, providerErrors)
		return
	}
	response := intelSearchDetail(record, results, providerErrors)
	response["persisted"] = true
	c.JSON(http.StatusCreated, response)
}

func (h *IntelCollectionHandler) Get(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil || h == nil || h.db == nil {
		unauthorized(c)
		return
	}
	record, err := h.db.GetIntelSearch(c.Request.Context(), c.Param("id"), user.ID)
	if err != nil {
		respondMutationError(c, err, "intel_search_not_found", "信息收集记录不存在", "get_intel_search_failed", "读取信息收集记录失败")
		return
	}
	results, errors, err := decodeIntelSearch(record)
	if err != nil {
		internalError(c, "decode_intel_search_failed", "读取情报结果失败")
		return
	}
	c.JSON(http.StatusOK, intelSearchDetail(*record, results, errors))
}

func (h *IntelCollectionHandler) Delete(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil || h == nil || h.db == nil {
		unauthorized(c)
		return
	}
	if err := h.db.DeleteIntelSearch(c.Request.Context(), c.Param("id"), user.ID); err != nil {
		respondMutationError(
			c,
			err,
			"intel_search_not_found",
			"信息收集记录不存在",
			"delete_intel_search_failed",
			"删除信息收集记录失败",
		)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *IntelCollectionHandler) Import(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil || h == nil || h.db == nil || h.service == nil {
		unauthorized(c)
		return
	}
	var request struct {
		ProjectID string `json:"projectId"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_intel_import", "导入请求格式错误")
		return
	}
	record, err := h.db.GetIntelSearch(c.Request.Context(), c.Param("id"), user.ID)
	if err != nil {
		respondMutationError(c, err, "intel_search_not_found", "信息收集记录不存在", "get_intel_search_failed", "读取信息收集记录失败")
		return
	}
	projectID := strings.TrimSpace(request.ProjectID)
	if projectID == "" {
		projectID = strings.TrimSpace(record.ProjectID)
	}
	if projectID == "" {
		badRequest(c, "project_required", "导入资产前必须选择项目")
		return
	}
	if _, err := h.db.GetProject(c.Request.Context(), projectID, user.ID); err != nil {
		badRequest(c, "invalid_project", "项目不存在或无权访问")
		return
	}
	results, _, err := decodeIntelSearch(record)
	if err != nil {
		internalError(c, "decode_intel_search_failed", "读取情报结果失败")
		return
	}
	summary, err := h.service.ImportIntelAssets(
		c.Request.Context(),
		user.ID,
		projectID,
		results,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":            "import_intel_assets_failed",
			"message":         "导入资产存在失败项",
			"project_id":      projectID,
			"created":         summary.Created,
			"existing":        summary.Existing,
			"skipped_invalid": summary.Skipped,
			"failed":          summary.Failed,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"projectId":      projectID,
		"created":        summary.Created,
		"existing":       summary.Existing,
		"skippedInvalid": summary.Skipped,
		"failed":         summary.Failed,
		"assetIds":       summary.AssetIDs,
	})
}

func decodeIntelSearch(record *database.IntelSearchRecord) ([]intel.Result, []string, error) {
	results := make([]intel.Result, 0)
	if err := json.Unmarshal([]byte(record.ResultsJSON), &results); err != nil {
		return nil, nil, err
	}
	errors := make([]string, 0)
	if strings.TrimSpace(record.ProviderErrorsJSON) != "" {
		if err := json.Unmarshal([]byte(record.ProviderErrorsJSON), &errors); err != nil {
			return nil, nil, err
		}
	}
	return results, errors, nil
}

func intelSearchSummaries(items []database.IntelSearchRecord) []gin.H {
	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		result = append(result, gin.H{
			"id":          item.ID,
			"projectId":   item.ProjectID,
			"provider":    item.Provider,
			"query":       item.Query,
			"page":        item.Page,
			"pageSize":    item.PageSize,
			"startTime":   item.StartTime,
			"resultCount": item.ResultCount,
			"createdAt":   item.CreatedAt,
		})
	}
	return result
}

func intelSearchDetail(
	record database.IntelSearchRecord,
	results []intel.Result,
	providerErrors []string,
) gin.H {
	return gin.H{
		"id":             record.ID,
		"projectId":      record.ProjectID,
		"provider":       record.Provider,
		"query":          record.Query,
		"page":           record.Page,
		"pageSize":       record.PageSize,
		"startTime":      record.StartTime,
		"resultCount":    record.ResultCount,
		"results":        results,
		"providerErrors": providerErrors,
		"createdAt":      record.CreatedAt,
	}
}

func respondIntelSearchPartial(
	c *gin.Context,
	record database.IntelSearchRecord,
	results []intel.Result,
	providerErrors []string,
) {
	response := intelSearchDetail(record, results, providerErrors)
	response["id"] = ""
	response["persisted"] = false
	response["persistWarning"] = "查询成功，但历史记录保存失败，本次结果未持久化"
	c.JSON(http.StatusOK, response)
}
