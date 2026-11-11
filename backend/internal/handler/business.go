package handler

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	agentpkg "sophon/internal/agent"
	"sophon/internal/database"
	knowledgepkg "sophon/internal/knowledge"
	"sophon/internal/middleware"
	storagepkg "sophon/internal/storage"
	"sophon/internal/task"
	"sophon/internal/vulnerabilityfmt"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

var safeSkillName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

type VulnerabilityReviewer interface {
	ReviewVulnerability(context.Context, database.Vulnerability) error
}

func respondVulnerabilityReviewFailure(c *gin.Context, err error) {
	var unavailable *agentpkg.VulnerabilityReviewUnavailableError
	if errors.As(err, &unavailable) {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"code":    "vulnerability_review_unavailable",
			"message": unavailable.Error(),
		})
		return
	}
	c.JSON(http.StatusUnprocessableEntity, gin.H{
		"code":    "vulnerability_review_rejected",
		"message": err.Error(),
	})
}

type BusinessHandler struct {
	db                    *database.DB
	skillsDir             string
	knowledge             *knowledgepkg.Service
	manager               *task.Manager
	storage               *storagepkg.Service
	vulnerabilityReviewer VulnerabilityReviewer
}

func NewBusinessHandler(
	db *database.DB,
	skillsDir string,
	knowledgeService *knowledgepkg.Service,
	taskManager *task.Manager,
	storageService *storagepkg.Service,
	vulnerabilityReviewer VulnerabilityReviewer,
) *BusinessHandler {
	if strings.TrimSpace(skillsDir) == "" {
		skillsDir = "/opt/sophon/skills"
	}
	return &BusinessHandler{
		db:                    db,
		skillsDir:             skillsDir,
		knowledge:             knowledgeService,
		manager:               taskManager,
		storage:               storageService,
		vulnerabilityReviewer: vulnerabilityReviewer,
	}
}

const (
	projectGoalsMaxRunes = 2000
	projectScopeMaxRunes = 4000
)

var projectStatuses = map[string]bool{
	"planning": true,
	"active":   true,
	"paused":   true,
	"done":     true,
	"archived": true,
}

// normalizeProjectStatus 空值回退为进行中，非法值返回 false。
func normalizeProjectStatus(value string) (string, bool) {
	status := strings.ToLower(strings.TrimSpace(value))
	if status == "" {
		return "active", true
	}
	if !projectStatuses[status] {
		return "", false
	}
	return status, true
}

// validateProjectBrief 校验项目目标与资产范围长度。
func validateProjectBrief(goals, scope string) error {
	if len([]rune(strings.TrimSpace(goals))) > projectGoalsMaxRunes {
		return fmt.Errorf("项目目标不能超过 %d 个字符", projectGoalsMaxRunes)
	}
	if len([]rune(strings.TrimSpace(scope))) > projectScopeMaxRunes {
		return fmt.Errorf("资产范围不能超过 %d 个字符", projectScopeMaxRunes)
	}
	return nil
}

func (h *BusinessHandler) validateProjectReference(
	ctx context.Context,
	userID string,
	projectID string,
) error {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil
	}
	if _, err := h.db.GetProject(ctx, projectID, userID); err != nil {
		return fmt.Errorf("项目不存在")
	}
	return nil
}

func (h *BusinessHandler) validateAssetReference(
	ctx context.Context,
	userID string,
	assetID string,
	projectID string,
) error {
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		return nil
	}
	asset, err := h.db.GetAsset(ctx, assetID, userID)
	if err != nil {
		return fmt.Errorf("资产不存在")
	}
	projectID = strings.TrimSpace(projectID)
	if projectID != "" && strings.TrimSpace(asset.ProjectID) != "" && asset.ProjectID != projectID {
		return fmt.Errorf("资产不属于当前项目")
	}
	return nil
}

func (h *BusinessHandler) CreateProject(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Goals       string `json:"goals"`
		Scope       string `json:"scope"`
		Status      string `json:"status"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || strings.TrimSpace(request.Name) == "" {
		badRequest(c, "invalid_project", "项目名称不能为空")
		return
	}
	if err := validateProjectBrief(request.Goals, request.Scope); err != nil {
		badRequest(c, "invalid_project", err.Error())
		return
	}
	status, statusOK := normalizeProjectStatus(request.Status)
	if !statusOK {
		badRequest(c, "invalid_project", "项目状态不合法")
		return
	}
	now := time.Now().UTC()
	item := database.Project{
		ID:          randomID(),
		OwnerUserID: user.ID,
		Name:        truncateRunes(request.Name, 100),
		Description: strings.TrimSpace(request.Description),
		Goals:       strings.TrimSpace(request.Goals),
		Scope:       strings.TrimSpace(request.Scope),
		Status:      status,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.db.CreateProject(c.Request.Context(), item); err != nil {
		internalError(c, "create_project_failed", "创建项目失败")
		return
	}
	// 把「资产范围」中的域名/IP/CIDR 同步成可执行资产，Policy Engine 只认 assets 表。
	if _, err := h.db.SyncProjectScopeAssets(c.Request.Context(), item.ID, user.ID, item.Scope); err != nil {
		log.Printf("sync project scope assets failed: project=%s err=%v", item.ID, err)
	}
	// 自动生成攻击路径骨架（起点/目标），失败不影响项目创建。
	if _, err := h.db.SyncProjectGraph(c.Request.Context(), item); err != nil {
		_ = err
	}
	c.JSON(http.StatusCreated, item)
}

func (h *BusinessHandler) ListProjects(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	limit := 100
	if rawLimit := strings.TrimSpace(c.Query("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			badRequest(c, "invalid_limit", "limit 参数不合法")
			return
		}
		if parsed < limit {
			limit = parsed
		}
	}
	before := strings.TrimSpace(c.Query("before"))
	if len(before) > 128 {
		badRequest(c, "invalid_cursor", "项目游标不合法")
		return
	}
	items, hasMore, err := h.db.ListProjectsWithCountsPage(
		c.Request.Context(),
		user.ID,
		limit,
		before,
	)
	if err != nil {
		internalError(c, "list_projects_failed", "读取项目失败")
		return
	}
	nextCursor := ""
	if hasMore && len(items) > 0 {
		nextCursor = items[len(items)-1].ID
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"hasMore":    hasMore,
		"nextCursor": nextCursor,
	})
}

func (h *BusinessHandler) GetProject(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	item, err := h.db.GetProject(c.Request.Context(), c.Param("id"), user.ID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": "project_not_found", "message": "项目不存在"})
		return
	}
	c.JSON(http.StatusOK, item)
}

func (h *BusinessHandler) UpdateProject(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Goals       string `json:"goals"`
		Scope       string `json:"scope"`
		Status      string `json:"status"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || strings.TrimSpace(request.Name) == "" {
		badRequest(c, "invalid_project", "项目名称不能为空")
		return
	}
	if err := validateProjectBrief(request.Goals, request.Scope); err != nil {
		badRequest(c, "invalid_project", err.Error())
		return
	}
	status, statusOK := normalizeProjectStatus(request.Status)
	if !statusOK {
		badRequest(c, "invalid_project", "项目状态不合法")
		return
	}
	item := database.Project{
		ID:          c.Param("id"),
		OwnerUserID: user.ID,
		Name:        truncateRunes(request.Name, 100),
		Description: strings.TrimSpace(request.Description),
		Goals:       strings.TrimSpace(request.Goals),
		Scope:       strings.TrimSpace(request.Scope),
		Status:      status,
		UpdatedAt:   time.Now().UTC(),
	}
	if err := h.db.UpdateProject(c.Request.Context(), item); err != nil {
		respondMutationError(c, err, "project_not_found", "项目不存在", "update_project_failed", "更新项目失败")
		return
	}
	// 项目范围变更后同步资产，保证 Policy Engine 的授权范围与界面一致。
	if _, err := h.db.SyncProjectScopeAssets(c.Request.Context(), item.ID, user.ID, item.Scope); err != nil {
		log.Printf("sync project scope assets failed: project=%s err=%v", item.ID, err)
	}
	if status != "active" && h.manager != nil {
		conversations, err := h.db.ListProjectConversations(
			c.Request.Context(),
			item.ID,
			user.ID,
		)
		if err == nil {
			for _, conversation := range conversations {
				h.manager.CancelConversation(conversation.ID, user.ID)
			}
		}
	}
	c.Status(http.StatusNoContent)
}

func (h *BusinessHandler) DeleteProject(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	projectID := strings.TrimSpace(c.Param("id"))
	conversations, _ := h.db.ListProjectConversations(c.Request.Context(), projectID, user.ID)
	for _, conversation := range conversations {
		if h.manager != nil {
			h.manager.CancelConversation(conversation.ID, user.ID)
		}
	}
	if err := h.db.DeleteProject(c.Request.Context(), c.Param("id"), user.ID); err != nil {
		respondMutationError(c, err, "project_not_found", "项目不存在", "delete_project_failed", "删除项目失败")
		return
	}
	for _, conversation := range conversations {
		if h.manager != nil {
			h.manager.CancelConversation(conversation.ID, user.ID)
		}
	}
	cleanupConversationStorage(h.storage, conversations)
	c.Status(http.StatusNoContent)
}

func cleanupConversationStorage(
	storageService *storagepkg.Service,
	conversations []database.Conversation,
) {
	if storageService == nil || len(conversations) == 0 {
		return
	}
	conversationIDs := make([]string, 0, len(conversations))
	for _, conversation := range conversations {
		if id := strings.TrimSpace(conversation.ID); id != "" {
			conversationIDs = append(conversationIDs, id)
		}
	}
	// 覆盖 workspace / reduction / conversation_artifacts / chat_uploads，
	// 避免删除项目后工作空间仍残留该会话目录。
	storageService.RemoveConversationDirs(conversationIDs)
}

func (h *BusinessHandler) UpsertProjectFact(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	if _, err := h.db.GetProject(c.Request.Context(), c.Param("id"), user.ID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": "project_not_found", "message": "项目不存在"})
		return
	}
	var request struct {
		AssetID    string `json:"assetId"`
		FactType   string `json:"factType"`
		Key        string `json:"key"`
		Value      string `json:"value"`
		Confidence int    `json:"confidence"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || strings.TrimSpace(request.Key) == "" {
		badRequest(c, "invalid_fact", "事实 key 不能为空")
		return
	}
	if request.Confidence <= 0 || request.Confidence > 100 {
		request.Confidence = 100
	}
	assetID, err := h.validateProjectAssetID(
		c.Request.Context(),
		c.Param("id"),
		user.ID,
		request.AssetID,
	)
	if err != nil {
		badRequest(c, "invalid_asset", "资产不存在或不属于当前项目")
		return
	}
	item := database.ProjectFact{
		ID:         randomID(),
		ProjectID:  c.Param("id"),
		AssetID:    assetID,
		FactType:   strings.TrimSpace(request.FactType),
		Key:        strings.TrimSpace(request.Key),
		Value:      strings.TrimSpace(request.Value),
		Confidence: request.Confidence,
		CreatedAt:  time.Now().UTC(),
	}
	item.UpdatedAt = item.CreatedAt
	if item.FactType == "" {
		item.FactType = "general"
	}
	stored, err := h.db.UpsertProjectFact(c.Request.Context(), item)
	if err != nil {
		internalError(c, "upsert_fact_failed", "保存项目事实失败")
		return
	}
	c.JSON(http.StatusOK, stored)
}

func (h *BusinessHandler) ListProjectFacts(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	if _, err := h.db.GetProject(c.Request.Context(), c.Param("id"), user.ID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": "project_not_found", "message": "项目不存在"})
		return
	}
	limit := clampQueryInt(c.Query("limit"), 200, 1, 500)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	assetID, err := h.validateProjectAssetID(
		c.Request.Context(),
		c.Param("id"),
		user.ID,
		c.Query("assetId"),
	)
	if err != nil {
		badRequest(c, "invalid_asset", "资产不存在或不属于当前项目")
		return
	}
	items, total, err := h.db.ListProjectFactsPageByAsset(
		c.Request.Context(),
		c.Param("id"),
		assetID,
		limit,
		offset,
	)
	if err != nil {
		internalError(c, "list_facts_failed", "读取项目事实失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"total":      total,
		"hasMore":    offset+len(items) < total,
		"nextOffset": offset + len(items),
	})
}

func (h *BusinessHandler) UpdateProjectFact(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	if _, err := h.db.GetProject(c.Request.Context(), c.Param("id"), user.ID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": "project_not_found", "message": "项目不存在"})
		return
	}
	var request struct {
		FactType   string `json:"factType"`
		Value      string `json:"value"`
		Confidence int    `json:"confidence"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_fact", "事实请求格式错误")
		return
	}
	if request.Confidence <= 0 || request.Confidence > 100 {
		request.Confidence = 100
	}
	item := database.ProjectFact{
		ID:         c.Param("factId"),
		ProjectID:  c.Param("id"),
		FactType:   defaultString(request.FactType, "general"),
		Value:      strings.TrimSpace(request.Value),
		Confidence: request.Confidence,
		UpdatedAt:  time.Now().UTC(),
	}
	if err := h.db.UpdateProjectFact(c.Request.Context(), item); err != nil {
		respondMutationError(c, err, "fact_not_found", "项目事实不存在", "update_fact_failed", "更新项目事实失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *BusinessHandler) validateProjectAssetID(
	ctx context.Context,
	projectID string,
	userID string,
	assetID string,
) (string, error) {
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		return "", nil
	}
	assets, err := h.db.ListProjectAssets(ctx, projectID, userID)
	if err != nil {
		return "", err
	}
	for _, asset := range assets {
		if asset.ID == assetID {
			return asset.ID, nil
		}
	}
	return "", fmt.Errorf("asset not found")
}

func (h *BusinessHandler) DeleteProjectFact(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	if _, err := h.db.GetProject(c.Request.Context(), c.Param("id"), user.ID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": "project_not_found", "message": "项目不存在"})
		return
	}
	if err := h.db.DeleteProjectFact(c.Request.Context(), c.Param("factId"), c.Param("id")); err != nil {
		respondMutationError(c, err, "fact_not_found", "项目事实不存在", "delete_fact_failed", "删除项目事实失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *BusinessHandler) CreateAsset(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		ProjectID   string `json:"projectId"`
		Name        string `json:"name"`
		Kind        string `json:"kind"`
		Value       string `json:"value"`
		Status      string `json:"status"`
		Criticality string `json:"criticality"`
		RiskScore   int    `json:"riskScore"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || strings.TrimSpace(request.Name) == "" || strings.TrimSpace(request.Value) == "" {
		badRequest(c, "invalid_asset", "资产名称和值不能为空")
		return
	}
	if err := h.validateProjectReference(c.Request.Context(), user.ID, request.ProjectID); err != nil {
		badRequest(c, "invalid_asset", err.Error())
		return
	}
	if request.RiskScore < 0 || request.RiskScore > 100 {
		badRequest(c, "invalid_asset", "风险分必须在 0 到 100 之间")
		return
	}
	now := time.Now().UTC()
	item := database.Asset{
		ID:          randomID(),
		ProjectID:   strings.TrimSpace(request.ProjectID),
		OwnerUserID: user.ID,
		Name:        truncateRunes(request.Name, 120),
		Kind:        defaultString(request.Kind, "domain"),
		Value:       strings.TrimSpace(request.Value),
		Status:      defaultString(request.Status, "unknown"),
		Criticality: defaultString(request.Criticality, "medium"),
		RiskScore:   request.RiskScore,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.db.CreateAsset(c.Request.Context(), item); err != nil {
		respondAssetMutationError(c, err, "create_asset_failed", "创建资产失败")
		return
	}
	c.JSON(http.StatusCreated, item)
}

func (h *BusinessHandler) ListAssets(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	if hasAssetQuery(c) {
		limit := clampQueryInt(c.Query("limit"), 20, 1, 200)
		offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
		items, total, err := h.db.ListAssetsFiltered(
			c.Request.Context(),
			database.AssetFilter{
				OwnerUserID: user.ID,
				ProjectID:   strings.TrimSpace(c.Query("projectId")),
				Kind:        strings.TrimSpace(c.Query("kind")),
				Status:      strings.TrimSpace(c.Query("status")),
				Search:      strings.TrimSpace(c.Query("search")),
				Limit:       limit,
				Offset:      offset,
			},
		)
		if err != nil {
			internalError(c, "list_assets_failed", "读取资产失败")
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"items":      items,
			"total":      total,
			"hasMore":    offset+len(items) < total,
			"nextOffset": offset + len(items),
		})
		return
	}
	items, err := h.db.ListAssets(c.Request.Context(), user.ID)
	if err != nil {
		internalError(c, "list_assets_failed", "读取资产失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func hasAssetQuery(c *gin.Context) bool {
	for _, key := range []string{"limit", "projectId", "kind", "status", "search"} {
		if strings.TrimSpace(c.Query(key)) != "" {
			return true
		}
	}
	return false
}

func (h *BusinessHandler) DeleteAsset(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	if err := h.db.DeleteAsset(c.Request.Context(), c.Param("id"), user.ID); err != nil {
		respondMutationError(c, err, "asset_not_found", "资产不存在", "delete_asset_failed", "删除资产失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *BusinessHandler) UpdateAsset(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		ProjectID   string `json:"projectId"`
		Name        string `json:"name"`
		Kind        string `json:"kind"`
		Value       string `json:"value"`
		Status      string `json:"status"`
		Criticality string `json:"criticality"`
		RiskScore   int    `json:"riskScore"`
	}
	if err := c.ShouldBindJSON(&request); err != nil ||
		strings.TrimSpace(request.Name) == "" ||
		strings.TrimSpace(request.Value) == "" {
		badRequest(c, "invalid_asset", "资产名称和值不能为空")
		return
	}
	if err := h.validateProjectReference(c.Request.Context(), user.ID, request.ProjectID); err != nil {
		badRequest(c, "invalid_asset", err.Error())
		return
	}
	if request.RiskScore < 0 || request.RiskScore > 100 {
		badRequest(c, "invalid_asset", "风险分必须在 0 到 100 之间")
		return
	}
	item := database.Asset{
		ID:          c.Param("id"),
		OwnerUserID: user.ID,
		ProjectID:   strings.TrimSpace(request.ProjectID),
		Name:        truncateRunes(request.Name, 120),
		Kind:        defaultString(request.Kind, "domain"),
		Value:       strings.TrimSpace(request.Value),
		Status:      defaultString(request.Status, "unknown"),
		Criticality: defaultString(request.Criticality, "medium"),
		RiskScore:   request.RiskScore,
		UpdatedAt:   time.Now().UTC(),
	}
	if err := h.db.UpdateAsset(c.Request.Context(), item); err != nil {
		if database.NoRows(err) {
			respondMutationError(c, err, "asset_not_found", "资产不存在", "update_asset_failed", "更新资产失败")
			return
		}
		respondAssetMutationError(c, err, "update_asset_failed", "更新资产失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *BusinessHandler) generatedVulnerabilityTitle(
	ctx context.Context,
	userID string,
	projectID string,
	assetID string,
	target string,
	vulnerabilityType string,
	impact string,
	_ string,
	id string,
) string {
	projectName := "未关联系统"
	projectHints := []string{target, impact}
	if projectID = strings.TrimSpace(projectID); projectID != "" {
		if project, err := h.db.GetProject(ctx, projectID, userID); err == nil {
			if name := strings.TrimSpace(project.Name); name != "" {
				projectName = name
			}
			projectHints = append(projectHints, project.Description, project.Goals, project.Scope)
		}
	}
	assetValue := ""
	assetName := ""
	if assetID = strings.TrimSpace(assetID); assetID != "" {
		if asset, err := h.db.GetAsset(ctx, assetID, userID); err == nil {
			assetValue = asset.Value
			assetName = asset.Name
		}
	}
	projectHints = append(projectHints, assetName, assetValue)
	return vulnerabilityfmt.BuildTitle(vulnerabilityfmt.TitleParts{
		ProjectName:          vulnerabilityfmt.InferProductName(projectName, projectHints...),
		VulnerabilityAddress: vulnerabilityfmt.VulnerabilityAddress(target, "", impact),
		VulnerabilityType:    vulnerabilityType,
		ImpactSummary:        vulnerabilityfmt.ShortImpact(vulnerabilityType),
		ID:                   id,
	})
}

func (h *BusinessHandler) CreateVulnerability(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		ProjectID         string   `json:"projectId"`
		AssetID           string   `json:"assetId"`
		Title             string   `json:"title"`
		TitleImpact       string   `json:"titleImpact"`
		Severity          string   `json:"severity"`
		VulnerabilityType string   `json:"vulnerabilityType"`
		Target            string   `json:"target"`
		Parameter         string   `json:"parameter"`
		HTTPMethod        string   `json:"httpMethod"`
		Preconditions     string   `json:"preconditions"`
		ReproductionSteps string   `json:"reproductionSteps"`
		Description       string   `json:"description"`
		Evidence          string   `json:"evidence"`
		EvidenceRefs      []string `json:"evidenceRefs"`
		Impact            string   `json:"impact"`
		Recommendation    string   `json:"recommendation"`
		RetestNotes       string   `json:"retestNotes"`
		VerificationState string   `json:"verificationState"`
		Confidence        int      `json:"confidence"`
		Exploitability    string   `json:"exploitability"`
		TestTechnique     string   `json:"testTechnique"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_vulnerability", "漏洞请求格式错误")
		return
	}
	vulnerabilityType, validType := vulnerabilityfmt.NormalizeType(request.VulnerabilityType)
	if !validType {
		badRequest(c, "invalid_vulnerability", "漏洞类型必须从平台规定列表中选择")
		return
	}
	severity, validSeverity := normalizeVulnerabilitySeverity(request.Severity)
	if !validSeverity {
		badRequest(c, "invalid_vulnerability", "漏洞严重度不合法")
		return
	}
	if vulnerabilityTextTooLong(
		request.Preconditions,
		request.ReproductionSteps,
		request.Description,
		request.Evidence,
		request.Impact,
		request.Recommendation,
		request.RetestNotes,
	) {
		badRequest(c, "invalid_vulnerability", "漏洞文本字段不能超过 50000 个字符")
		return
	}
	if strings.TrimSpace(request.Impact) == "" {
		badRequest(c, "invalid_vulnerability", "漏洞危害不能为空")
		return
	}
	if !vulnerabilityfmt.ValidateEvidence(request.Evidence, request.EvidenceRefs) {
		badRequest(c, "invalid_vulnerability_evidence", "漏洞必须提供证据")
		return
	}
	if err := vulnerabilityfmt.ValidateReproduction(request.ReproductionSteps); err != nil {
		badRequest(c, "invalid_vulnerability", err.Error())
		return
	}
	if err := h.validateProjectReference(c.Request.Context(), user.ID, request.ProjectID); err != nil {
		badRequest(c, "invalid_vulnerability", err.Error())
		return
	}
	if err := h.validateAssetReference(
		c.Request.Context(),
		user.ID,
		request.AssetID,
		request.ProjectID,
	); err != nil {
		badRequest(c, "invalid_vulnerability", err.Error())
		return
	}
	now := time.Now().UTC()
	id := randomID()
	item := database.Vulnerability{
		ID:          id,
		ProjectID:   strings.TrimSpace(request.ProjectID),
		AssetID:     strings.TrimSpace(request.AssetID),
		OwnerUserID: user.ID,
		Title: truncateRunes(h.generatedVulnerabilityTitle(
			c.Request.Context(),
			user.ID,
			request.ProjectID,
			request.AssetID,
			request.Target,
			vulnerabilityType,
			request.Impact,
			request.TitleImpact,
			id,
		), 240),
		Severity:          severity,
		Status:            "open",
		VulnerabilityType: vulnerabilityType,
		Target:            truncateRunes(request.Target, 240),
		Parameter:         truncateRunes(request.Parameter, 120),
		HTTPMethod:        strings.ToUpper(truncateRunes(request.HTTPMethod, 16)),
		Preconditions:     vulnerabilityfmt.NormalizePreconditions(request.Preconditions),
		ReproductionSteps: strings.TrimSpace(request.ReproductionSteps),
		Description:       strings.TrimSpace(request.Description),
		Evidence:          strings.TrimSpace(request.Evidence),
		EvidenceRefs:      request.EvidenceRefs,
		Impact:            strings.TrimSpace(request.Impact),
		Recommendation:    strings.TrimSpace(request.Recommendation),
		RetestNotes:       vulnerabilityfmt.NormalizeRetestNotes(request.RetestNotes),
		VerificationState: strings.TrimSpace(request.VerificationState),
		Confidence:        request.Confidence,
		Exploitability:    strings.TrimSpace(request.Exploitability),
		TestTechnique:     strings.TrimSpace(request.TestTechnique),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if strings.TrimSpace(item.VerificationState) == "" {
		switch {
		case hasStructuredEvidenceRefs(item.EvidenceRefs):
			item.VerificationState = "verified"
		case strings.TrimSpace(item.Evidence) != "":
			item.VerificationState = "observed"
		default:
			item.VerificationState = "unverified"
		}
	}
	item = database.NormalizeVulnerabilityEvidence(item)
	if item.Status == "confirmed" ||
		item.VerificationState == "verified" ||
		item.VerificationState == "exploitable" {
		if !hasStructuredEvidenceRefs(item.EvidenceRefs) {
			badRequest(c, "invalid_vulnerability_evidence", "已验证漏洞必须提供结构化证据引用")
			return
		}
		if err := database.ValidateVulnerabilityEvidence(item); err != nil {
			badRequest(c, "invalid_vulnerability_evidence", err.Error())
			return
		}
		if err := h.validateVulnerabilityEvidenceReferences(
			c.Request.Context(),
			user.ID,
			item,
		); err != nil {
			badRequest(c, "invalid_vulnerability_evidence", err.Error())
			return
		}
	}
	if h.vulnerabilityReviewer == nil {
		respondVulnerabilityReviewFailure(c, &agentpkg.VulnerabilityReviewUnavailableError{
			Reason: "审核器未配置",
		})
		return
	}
	if err := h.vulnerabilityReviewer.ReviewVulnerability(c.Request.Context(), item); err != nil {
		respondVulnerabilityReviewFailure(c, err)
		return
	}
	if err := h.db.CreateVulnerability(c.Request.Context(), item); err != nil {
		internalError(c, "create_vulnerability_failed", "创建漏洞失败")
		return
	}
	c.JSON(http.StatusCreated, item)
}

func (h *BusinessHandler) ListVulnerabilities(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	limit := clampQueryInt(c.Query("limit"), 20, 1, 200)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	items, total, err := h.db.ListVulnerabilitiesFiltered(
		c.Request.Context(),
		database.VulnerabilityFilter{
			OwnerUserID: user.ID,
			ProjectID:   strings.TrimSpace(c.Query("projectId")),
			Severity:    strings.TrimSpace(c.Query("severity")),
			Status:      strings.TrimSpace(c.Query("status")),
			Search:      strings.TrimSpace(c.Query("search")),
			Limit:       limit,
			Offset:      offset,
		},
	)
	if err != nil {
		internalError(c, "list_vulnerabilities_failed", "读取漏洞失败")
		return
	}
	totalPages := (total + limit - 1) / limit
	if totalPages == 0 {
		totalPages = 1
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"total":      total,
		"page":       offset/limit + 1,
		"pageSize":   limit,
		"totalPages": totalPages,
	})
}

func (h *BusinessHandler) VulnerabilityStats(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	severityStats, statusStats, total, err := h.db.VulnerabilityStatsFiltered(
		c.Request.Context(),
		database.VulnerabilityFilter{
			OwnerUserID: user.ID,
			ProjectID:   strings.TrimSpace(c.Query("projectId")),
			Severity:    strings.TrimSpace(c.Query("severity")),
			Status:      strings.TrimSpace(c.Query("status")),
			Search:      strings.TrimSpace(c.Query("search")),
		},
	)
	if err != nil {
		internalError(c, "vulnerability_stats_failed", "读取漏洞统计失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"severity": severityStats,
		"status":   statusStats,
		"total":    total,
	})
}

func (h *BusinessHandler) UpdateVulnerability(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		ProjectID         string   `json:"projectId"`
		AssetID           string   `json:"assetId"`
		Title             string   `json:"title"`
		TitleImpact       string   `json:"titleImpact"`
		Severity          string   `json:"severity"`
		Status            string   `json:"status"`
		VulnerabilityType string   `json:"vulnerabilityType"`
		Target            string   `json:"target"`
		Parameter         string   `json:"parameter"`
		HTTPMethod        string   `json:"httpMethod"`
		Preconditions     string   `json:"preconditions"`
		ReproductionSteps string   `json:"reproductionSteps"`
		Description       string   `json:"description"`
		Evidence          string   `json:"evidence"`
		EvidenceRefs      []string `json:"evidenceRefs"`
		Impact            string   `json:"impact"`
		Recommendation    string   `json:"recommendation"`
		RetestNotes       string   `json:"retestNotes"`
		VerificationState string   `json:"verificationState"`
		Confidence        *int     `json:"confidence"`
		Exploitability    string   `json:"exploitability"`
		TestTechnique     string   `json:"testTechnique"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_vulnerability", "漏洞请求格式错误")
		return
	}
	severity, validSeverity := normalizeVulnerabilitySeverity(request.Severity)
	if !validSeverity {
		badRequest(c, "invalid_vulnerability", "漏洞严重度不合法")
		return
	}
	status, validStatus := normalizeVulnerabilityStatus(request.Status)
	if !validStatus {
		badRequest(c, "invalid_vulnerability", "漏洞状态不合法")
		return
	}
	if vulnerabilityTextTooLong(
		request.Preconditions,
		request.ReproductionSteps,
		request.Description,
		request.Evidence,
		request.Impact,
		request.Recommendation,
		request.RetestNotes,
	) {
		badRequest(c, "invalid_vulnerability", "漏洞文本字段不能超过 50000 个字符")
		return
	}
	if err := h.validateProjectReference(c.Request.Context(), user.ID, request.ProjectID); err != nil {
		badRequest(c, "invalid_vulnerability", err.Error())
		return
	}
	if err := h.validateAssetReference(
		c.Request.Context(),
		user.ID,
		request.AssetID,
		request.ProjectID,
	); err != nil {
		badRequest(c, "invalid_vulnerability", err.Error())
		return
	}
	existing, err := h.db.GetVulnerability(c.Request.Context(), c.Param("id"), user.ID)
	if err != nil {
		respondMutationError(c, err, "vulnerability_not_found", "漏洞不存在", "update_vulnerability_failed", "更新漏洞失败")
		return
	}
	contentChanged := strings.TrimSpace(request.ProjectID) != existing.ProjectID ||
		strings.TrimSpace(request.AssetID) != existing.AssetID ||
		strings.TrimSpace(request.VulnerabilityType) != strings.TrimSpace(existing.VulnerabilityType) ||
		strings.TrimSpace(request.Target) != existing.Target ||
		strings.TrimSpace(request.Parameter) != existing.Parameter ||
		strings.ToUpper(strings.TrimSpace(request.HTTPMethod)) != existing.HTTPMethod ||
		strings.TrimSpace(request.Preconditions) != existing.Preconditions ||
		strings.TrimSpace(request.ReproductionSteps) != existing.ReproductionSteps ||
		strings.TrimSpace(request.Description) != existing.Description ||
		strings.TrimSpace(request.Evidence) != existing.Evidence ||
		strings.TrimSpace(request.Impact) != existing.Impact ||
		strings.TrimSpace(request.Recommendation) != existing.Recommendation ||
		strings.TrimSpace(request.RetestNotes) != existing.RetestNotes ||
		strings.TrimSpace(request.Exploitability) != existing.Exploitability ||
		strings.TrimSpace(request.TestTechnique) != existing.TestTechnique
	vulnerabilityType, validType := vulnerabilityfmt.NormalizeType(request.VulnerabilityType)
	if contentChanged {
		if !validType {
			badRequest(c, "invalid_vulnerability", "漏洞类型必须从平台规定列表中选择")
			return
		}
		if strings.TrimSpace(request.Impact) == "" {
			badRequest(c, "invalid_vulnerability", "漏洞危害不能为空")
			return
		}
		if !vulnerabilityfmt.ValidateEvidence(request.Evidence, request.EvidenceRefs) {
			badRequest(c, "invalid_vulnerability_evidence", "漏洞必须提供证据")
			return
		}
		if err := vulnerabilityfmt.ValidateReproduction(request.ReproductionSteps); err != nil {
			badRequest(c, "invalid_vulnerability", err.Error())
			return
		}
	} else if !validType {
		vulnerabilityType = existing.VulnerabilityType
	}
	item := *existing
	item.Severity = severity
	item.Status = status
	if contentChanged {
		item.ProjectID = strings.TrimSpace(request.ProjectID)
		item.AssetID = strings.TrimSpace(request.AssetID)
		item.Title = truncateRunes(h.generatedVulnerabilityTitle(
			c.Request.Context(),
			user.ID,
			request.ProjectID,
			request.AssetID,
			request.Target,
			vulnerabilityType,
			request.Impact,
			request.TitleImpact,
			existing.ID,
		), 240)
		item.VulnerabilityType = vulnerabilityType
		item.Target = truncateRunes(request.Target, 240)
		item.Parameter = truncateRunes(request.Parameter, 120)
		item.HTTPMethod = strings.ToUpper(truncateRunes(request.HTTPMethod, 16))
		item.Preconditions = vulnerabilityfmt.NormalizePreconditions(request.Preconditions)
		item.ReproductionSteps = strings.TrimSpace(request.ReproductionSteps)
		item.Description = strings.TrimSpace(request.Description)
		item.Evidence = strings.TrimSpace(request.Evidence)
		if request.EvidenceRefs != nil {
			item.EvidenceRefs = request.EvidenceRefs
		}
		item.Impact = strings.TrimSpace(request.Impact)
		item.Recommendation = strings.TrimSpace(request.Recommendation)
		item.RetestNotes = vulnerabilityfmt.NormalizeRetestNotes(request.RetestNotes)
	}
	if state := strings.TrimSpace(request.VerificationState); state != "" {
		item.VerificationState = state
	}
	if request.Confidence != nil {
		item.Confidence = *request.Confidence
	}
	item.Exploitability = strings.TrimSpace(request.Exploitability)
	item.TestTechnique = strings.TrimSpace(request.TestTechnique)
	item.UpdatedAt = time.Now().UTC()
	item = database.NormalizeVulnerabilityEvidence(item)
	statusEnteringConfirmed := item.Status == "confirmed" && existing.Status != "confirmed"
	stateRequiresEvidence := item.VerificationState == "verified" ||
		item.VerificationState == "exploitable"
	if statusEnteringConfirmed || stateRequiresEvidence {
		if !hasStructuredEvidenceRefs(item.EvidenceRefs) {
			badRequest(c, "invalid_vulnerability_evidence", "已验证漏洞必须提供结构化证据引用")
			return
		}
		if err := database.ValidateVulnerabilityEvidence(item); err != nil {
			badRequest(c, "invalid_vulnerability_evidence", err.Error())
			return
		}
		if err := h.validateVulnerabilityEvidenceReferences(
			c.Request.Context(),
			user.ID,
			item,
		); err != nil {
			badRequest(c, "invalid_vulnerability_evidence", err.Error())
			return
		}
	}
	if agentpkg.VulnerabilityNeedsReview(*existing, item) {
		if h.vulnerabilityReviewer == nil {
			respondVulnerabilityReviewFailure(c, &agentpkg.VulnerabilityReviewUnavailableError{
				Reason: "审核器未配置",
			})
			return
		}
		if err := h.vulnerabilityReviewer.ReviewVulnerability(c.Request.Context(), item); err != nil {
			respondVulnerabilityReviewFailure(c, err)
			return
		}
	}
	if err := h.db.UpdateVulnerability(c.Request.Context(), item); err != nil {
		respondMutationError(c, err, "vulnerability_not_found", "漏洞不存在", "update_vulnerability_failed", "更新漏洞失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func hasStructuredEvidenceRefs(refs []string) bool {
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		for _, prefix := range []string{"tool:", "file:", "artifact:", "fact:", "conversation:"} {
			if strings.HasPrefix(strings.ToLower(ref), prefix) && len(ref) > len(prefix) {
				return true
			}
		}
	}
	return false
}

func (h *BusinessHandler) validateVulnerabilityEvidenceReferences(
	ctx context.Context,
	userID string,
	item database.Vulnerability,
) error {
	artifactRoot := ""
	if h.storage != nil {
		artifactRoot = h.storage.ArtifactRoot()
	}
	return h.db.ValidateEvidenceReferences(ctx, database.EvidenceReferenceOptions{
		ProjectID:         item.ProjectID,
		UserID:            userID,
		Refs:              item.EvidenceRefs,
		ArtifactRoot:      artifactRoot,
		RequireStructured: true,
	})
}

func (h *BusinessHandler) DeleteVulnerability(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	if err := h.db.DeleteVulnerability(c.Request.Context(), c.Param("id"), user.ID); err != nil {
		respondMutationError(c, err, "vulnerability_not_found", "漏洞不存在", "delete_vulnerability_failed", "删除漏洞失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *BusinessHandler) CreateKnowledgeItem(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		Category string `json:"category"`
		Title    string `json:"title"`
		Content  string `json:"content"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || strings.TrimSpace(request.Title) == "" {
		badRequest(c, "invalid_knowledge", "知识标题不能为空")
		return
	}
	item, err := h.knowledge.CreateItem(
		c.Request.Context(),
		user.ID,
		request.Category,
		request.Title,
		request.Content,
	)
	if err != nil {
		internalError(c, "create_knowledge_failed", "创建知识失败")
		return
	}
	c.JSON(http.StatusCreated, item)
}

func (h *BusinessHandler) ListKnowledgeItems(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	items, err := h.db.ListKnowledgeItems(c.Request.Context(), user.ID)
	if err != nil {
		internalError(c, "list_knowledge_failed", "读取知识库失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *BusinessHandler) SearchKnowledge(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		Query string `json:"query"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_query", "查询格式错误")
		return
	}
	items, err := h.knowledge.Search(c.Request.Context(), user.ID, request.Query, 5)
	if err != nil {
		internalError(c, "search_knowledge_failed", "搜索知识库失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *BusinessHandler) UpdateKnowledgeItem(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		Category string `json:"category"`
		Title    string `json:"title"`
		Content  string `json:"content"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || strings.TrimSpace(request.Title) == "" {
		badRequest(c, "invalid_knowledge", "知识标题不能为空")
		return
	}
	if _, err := h.knowledge.UpdateItem(
		c.Request.Context(),
		user.ID,
		c.Param("id"),
		request.Category,
		request.Title,
		request.Content,
	); err != nil {
		respondMutationError(c, err, "knowledge_not_found", "知识不存在", "update_knowledge_failed", "更新知识失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *BusinessHandler) DeleteKnowledgeItem(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	if err := h.knowledge.DeleteItem(c.Request.Context(), user.ID, c.Param("id")); err != nil {
		respondMutationError(c, err, "knowledge_not_found", "知识不存在", "delete_knowledge_failed", "删除知识失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *BusinessHandler) CreateWebShellConnection(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		ProjectID string `json:"projectId"`
		Name      string `json:"name"`
		URL       string `json:"url"`
		Method    string `json:"method"`
		Password  string `json:"password"`
		Encoding  string `json:"encoding"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || strings.TrimSpace(request.Name) == "" || strings.TrimSpace(request.URL) == "" {
		badRequest(c, "invalid_webshell", "名称和 URL 不能为空")
		return
	}
	if err := h.validateProjectReference(c.Request.Context(), user.ID, request.ProjectID); err != nil {
		badRequest(c, "invalid_webshell", err.Error())
		return
	}
	now := time.Now().UTC()
	item := database.WebShellConnection{
		ID:          randomID(),
		ProjectID:   strings.TrimSpace(request.ProjectID),
		OwnerUserID: user.ID,
		Name:        truncateRunes(request.Name, 120),
		URL:         strings.TrimSpace(request.URL),
		Method:      defaultString(request.Method, "POST"),
		Password:    request.Password,
		Encoding:    defaultString(request.Encoding, "utf-8"),
		Status:      "unknown",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.db.CreateWebShellConnection(c.Request.Context(), item); err != nil {
		internalError(c, "create_webshell_failed", "创建 WebShell 连接失败")
		return
	}
	c.JSON(http.StatusCreated, webshellResponse(item))
}

func (h *BusinessHandler) ListWebShellConnections(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	items, err := h.db.ListWebShellConnections(c.Request.Context(), user.ID)
	if err != nil {
		internalError(c, "list_webshell_failed", "读取 WebShell 连接失败")
		return
	}
	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		result = append(result, webshellResponse(item))
	}
	c.JSON(http.StatusOK, gin.H{"items": result})
}

func (h *BusinessHandler) DeleteWebShellConnection(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	if err := h.db.DeleteWebShellConnection(c.Request.Context(), c.Param("id"), user.ID); err != nil {
		internalError(c, "delete_webshell_failed", "删除 WebShell 连接失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *BusinessHandler) ListSkills(c *gin.Context) {
	entries, err := os.ReadDir(h.skillsDir)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusOK, gin.H{"items": []interface{}{}})
			return
		}
		internalError(c, "list_skills_failed", "读取 Skills 失败")
		return
	}
	items := make([]gin.H, 0)
	for _, entry := range entries {
		if !entry.IsDir() || !safeSkillName.MatchString(entry.Name()) {
			continue
		}
		path := filepath.Join(h.skillsDir, entry.Name(), "SKILL.md")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		items = append(items, skillMetadataResponse(parseSkillMetadata(entry.Name(), h.skillsDir)))
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *BusinessHandler) GetSkill(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	if !safeSkillName.MatchString(name) {
		badRequest(c, "invalid_skill_name", "Skill 名称不合法")
		return
	}
	content, err := os.ReadFile(filepath.Join(h.skillsDir, name, "SKILL.md"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": "skill_not_found", "message": "Skill 不存在"})
		return
	}
	response := skillMetadataResponse(parseSkillMetadata(name, h.skillsDir))
	response["content"] = string(content)
	c.JSON(http.StatusOK, response)
}

func (h *BusinessHandler) CreateSkill(c *gin.Context) {
	var request struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Content     string `json:"content"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_skill", "Skill 请求格式错误")
		return
	}
	name := strings.TrimSpace(request.Name)
	if !safeSkillName.MatchString(name) {
		badRequest(c, "invalid_skill_name", "Skill 名称只能是字母、数字、下划线或短横线")
		return
	}
	dir := filepath.Join(h.skillsDir, name)
	if _, err := os.Stat(dir); err == nil {
		badRequest(c, "skill_exists", "Skill 已存在")
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		internalError(c, "create_skill_failed", "创建 Skill 目录失败")
		return
	}
	content := strings.TrimSpace(request.Content)
	if content == "" {
		content = skillTemplate(name, strings.TrimSpace(request.Description))
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(content), 0o644); err != nil {
		internalError(c, "create_skill_failed", "创建 Skill 失败")
		return
	}
	c.JSON(http.StatusCreated, skillMetadataResponse(parseSkillMetadata(name, h.skillsDir)))
}

func (h *BusinessHandler) DeleteSkill(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	if !safeSkillName.MatchString(name) {
		badRequest(c, "invalid_skill_name", "Skill 名称不合法")
		return
	}
	dir := filepath.Join(h.skillsDir, name)
	if _, err := os.Stat(filepath.Join(dir, "SKILL.md")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": "skill_not_found", "message": "Skill 不存在"})
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		internalError(c, "delete_skill_failed", "删除 Skill 失败")
		return
	}
	c.Status(http.StatusNoContent)
}

type skillMetadata struct {
	Name        string
	Description string
	Tags        []string
	Enabled     bool
	Path        string
	FileCount   int
}

type skillFrontmatter struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Enabled     *bool  `yaml:"enabled"`
	Metadata    struct {
		Tags []string `yaml:"tags"`
	} `yaml:"metadata"`
}

func parseSkillMetadata(name, root string) skillMetadata {
	path := filepath.Join(root, name, "SKILL.md")
	meta := skillMetadata{
		Name:    name,
		Enabled: true,
		Path:    path,
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return meta
	}
	var parsed skillFrontmatter
	if front := skillFrontmatterText(string(raw)); front != "" {
		_ = yaml.Unmarshal([]byte(front), &parsed)
	}
	if value := strings.TrimSpace(parsed.Name); value != "" {
		meta.Name = value
	}
	meta.Description = strings.TrimSpace(parsed.Description)
	meta.Tags = parsed.Metadata.Tags
	if parsed.Enabled != nil {
		meta.Enabled = *parsed.Enabled
	}
	meta.FileCount = countSkillFiles(filepath.Join(root, name))
	return meta
}

func skillFrontmatterText(content string) string {
	content = strings.TrimPrefix(content, "\ufeff")
	if !strings.HasPrefix(content, "---") {
		return ""
	}
	rest := content[3:]
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func countSkillFiles(dir string) int {
	count := 0
	_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry == nil || entry.IsDir() {
			return nil
		}
		count++
		return nil
	})
	return count
}

func skillMetadataResponse(meta skillMetadata) gin.H {
	tags := meta.Tags
	if tags == nil {
		tags = []string{}
	}
	return gin.H{
		"name":        meta.Name,
		"description": meta.Description,
		"tags":        tags,
		"enabled":     meta.Enabled,
		"path":        meta.Path,
		"fileCount":   meta.FileCount,
	}
}

func skillTemplate(name, description string) string {
	if description == "" {
		description = name
	}
	return fmt.Sprintf("---\nname: %s\ndescription: %s\nmetadata:\n  tags: []\n---\n\n## %s\n\n在这里编写技能说明。\n", name, description, name)
}

func (h *BusinessHandler) SaveSkill(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	if !safeSkillName.MatchString(name) {
		badRequest(c, "invalid_skill_name", "Skill 名称不合法")
		return
	}
	var request struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || strings.TrimSpace(request.Content) == "" {
		badRequest(c, "invalid_skill", "Skill 内容不能为空")
		return
	}
	if len(request.Content) > 1024*1024 {
		badRequest(c, "skill_too_large", "Skill 内容不能超过 1MB")
		return
	}
	dir := filepath.Join(h.skillsDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		internalError(c, "create_skill_failed", "创建 Skill 目录失败")
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(request.Content), 0o644); err != nil {
		internalError(c, "save_skill_failed", "保存 Skill 失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"name": name,
		"path": filepath.Join(dir, "SKILL.md"),
	})
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func clampQueryInt(raw string, fallback, min, max int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < min {
		return fallback
	}
	if value > max {
		return max
	}
	return value
}

func respondMutationError(
	c *gin.Context,
	err error,
	notFoundCode string,
	notFoundMessage string,
	internalCode string,
	internalMessage string,
) {
	if database.NoRows(err) {
		c.JSON(http.StatusNotFound, gin.H{"code": notFoundCode, "message": notFoundMessage})
		return
	}
	internalError(c, internalCode, internalMessage)
}

func respondAssetMutationError(
	c *gin.Context,
	err error,
	internalCode string,
	internalMessage string,
) {
	switch {
	case errors.Is(err, database.ErrAssetDuplicate):
		c.JSON(http.StatusConflict, gin.H{
			"code":    "asset_duplicate",
			"message": "同一项目下已存在相同类型和值的资产",
		})
	case errors.Is(err, database.ErrAssetInUse):
		c.JSON(http.StatusConflict, gin.H{
			"code":    "asset_in_use",
			"message": "资产已被漏洞、攻击路径或事实引用，不能跨项目移动",
		})
	case errors.Is(err, database.ErrInvalidAsset):
		message := strings.TrimPrefix(err.Error(), database.ErrInvalidAsset.Error()+": ")
		badRequest(c, "invalid_asset", message)
	default:
		internalError(c, internalCode, internalMessage)
	}
}

func webshellResponse(item database.WebShellConnection) gin.H {
	return gin.H{
		"id":          item.ID,
		"projectId":   item.ProjectID,
		"ownerUserId": item.OwnerUserID,
		"name":        item.Name,
		"url":         item.URL,
		"method":      item.Method,
		"encoding":    item.Encoding,
		"status":      item.Status,
		"hasPassword": item.Password != "",
		"createdAt":   item.CreatedAt,
		"updatedAt":   item.UpdatedAt,
	}
}
