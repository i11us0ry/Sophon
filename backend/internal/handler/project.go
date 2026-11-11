package handler

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/middleware"
	storagepkg "sophon/internal/storage"
	"sophon/internal/task"

	"github.com/gin-gonic/gin"
)

var attackStepStatuses = map[string]bool{
	"todo":   true,
	"doing":  true,
	"done":   true,
	"failed": true,
}

var attackStepSeverities = map[string]bool{
	"info":     true,
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

type ProjectHandler struct {
	db      *database.DB
	manager *task.Manager
	storage *storagepkg.Service
}

func NewProjectHandler(
	db *database.DB,
	manager *task.Manager,
	storageService *storagepkg.Service,
) *ProjectHandler {
	return &ProjectHandler{db: db, manager: manager, storage: storageService}
}

func (h *ProjectHandler) Summary(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	counts, err := h.db.ProjectSummary(c.Request.Context(), project.ID, project.OwnerUserID)
	if err != nil {
		internalError(c, "project_summary_failed", "读取项目统计失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"counts": counts})
}

func (h *ProjectHandler) ListAssets(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	user := middleware.UserFromContext(c)
	limit := clampQueryInt(c.Query("limit"), 200, 1, 500)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	items, total, err := h.db.ListProjectAssetsPage(
		c.Request.Context(),
		project.ID,
		user.ID,
		limit,
		offset,
	)
	if err != nil {
		internalError(c, "list_project_assets_failed", "读取项目资产失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"total":      total,
		"hasMore":    offset+len(items) < total,
		"nextOffset": offset + len(items),
	})
}

func (h *ProjectHandler) ListConversations(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	user := middleware.UserFromContext(c)
	limit := clampQueryInt(c.Query("limit"), 200, 1, 500)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	items, total, err := h.db.ListProjectConversationsPage(
		c.Request.Context(),
		project.ID,
		user.ID,
		limit,
		offset,
	)
	if err != nil {
		internalError(c, "list_project_conversations_failed", "读取项目对话失败")
		return
	}
	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		result = append(result, conversationResponse(item))
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      result,
		"total":      total,
		"hasMore":    offset+len(items) < total,
		"nextOffset": offset + len(items),
	})
}

func (h *ProjectHandler) ListVulnerabilities(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	user := middleware.UserFromContext(c)
	limit := clampQueryInt(c.Query("limit"), 200, 1, 500)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	items, total, err := h.db.ListVulnerabilitiesFiltered(
		c.Request.Context(),
		database.VulnerabilityFilter{
			OwnerUserID: user.ID,
			ProjectID:   project.ID,
			Limit:       limit,
			Offset:      offset,
		},
	)
	if err != nil {
		internalError(c, "list_project_vulnerabilities_failed", "读取项目漏洞失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"total":      total,
		"hasMore":    offset+len(items) < total,
		"nextOffset": offset + len(items),
	})
}

func (h *ProjectHandler) ListAttackSteps(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	items, err := h.db.ListProjectAttackSteps(c.Request.Context(), project.ID)
	if err != nil {
		internalError(c, "list_attack_steps_failed", "读取攻击路径失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *ProjectHandler) CreateAttackStep(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	var request attackStepRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_attack_step", "攻击路径请求格式错误")
		return
	}
	name := truncateRunes(request.Name, 120)
	if strings.TrimSpace(name) == "" {
		badRequest(c, "invalid_attack_step", "步骤名称不能为空")
		return
	}
	order, err := h.db.NextAttackStepOrder(c.Request.Context(), project.ID)
	if err != nil {
		internalError(c, "create_attack_step_failed", "创建攻击路径失败")
		return
	}
	now := time.Now().UTC()
	step := database.AttackStep{
		ID:          randomID(),
		ProjectID:   project.ID,
		StepOrder:   order,
		Name:        name,
		Description: strings.TrimSpace(request.Description),
		Status:      normalizeAttackStepStatus(request.Status),
		Severity:    normalizeAttackStepSeverity(request.Severity),
		Technique:   truncateRunes(request.Technique, 60),
		Evidence:    strings.TrimSpace(request.Evidence),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.db.CreateProjectAttackStep(c.Request.Context(), step); err != nil {
		internalError(c, "create_attack_step_failed", "创建攻击路径失败")
		return
	}
	c.JSON(http.StatusCreated, step)
}

func (h *ProjectHandler) UpdateAttackStep(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	step, err := h.db.GetProjectAttackStep(c.Request.Context(), c.Param("stepId"), project.ID)
	if err != nil {
		respondMutationError(c, err, "attack_step_not_found", "攻击步骤不存在", "update_attack_step_failed", "更新攻击路径失败")
		return
	}
	var request attackStepRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_attack_step", "攻击路径请求格式错误")
		return
	}
	if name := truncateRunes(request.Name, 120); strings.TrimSpace(name) != "" {
		step.Name = name
	}
	if request.StepOrder != nil {
		step.StepOrder = *request.StepOrder
	}
	if request.Status != "" {
		step.Status = normalizeAttackStepStatus(request.Status)
	}
	if request.Severity != "" {
		step.Severity = normalizeAttackStepSeverity(request.Severity)
	}
	step.Description = strings.TrimSpace(request.Description)
	step.Technique = truncateRunes(request.Technique, 60)
	step.Evidence = strings.TrimSpace(request.Evidence)
	step.UpdatedAt = time.Now().UTC()
	if err := h.db.UpdateProjectAttackStep(c.Request.Context(), *step); err != nil {
		respondMutationError(c, err, "attack_step_not_found", "攻击步骤不存在", "update_attack_step_failed", "更新攻击路径失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *ProjectHandler) DeleteAttackStep(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	if err := h.db.DeleteProjectAttackStep(
		c.Request.Context(),
		c.Param("stepId"),
		project.ID,
	); err != nil {
		respondMutationError(c, err, "attack_step_not_found", "攻击步骤不存在", "delete_attack_step_failed", "删除攻击路径失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *ProjectHandler) BatchDeleteProjects(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_batch_request", "批量请求格式错误")
		return
	}
	ids := normalizeIDList(request.IDs)
	if len(ids) == 0 {
		badRequest(c, "invalid_batch_request", "请至少选择一个项目")
		return
	}
	deleted := 0
	for _, id := range ids {
		conversations, _ := h.db.ListProjectConversations(c.Request.Context(), id, user.ID)
		for _, conversation := range conversations {
			if h.manager != nil {
				h.manager.CancelConversation(conversation.ID, user.ID)
			}
		}
		if err := h.db.DeleteProject(c.Request.Context(), id, user.ID); err != nil {
			if database.NoRows(err) {
				continue
			}
			internalError(c, "batch_delete_projects_failed", "批量删除项目失败")
			return
		}
		for _, conversation := range conversations {
			if h.manager != nil {
				h.manager.CancelConversation(conversation.ID, user.ID)
			}
		}
		cleanupConversationStorage(h.storage, conversations)
		deleted++
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted})
}

func (h *ProjectHandler) ReorderAttackSteps(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	var request struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_attack_step_order", "重排请求格式错误")
		return
	}
	ids := make([]string, 0, len(request.IDs))
	for _, id := range request.IDs {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			ids = append(ids, trimmed)
		}
	}
	if len(ids) == 0 {
		badRequest(c, "invalid_attack_step_order", "缺少步骤 ID")
		return
	}
	if err := h.db.ReorderProjectAttackSteps(c.Request.Context(), project.ID, ids); err != nil {
		respondMutationError(c, err, "attack_step_not_found", "攻击步骤不存在", "reorder_attack_steps_failed", "调整攻击路径顺序失败")
		return
	}
	c.Status(http.StatusNoContent)
}

type attackStepRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Severity    string `json:"severity"`
	Technique   string `json:"technique"`
	Evidence    string `json:"evidence"`
	StepOrder   *int   `json:"stepOrder"`
}

var graphNodeKinds = map[string]bool{
	"begin":   true,
	"goal":    true,
	"intent":  true,
	"fact":    true,
	"finding": true,
	"hint":    true,
}

var graphNodeStatuses = map[string]map[string]bool{
	"begin":   {"open": true},
	"goal":    {"open": true, "met": true, "abandoned": true},
	"intent":  {"open": true, "running": true, "done": true, "blocked": true, "exhausted": true, "capacity_blocked": true},
	"fact":    {"confirmed": true, "dismissed": true},
	"finding": {"confirmed": true, "dismissed": true},
	"hint":    {"active": true, "consumed": true},
}

var graphDefaultStatus = map[string]string{
	"begin":   "open",
	"goal":    "open",
	"intent":  "open",
	"fact":    "confirmed",
	"finding": "confirmed",
	"hint":    "active",
}

var graphEdgeRelations = map[string]bool{
	"spawns":       true,
	"derived_from": true,
	"yields":       true,
	"proves":       true,
	"blocks":       true,
	"contradicts":  true,
}

type graphNodeRequest struct {
	Kind       string `json:"kind"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	Status     string `json:"status"`
	Confidence int    `json:"confidence"`
	Severity   string `json:"severity"`
	AssetID    string `json:"assetId"`
	ParentID   string `json:"parentId"`
	Relation   string `json:"relation"`
}

func normalizeGraphNode(request graphNodeRequest) (database.GraphNode, error) {
	kind := strings.TrimSpace(request.Kind)
	if !graphNodeKinds[kind] {
		return database.GraphNode{}, fmt.Errorf("节点类型不合法")
	}
	title := truncateRunes(strings.TrimSpace(request.Title), 200)
	if title == "" {
		return database.GraphNode{}, fmt.Errorf("节点标题不能为空")
	}
	status := strings.TrimSpace(request.Status)
	if status == "" {
		status = graphDefaultStatus[kind]
	}
	if !graphNodeStatuses[kind][status] {
		return database.GraphNode{}, fmt.Errorf("节点状态不合法")
	}
	confidence := request.Confidence
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}
	severity := ""
	if kind == "finding" {
		severity = strings.TrimSpace(request.Severity)
		if severity == "" {
			severity = "medium"
		}
		if !attackStepSeverities[severity] {
			return database.GraphNode{}, fmt.Errorf("漏洞严重度不合法")
		}
	}
	return database.GraphNode{
		Kind:       kind,
		Title:      title,
		Detail:     truncateRunes(strings.TrimSpace(request.Detail), 4000),
		Status:     status,
		Confidence: confidence,
		Severity:   severity,
		AssetID:    strings.TrimSpace(request.AssetID),
	}, nil
}

func (h *ProjectHandler) ListGraph(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	assetID := strings.TrimSpace(c.Query("assetId"))
	if assetID != "" && !h.graphAssetAllowed(c, project.ID, assetID) {
		return
	}
	nodes, err := h.db.ListProjectGraphNodesByAsset(ctx, project.ID, assetID)
	if err != nil {
		internalError(c, "list_project_graph_failed", "读取攻击路径图失败")
		return
	}
	if strings.EqualFold(strings.TrimSpace(c.Query("view")), "chain") {
		edges, err := h.db.ListProjectGraphEdges(ctx, project.ID)
		if err != nil {
			internalError(c, "list_project_graph_failed", "读取攻击路径图失败")
			return
		}
		assets, err := h.db.ListProjectAssets(ctx, project.ID, project.OwnerUserID)
		if err != nil {
			internalError(c, "list_project_graph_failed", "读取项目资产失败")
			return
		}
		chains, err := h.db.ListProjectCampaignChains(ctx, project.ID, 100)
		if err != nil {
			internalError(c, "list_project_graph_failed", "读取跨资产攻击链失败")
			return
		}
		view := buildAttackChainView(nodes, edges, assets, chains, assetID)
		c.JSON(http.StatusOK, gin.H{
			"nodes": view.Nodes,
			"edges": view.Edges,
			"view":  "chain",
		})
		return
	}
	nodeIDs := make([]string, 0, len(nodes))
	for _, node := range nodes {
		nodeIDs = append(nodeIDs, node.ID)
	}
	edges, err := h.db.ListProjectGraphEdgesForNodes(ctx, project.ID, nodeIDs)
	if err != nil {
		internalError(c, "list_project_graph_failed", "读取攻击路径图失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": edges})
}

// SyncGraph 补全攻击路径：生成起点/目标骨架，并把既有事实与漏洞回填成节点与连线（幂等）。
func (h *ProjectHandler) SyncGraph(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	result, err := h.db.SyncProjectGraph(c.Request.Context(), *project)
	if err != nil {
		internalError(c, "sync_project_graph_failed", "补全攻击路径失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"createdNodes": result.CreatedNodes,
		"updatedNodes": result.UpdatedNodes,
		"createdEdges": result.CreatedEdges,
	})
}

func (h *ProjectHandler) CreateGraphNode(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	var request graphNodeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_graph_node", "节点请求格式错误")
		return
	}
	node, err := normalizeGraphNode(request)
	if err != nil {
		badRequest(c, "invalid_graph_node", err.Error())
		return
	}
	if !h.graphAssetAllowed(c, project.ID, node.AssetID) {
		return
	}
	ctx := c.Request.Context()
	parentID := strings.TrimSpace(request.ParentID)
	relation := strings.TrimSpace(request.Relation)
	if parentID != "" {
		parentNode, err := h.db.GetProjectGraphNode(ctx, parentID, project.ID)
		if err != nil {
			badRequest(c, "invalid_graph_parent", "前置节点不存在")
			return
		}
		if parentNode.AssetID != "" &&
			node.AssetID != "" &&
			parentNode.AssetID != node.AssetID {
			badRequest(c, "invalid_graph_parent", "前置节点与当前节点不属于同一资产")
			return
		}
		if relation == "" {
			relation = "spawns"
		}
		if !graphEdgeRelations[relation] {
			badRequest(c, "invalid_graph_edge", "关系类型不合法")
			return
		}
	}

	now := time.Now().UTC()
	node.ID = randomID()
	node.ProjectID = project.ID
	node.Source = "manual"
	node.CreatedAt = now
	node.UpdatedAt = now
	edges := make([]database.GraphEdge, 0, 1)
	if parentID != "" {
		edges = append(edges, database.GraphEdge{
			ID:        randomID(),
			ProjectID: project.ID,
			SrcID:     parentID,
			DstID:     node.ID,
			Rel:       relation,
			CreatedAt: now,
		})
	}
	if err := h.db.CreateProjectGraphBatch(ctx, []database.GraphNode{node}, edges); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			badRequest(c, "graph_node_exists", "同类型同名节点已存在")
			return
		}
		internalError(c, "create_graph_node_failed", "创建节点失败")
		return
	}
	c.JSON(http.StatusCreated, node)
}

func (h *ProjectHandler) UpdateGraphNode(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	existing, err := h.db.GetProjectGraphNode(ctx, c.Param("nodeId"), project.ID)
	if err != nil {
		respondMutationError(c, err, "graph_node_not_found", "节点不存在", "update_graph_node_failed", "更新节点失败")
		return
	}
	var request graphNodeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_graph_node", "节点请求格式错误")
		return
	}
	updated, err := normalizeGraphNode(request)
	if err != nil {
		badRequest(c, "invalid_graph_node", err.Error())
		return
	}
	if !h.graphAssetAllowed(c, project.ID, updated.AssetID) {
		return
	}
	updated.ID = existing.ID
	updated.ProjectID = existing.ProjectID
	updated.Source = existing.Source
	updated.CreatedAt = existing.CreatedAt
	updated.UpdatedAt = time.Now().UTC()
	if err := h.db.UpdateProjectGraphNode(ctx, updated); err != nil {
		respondMutationError(c, err, "graph_node_not_found", "节点不存在", "update_graph_node_failed", "更新节点失败")
		return
	}
	c.JSON(http.StatusOK, updated)
}

func (h *ProjectHandler) DeleteGraphNode(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	if err := h.db.DeleteProjectGraphNode(c.Request.Context(), c.Param("nodeId"), project.ID); err != nil {
		respondMutationError(c, err, "graph_node_not_found", "节点不存在", "delete_graph_node_failed", "删除节点失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *ProjectHandler) CreateGraphEdge(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	var request struct {
		SrcID string `json:"srcId"`
		DstID string `json:"dstId"`
		Rel   string `json:"rel"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_graph_edge", "关系请求格式错误")
		return
	}
	srcID := strings.TrimSpace(request.SrcID)
	dstID := strings.TrimSpace(request.DstID)
	rel := strings.TrimSpace(request.Rel)
	if srcID == "" || dstID == "" || srcID == dstID {
		badRequest(c, "invalid_graph_edge", "关系两端节点不合法")
		return
	}
	if !graphEdgeRelations[rel] {
		badRequest(c, "invalid_graph_edge", "关系类型不合法")
		return
	}
	ctx := c.Request.Context()
	srcNode, err := h.db.GetProjectGraphNode(ctx, srcID, project.ID)
	if err != nil {
		badRequest(c, "invalid_graph_edge", "源节点不存在")
		return
	}
	dstNode, err := h.db.GetProjectGraphNode(ctx, dstID, project.ID)
	if err != nil {
		badRequest(c, "invalid_graph_edge", "目标节点不存在")
		return
	}
	if srcNode.AssetID != "" &&
		dstNode.AssetID != "" &&
		srcNode.AssetID != dstNode.AssetID {
		badRequest(c, "invalid_graph_edge", "跨资产连线必须通过 Campaign 攻击链生成")
		return
	}
	edge := database.GraphEdge{
		ID:        randomID(),
		ProjectID: project.ID,
		SrcID:     srcID,
		DstID:     dstID,
		Rel:       rel,
		CreatedAt: time.Now().UTC(),
	}
	if err := h.db.CreateProjectGraphEdge(ctx, edge); err != nil {
		internalError(c, "create_graph_edge_failed", "创建关系失败")
		return
	}
	c.JSON(http.StatusCreated, edge)
}

func (h *ProjectHandler) DeleteGraphEdge(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	if err := h.db.DeleteProjectGraphEdge(c.Request.Context(), c.Param("edgeId"), project.ID); err != nil {
		respondMutationError(c, err, "graph_edge_not_found", "关系不存在", "delete_graph_edge_failed", "删除关系失败")
		return
	}
	c.Status(http.StatusNoContent)
}

// UpdateGraphLayout 批量保存画布节点坐标。
func (h *ProjectHandler) UpdateGraphLayout(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	var request struct {
		Items []database.GraphLayoutItem `json:"items"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_graph_layout", "布局请求格式错误")
		return
	}
	if len(request.Items) == 0 || len(request.Items) > 500 {
		badRequest(c, "invalid_graph_layout", "布局数量需在 1-500 之间")
		return
	}
	const coordinateLimit = 100000
	for _, item := range request.Items {
		if strings.TrimSpace(item.ID) == "" {
			badRequest(c, "invalid_graph_layout", "布局缺少节点 ID")
			return
		}
		if item.X < -coordinateLimit || item.X > coordinateLimit ||
			item.Y < -coordinateLimit || item.Y > coordinateLimit {
			badRequest(c, "invalid_graph_layout", "坐标超出范围")
			return
		}
	}
	if err := h.db.UpdateProjectGraphLayout(c.Request.Context(), project.ID, request.Items); err != nil {
		respondMutationError(c, err, "graph_node_not_found", "节点不存在", "update_graph_layout_failed", "保存布局失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"saved": len(request.Items)})
}

// ImportAttackSteps 把旧的线性攻击步骤一次性导入为 intent 节点链。
func (h *ProjectHandler) ImportAttackSteps(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	imported, err := h.db.CountProjectGraphNodesBySource(ctx, project.ID, "step-import")
	if err != nil {
		internalError(c, "import_attack_steps_failed", "读取导入状态失败")
		return
	}
	if imported > 0 {
		badRequest(c, "graph_already_imported", "攻击步骤已经导入过")
		return
	}
	steps, err := h.db.ListProjectAttackSteps(ctx, project.ID)
	if err != nil {
		internalError(c, "import_attack_steps_failed", "读取攻击步骤失败")
		return
	}
	if len(steps) == 0 {
		badRequest(c, "graph_nothing_to_import", "没有可导入的攻击步骤")
		return
	}
	statusMap := map[string]string{
		"todo":   "open",
		"doing":  "running",
		"done":   "done",
		"failed": "blocked",
	}
	now := time.Now().UTC()
	previousID := ""
	nodes := make([]database.GraphNode, 0, len(steps))
	edges := make([]database.GraphEdge, 0, len(steps)-1)
	for _, step := range steps {
		status := statusMap[step.Status]
		if status == "" {
			status = "open"
		}
		detail := strings.Join([]string{
			strings.TrimSpace(step.Description),
			strings.TrimSpace(step.Technique),
			strings.TrimSpace(step.Evidence),
		}, "\n")
		node := database.GraphNode{
			ID:        randomID(),
			ProjectID: project.ID,
			Kind:      "intent",
			Title:     truncateRunes(step.Name, 200),
			Detail:    truncateRunes(strings.TrimSpace(detail), 4000),
			Status:    status,
			Source:    "step-import",
			CreatedAt: now,
			UpdatedAt: now,
		}
		nodes = append(nodes, node)
		if previousID != "" {
			edges = append(edges, database.GraphEdge{
				ID:        randomID(),
				ProjectID: project.ID,
				SrcID:     previousID,
				DstID:     node.ID,
				Rel:       "derived_from",
				CreatedAt: now,
			})
		}
		previousID = node.ID
	}
	if err := h.db.CreateProjectGraphBatch(ctx, nodes, edges); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			badRequest(c, "graph_node_exists", "攻击步骤与现有节点冲突，未执行部分导入")
			return
		}
		internalError(c, "import_attack_steps_failed", "导入攻击步骤失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"imported": len(nodes)})
}

func (h *ProjectHandler) graphAssetAllowed(c *gin.Context, projectID, assetID string) bool {
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		return true
	}
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return false
	}
	items, err := h.db.ListProjectAssets(c.Request.Context(), projectID, user.ID)
	if err != nil {
		internalError(c, "list_project_assets_failed", "读取项目资产失败")
		return false
	}
	for _, item := range items {
		if item.ID == assetID {
			return true
		}
	}
	badRequest(c, "invalid_graph_asset", "资产不属于当前项目")
	return false
}

func (h *ProjectHandler) projectForRequest(c *gin.Context) (*database.Project, bool) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return nil, false
	}
	project, err := h.db.GetProject(c.Request.Context(), c.Param("id"), user.ID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"code":    "project_not_found",
			"message": "项目不存在",
		})
		return nil, false
	}
	return project, true
}

func normalizeAttackStepStatus(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if attackStepStatuses[value] {
		return value
	}
	return "todo"
}

func normalizeAttackStepSeverity(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if attackStepSeverities[value] {
		return value
	}
	return "medium"
}
