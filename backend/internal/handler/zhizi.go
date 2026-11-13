package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"sophon/internal/database"
	"sophon/internal/middleware"
	zhizipkg "sophon/internal/zhizi"

	"github.com/gin-gonic/gin"
)

const (
	maxZhiziPrivateKey = 64 * 1024
	maxZhiziPassword   = 8 * 1024
)

type ZhiziHandler struct {
	db       *database.DB
	executor *zhizipkg.Executor
	initMu   sync.Mutex
	initJobs map[string]bool
}

type zhiziNodeRequest struct {
	Name             string            `json:"name"`
	Host             string            `json:"host"`
	Hosts            []string          `json:"hosts"`
	Port             int               `json:"port"`
	Username         string            `json:"username"`
	AuthType         string            `json:"authType"`
	Password         string            `json:"password"`
	PrivateKey       string            `json:"privateKey"`
	HostFingerprint  string            `json:"hostFingerprint"`
	HostFingerprints map[string]string `json:"hostFingerprints"`
	WorkRoot         string            `json:"workRoot"`
	MaxSlots         int               `json:"maxSlots"`
	Enabled          *bool             `json:"enabled"`
}

func NewZhiziHandler(db *database.DB, executor *zhizipkg.Executor) *ZhiziHandler {
	return &ZhiziHandler{
		db:       db,
		executor: executor,
		initJobs: map[string]bool{},
	}
}

func (h *ZhiziHandler) List(c *gin.Context) {
	items, err := h.db.ListZhiziNodes(c.Request.Context())
	if err != nil {
		internalError(c, "list_zhizi_nodes_failed", "读取智子分身失败")
		return
	}
	availability, err := h.db.ZhiziAvailability(c.Request.Context())
	if err != nil {
		internalError(c, "zhizi_availability_failed", "统计智子分身容量失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "availability": availability})
}

func (h *ZhiziHandler) Create(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request zhiziNodeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_zhizi_node", "智子分身请求格式错误")
		return
	}
	hosts := normalizeZhiziHosts(request.Host, request.Hosts)
	if len(hosts) == 0 {
		badRequest(c, "invalid_zhizi_node", "至少提供一个主机地址")
		return
	}
	if len(hosts) > 100 {
		badRequest(c, "invalid_zhizi_node", "单次最多添加 100 个主机")
		return
	}
	authType := strings.ToLower(strings.TrimSpace(request.AuthType))
	if len(hosts) > 1 && authType != "password" {
		badRequest(c, "invalid_zhizi_batch", "批量添加多个主机仅支持密码认证")
		return
	}
	request.Host = hosts[0]
	node, secret, ok := validateZhiziNodeRequest(c, request, true)
	if !ok {
		return
	}
	nodes := make([]database.ZhiziNode, 0, len(hosts))
	for _, host := range hosts {
		item := node
		item.ID = randomID()
		item.CreatedByUserID = user.ID
		item.Host = host
		item.Name = zhiziBatchNodeName(node.Name, host, len(hosts))
		item.HostKeyFingerprint = zhiziFingerprintForHost(request, host)
		if !validZhiziFingerprint(item.HostKeyFingerprint) {
			badRequest(c, "invalid_zhizi_fingerprint", "每个主机都必须提供有效的 SHA256 主机指纹")
			return
		}
		nodes = append(nodes, item)
	}
	created, err := h.db.CreateZhiziNodes(c.Request.Context(), nodes, secret)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			c.JSON(http.StatusConflict, gin.H{"code": "zhizi_node_exists", "message": "智子分身名称已存在"})
			return
		}
		internalError(c, "create_zhizi_node_failed", "创建智子分身失败")
		return
	}
	if len(created) == 1 {
		c.JSON(http.StatusCreated, created[0])
		return
	}
	c.JSON(http.StatusCreated, gin.H{"items": created})
}

func (h *ZhiziHandler) Update(c *gin.Context) {
	existing, existingSecret, err := h.db.GetZhiziNodeSecret(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": "zhizi_node_not_found", "message": "智子分身不存在"})
		return
	}
	if existing.ActiveSlots > 0 {
		c.JSON(http.StatusConflict, gin.H{
			"code":    "zhizi_node_in_use",
			"message": "节点仍有任务占用，请停止任务后再编辑",
		})
		return
	}
	if existing.InitStatus == "queued" || existing.InitStatus == "running" {
		c.JSON(http.StatusConflict, gin.H{
			"code":    "zhizi_node_initializing",
			"message": "节点正在初始化，请等待完成后再编辑",
		})
		return
	}
	var request zhiziNodeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_zhizi_node", "智子分身请求格式错误")
		return
	}
	node, secret, ok := validateZhiziNodeRequest(c, request, false)
	if !ok {
		return
	}
	if node.AuthType == "key" && strings.TrimSpace(secret.PrivateKey) == "" &&
		(strings.TrimSpace(existingSecret.PrivateKey) == "" || existing.AuthType != "key") {
		badRequest(c, "invalid_zhizi_credential", "切换私钥认证需要提供 SSH 私钥")
		return
	}
	if node.AuthType == "password" && strings.TrimSpace(secret.Password) == "" &&
		(strings.TrimSpace(existingSecret.Password) == "" || existing.AuthType != "password") {
		badRequest(c, "invalid_zhizi_credential", "切换密码认证需要提供 SSH 密码")
		return
	}
	node.ID = c.Param("id")
	node.HostKeyFingerprint = zhiziFingerprintForHost(request, node.Host)
	if !validZhiziFingerprint(node.HostKeyFingerprint) {
		if strings.EqualFold(existing.Host, node.Host) && existing.Port == node.Port &&
			validZhiziFingerprint(existing.HostKeyFingerprint) {
			node.HostKeyFingerprint = existing.HostKeyFingerprint
		} else {
			badRequest(c, "invalid_zhizi_fingerprint", "主机或端口变化后必须重新确认 SHA256 主机指纹")
			return
		}
	}
	updated, err := h.db.UpdateZhiziNode(c.Request.Context(), node, secret)
	if err != nil {
		if respondZhiziNodeStateConflict(c, err) {
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			c.JSON(http.StatusConflict, gin.H{"code": "zhizi_node_exists", "message": "智子分身名称已存在"})
			return
		}
		internalError(c, "update_zhizi_node_failed", "更新智子分身失败")
		return
	}
	c.JSON(http.StatusOK, updated)
}

func (h *ZhiziHandler) Disable(c *gin.Context) {
	if err := h.db.SetZhiziNodeEnabled(c.Request.Context(), c.Param("id"), false); err != nil {
		respondMutationError(c, err, "zhizi_node_not_found", "智子分身不存在",
			"disable_zhizi_node_failed", "停用智子分身失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *ZhiziHandler) Test(c *gin.Context) {
	nodeID := c.Param("id")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	testErr := h.executor.TestNode(ctx, nodeID)
	_ = h.db.RecordZhiziNodeTest(c.Request.Context(), nodeID, testErr)
	if testErr != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"code":    "zhizi_connection_failed",
			"message": "SSH 连接测试失败",
			"error":   testErr.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type zhiziBatchTestItem struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Host    string `json:"host"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func (h *ZhiziHandler) TestBatch(c *gin.Context) {
	var request struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_zhizi_batch_test", "批量测试请求格式错误")
		return
	}
	ids := normalizeIDList(request.IDs)
	if len(ids) == 0 {
		badRequest(c, "invalid_zhizi_batch_test", "请至少选择一个节点")
		return
	}
	if len(ids) > 100 {
		badRequest(c, "invalid_zhizi_batch_test", "单次最多测试 100 个节点")
		return
	}
	nodes, err := h.db.ListZhiziNodes(c.Request.Context())
	if err != nil {
		internalError(c, "list_zhizi_nodes_failed", "读取智子分身失败")
		return
	}
	byID := make(map[string]database.ZhiziNode, len(nodes))
	for _, node := range nodes {
		byID[node.ID] = node
	}
	selected := make([]database.ZhiziNode, 0, len(ids))
	for _, id := range ids {
		node, exists := byID[id]
		if !exists || !node.Enabled || !validZhiziFingerprint(node.HostKeyFingerprint) {
			badRequest(c, "invalid_zhizi_batch_test", "所选节点不存在、已停用或未确认主机指纹")
			return
		}
		selected = append(selected, node)
	}

	results := make([]zhiziBatchTestItem, len(selected))
	sem := make(chan struct{}, 4)
	var wait sync.WaitGroup
	for index, node := range selected {
		index, node := index, node
		wait.Add(1)
		go func() {
			defer wait.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			item := zhiziBatchTestItem{
				ID:   node.ID,
				Name: node.Name,
				Host: node.Host,
			}
			testCtx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
			testErr := h.executor.TestNode(testCtx, node.ID)
			cancel()
			recordCtx, recordCancel := context.WithTimeout(
				context.WithoutCancel(c.Request.Context()),
				5*time.Second,
			)
			_ = h.db.RecordZhiziNodeTest(recordCtx, node.ID, testErr)
			recordCancel()
			if testErr != nil {
				item.Error = testErr.Error()
			} else {
				item.Success = true
			}
			results[index] = item
		}()
	}
	wait.Wait()
	succeeded := 0
	for _, item := range results {
		if item.Success {
			succeeded++
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"total":     len(results),
		"succeeded": succeeded,
		"failed":    len(results) - succeeded,
		"items":     results,
	})
}

func (h *ZhiziHandler) InitializeBatch(c *gin.Context) {
	var request struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_zhizi_batch_init", "批量初始化请求格式错误")
		return
	}
	ids := normalizeIDList(request.IDs)
	if len(ids) == 0 || len(ids) > 100 {
		badRequest(c, "invalid_zhizi_batch_init", "请选择 1 到 100 个节点")
		return
	}
	nodes, err := h.db.ListZhiziNodes(c.Request.Context())
	if err != nil {
		internalError(c, "list_zhizi_nodes_failed", "读取智子分身失败")
		return
	}
	byID := make(map[string]database.ZhiziNode, len(nodes))
	for _, node := range nodes {
		byID[node.ID] = node
	}
	selected := make([]database.ZhiziNode, 0, len(ids))
	for _, id := range ids {
		node, exists := byID[id]
		if !exists || !node.Enabled || !validZhiziFingerprint(node.HostKeyFingerprint) {
			badRequest(c, "invalid_zhizi_batch_init", "所选节点不存在、已停用或未确认主机指纹")
			return
		}
		selected = append(selected, node)
	}
	accepted := 0
	skipped := 0
	for _, node := range selected {
		h.initMu.Lock()
		if h.initJobs[node.ID] {
			h.initMu.Unlock()
			skipped++
			continue
		}
		h.initJobs[node.ID] = true
		h.initMu.Unlock()
		if err := h.db.SetZhiziNodeInitQueued(c.Request.Context(), node.ID); err != nil {
			h.initMu.Lock()
			delete(h.initJobs, node.ID)
			h.initMu.Unlock()
			internalError(c, "queue_zhizi_init_failed", "加入初始化队列失败")
			return
		}
		accepted++
		go h.runNodeInitialization(node.ID)
	}
	c.JSON(http.StatusAccepted, gin.H{
		"accepted": accepted,
		"skipped":  skipped,
	})
}

func (h *ZhiziHandler) runNodeInitialization(nodeID string) {
	defer func() {
		h.initMu.Lock()
		delete(h.initJobs, nodeID)
		h.initMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	runningCtx, runningCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	_ = h.db.SetZhiziNodeInitRunning(runningCtx, nodeID)
	runningCancel()
	result, err := h.executor.RunNodeScript(ctx, nodeID, zhizipkg.InitializationScript)
	message := strings.TrimSpace(strings.Join([]string{result.Stdout, result.Stderr}, "\n"))
	if err != nil {
		if message != "" {
			message += "\n"
		}
		message += err.Error()
	}
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 10*time.Second)
	_ = h.db.FinishZhiziNodeInit(finishCtx, nodeID, err == nil, message)
	finishCancel()
}

func (h *ZhiziHandler) DeleteBatch(c *gin.Context) {
	var request struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_zhizi_batch_delete", "批量删除请求格式错误")
		return
	}
	ids := normalizeIDList(request.IDs)
	if len(ids) == 0 || len(ids) > 100 {
		badRequest(c, "invalid_zhizi_batch_delete", "请选择 1 到 100 个节点")
		return
	}
	nodes, err := h.db.ListZhiziNodes(c.Request.Context())
	if err != nil {
		internalError(c, "list_zhizi_nodes_failed", "读取智子分身失败")
		return
	}
	byID := make(map[string]database.ZhiziNode, len(nodes))
	for _, node := range nodes {
		byID[node.ID] = node
	}
	for _, id := range ids {
		node, exists := byID[id]
		if !exists {
			continue
		}
		if node.ActiveSlots > 0 {
			c.JSON(http.StatusConflict, gin.H{
				"code":    "zhizi_node_in_use",
				"message": "所选节点仍有任务占用，请停止任务后再删除",
			})
			return
		}
		if node.InitStatus == "queued" || node.InitStatus == "running" {
			c.JSON(http.StatusConflict, gin.H{
				"code":    "zhizi_node_initializing",
				"message": "所选节点正在初始化，请等待完成后再删除",
			})
			return
		}
	}
	deleted, err := h.db.DeleteZhiziNodes(c.Request.Context(), ids)
	if err != nil {
		if respondZhiziNodeStateConflict(c, err) {
			return
		}
		internalError(c, "delete_zhizi_nodes_failed", "批量删除智子分身失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted})
}

func (h *ZhiziHandler) Availability(c *gin.Context) {
	result, err := h.db.ZhiziAvailability(c.Request.Context())
	if err != nil {
		internalError(c, "zhizi_availability_failed", "统计智子分身容量失败")
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *ZhiziHandler) Probe(c *gin.Context) {
	var request struct {
		Host  string   `json:"host"`
		Hosts []string `json:"hosts"`
		Port  int      `json:"port"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_zhizi_probe", "主机指纹探测请求格式错误")
		return
	}
	hosts := normalizeZhiziHosts(request.Host, request.Hosts)
	if len(hosts) == 0 || len(hosts) > 100 {
		badRequest(c, "invalid_zhizi_probe", "主机数量必须在 1 到 100 之间")
		return
	}
	for _, host := range hosts {
		if !validZhiziHost(host) {
			badRequest(c, "invalid_zhizi_probe", "主机地址不合法: "+host)
			return
		}
	}
	if request.Port <= 0 {
		request.Port = 22
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	items, err := h.executor.ProbeHosts(ctx, hosts, request.Port)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"code":    "zhizi_fingerprint_probe_failed",
			"message": "SSH 主机指纹探测失败",
			"error":   err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *ZhiziHandler) GetConversationState(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	state, err := h.db.GetZhiziConversationState(c.Request.Context(), c.Param("id"), user.ID)
	if errors.Is(err, database.ErrZhiziConversationUnauthorized) {
		c.JSON(http.StatusNotFound, gin.H{"code": "conversation_not_found", "message": "对话不存在"})
		return
	}
	if err != nil {
		internalError(c, "get_zhizi_conversation_failed", "读取智子分身状态失败")
		return
	}
	c.JSON(http.StatusOK, state)
}

func (h *ZhiziHandler) SetConversationState(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.Enabled == nil {
		badRequest(c, "invalid_zhizi_setting", "智子分身开关参数错误")
		return
	}
	if *request.Enabled {
		availability, err := h.db.ZhiziAvailability(c.Request.Context())
		if err != nil {
			internalError(c, "zhizi_availability_failed", "统计智子分身容量失败")
			return
		}
		if availability.Available <= 0 {
			c.JSON(http.StatusConflict, gin.H{
				"code":    "zhizi_no_capacity",
				"message": "当前没有可用的智子分身容量",
			})
			return
		}
	}
	err := h.db.SetZhiziConversationEnabled(
		c.Request.Context(),
		c.Param("id"),
		user.ID,
		*request.Enabled,
	)
	if errors.Is(err, database.ErrZhiziConversationUnauthorized) {
		c.JSON(http.StatusNotFound, gin.H{"code": "conversation_not_found", "message": "对话不存在"})
		return
	}
	if err != nil {
		internalError(c, "set_zhizi_conversation_failed", "更新智子分身开关失败")
		return
	}
	state, err := h.db.GetZhiziConversationState(c.Request.Context(), c.Param("id"), user.ID)
	if err != nil {
		internalError(c, "get_zhizi_conversation_failed", "读取智子分身状态失败")
		return
	}
	c.JSON(http.StatusOK, state)
}

func validateZhiziNodeRequest(
	c *gin.Context,
	request zhiziNodeRequest,
	requireSecret bool,
) (database.ZhiziNode, database.ZhiziNodeSecret, bool) {
	name := truncateRunes(strings.TrimSpace(request.Name), 80)
	host := strings.TrimSpace(request.Host)
	username := strings.TrimSpace(request.Username)
	authType := strings.ToLower(strings.TrimSpace(request.AuthType))
	workRoot := strings.TrimSpace(request.WorkRoot)
	if name == "" {
		badRequest(c, "invalid_zhizi_node", "名称不能为空")
		return database.ZhiziNode{}, database.ZhiziNodeSecret{}, false
	}
	if !validZhiziHost(host) {
		badRequest(c, "invalid_zhizi_node", "主机地址不合法")
		return database.ZhiziNode{}, database.ZhiziNodeSecret{}, false
	}
	if request.Port <= 0 {
		request.Port = 22
	}
	if request.Port > 65535 {
		badRequest(c, "invalid_zhizi_node", "SSH 端口不合法")
		return database.ZhiziNode{}, database.ZhiziNodeSecret{}, false
	}
	if username == "" || len(username) > 128 {
		badRequest(c, "invalid_zhizi_node", "SSH 用户不合法")
		return database.ZhiziNode{}, database.ZhiziNodeSecret{}, false
	}
	if authType != "key" && authType != "password" {
		badRequest(c, "invalid_zhizi_node", "认证方式必须是 key 或 password")
		return database.ZhiziNode{}, database.ZhiziNodeSecret{}, false
	}
	if workRoot == "" {
		workRoot = "/home/" + username + "/sophon"
	}
	if !strings.HasPrefix(workRoot, "/") || strings.Contains(workRoot, "..") || len(workRoot) > 512 {
		badRequest(c, "invalid_zhizi_work_root", "远端工作目录必须是不含 .. 的绝对路径")
		return database.ZhiziNode{}, database.ZhiziNodeSecret{}, false
	}
	if request.MaxSlots <= 0 {
		request.MaxSlots = 1
	}
	if request.MaxSlots > 64 {
		badRequest(c, "invalid_zhizi_slots", "单节点最多配置 64 个 slot")
		return database.ZhiziNode{}, database.ZhiziNodeSecret{}, false
	}
	if len(request.Password) > maxZhiziPassword || len(request.PrivateKey) > maxZhiziPrivateKey {
		badRequest(c, "invalid_zhizi_credential", "SSH 凭据超过长度限制")
		return database.ZhiziNode{}, database.ZhiziNodeSecret{}, false
	}
	if requireSecret {
		if authType == "key" && strings.TrimSpace(request.PrivateKey) == "" {
			badRequest(c, "invalid_zhizi_credential", "私钥认证需要提供 SSH 私钥")
			return database.ZhiziNode{}, database.ZhiziNodeSecret{}, false
		}
		if authType == "password" && strings.TrimSpace(request.Password) == "" {
			badRequest(c, "invalid_zhizi_credential", "密码认证需要提供 SSH 密码")
			return database.ZhiziNode{}, database.ZhiziNodeSecret{}, false
		}
	}
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	return database.ZhiziNode{
			Name:     name,
			Host:     host,
			Port:     request.Port,
			Username: username,
			AuthType: authType,
			WorkRoot: workRoot,
			MaxSlots: request.MaxSlots,
			Enabled:  enabled,
		}, database.ZhiziNodeSecret{
			Password:   request.Password,
			PrivateKey: request.PrivateKey,
		}, true
}

func validZhiziHost(host string) bool {
	host = strings.Trim(host, "[]")
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/ \t\r\n") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 ||
			strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func normalizeZhiziHosts(primary string, values []string) []string {
	candidates := make([]string, 0, len(values)+1)
	if strings.TrimSpace(primary) != "" {
		candidates = append(candidates, strings.Split(primary, "\n")...)
	}
	for _, value := range values {
		candidates = append(candidates, strings.FieldsFunc(value, func(char rune) bool {
			return char == '\n' || char == '\r' || char == ',' || char == ';'
		})...)
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		key := strings.ToLower(candidate)
		if candidate == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, candidate)
	}
	return result
}

func zhiziBatchNodeName(prefix string, host string, total int) string {
	prefix = strings.TrimSpace(prefix)
	if total <= 1 {
		return prefix
	}
	suffix := "-" + strings.ReplaceAll(strings.TrimSpace(host), ":", "-")
	maxPrefixRunes := max(1, 80-len([]rune(suffix)))
	return truncateRunes(truncateRunes(prefix, maxPrefixRunes)+suffix, 80)
}

func zhiziFingerprintForHost(request zhiziNodeRequest, host string) string {
	target := strings.ToLower(strings.TrimSpace(host))
	for candidate, fingerprint := range request.HostFingerprints {
		if strings.ToLower(strings.TrimSpace(candidate)) == target {
			return strings.TrimSpace(fingerprint)
		}
	}
	if len(request.HostFingerprints) == 0 {
		return strings.TrimSpace(request.HostFingerprint)
	}
	return ""
}

func validZhiziFingerprint(value string) bool {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "SHA256:") {
		return false
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	return err == nil && len(raw) == 32
}

func respondZhiziNodeStateConflict(c *gin.Context, err error) bool {
	switch {
	case errors.Is(err, database.ErrZhiziNodeInUse):
		c.JSON(http.StatusConflict, gin.H{
			"code":    "zhizi_node_in_use",
			"message": "所选节点仍有任务占用，请停止任务后再操作",
		})
		return true
	case errors.Is(err, database.ErrZhiziNodeInitializing):
		c.JSON(http.StatusConflict, gin.H{
			"code":    "zhizi_node_initializing",
			"message": "所选节点正在初始化，请等待完成后再操作",
		})
		return true
	default:
		return false
	}
}
