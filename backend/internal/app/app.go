package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	agentpkg "sophon/internal/agent"
	agentrolepkg "sophon/internal/agentrole"
	"sophon/internal/auth"
	"sophon/internal/config"
	"sophon/internal/database"
	"sophon/internal/handler"
	knowledgepkg "sophon/internal/knowledge"
	"sophon/internal/mcpclient"
	authmiddleware "sophon/internal/middleware"
	"sophon/internal/observability"
	rbacpkg "sophon/internal/rbac"
	storagepkg "sophon/internal/storage"
	"sophon/internal/task"

	"github.com/cloudwego/eino/components/tool"
	"github.com/gin-gonic/gin"
)

type App struct {
	config  config.Config
	router  *gin.Engine
	db      *database.DB
	mcp     *mcpclient.Manager
	storage *storagepkg.Service
	tasks   *task.Manager
	events  *observability.Emitter
}

func New(cfg config.Config) (*App, error) {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	_ = router.SetTrustedProxies([]string{"127.0.0.1", "::1"})

	db, err := database.Open(filepath.Join(cfg.DataDir, "sophon.db"))
	if err != nil {
		return nil, err
	}
	recoverInterruptedAgentRuns(context.Background(), db)
	if paused, err := db.PauseRunningCampaigns(context.Background()); err != nil {
		log.Printf("campaign recovery: %v", err)
	} else if paused > 0 {
		log.Printf("campaign recovery: 已暂停 %d 个运行中的批量任务", paused)
	}
	if affected, err := db.FailRunningToolExecutions(
		context.Background(),
		"服务重启导致执行中断",
	); err != nil {
		log.Printf("tool execution recovery: %v", err)
	} else if affected > 0 {
		log.Printf("tool execution recovery: 已清理 %d 条遗留 running 记录", affected)
	}
	if affected, err := db.InterruptRunningToolJobs(
		context.Background(),
		"服务重启导致 Job 中断，可调用 job(action=resume) 从检查点继续",
	); err != nil {
		log.Printf("tool job recovery: %v", err)
	} else if affected > 0 {
		log.Printf("tool job recovery: 已标记 %d 个中断 Job", affected)
	}
	if affected, err := db.ResetRunningProjectHypotheses(
		context.Background(),
		"服务重启导致 Worker 中断，已释放为待重试",
	); err != nil {
		log.Printf("project hypothesis recovery: %v", err)
	} else if affected > 0 {
		log.Printf("project hypothesis recovery: 已释放 %d 条遗留 running 假设", affected)
	}

	authService := auth.NewService(
		db,
		time.Duration(cfg.SessionDurationHours)*time.Hour,
		cfg.CookieSecure,
		cfg.BootstrapAdminUsername,
		cfg.BootstrapAdminPassword,
	)
	bootstrapPassword, err := authService.Bootstrap(context.Background())
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("bootstrap administrator: %w", err)
	}
	if bootstrapPassword != "" {
		passwordFile := filepath.Join(cfg.DataDir, "bootstrap_admin_password.txt")
		if err := os.WriteFile(passwordFile, []byte(bootstrapPassword+"\n"), 0o600); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("write bootstrap password file: %w", err)
		}
		log.Printf(
			"bootstrap administrator created: username=%s 初始密码已写入 %s（首次登录后请修改密码并删除该文件）",
			cfg.BootstrapAdminUsername,
			passwordFile,
		)
	}

	rbacService := rbacpkg.NewService(db)
	if err := rbacService.Seed(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("seed rbac roles: %w", err)
	}
	if err := agentrolepkg.SyncFromDir(context.Background(), db, cfg.RolesDir); err != nil {
		log.Printf("agent role sync: %v", err)
	}

	mcpManager := mcpclient.NewManager(
		db,
		time.Duration(cfg.MCPConnectTimeout)*time.Second,
		time.Duration(cfg.MCPCallTimeout)*time.Second,
		cfg.MCPMaxConcurrentPerServer,
		cfg.MCPMaxConcurrentTotal,
	)
	mcpManager.SetExecutionRecorder(db)
	mcpManager.SetProxyEnv(cfg.Proxy.Environment())
	mcpTools, err := startMCPServers(context.Background(), db, mcpManager, cfg)
	if err != nil {
		_ = mcpManager.Close()
		_ = db.Close()
		return nil, err
	}
	embedder, err := knowledgepkg.NewEmbedder(cfg)
	if err != nil {
		_ = mcpManager.Close()
		_ = db.Close()
		return nil, fmt.Errorf("create embedding client: %w", err)
	}
	knowledgeService := knowledgepkg.NewService(db, embedder)
	agentService, err := agentpkg.NewService(db, cfg, mcpTools, knowledgeService)
	if err != nil {
		_ = mcpManager.Close()
		_ = db.Close()
		return nil, err
	}
	// 运行事件流：默认写 <data_dir>/observability/events.jsonl，只记录元数据。
	events, err := observability.New(observability.Config{
		Enabled:    cfg.Observability.Enabled,
		JSONLPath:  cfg.Observability.JSONLPath,
		MaxFileMB:  cfg.Observability.MaxFileMB,
		SampleRate: cfg.Observability.SampleRate,
	})
	if err != nil {
		log.Printf("observability: 事件流未启用: %v", err)
		events = nil
	}
	agentService.SetObservability(events)
	requalifyCtx, requalifyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	requalified, requalifyErr := agentService.RequalifyLegacyUploadCleanHypotheses(requalifyCtx)
	requalifyCancel()
	if requalifyErr != nil {
		log.Printf("upload evidence requalification: %v", requalifyErr)
	} else if requalified > 0 {
		log.Printf("upload evidence requalification: 已将 %d 条证据不足的上传 tested_clean 降级为 suspicious", requalified)
	}
	go func() {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		recovered, err := agentService.RecoverBlockedIntentAlternatives(recoveryCtx)
		if err != nil {
			log.Printf("recover blocked intent alternatives: %v", err)
			return
		}
		if recovered > 0 {
			log.Printf("recover blocked intent alternatives: 已派生 %d 条替代路径", recovered)
		}
	}()
	taskManager := task.NewManager()
	storageService := storagepkg.NewService(db, cfg.Storage, cfg.DataDir)
	chatUploadsDir := filepath.Join(storageService.ArtifactRoot(), "chat_uploads")

	health := handler.NewHealthHandler(cfg.Version)
	authHandler := handler.NewAuthHandler(authService, db)
	chatHandler := handler.NewChatHandler(
		db,
		agentService,
		taskManager,
		chatUploadsDir,
		storageService,
	)
	governanceHandler := handler.NewGovernanceHandler(db)
	businessHandler := handler.NewBusinessHandler(
		db,
		cfg.SkillsDir,
		knowledgeService,
		taskManager,
		storageService,
		agentService,
	)
	settingsHandler := handler.NewSettingsHandler(cfg, knowledgeService, agentService)
	interceptHandler := handler.NewInterceptHandler(db)
	rbacHandler := handler.NewRBACHandler(rbacService)
	dashboardHandler := handler.NewDashboardHandler(db)
	contextHandler := handler.NewContextHandler(db)
	vulnerabilityHandler := handler.NewVulnerabilityHandler(
		db,
		chatHandler,
		storageService.ArtifactRoot(),
	)
	agentRoleHandler := handler.NewAgentRoleHandler(db, cfg.SkillsDir)
	mcpHandler := handler.NewMCPHandler(db, mcpManager, toolsDirectory(cfg), agentService)
	projectHandler := handler.NewProjectHandler(db, taskManager, storageService)
	storageHandler := handler.NewStorageHandler(storageService, cfg.ConfigPath)
	workspaceHandler := handler.NewWorkspaceHandler(storageService)
	observabilityHandler := handler.NewObservabilityHandler(events)
	attachmentHandler := handler.NewAttachmentHandler(
		db,
		chatUploadsDir,
	)

	router.GET("/livez", health.Live)
	router.GET("/readyz", health.Ready)

	api := router.Group("/api")
	api.GET("/health", health.Health)
	api.GET("/version", health.Version)
	api.POST("/auth/login", authHandler.Login)

	protected := api.Group("")
	protected.Use(authmiddleware.RequireAuth(authService))
	protected.Use(authmiddleware.LimitJSONBody(2 << 20))
	protected.Use(authmiddleware.AuditMutations(db))
	// 所有写方法统一强制 CSRF（GET/HEAD/OPTIONS 自动放行），避免逐路由遗漏。
	protected.Use(authmiddleware.RequireCSRF(authService))
	protected.Use(authmiddleware.RequireRoutePermission(rbacService))
	protected.GET("/auth/me", authHandler.Me)
	protected.PUT("/auth/profile", authHandler.UpdateProfile)
	protected.POST("/auth/logout", authHandler.Logout)
	protected.POST("/auth/password", authHandler.ChangePassword)

	protected.GET("/rbac/me", rbacHandler.Me)
	protected.GET("/dashboard/summary", dashboardHandler.Summary)
	protected.GET("/dashboard/tokens", dashboardHandler.Tokens)
	protected.GET("/context/metrics", contextHandler.Metrics)
	protected.GET("/context/compactions", contextHandler.Compactions)
	protected.GET("/observability/metrics", observabilityHandler.Metrics)
	protected.GET("/observability/events", observabilityHandler.Events)
	protected.GET("/agent-roles", agentRoleHandler.List)
	protected.POST("/agent-roles", agentRoleHandler.Create)
	protected.PUT("/agent-roles/:id", agentRoleHandler.Update)
	protected.DELETE("/agent-roles/:id", agentRoleHandler.Delete)
	protected.GET("/rbac/metadata", rbacHandler.Metadata)
	protected.GET("/rbac/roles", rbacHandler.ListRoles)
	protected.POST("/rbac/roles", rbacHandler.CreateRole)
	protected.PUT("/rbac/roles/:name", rbacHandler.UpdateRole)
	protected.DELETE("/rbac/roles/:name", rbacHandler.DeleteRole)
	protected.GET("/rbac/users", rbacHandler.ListUsers)
	protected.POST("/rbac/users", rbacHandler.CreateUser)
	protected.PUT("/rbac/users/:id", rbacHandler.UpdateUser)
	protected.DELETE("/rbac/users/:id", rbacHandler.DeleteUser)

	protected.POST("/conversations", chatHandler.CreateConversation)
	protected.POST("/conversations/batch", chatHandler.CreateConversationBatch)
	protected.POST("/conversation-batches/:id/start", chatHandler.StartCampaign)
	protected.POST("/conversation-batches/:id/pause", chatHandler.PauseCampaign)
	protected.POST("/conversation-batches/:id/resume", chatHandler.ResumeCampaign)
	protected.POST("/conversation-batches/:id/stop", chatHandler.StopCampaign)
	protected.GET("/conversation-batches/:id/status", chatHandler.GetCampaignStatus)
	protected.GET("/conversation-batches/:id/groups", chatHandler.ListCampaignGroups)
	protected.GET("/conversation-batches/:id/tasks", chatHandler.ListCampaignTasks)
	protected.GET("/conversation-batches/:id/endpoints", chatHandler.ListCampaignEndpoints)
	protected.GET("/conversation-batches/:id/frontier", chatHandler.ListCampaignFrontier)
	protected.GET("/conversation-batches/:id/verifications", chatHandler.ListCampaignVerifications)
	protected.GET("/conversation-batches/:id/links", chatHandler.ListCampaignLinks)
	protected.POST("/conversation-batches/:id/priority/recompute", chatHandler.RecomputeCampaignPriorities)
	protected.PUT("/conversation-batches/:id/groups/:groupId/priority", chatHandler.SetCampaignGroupPriority)
	protected.GET("/conversation-batches/:id/chains", chatHandler.ListCampaignChains)
	protected.GET("/conversation-batches/:id/memory", chatHandler.QueryCampaignMemory)
	protected.GET("/conversations", chatHandler.ListConversations)
	protected.POST("/conversations/batch-delete", chatHandler.BatchDeleteConversations)
	protected.GET("/conversations/:id", chatHandler.GetConversation)
	protected.GET("/conversations/:id/agent-settings", chatHandler.GetConversationAgentSettings)
	protected.PUT("/conversations/:id/agent-settings", chatHandler.SetConversationAgentSettings)
	protected.POST("/conversations/:id/stop", chatHandler.StopConversation)
	protected.GET("/conversations/:id/children", chatHandler.ListConversationChildren)
	protected.GET("/conversations/:id/resumable-run", chatHandler.GetResumableRun)
	protected.POST("/conversations/:id/resume", chatHandler.Resume)
	protected.DELETE("/conversations/:id", chatHandler.DeleteConversation)
	protected.GET("/conversations/:id/messages", chatHandler.ListMessages)
	protected.GET("/conversations/:id/process-details", chatHandler.ListProcessDetails)
	protected.GET("/conversations/:id/hitl", chatHandler.GetConversationHITL)
	protected.PUT("/conversations/:id/hitl", chatHandler.UpdateConversationHITL)
	protected.POST("/conversations/:id/regenerate", chatHandler.Regenerate)
	protected.POST("/conversations/:id/attachments", attachmentHandler.Upload)
	protected.GET("/conversations/:id/attachments", attachmentHandler.List)
	protected.GET("/attachments/:id/content", attachmentHandler.Download)
	protected.DELETE("/attachments/:id", attachmentHandler.Delete)
	protected.POST("/chat/stream", chatHandler.Stream)
	protected.GET("/tasks/:taskId", chatHandler.GetTask)
	protected.POST("/tasks/:taskId/cancel", chatHandler.CancelTask)

	protected.GET("/audit/logs", governanceHandler.ListAuditLogs)
	protected.GET("/monitor/executions", governanceHandler.ListToolExecutions)
	protected.GET("/hitl/pending", governanceHandler.ListPendingHITL)
	protected.POST("/hitl/:id/decision", governanceHandler.DecideHITL)
	protected.GET("/workspace/categories", workspaceHandler.Categories)
	protected.GET("/workspace/list", workspaceHandler.List)
	protected.GET("/workspace/content", workspaceHandler.Content)
	protected.PUT("/workspace/content", workspaceHandler.SaveContent)
	protected.GET("/workspace/download", workspaceHandler.Download)
	protected.DELETE("/workspace/delete", workspaceHandler.Delete)
	protected.POST("/workspace/batch-delete", workspaceHandler.BatchDelete)

	protected.POST("/projects", businessHandler.CreateProject)
	protected.POST("/projects/batch", businessHandler.CreateProjectsBatch)
	protected.POST("/projects/batch-start", chatHandler.StartProjectsBatch)
	protected.GET("/projects", businessHandler.ListProjects)
	protected.POST("/projects/batch-delete", projectHandler.BatchDeleteProjects)
	protected.GET("/projects/:id", businessHandler.GetProject)
	protected.PUT("/projects/:id", businessHandler.UpdateProject)
	protected.DELETE("/projects/:id", businessHandler.DeleteProject)
	protected.POST("/projects/:id/facts", businessHandler.UpsertProjectFact)
	protected.GET("/projects/:id/facts", businessHandler.ListProjectFacts)
	protected.PUT("/projects/:id/facts/:factId", businessHandler.UpdateProjectFact)
	protected.DELETE("/projects/:id/facts/:factId", businessHandler.DeleteProjectFact)
	protected.GET("/projects/:id/summary", projectHandler.Summary)
	protected.GET("/projects/:id/coverage", projectHandler.Coverage)
	protected.GET("/projects/:id/export", projectHandler.Export)
	protected.GET("/projects/:id/assets", projectHandler.ListAssets)
	protected.GET("/projects/:id/conversations", projectHandler.ListConversations)
	protected.GET("/projects/:id/vulnerabilities", projectHandler.ListVulnerabilities)
	protected.GET("/projects/:id/attack-steps", projectHandler.ListAttackSteps)
	protected.POST("/projects/:id/attack-steps", projectHandler.CreateAttackStep)
	protected.POST("/projects/:id/attack-steps/reorder", projectHandler.ReorderAttackSteps)
	protected.PUT("/projects/:id/attack-steps/:stepId", projectHandler.UpdateAttackStep)
	protected.DELETE("/projects/:id/attack-steps/:stepId", projectHandler.DeleteAttackStep)
	protected.POST("/projects/:id/attack-steps/import", projectHandler.ImportAttackSteps)
	protected.GET("/projects/:id/graph", projectHandler.ListGraph)
	protected.POST("/projects/:id/graph/sync", projectHandler.SyncGraph)
	protected.POST("/projects/:id/graph/nodes", projectHandler.CreateGraphNode)
	protected.PUT("/projects/:id/graph/nodes/:nodeId", projectHandler.UpdateGraphNode)
	protected.DELETE("/projects/:id/graph/nodes/:nodeId", projectHandler.DeleteGraphNode)
	protected.POST("/projects/:id/graph/edges", projectHandler.CreateGraphEdge)
	protected.DELETE("/projects/:id/graph/edges/:edgeId", projectHandler.DeleteGraphEdge)
	protected.PUT("/projects/:id/graph/layout", projectHandler.UpdateGraphLayout)

	protected.POST("/assets", businessHandler.CreateAsset)
	protected.GET("/assets", businessHandler.ListAssets)
	protected.PUT("/assets/:id", businessHandler.UpdateAsset)
	protected.DELETE("/assets/:id", businessHandler.DeleteAsset)

	protected.POST("/vulnerabilities", businessHandler.CreateVulnerability)
	protected.GET("/vulnerabilities", businessHandler.ListVulnerabilities)
	protected.GET("/vulnerabilities/stats", businessHandler.VulnerabilityStats)
	protected.GET("/vulnerabilities/export", vulnerabilityHandler.Export)
	protected.GET("/vulnerabilities/:id/related-conversations", vulnerabilityHandler.ListRelatedConversations)
	protected.GET("/vulnerabilities/:id/retests", vulnerabilityHandler.ListRetests)
	protected.POST("/vulnerabilities/:id/retest/stream", vulnerabilityHandler.StartRetestStream)
	protected.POST("/vulnerabilities/:id/retest", vulnerabilityHandler.Retest)
	protected.POST("/vulnerabilities/batch-status", vulnerabilityHandler.BatchUpdateStatus)
	protected.POST("/vulnerabilities/batch-delete", vulnerabilityHandler.BatchDelete)
	protected.GET("/vulnerabilities/:id", vulnerabilityHandler.Get)
	protected.PUT("/vulnerabilities/:id", businessHandler.UpdateVulnerability)
	protected.DELETE("/vulnerabilities/:id", businessHandler.DeleteVulnerability)

	protected.POST("/knowledge/items", businessHandler.CreateKnowledgeItem)
	protected.GET("/knowledge/items", businessHandler.ListKnowledgeItems)
	protected.PUT("/knowledge/items/:id", businessHandler.UpdateKnowledgeItem)
	protected.DELETE("/knowledge/items/:id", businessHandler.DeleteKnowledgeItem)
	protected.POST("/knowledge/search", businessHandler.SearchKnowledge)

	protected.POST("/webshell/connections", businessHandler.CreateWebShellConnection)
	protected.GET("/webshell/connections", businessHandler.ListWebShellConnections)
	protected.DELETE("/webshell/connections/:id", businessHandler.DeleteWebShellConnection)

	protected.GET("/skills", businessHandler.ListSkills)
	protected.POST("/skills", businessHandler.CreateSkill)
	protected.GET("/skills/:name", businessHandler.GetSkill)
	protected.PUT("/skills/:name", businessHandler.SaveSkill)
	protected.DELETE("/skills/:name", businessHandler.DeleteSkill)
	protected.GET("/mcp/servers", mcpHandler.List)
	protected.POST("/mcp/servers", mcpHandler.Create)
	protected.PUT("/mcp/servers/:id", mcpHandler.Update)
	protected.DELETE("/mcp/servers/:id", mcpHandler.Delete)
	protected.POST("/mcp/servers/:id/test", mcpHandler.Test)
	protected.GET("/mcp/tools", mcpHandler.Tools)
	protected.GET("/mcp/agent-tools", mcpHandler.AgentTools)
	protected.PUT("/mcp/tools", mcpHandler.UpdateTools)
	protected.POST("/mcp/tools/doctor", mcpHandler.Doctor)
	protected.GET("/settings/ai", settingsHandler.AIStatus)
	protected.GET("/settings/llm/keys", settingsHandler.ListLLMKeys)
	protected.POST("/settings/llm/keys", settingsHandler.AddLLMKeys)
	protected.DELETE("/settings/llm/keys/:id", settingsHandler.DeleteLLMKey)
	protected.POST("/settings/llm/keys/test", settingsHandler.TestLLMKeys)
	protected.GET("/system/stats", health.System)
	protected.POST("/settings/llm/models", settingsHandler.ListModels)
	protected.PUT("/settings/ai", settingsHandler.Update)
	protected.GET("/settings/storage", storageHandler.Status)
	protected.PUT("/settings/storage", storageHandler.Update)
	protected.POST("/settings/storage/cleanup", storageHandler.Cleanup)
	protected.GET("/intercept/rules", interceptHandler.List)
	protected.POST("/intercept/rules/test", interceptHandler.Test)

	interceptAdmin := protected.Group("/intercept/rules")
	interceptAdmin.Use(authmiddleware.RequireRole("admin"))
	interceptAdmin.POST("", interceptHandler.Create)
	interceptAdmin.PUT("/:id", interceptHandler.Update)
	interceptAdmin.DELETE("/:id", interceptHandler.Delete)
	interceptAdmin.PUT("/:id/toggle", interceptHandler.Toggle)

	admin := protected.Group("/admin")
	admin.Use(authmiddleware.RequireRole("admin"))
	admin.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"scope":  "admin",
		})
	})

	if resumed, err := chatHandler.ResumeAutoCampaigns(context.Background()); err != nil {
		log.Printf("campaign auto resume: %v", err)
	} else if resumed > 0 {
		log.Printf("campaign auto resume: 已恢复 %d 个连续任务", resumed)
	}

	return &App{
		config:  cfg,
		router:  router,
		db:      db,
		mcp:     mcpManager,
		storage: storageService,
		tasks:   taskManager,
		events:  events,
	}, nil
}

const builtinMCPServerName = "sophon-mcp-tools"
const toolRunnerServerName = "sophon-tool-runner"

func startMCPServers(
	ctx context.Context,
	db *database.DB,
	manager *mcpclient.Manager,
	cfg config.Config,
) ([]tool.BaseTool, error) {
	now := time.Now().UTC()
	builtin := database.MCPServer{
		ID:        "builtin-" + builtinMCPServerName,
		Name:      builtinMCPServerName,
		Transport: "stdio",
		Command:   cfg.MCPCommand,
		Enabled:   true,
		Builtin:   true,
		Status:    "unknown",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.UpsertMCPServer(ctx, builtin); err != nil {
		return nil, fmt.Errorf("register builtin MCP server: %w", err)
	}
	if stored, err := db.GetMCPServerByName(ctx, builtin.Name); err == nil {
		builtin = *stored
		builtin.Command = cfg.MCPCommand
		builtin.Enabled = true
		builtin.Builtin = true
	}

	// CS AI 工具目录：首次启动时注册为受管理的 stdio MCP 服务，默认启用。
	if _, err := db.GetMCPServerByName(ctx, toolRunnerServerName); database.NoRows(err) {
		runner := database.MCPServer{
			ID:        "mcp-" + toolRunnerServerName,
			Name:      toolRunnerServerName,
			Transport: "stdio",
			Command:   toolRunnerCommand(cfg),
			Args:      []string{"--tools-dir", toolsDirectory(cfg)},
			Env: map[string]string{
				"SOPHON_WORKSPACE_ROOT": toolWorkspaceRoot(cfg),
			},
			Description: "CS AI tools/ 工具目录（YAML 定义的外部命令）",
			Enabled:     true,
			Status:      "unknown",
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := db.CreateMCPServer(ctx, runner); err != nil {
			log.Printf("seed tool runner MCP server: %v", err)
		}
	}
	if stored, err := db.GetMCPServerByName(ctx, toolRunnerServerName); err == nil {
		stored.Command = toolRunnerCommand(cfg)
		stored.Args = []string{"--tools-dir", toolsDirectory(cfg)}
		if stored.Env == nil {
			stored.Env = map[string]string{}
		}
		stored.Env["SOPHON_WORKSPACE_ROOT"] = toolWorkspaceRoot(cfg)
		stored.Enabled = true
		stored.UpdatedAt = time.Now().UTC()
		if err := db.UpdateMCPServer(ctx, *stored); err != nil {
			log.Printf("update tool runner MCP server: %v", err)
		}
	}

	storedServers, err := db.ListMCPServers(ctx)
	if err != nil {
		return nil, err
	}
	external := make([]database.MCPServer, 0, len(storedServers))
	for _, item := range storedServers {
		if item.Builtin || item.Name == builtin.Name {
			continue
		}
		external = append(external, item)
	}
	return manager.Start(ctx, builtin, external)
}

func toolRunnerCommand(cfg config.Config) string {
	command := strings.TrimSpace(cfg.MCPCommand)
	if command == "" {
		return "/opt/sophon/backend/sophon-tool-runner"
	}
	return filepath.Join(filepath.Dir(command), "sophon-tool-runner")
}

func toolsDirectory(cfg config.Config) string {
	if configPath := strings.TrimSpace(cfg.ConfigPath); configPath != "" {
		return filepath.Join(filepath.Dir(configPath), "tools")
	}
	return "/opt/sophon/tools"
}

func toolWorkspaceRoot(cfg config.Config) string {
	root := strings.TrimSpace(cfg.Storage.ArtifactRoot)
	if root == "" {
		return ""
	}
	relative := "tmp/workspace"
	if category, ok := cfg.Storage.Categories["workspace"]; ok &&
		strings.TrimSpace(category.Path) != "" {
		relative = strings.TrimSpace(category.Path)
	}
	return filepath.Join(root, filepath.FromSlash(relative))
}

func (a *App) Run(ctx context.Context) error {
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	defer func() {
		if a.mcp != nil {
			_ = a.mcp.Close()
		}
		if a.events != nil {
			_ = a.events.Close()
		}
		_ = a.db.Close()
	}()
	cleanupDone := make(chan struct{})
	defer func() { <-cleanupDone }()
	go func() {
		defer close(cleanupDone)
		a.cleanupExpiredSessions(runCtx)
	}()
	if a.storage != nil {
		a.storage.Start(runCtx)
	}

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", a.config.Host, a.config.Port),
		Handler:           a.router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	shutdownDone := make(chan struct{})
	go func() {
		<-runCtx.Done()
		defer close(shutdownDone)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		if a.tasks != nil {
			drainCtx, drainCancel := context.WithTimeout(context.Background(), 30*time.Second)
			drainErr := a.tasks.WaitForIdle(drainCtx)
			drainCancel()
			if drainErr != nil {
				cancelled := a.tasks.CancelAll()
				log.Printf("shutdown: Agent 任务等待超时，已取消 %d 个任务", cancelled)
				cancelWaitCtx, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
				_ = a.tasks.WaitForIdle(cancelWaitCtx)
				cancelWait()
			}
		}
	}()

	serveErr := server.ListenAndServe()
	stop()
	<-shutdownDone
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}

func (a *App) cleanupExpiredSessions(ctx context.Context) {
	if a == nil || a.db == nil {
		return
	}
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		deleted, err := a.db.DeleteExpiredSessions(cleanupCtx, time.Now().UTC())
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("session cleanup: %v", err)
			}
			return
		}
		if deleted > 0 {
			log.Printf("session cleanup: 已清理 %d 个过期会话", deleted)
		}
	}
	cleanup()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
		}
	}
}
