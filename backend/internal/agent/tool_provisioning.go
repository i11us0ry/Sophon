package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
	"sophon/internal/toolrunner"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

const maxRegisteredToolOutput = 256 * 1024

func objectParam(desc string) *schema.ParameterInfo {
	return &schema.ParameterInfo{Type: schema.Object, Desc: desc}
}

func booleanParam(desc string) *schema.ParameterInfo {
	return &schema.ParameterInfo{Type: schema.Boolean, Desc: desc}
}

func newToolProvisioningTools(service *Service) []tool.BaseTool {
	return []tool.BaseTool{
		newToolProbeTool(service),
		newToolRegisterTool(service),
		newToolRunTool(service),
		newToolEnvAddPathTool(service),
		newToolUnregisterTool(service),
	}
}

func newToolProbeTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name: "tool_probe",
		desc: "探测工具是否已存在于系统 PATH、当前会话/项目注册表或常见工具目录，并返回可用的包管理器、编译器和 Catalog 状态。",
		params: map[string]*schema.ParameterInfo{
			"name":    stringParam("工具名称，例如 nuclei", true),
			"command": stringParam("可选命令名或绝对路径；为空时使用 name"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Name    string `json:"name"`
				Command string `json:"command"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			if service == nil || service.db == nil {
				return "", fmt.Errorf("工具注册服务不可用")
			}
			_, userID, projectID, err := service.currentProject(ctx)
			if err != nil {
				return "", err
			}
			conversationID := execctx.ConversationID(ctx)
			registered, err := service.db.ListRegisteredTools(ctx, userID, projectID, conversationID)
			if err != nil {
				return "", err
			}
			command := firstNonEmpty(strings.TrimSpace(request.Command), strings.TrimSpace(request.Name))
			lookupPaths, _ := service.toolRuntimePaths(ctx)
			foundPath, lookupErr := lookupExecutable(command, lookupPaths)
			matches := make([]database.RegisteredTool, 0)
			registeredUsable := false
			for _, item := range registered {
				if strings.EqualFold(item.Name, request.Name) ||
					(strings.TrimSpace(request.Command) != "" && strings.EqualFold(item.Command, request.Command)) {
					matches = append(matches, item)
					if path, err := lookupExecutable(item.Command, lookupPaths); err == nil {
						registeredUsable = true
						if foundPath == "" {
							foundPath = path
						}
					}
				}
			}
			catalogStatus := any(nil)
			if service.catalog != nil {
				if status, catalogErr := service.catalog.Status(ctx, request.Name); catalogErr == nil {
					catalogStatus = status
				}
			}
			result := map[string]any{
				"name":               request.Name,
				"command":            command,
				"found":              foundPath != "" || registeredUsable,
				"path":               foundPath,
				"lookupError":        errorString(lookupErr),
				"registeredTools":    matches,
				"searchedPaths":      lookupPaths,
				"projectId":          projectID,
				"conversationId":     conversationID,
				"packageManagers":    availableCommands("apt", "apt-get", "dnf", "yum", "apk", "pip", "pip3", "uv", "npm", "pnpm", "cargo", "go"),
				"compilers":          availableCommands("gcc", "g++", "clang", "make", "cmake", "javac", "go", "rustc", "dotnet"),
				"catalog":            catalogStatus,
				"recommendedToolDir": filepath.Join(projectIDToolRoot(service, ctx), "bin"),
			}
			return marshalToolProvisioningResult(result)
		},
	}
}

func newToolRegisterTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name: "tool_register",
		desc: "注册 Agent 自己下载、解压或编译的工具。支持 session/project/global 作用域，记录命令、参数、环境变量、版本、来源和健康检查。不会限制 Agent 使用任意下载或构建方式。",
		params: map[string]*schema.ParameterInfo{
			"name":         stringParam("工具名称", true),
			"command":      stringParam("命令名或绝对路径", true),
			"args":         stringArrayParam("运行时默认参数"),
			"env":          objectParam("工具运行时环境变量"),
			"version":      stringParam("工具版本"),
			"source":       stringParam("来源，例如 release/git/build/manual"),
			"scope":        stringParam("作用域：session/project/global，默认 project"),
			"health_check": stringArrayParam("健康检查参数，例如 [\"--version\"]"),
			"enabled":      booleanParam("是否启用，默认 true"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Name        string            `json:"name"`
				Command     string            `json:"command"`
				Args        []string          `json:"args"`
				Env         map[string]string `json:"env"`
				Version     string            `json:"version"`
				Source      string            `json:"source"`
				Scope       string            `json:"scope"`
				HealthCheck []string          `json:"health_check"`
				Enabled     *bool             `json:"enabled"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			scope, projectID, conversationID, err := resolveToolRegistryScope(ctx, service, request.Scope)
			if err != nil {
				return "", err
			}
			_, userID, _, err := service.currentProject(ctx)
			if err != nil {
				return "", err
			}
			command := expandToolPath(request.Command, service, ctx, userID, projectID, conversationID)
			enabled := true
			if request.Enabled != nil {
				enabled = *request.Enabled
			}
			item, err := service.db.UpsertRegisteredTool(ctx, database.RegisteredTool{
				ID:             randomID(),
				OwnerUserID:    userID,
				ProjectID:      projectID,
				ConversationID: conversationID,
				Scope:          scope,
				Name:           request.Name,
				Command:        command,
				Args:           request.Args,
				Env:            request.Env,
				Version:        request.Version,
				Source:         request.Source,
				HealthCheck:    request.HealthCheck,
				Enabled:        enabled,
				Status:         "registered",
			})
			if err != nil {
				return "", err
			}
			if filepath.IsAbs(command) {
				localDir := filepath.Dir(command)
				if info, statErr := os.Stat(localDir); statErr == nil && info.IsDir() {
					_, _ = service.db.UpsertToolRuntimePath(ctx, database.ToolRuntimePath{
						ID:             randomID(),
						OwnerUserID:    userID,
						ProjectID:      projectID,
						ConversationID: conversationID,
						Scope:          scope,
						Path:           localDir,
					})
				}
			}
			healthOutput := ""
			healthErr := error(nil)
			if len(request.HealthCheck) > 0 {
				healthOutput, healthErr = service.runRegisteredTool(
					ctx,
					*item,
					request.HealthCheck,
					service.currentToolWorkdir(ctx),
					15*time.Second,
				)
				if healthErr != nil {
					item.Status = "unverified"
					item.LastError = healthErr.Error()
				} else {
					item.Status = "verified"
				}
				updated, updateErr := service.db.UpsertRegisteredTool(ctx, *item)
				if updateErr == nil {
					item = updated
				}
			}
			service.auditToolProvisioning(
				ctx,
				userID,
				"tool.register",
				item.ID,
				"success",
				fmt.Sprintf("name=%s scope=%s command=%s source=%s", item.Name, item.Scope, item.Command, item.Source),
			)
			return marshalToolProvisioningResult(map[string]any{
				"tool":         item,
				"healthOutput": healthOutput,
				"healthError":  errorString(healthErr),
				"next":         "可直接使用 tool_run，或将工具目录加入 tool_env_add_path 后继续使用 exec",
			})
		},
	}
}

func newToolRunTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name: "tool_run",
		desc: "运行已注册工具，并自动应用注册时保存的默认参数、环境变量和工作目录。Agent 仍可继续使用 exec 执行任意未注册命令。",
		params: map[string]*schema.ParameterInfo{
			"name":    stringParam("已注册工具名称", true),
			"args":    stringArrayParam("本次调用参数"),
			"workdir": stringParam("可选工作目录"),
			"timeout": integerParam("超时秒数，默认 120"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Name    string   `json:"name"`
				Args    []string `json:"args"`
				Workdir string   `json:"workdir"`
				Timeout flexInt  `json:"timeout"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := service.currentProject(ctx)
			if err != nil {
				return "", err
			}
			items, err := service.db.ListRegisteredTools(ctx, userID, projectID, execctx.ConversationID(ctx))
			if err != nil {
				return "", err
			}
			var selected *database.RegisteredTool
			for index := range items {
				if strings.EqualFold(items[index].Name, request.Name) {
					selected = &items[index]
					break
				}
			}
			if selected == nil {
				return "", fmt.Errorf("未找到已注册工具 %s；可先使用 tool_probe 或 tool_register", request.Name)
			}
			selectedTool := *selected
			if !filepath.IsAbs(selectedTool.Command) {
				paths, _ := service.toolRuntimePathsForProject(ctx, userID, projectID, execctx.ConversationID(ctx))
				if resolved, lookupErr := lookupExecutable(selectedTool.Command, paths); lookupErr == nil {
					selectedTool.Command = resolved
				}
			}
			workdir := strings.TrimSpace(request.Workdir)
			if workdir == "" {
				workdir = service.currentToolWorkdir(ctx)
			}
			timeout := time.Duration(int(request.Timeout)) * time.Second
			if timeout <= 0 {
				timeout = 120 * time.Second
			}
			output, runErr := service.runRegisteredTool(ctx, selectedTool, request.Args, workdir, timeout)
			result := "success"
			if runErr != nil {
				result = "failed"
			}
			service.auditToolProvisioning(
				ctx,
				userID,
				"tool.run",
				selectedTool.ID,
				result,
				fmt.Sprintf("name=%s command=%s arg_count=%d error=%s", selectedTool.Name, selectedTool.Command, len(request.Args), errorString(runErr)),
			)
			if runErr != nil {
				if strings.TrimSpace(output) != "" {
					return "", fmt.Errorf("%w\n输出：%s", runErr, truncateProjectText(output, projectToolLongText))
				}
				return "", runErr
			}
			return marshalToolProvisioningResult(map[string]any{
				"tool":   selected.Name,
				"output": output,
				"error":  errorString(runErr),
			})
		},
	}
}

func newToolEnvAddPathTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name: "tool_env_add_path",
		desc: "将工具目录加入当前会话、项目或全局动态 PATH。不会修改 .bashrc、profile 或容器系统环境。",
		params: map[string]*schema.ParameterInfo{
			"path":  stringParam("工具目录绝对路径", true),
			"scope": stringParam("作用域：session/project/global，默认 project"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Path  string `json:"path"`
				Scope string `json:"scope"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			absolute, err := filepath.Abs(strings.TrimSpace(request.Path))
			if err != nil {
				return "", fmt.Errorf("解析工具目录失败: %w", err)
			}
			info, err := os.Stat(absolute)
			if err != nil {
				return "", fmt.Errorf("工具目录不存在: %w", err)
			}
			if !info.IsDir() {
				return "", fmt.Errorf("工具 PATH 必须是目录: %s", absolute)
			}
			scope, projectID, conversationID, err := resolveToolRegistryScope(ctx, service, request.Scope)
			if err != nil {
				return "", err
			}
			_, userID, _, err := service.currentProject(ctx)
			if err != nil {
				return "", err
			}
			item, err := service.db.UpsertToolRuntimePath(ctx, database.ToolRuntimePath{
				ID:             randomID(),
				OwnerUserID:    userID,
				ProjectID:      projectID,
				ConversationID: conversationID,
				Scope:          scope,
				Path:           absolute,
			})
			if err != nil {
				return "", err
			}
			service.auditToolProvisioning(
				ctx,
				userID,
				"tool.path.add",
				item.ID,
				"success",
				fmt.Sprintf("scope=%s path=%s", item.Scope, item.Path),
			)
			return marshalToolProvisioningResult(item)
		},
	}
}

func newToolUnregisterTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name: "tool_unregister",
		desc: "删除工具注册或动态 PATH 条目。kind=path 时删除 PATH，其他值删除工具注册。",
		params: map[string]*schema.ParameterInfo{
			"id":   stringParam("工具注册或 PATH 条目 id", true),
			"kind": stringParam("类型：tool 或 path，默认 tool"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				ID   string `json:"id"`
				Kind string `json:"kind"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, _, err := service.currentProject(ctx)
			if err != nil {
				return "", err
			}
			var deleted bool
			if strings.EqualFold(strings.TrimSpace(request.Kind), "path") {
				deleted, err = service.db.DeleteToolRuntimePath(ctx, request.ID, userID)
			} else {
				deleted, err = service.db.DeleteRegisteredTool(ctx, request.ID, userID)
			}
			if err != nil {
				return "", err
			}
			result := "failed"
			if deleted {
				result = "success"
			}
			service.auditToolProvisioning(
				ctx,
				userID,
				"tool.unregister",
				request.ID,
				result,
				fmt.Sprintf("kind=%s deleted=%t", request.Kind, deleted),
			)
			return marshalToolProvisioningResult(map[string]any{"deleted": deleted})
		},
	}
}

func resolveToolRegistryScope(
	ctx context.Context,
	service *Service,
	requested string,
) (string, string, string, error) {
	scope := database.ToolScopeProject
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case database.ToolScopeSession, "conversation":
		scope = database.ToolScopeSession
	case database.ToolScopeGlobal:
		scope = database.ToolScopeGlobal
	case "", database.ToolScopeProject:
	default:
		return "", "", "", fmt.Errorf("scope 必须是 session/project/global")
	}
	projectID := strings.TrimSpace(execctx.ProjectID(ctx))
	if projectID == "" && service != nil && service.db != nil {
		if _, _, resolvedProjectID, err := service.currentProject(ctx); err == nil {
			projectID = strings.TrimSpace(resolvedProjectID)
		}
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	if scope == database.ToolScopeProject && projectID == "" {
		return "", "", "", fmt.Errorf("项目级工具需要当前对话绑定项目")
	}
	if scope == database.ToolScopeSession && conversationID == "" {
		return "", "", "", fmt.Errorf("会话级工具需要 conversation_id")
	}
	return scope, projectID, conversationID, nil
}

func lookupExecutable(command string, paths []string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("命令为空")
	}
	if filepath.IsAbs(command) {
		info, err := os.Stat(command)
		if err != nil {
			return "", err
		}
		if info.IsDir() || info.Mode()&0o111 == 0 {
			return "", fmt.Errorf("命令不可执行")
		}
		return command, nil
	}
	search := append([]string(nil), paths...)
	search = append(search, strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))...)
	seen := map[string]bool{}
	for _, dir := range search {
		dir = strings.TrimSpace(dir)
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		candidate := filepath.Join(dir, command)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("命令不在 PATH 或已注册工具目录中")
}

func availableCommands(names ...string) []string {
	result := make([]string, 0, len(names))
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			result = append(result, path)
		}
	}
	sort.Strings(result)
	return result
}

func (s *Service) runRegisteredTool(
	parent context.Context,
	item database.RegisteredTool,
	args []string,
	workdir string,
	timeout time.Duration,
) (string, error) {
	command := strings.TrimSpace(item.Command)
	if command == "" {
		return "", fmt.Errorf("已注册工具 %s 缺少命令", item.Name)
	}
	fullArgs := append(append([]string(nil), item.Args...), args...)
	conversationID := strings.TrimSpace(execctx.ConversationID(parent))
	userID := strings.TrimSpace(execctx.UserID(parent))
	if conversationID == "" || userID == "" {
		return "", fmt.Errorf("运行注册工具缺少会话或用户上下文")
	}
	policyArgs := map[string]interface{}{
		"command": renderRegisteredToolCommand(command, fullArgs),
	}
	if strings.TrimSpace(workdir) != "" {
		policyArgs["workdir"] = strings.TrimSpace(workdir)
	}
	if err := s.toolInterceptor(conversationID, userID, nil)(
		parent,
		toolRunnerServerName,
		"exec",
		policyArgs,
	); err != nil {
		return "", err
	}

	parameters := make([]toolrunner.Parameter, 0, len(fullArgs))
	input := map[string]any{}
	for index, value := range fullArgs {
		position := index
		name := fmt.Sprintf("arg%d", index)
		parameters = append(parameters, toolrunner.Parameter{
			Name:     name,
			Type:     "string",
			Required: true,
			Position: &position,
		})
		input[name] = value
	}
	for key, value := range policyArgs {
		if strings.HasPrefix(key, "_sophon_") {
			input[key] = value
		}
	}
	if strings.TrimSpace(workdir) != "" {
		input[toolRunnerWorkspaceArg] = strings.TrimSpace(workdir)
	}
	executor := &toolrunner.Executor{
		Timeout:        timeout,
		MaxOutputBytes: maxRegisteredToolOutput,
		WorkspaceRoot:  strings.TrimSpace(s.cfg.Storage.ArtifactRoot),
	}
	result, err := executor.Run(parent, toolrunner.Tool{
		Name:        item.Name,
		Command:     command,
		Enabled:     true,
		Args:        item.Args,
		Parameters:  parameters,
		Environment: item.Env,
	}, input)
	if result == nil {
		return "", err
	}
	return result.Output, err
}

func renderRegisteredToolCommand(command string, args []string) string {
	values := append([]string{shellQuoteArgument(command)}, args...)
	for index := 1; index < len(values); index++ {
		values[index] = shellQuoteArgument(values[index])
	}
	return strings.Join(values, " ")
}

func shellQuoteArgument(value string) string {
	if value == "" {
		return "''"
	}
	if !strings.ContainsAny(value, " \t\r\n'\"`$&|;<>()*?[]{}!#") {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func expandToolPath(
	command string,
	service *Service,
	ctx context.Context,
	userID string,
	projectID string,
	conversationID string,
) string {
	command = strings.TrimSpace(command)
	if command == "" || filepath.IsAbs(command) {
		return command
	}
	paths, _ := service.toolRuntimePathsForProject(ctx, userID, projectID, conversationID)
	if path, err := lookupExecutable(command, paths); err == nil {
		return path
	}
	return command
}

func projectIDToolRoot(service *Service, ctx context.Context) string {
	if service == nil {
		return ""
	}
	if workspace := service.currentToolWorkdir(ctx); workspace != "" {
		return filepath.Join(workspace, "tools")
	}
	return filepath.Join(os.TempDir(), "sophon-tools")
}

func (s *Service) currentToolWorkdir(ctx context.Context) string {
	if s == nil {
		return ""
	}
	paths, err := s.agentWorkspacePaths(ctx, execctx.ConversationID(ctx))
	if err != nil {
		return ""
	}
	workdir := paths.ConversationRoot
	if subagent, ok := execctx.Subagent(ctx); ok && strings.TrimSpace(subagent.ID) != "" {
		workdir = filepath.Join(workdir, "subagents", filepath.Base(subagent.ID))
	}
	return workdir
}

func (s *Service) toolRuntimePaths(ctx context.Context) ([]string, error) {
	_, userID, projectID, err := s.currentProject(ctx)
	if err != nil {
		return nil, err
	}
	return s.toolRuntimePathsForProject(ctx, userID, projectID, execctx.ConversationID(ctx))
}

func (s *Service) toolRuntimePathsForProject(
	ctx context.Context,
	userID string,
	projectID string,
	conversationID string,
) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	paths := make([]string, 0)
	add := func(value string) {
		value = strings.TrimSpace(value)
		for _, existing := range paths {
			if existing == value {
				return
			}
		}
		if value != "" {
			paths = append(paths, value)
		}
	}
	if workspace := s.currentToolWorkdir(ctx); workspace != "" {
		add(filepath.Join(workspace, "tools", "bin"))
	}
	items, err := s.db.ListToolRuntimePaths(ctx, userID, projectID, conversationID)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		add(item.Path)
	}
	for _, path := range s.registeredToolPathDirs(ctx, userID, projectID, conversationID) {
		add(path)
	}
	return paths, nil
}

func uniquePathList(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func (s *Service) registeredToolPathDirs(
	ctx context.Context,
	userID string,
	projectID string,
	conversationID string,
) []string {
	if s == nil || s.db == nil {
		return nil
	}
	items, err := s.db.ListRegisteredTools(ctx, userID, projectID, conversationID)
	if err != nil {
		return nil
	}
	paths := make([]string, 0)
	seen := map[string]bool{}
	for _, item := range items {
		if !filepath.IsAbs(item.Command) {
			continue
		}
		dir := filepath.Dir(item.Command)
		if !seen[dir] {
			seen[dir] = true
			paths = append(paths, dir)
		}
	}
	return paths
}

func marshalToolProvisioningResult(value any) (string, error) {
	return marshalToolCatalogResult(value)
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s *Service) auditToolProvisioning(
	ctx context.Context,
	userID string,
	action string,
	resourceID string,
	result string,
	detail string,
) {
	if s == nil || s.db == nil {
		return
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_ = s.db.AddAuditLog(auditCtx, database.AuditLog{
		UserID:       userID,
		Action:       action,
		ResourceType: "tool_registry",
		ResourceID:   resourceID,
		Result:       result,
		Detail:       truncateProjectText(detail, projectToolLongText),
	})
}
