package toolcatalog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sophon/internal/toolrunner"
)

const (
	SourceArtifact = "artifact"
	SourceBundled  = "bundled"
	SourceSystem   = "system"
	SourcePython   = "python"
	SourceBuiltin  = "builtin"
	SourceDisabled = "disabled"
)

func (c *Catalog) loadToolDefinitions() ([]toolrunner.Tool, error) {
	if strings.TrimSpace(c.toolsDir) == "" {
		return nil, fmt.Errorf("工具定义目录未配置")
	}
	return toolrunner.LoadDir(c.toolsDir)
}

func (c *Catalog) loadDefinitionByName(name string) (toolrunner.Tool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return toolrunner.Tool{}, fmt.Errorf("工具名称不能为空")
	}
	definitions, err := c.loadToolDefinitions()
	if err != nil {
		return toolrunner.Tool{}, err
	}
	for _, definition := range definitions {
		if strings.EqualFold(definition.Name, name) {
			return definition, nil
		}
	}
	return toolrunner.Tool{}, fmt.Errorf("工具目录中不存在 %s", name)
}

func (c *Catalog) statusForDefinition(ctx context.Context, definition toolrunner.Tool) (Status, error) {
	status := Status{
		Name:                 definition.Name,
		Description:          definition.Summary(),
		Architecture:         CurrentArchitecture(),
		Source:               c.definitionSource(definition),
		ToolDefinitionExists: true,
	}
	if !definition.Enabled {
		status.State = "disabled"
		status.Detail = "工具定义已停用"
		return status, nil
	}

	found, executable, detail := commandStatus(definition.Command)
	status.Executable = found && executable
	if !found {
		status.State = "missing"
		status.Detail = detail
		return status, nil
	}
	if !executable {
		status.State = "not_executable"
		status.Detail = detail
		return status, nil
	}
	if missing := c.missingScriptPaths(definition.Args); len(missing) > 0 {
		status.State = "missing"
		status.Detail = "工具文件不存在: " + strings.Join(missing, ", ")
		return status, nil
	}

	missingBinaries := missingRequirements(definition.RequiresBinaries)
	missingModules := missingPythonModules(ctx, definition.Command, definition.RequiresPython)
	if len(missingBinaries) > 0 || len(missingModules) > 0 {
		parts := make([]string, 0, 2)
		if len(missingBinaries) > 0 {
			parts = append(parts, "缺失外部命令: "+strings.Join(missingBinaries, ", "))
		}
		if len(missingModules) > 0 {
			parts = append(parts, "缺失 Python 模块: "+strings.Join(missingModules, ", "))
		}
		status.State = "missing_dependency"
		status.Detail = strings.Join(parts, "；")
		return status, nil
	}

	status.Installed = true
	status.State = "installed"
	status.Detail = "命令和声明依赖可用"
	return status, nil
}

func (c *Catalog) installedRuntimeStatus(ctx context.Context, name string) (Status, bool) {
	definition, err := c.loadDefinitionByName(name)
	if err != nil || !definitionUsesRuntimeCommand(definition) {
		return Status{}, false
	}
	status, err := c.statusForDefinition(ctx, definition)
	if err != nil || !status.Installed {
		return Status{}, false
	}
	status.Installable = false
	status.Detail = "使用系统 PATH 或 Python 环境中的现有工具"
	return status, true
}

func definitionUsesRuntimeCommand(definition toolrunner.Tool) bool {
	command := strings.TrimSpace(definition.Command)
	if command == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(command))
	if base != "python" && base != "python3" &&
		base != "sh" && base != "bash" {
		return true
	}
	return (base == "python" || base == "python3") &&
		len(definition.Args) >= 2 &&
		definition.Args[0] == "-c" &&
		len(definition.RequiresPython) > 0
}

func (c *Catalog) definitionSource(definition toolrunner.Tool) string {
	if !definition.Enabled {
		return SourceDisabled
	}
	command := strings.TrimSpace(definition.Command)
	switch strings.ToLower(filepath.Base(command)) {
	case "sh", "bash":
		return SourceBuiltin
	}
	if filepath.IsAbs(command) {
		return c.sourceForPath(command)
	}
	for _, arg := range definition.Args {
		if filepath.IsAbs(strings.TrimSpace(arg)) {
			if source := c.sourceForPath(arg); source == SourceBundled || source == SourceBuiltin {
				return source
			}
		}
	}
	switch strings.ToLower(filepath.Base(command)) {
	case "python", "python3":
		return SourcePython
	default:
		return SourceSystem
	}
}

func (c *Catalog) sourceForPath(path string) string {
	if pathWithin(c.installRoot, path) {
		return SourceBundled
	}
	if pathWithin(c.toolsDir, path) {
		return SourceBuiltin
	}
	return SourceSystem
}

func (c *Catalog) missingScriptPaths(args []string) []string {
	missing := make([]string, 0)
	for _, arg := range args {
		path := strings.TrimSpace(arg)
		if !filepath.IsAbs(path) {
			continue
		}
		if !pathWithin(c.installRoot, path) && !pathWithin(c.toolsDir, path) {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			missing = append(missing, path)
		}
	}
	return missing
}

func commandStatus(command string) (bool, bool, string) {
	command = strings.TrimSpace(command)
	if command == "" {
		return false, false, "工具命令为空"
	}
	if !filepath.IsAbs(command) {
		path, err := exec.LookPath(command)
		if err != nil {
			return false, false, "命令不存在: " + command
		}
		command = path
	}
	info, err := os.Stat(command)
	if err != nil {
		if os.IsNotExist(err) {
			return false, false, "命令不存在: " + command
		}
		return false, false, "无法读取命令状态: " + err.Error()
	}
	if info.IsDir() {
		return false, false, "命令不是普通文件: " + command
	}
	if info.Mode()&0o111 == 0 {
		return true, false, "命令不可执行: " + command
	}
	return true, true, ""
}

func missingRequirements(requirements []string) []string {
	missing := make([]string, 0)
	for _, requirement := range requirements {
		found, executable, _ := commandStatus(requirement)
		if !found || !executable {
			missing = append(missing, requirement)
		}
	}
	return missing
}

func missingPythonModules(ctx context.Context, interpreter string, modules []string) []string {
	if len(modules) == 0 {
		return nil
	}
	interpreter = strings.TrimSpace(interpreter)
	switch strings.ToLower(filepath.Base(interpreter)) {
	case "python", "python3":
	default:
		interpreter = "python3"
	}
	const checkScript = `import importlib.util,json,sys; print(json.dumps([m for m in sys.argv[1:] if importlib.util.find_spec(m) is None]))`
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := execCommandContext(checkCtx, interpreter, append([]string{"-c", checkScript}, modules...)...)
	output, err := cmd.Output()
	if err != nil {
		return modules
	}
	var missing []string
	if err := json.Unmarshal(output, &missing); err != nil {
		return modules
	}
	return missing
}

func pathWithin(root, path string) bool {
	root = strings.TrimSpace(root)
	path = strings.TrimSpace(path)
	if root == "" || path == "" {
		return false
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
