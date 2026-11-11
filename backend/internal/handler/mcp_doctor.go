package handler

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"sophon/internal/middleware"
	"sophon/internal/toolrunner"
)

const (
	doctorStatusAvailable         = "available"
	doctorStatusMissingBinary     = "missing_binary"
	doctorStatusMissingDependency = "missing_dependency"
	doctorStatusDisabled          = "disabled"
	doctorStatusServerError       = "server_error"
)

// optionalPythonModules 是工具脚本里用 try/except 兜底的可选依赖，缺失不影响执行。
var optionalPythonModules = map[string]bool{
	"charset_normalizer": true,
	"chardet":            true,
	"h2":                 true,
}

var linuxCapabilityBits = map[string]uint{
	"cap_net_bind_service": 10,
	"cap_net_admin":        12,
	"cap_net_raw":          13,
}

var pythonImportPattern = regexp.MustCompile(
	`(?m)^\s*(?:import\s+([A-Za-z_][A-Za-z0-9_]*)|from\s+([A-Za-z_][A-Za-z0-9_]*)\s+import\b)`,
)

// 包装脚本里 subprocess 调用的外部命令：cmd = ["rpcclient", ...] 或 subprocess.run(["nmap", ...])。
var (
	commandListPattern    = regexp.MustCompile(`(?m)(?:^|\s)(?:cmd|command|argv)\s*=\s*\[\s*"([^"]+)"`)
	subprocessListPattern = regexp.MustCompile(
		`subprocess\.(?:run|Popen|call|check_call|check_output)\(\s*\[\s*"([^"]+)"`,
	)
)

type mcpDoctorItem struct {
	ServerName string `json:"serverName"`
	Tool       string `json:"tool"`
	Enabled    bool   `json:"enabled"`
	Registered bool   `json:"registered"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
}

type mcpDoctorSummary struct {
	Total             int `json:"total"`
	Available         int `json:"available"`
	MissingBinary     int `json:"missingBinary"`
	MissingDependency int `json:"missingDependency"`
	Disabled          int `json:"disabled"`
	ServerError       int `json:"serverError"`
}

// Doctor 对 MCP 工具做可调用性自检：服务连接、命令二进制、Python 依赖与启停配置。
// 不会真实执行工具，避免误扫与副作用。
func (h *MCPHandler) Doctor(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	servers, err := h.db.ListMCPServers(ctx)
	if err != nil {
		internalError(c, "mcp_doctor_failed", "读取 MCP 服务失败")
		return
	}
	settings, err := h.db.ListMCPToolSettings(ctx)
	if err != nil {
		internalError(c, "mcp_doctor_failed", "读取 MCP 工具配置失败")
		return
	}
	dbState := make(map[string]bool, len(settings))
	for _, item := range settings {
		dbState[item.ServerName+"\x00"+item.ToolName] = item.Enabled
	}

	registeredByServer := make(map[string][]string)
	toolServer := make(map[string]string)
	runnerName := ""
	for _, server := range servers {
		if strings.Contains(filepath.Base(server.Command), "tool-runner") {
			runnerName = server.Name
		}
		if !server.Enabled {
			continue
		}
		for _, info := range h.manager.Tools(server.ID) {
			registeredByServer[server.ID] = append(registeredByServer[server.ID], info.Name)
			if _, exists := toolServer[info.Name]; !exists {
				toolServer[info.Name] = server.Name
			}
		}
	}

	defs, loadErr := toolrunner.LoadDir(h.toolsDir)

	type pendingTool struct {
		def          toolrunner.Tool
		serverName   string
		registered   bool
		dbEnabled    bool
		modules      []string
		binaries     []string
		capabilities []string
	}
	pending := make([]pendingTool, 0, len(defs))
	commandSet := map[string]bool{}
	moduleSet := map[string]bool{}
	binarySet := map[string]bool{}
	capabilitySet := map[string]map[string]bool{}
	for _, def := range defs {
		serverName := toolServer[def.Name]
		registered := serverName != ""
		if serverName == "" {
			serverName = runnerName
		}
		dbEnabled := true
		if value, ok := dbState[serverName+"\x00"+def.Name]; ok {
			dbEnabled = value
		}
		item := pendingTool{
			def:        def,
			serverName: serverName,
			registered: registered,
			dbEnabled:  dbEnabled,
		}
		if def.Enabled && registered && dbEnabled {
			commandSet[def.Command] = true
			item.modules = requiredPythonModules(def)
			item.binaries = requiredBinaries(def)
			item.capabilities = dedupeStrings(def.RequiresCapabilities)
			for _, module := range item.modules {
				moduleSet[module] = true
			}
			for _, binary := range item.binaries {
				binarySet[binary] = true
			}
			for _, capability := range item.capabilities {
				capability = strings.ToLower(strings.TrimSpace(capability))
				if capability == "" {
					continue
				}
				if capabilitySet[def.Command] == nil {
					capabilitySet[def.Command] = map[string]bool{}
				}
				capabilitySet[def.Command][capability] = true
			}
		}
		pending = append(pending, item)
	}

	commandMissing := make(map[string]string, len(commandSet))
	for command := range commandSet {
		if _, lookErr := exec.LookPath(command); lookErr != nil {
			commandMissing[command] = lookErr.Error()
		}
	}
	binaryMissing := make(map[string]string, len(binarySet))
	for binary := range binarySet {
		if commandSet[binary] {
			continue
		}
		if _, lookErr := exec.LookPath(binary); lookErr != nil {
			binaryMissing[binary] = lookErr.Error()
		}
	}
	missingModules := checkPythonModules(ctx, moduleSet)
	missingCapabilities := checkRequiredCapabilities(ctx, capabilitySet)

	items := make([]mcpDoctorItem, 0, len(pending))
	seenTools := make(map[string]bool, len(pending))
	for _, item := range pending {
		seenTools[item.def.Name] = true
		status, detail := classifyDoctorTool(
			item.def.Enabled,
			item.registered,
			item.dbEnabled,
			commandMissing[item.def.Command],
			filterMissingBinaries(item.binaries, binaryMissing),
			filterMissingCapabilities(item.capabilities, missingCapabilities[item.def.Command]),
			filterMissingModules(item.modules, missingModules),
		)
		items = append(items, mcpDoctorItem{
			ServerName: item.serverName,
			Tool:       item.def.Name,
			Enabled:    item.def.Enabled && item.registered && item.dbEnabled,
			Registered: item.registered,
			Status:     status,
			Detail:     detail,
		})
	}

	// 非 YAML 工具（由服务自身实现）：服务已连接且返回了该工具即视为可用。
	for _, server := range servers {
		if !server.Enabled {
			continue
		}
		for _, name := range registeredByServer[server.ID] {
			if seenTools[name] {
				continue
			}
			seenTools[name] = true
			items = append(items, mcpDoctorItem{
				ServerName: server.Name,
				Tool:       name,
				Enabled:    true,
				Registered: true,
				Status:     doctorStatusAvailable,
				Detail:     "MCP 服务已连接且提供该工具",
			})
		}
	}

	for _, server := range servers {
		if !server.Enabled || len(registeredByServer[server.ID]) > 0 {
			continue
		}
		detail := strings.TrimSpace(server.LastError)
		if detail == "" {
			detail = "服务未连接或未返回工具"
		}
		items = append(items, mcpDoctorItem{
			ServerName: server.Name,
			Tool:       "*",
			Status:     doctorStatusServerError,
			Detail:     detail,
		})
	}
	if loadErr != nil {
		items = append(items, mcpDoctorItem{
			ServerName: runnerName,
			Tool:       "*",
			Status:     doctorStatusServerError,
			Detail:     "读取工具目录失败: " + loadErr.Error(),
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].ServerName != items[j].ServerName {
			return items[i].ServerName < items[j].ServerName
		}
		return items[i].Tool < items[j].Tool
	})

	summary := mcpDoctorSummary{Total: len(items)}
	for _, item := range items {
		switch item.Status {
		case doctorStatusAvailable:
			summary.Available++
		case doctorStatusMissingBinary:
			summary.MissingBinary++
		case doctorStatusMissingDependency:
			summary.MissingDependency++
		case doctorStatusDisabled:
			summary.Disabled++
		case doctorStatusServerError:
			summary.ServerError++
		}
	}
	c.JSON(200, gin.H{
		"summary":  summary,
		"items":    items,
		"toolsDir": h.toolsDir,
	})
}

// classifyDoctorTool 汇总单个工具的自检结论，优先级：停用 > 未注册 > 缺命令 > 缺依赖 > 可用。
func classifyDoctorTool(
	yamlEnabled bool,
	registered bool,
	dbEnabled bool,
	commandDetail string,
	missingBinaries []string,
	missingCapabilities []string,
	missingModules []string,
) (string, string) {
	if !yamlEnabled {
		return doctorStatusDisabled, "工具定义已停用（enabled: false）"
	}
	if !registered {
		return doctorStatusDisabled, "未在 MCP 服务中注册"
	}
	if !dbEnabled {
		return doctorStatusDisabled, "工具配置中已停用"
	}
	if strings.TrimSpace(commandDetail) != "" {
		return doctorStatusMissingBinary, "命令不可执行: " + commandDetail
	}
	if len(missingBinaries) > 0 {
		return doctorStatusMissingDependency, "缺失外部命令: " + strings.Join(missingBinaries, ", ")
	}
	if len(missingCapabilities) > 0 {
		return doctorStatusMissingDependency, "缺少 Linux capability: " + strings.Join(missingCapabilities, ", ")
	}
	if len(missingModules) > 0 {
		return doctorStatusMissingDependency, "缺失 Python 模块: " + strings.Join(missingModules, ", ")
	}
	return doctorStatusAvailable, "命令与依赖可用"
}

func checkRequiredCapabilities(
	ctx context.Context,
	requirements map[string]map[string]bool,
) map[string][]string {
	missing := make(map[string][]string)
	if len(requirements) == 0 {
		return missing
	}
	processMask := processEffectiveCapabilities()
	getcapPath, _ := exec.LookPath("getcap")
	for command, capabilities := range requirements {
		commandPath, err := exec.LookPath(command)
		if err != nil {
			continue
		}
		for capability := range capabilities {
			bit, known := linuxCapabilityBits[capability]
			if known && processMask&(uint64(1)<<bit) != 0 {
				continue
			}
			if getcapPath != "" &&
				binaryHasEffectiveCapability(ctx, getcapPath, commandPath, capability) {
				continue
			}
			missing[command] = append(missing[command], capability)
		}
		sort.Strings(missing[command])
	}
	return missing
}

func filterMissingCapabilities(required []string, missing []string) []string {
	if len(required) == 0 || len(missing) == 0 {
		return nil
	}
	missingSet := make(map[string]bool, len(missing))
	for _, capability := range missing {
		missingSet[strings.ToLower(strings.TrimSpace(capability))] = true
	}
	result := make([]string, 0, len(required))
	for _, capability := range required {
		normalized := strings.ToLower(strings.TrimSpace(capability))
		if missingSet[normalized] {
			result = append(result, normalized)
		}
	}
	return dedupeStrings(result)
}

func processEffectiveCapabilities() uint64 {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		mask, err := parseCapabilityMask(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")))
		if err != nil {
			return 0
		}
		return mask
	}
	return 0
}

func parseCapabilityMask(raw string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(raw), 16, 64)
}

func binaryHasEffectiveCapability(
	ctx context.Context,
	getcapPath string,
	commandPath string,
	capability string,
) bool {
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(checkCtx, getcapPath, commandPath).Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(output), "\n") {
		lower := strings.ToLower(line)
		index := strings.Index(lower, capability+"=")
		if index < 0 {
			continue
		}
		flags := lower[index+len(capability)+1:]
		if end := strings.IndexAny(flags, ", \t"); end >= 0 {
			flags = flags[:end]
		}
		return strings.Contains(flags, "e")
	}
	return false
}

// pythonImports 提取内联 python3 -c 脚本的必需第三方模块，忽略可选依赖。
func pythonImports(def toolrunner.Tool) []string {
	script := inlinePythonScript(def)
	if script == "" {
		return nil
	}
	found := map[string]bool{}
	for _, match := range pythonImportPattern.FindAllStringSubmatch(script, -1) {
		module := strings.TrimSpace(match[1])
		if module == "" {
			module = strings.TrimSpace(match[2])
		}
		if module == "" || optionalPythonModules[module] {
			continue
		}
		found[module] = true
	}
	result := make([]string, 0, len(found))
	for module := range found {
		result = append(result, module)
	}
	sort.Strings(result)
	return result
}

// requiredPythonModules 合并 YAML 显式声明与内联脚本静态扫描到的模块。
func requiredPythonModules(def toolrunner.Tool) []string {
	modules := append([]string(nil), def.RequiresPython...)
	modules = append(modules, pythonImports(def)...)
	return dedupeStrings(modules)
}

// requiredBinaries 合并 YAML 显式声明与包装脚本里 subprocess 调用的外部命令。
func requiredBinaries(def toolrunner.Tool) []string {
	binaries := append([]string(nil), def.RequiresBinaries...)
	binaries = append(binaries, scriptBinaries(def)...)
	return dedupeStrings(binaries)
}

// scriptBinaries 从内联脚本里提取 cmd = ["tool", ...] / subprocess.run(["tool", ...]) 形式的外部命令。
func scriptBinaries(def toolrunner.Tool) []string {
	script := inlinePythonScript(def)
	if script == "" {
		return nil
	}
	found := make([]string, 0, 2)
	for _, pattern := range []*regexp.Regexp{commandListPattern, subprocessListPattern} {
		for _, match := range pattern.FindAllStringSubmatch(script, -1) {
			name := strings.TrimSpace(match[1])
			if name == "" || strings.HasPrefix(name, "-") || isInterpreterCommand(name) {
				continue
			}
			found = append(found, name)
		}
	}
	return found
}

// isInterpreterCommand 跳过解释器与 shell 内建，它们由命令本身或系统保证存在。
func isInterpreterCommand(name string) bool {
	switch strings.ToLower(filepath.Base(name)) {
	case "python", "python3", "sh", "bash", "zsh", "echo", "true", "false", "cat":
		return true
	default:
		return false
	}
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		result = append(result, trimmed)
	}
	if len(result) == 0 {
		return nil
	}
	sort.Strings(result)
	return result
}

func filterMissingBinaries(binaries []string, missing map[string]string) []string {
	result := make([]string, 0, len(binaries))
	for _, binary := range binaries {
		if _, ok := missing[binary]; ok {
			result = append(result, binary)
		}
	}
	return result
}

func inlinePythonScript(def toolrunner.Tool) string {
	if len(def.Args) < 2 || strings.TrimSpace(def.Args[0]) != "-c" {
		return ""
	}
	command := filepath.Base(strings.TrimSpace(def.Command))
	if command != "python3" && command != "python" {
		return ""
	}
	return def.Args[1]
}

func checkPythonModules(ctx context.Context, modules map[string]bool) map[string]bool {
	missing := map[string]bool{}
	if len(modules) == 0 {
		return missing
	}
	list := make([]string, 0, len(modules))
	for module := range modules {
		list = append(list, module)
	}
	sort.Strings(list)
	payload, err := json.Marshal(list)
	if err != nil {
		return missing
	}
	script := "import importlib.util, json, sys\n" +
		"mods = json.loads(sys.argv[1])\n" +
		"missing = [m for m in mods if m not in sys.stdlib_module_names and importlib.util.find_spec(m) is None]\n" +
		"print('\\n'.join(missing))\n"
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	output, runErr := exec.CommandContext(checkCtx, "python3", "-c", script, string(payload)).Output()
	if runErr != nil {
		for _, module := range list {
			missing[module] = true
		}
		return missing
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			missing[line] = true
		}
	}
	return missing
}

func filterMissingModules(modules []string, missing map[string]bool) []string {
	result := make([]string, 0, len(modules))
	for _, module := range modules {
		if missing[module] {
			result = append(result, module)
		}
	}
	return result
}
