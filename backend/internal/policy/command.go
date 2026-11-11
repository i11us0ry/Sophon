package policy

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type CommandAnalysis struct {
	Capability       Capability
	Targets          []string
	Reason           string
	Catastrophic     bool
	Delete           bool
	UnresolvedTarget bool
}

var hostPattern = regexp.MustCompile(
	`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+$`,
)

var (
	pythonURLPattern     = regexp.MustCompile(`(?i)https?://[a-z0-9][a-z0-9._:-]*(?:/[^\s"'<>]*)?`)
	pythonNetworkPattern = regexp.MustCompile(
		`(?i)(?:requests\.(get|post|put|patch|delete|head|options)|httpx\.(get|post|put|patch|delete|head)|` +
			`urllib\.request|urlopen|aiohttp|socket\.(?:create_connection|socket|connect)|http\.client|` +
			`https?connection|subprocess\.|os\.system)`,
	)
	pythonHostPattern = regexp.MustCompile(
		`(?i)(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}`,
	)
	pythonStringPattern     = regexp.MustCompile(`(?s)"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`)
	pythonWriteOpenPattern  = regexp.MustCompile(`(?is)open\s*\([^)]*,\s*['"](?:w|a|x|\+)[^'"]*['"]`)
	pythonSQLLiteralPattern = regexp.MustCompile(
		`(?is)(?:\bselect\b[\s\S]*?\bfrom\b|\binsert\s+into\b|` +
			`\bupdate\s+\S+\s+set\b|\bdelete\s+from\b|\bdeclare\s+@\w+|` +
			`\bexec(?:ute)?\s+[\[(@]|\buse\s+[\[\w])`,
	)
	pythonImportLinePattern     = regexp.MustCompile(`(?m)^\s*import\s+([^\n#]+)`)
	pythonFromImportLinePattern = regexp.MustCompile(
		`(?m)^\s*from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import\b`,
	)
	pythonModulePartPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	shellVariablePattern    = regexp.MustCompile(`(?m)(?:^|;)\s*([A-Za-z_][A-Za-z0-9_]*)=([^\s;]+)`)
	shellExpansionPattern   = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
	shellFunctionPattern    = regexp.MustCompile(`(?m)^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\)`)
	literalIPv4Pattern      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	detachedCommandPattern  = regexp.MustCompile(`(?i)(?:^|[;&|()\n])\s*(?:nohup|setsid|disown|coproc)\b`)
	detachedLauncherPattern = regexp.MustCompile(`(?i)\b(?:nohup|setsid|disown|coproc)\b`)
	pythonDetachPattern     = regexp.MustCompile(`(?i)(?:os\.setsid\s*\(|start_new_session\s*=\s*True|preexec_fn\s*=\s*os\.setsid)`)
	nestedShellPattern      = regexp.MustCompile(`(?i)(?:\b(?:sh|bash|zsh|ksh|dash)\s+-c\b|\beval\b)`)
	heredocDelimiterPattern = regexp.MustCompile(`<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)
)

const (
	maxPythonImportDepth = 4
	maxPythonImportFiles = 20
	maxPythonModuleBytes = 1 << 20
)

var internalDomainSuffixes = []string{
	".corp", ".example", ".home", ".internal", ".intranet", ".lan",
	".local", ".localhost", ".test",
}

// ContainsDetachedLauncher 对 Python 等解释器脚本检查显式脱离会话的调用。
func ContainsDetachedLauncher(script string) bool {
	return pythonDetachPattern.MatchString(strings.TrimSpace(script))
}

func AnalyzeCommand(command string) CommandAnalysis {
	command = strings.TrimSpace(command)
	if command == "" {
		return CommandAnalysis{
			Capability: CapabilityDestructive,
			Reason:     "空命令无法判定安全级别",
		}
	}
	lower := strings.ToLower(command)
	if isCatastrophicCommand(lower) {
		return CommandAnalysis{
			Capability:   CapabilityDestructive,
			Reason:       "命令属于灾难性批量删除或系统破坏操作",
			Catastrophic: true,
			Delete:       true,
		}
	}
	if hasDynamicExecution(lower) {
		return CommandAnalysis{
			Capability: CapabilityDestructive,
			Reason:     "命令包含动态执行或脚本解析，无法静态证明安全",
		}
	}

	worst := CapabilityPassive
	reason := "命令仅进行本地或只读操作"
	targets := map[string]bool{}
	deleteBehavior := false
	unresolvedNetworkTarget := false
	variables := collectShellVariables(command)
	functions := collectShellFunctions(command)
	for _, segment := range splitShellCommands(command) {
		words := shellWords(segment)
		words = expandShellWords(words, variables)
		if isAssignmentOnlySegment(words) {
			continue
		}
		words = unwrapCommandPrefix(words)
		words = stripLeadingShellControlWords(words)
		if len(words) == 0 {
			continue
		}
		if isShellFunctionDefinition(words) {
			continue
		}
		program := strings.ToLower(filepath.Base(strings.TrimSpace(words[0])))
		if functions[program] {
			// 函数体本身会在后续 segment 中被分析；调用点只作为轻量 wrapper。
			continue
		}
		segmentCapability, segmentReason := classifySegment(program, words)
		if isDeleteSegment(program, words) {
			deleteBehavior = true
		}
		if segmentCapability.Rank() > worst.Rank() {
			worst = segmentCapability
			reason = segmentReason
		}
		segmentTargets := extractTargets(program, words)
		if program == "openssl" && len(segmentTargets) == 0 && strings.Contains(segment, "$") {
			// openssl -connect 可能来自 for 循环/函数参数：使用命令中可静态确认的
			// 字面 IP 做授权校验，变量完全动态时仍会 fail-closed。
			segmentTargets = extractLiteralIPv4Targets(command)
		}
		if isNetworkProgram(program, words) &&
			len(segmentTargets) == 0 &&
			!isNetworkInfoCommand(words) {
			unresolvedNetworkTarget = true
		}
		for _, target := range segmentTargets {
			targets[target] = true
		}
	}
	if worst == CapabilityPassive {
		worst = CapabilityRead
	}
	result := CommandAnalysis{
		Capability:       worst,
		Reason:           reason,
		Delete:           deleteBehavior,
		UnresolvedTarget: unresolvedNetworkTarget,
	}
	for target := range targets {
		result.Targets = append(result.Targets, target)
	}
	return result
}

// ContainsDetachedBackground 拒绝 Agent 自行脱离进程树或创建 shell 后台任务。
// Job 执行也复用该检查，确保受控执行器不会变成新的后台逃逸入口。
func ContainsDetachedBackground(command string) bool {
	command = strings.TrimSpace(command)
	if command == "" {
		return false
	}
	heredoc := ""
	for _, line := range strings.Split(command, "\n") {
		trimmed := strings.TrimSpace(line)
		if heredoc != "" {
			if trimmed == heredoc {
				heredoc = ""
			}
			continue
		}
		if detachedCommandPattern.MatchString(line) {
			return true
		}
		if match := heredocDelimiterPattern.FindStringSubmatch(line); len(match) >= 2 {
			heredoc = match[1]
		}
		if containsBackgroundOperator(line, false) {
			return true
		}
		if nestedShellPattern.MatchString(line) {
			if detachedLauncherPattern.MatchString(line) || containsBackgroundOperator(line, true) {
				return true
			}
		}
	}
	return false
}

func containsBackgroundOperator(line string, ignoreQuotes bool) bool {
	var quote rune
	escaped := false
	runes := []rune(line)
	for index, current := range runes {
		if escaped {
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
			continue
		}
		if !ignoreQuotes {
			if quote != 0 {
				if current == quote {
					quote = 0
				}
				continue
			}
			if current == '\'' || current == '"' {
				quote = current
				continue
			}
		}
		if current != '&' {
			continue
		}
		var previous rune
		if index > 0 {
			previous = runes[index-1]
		}
		var next rune
		if index+1 < len(runes) {
			next = runes[index+1]
		}
		switch {
		case previous == '&' || next == '&':
			continue
		case previous == '>':
			continue
		case next == '>':
			continue
		default:
			return true
		}
	}
	return false
}

func stripLeadingShellControlWords(words []string) []string {
	for len(words) > 0 {
		switch strings.ToLower(strings.TrimSpace(words[0])) {
		case "do", "then", "else", "elif", "{":
			words = words[1:]
		default:
			return words
		}
	}
	return words
}

func collectShellFunctions(command string) map[string]bool {
	functions := map[string]bool{}
	for _, match := range shellFunctionPattern.FindAllStringSubmatch(command, -1) {
		if len(match) >= 2 {
			functions[strings.ToLower(match[1])] = true
		}
	}
	return functions
}

func isShellFunctionDefinition(words []string) bool {
	if len(words) == 0 {
		return false
	}
	first := strings.ToLower(strings.TrimSpace(words[0]))
	return strings.HasSuffix(first, "()") ||
		(first == "function" && len(words) > 1 && strings.HasSuffix(strings.ToLower(words[1]), "()"))
}

func extractLiteralIPv4Targets(command string) []string {
	targets := map[string]bool{}
	for _, match := range literalIPv4Pattern.FindAllString(command, -1) {
		if ip := net.ParseIP(match); ip != nil {
			targets[ip.String()] = true
		}
	}
	out := make([]string, 0, len(targets))
	for target := range targets {
		out = append(out, target)
	}
	sort.Strings(out)
	return out
}

func collectShellVariables(command string) map[string]string {
	variables := map[string]string{}
	for _, match := range shellVariablePattern.FindAllStringSubmatch(command, -1) {
		if len(match) == 3 {
			variables[match[1]] = match[2]
		}
	}
	return variables
}

func expandShellWords(words []string, variables map[string]string) []string {
	if len(variables) == 0 {
		return words
	}
	expanded := make([]string, len(words))
	for index, word := range words {
		expanded[index] = shellExpansionPattern.ReplaceAllStringFunc(word, func(match string) string {
			parts := shellExpansionPattern.FindStringSubmatch(match)
			name := ""
			if len(parts) >= 3 {
				name = parts[1]
				if name == "" {
					name = parts[2]
				}
			}
			if value, ok := variables[name]; ok {
				return value
			}
			return match
		})
	}
	return expanded
}

func isAssignmentOnlySegment(words []string) bool {
	if len(words) == 0 {
		return false
	}
	for _, word := range words {
		if !shellVariablePattern.MatchString(" " + word) {
			return false
		}
	}
	return true
}

func isNetworkProgram(program string, words []string) bool {
	switch program {
	case "curl", "wget", "nc", "netcat", "socat", "ssh", "scp", "ftp",
		"dig", "host", "nslookup", "ping", "ping6", "traceroute",
		"traceroute6", "telnet":
		return true
	case "openssl":
		for _, word := range words[1:] {
			switch strings.ToLower(strings.TrimSpace(word)) {
			case "s_client", "s_server", "ocsp":
				return true
			}
		}
		return false
	default:
		return isKnownIntrusiveTool(program)
	}
}

// unwrapCommandPrefix 去掉常见命令包装器，让内部真实程序参与能力与目标判定。
func unwrapCommandPrefix(words []string) []string {
	for len(words) > 0 {
		switch strings.ToLower(strings.TrimSpace(words[0])) {
		case "timeout":
			index := 1
			for index < len(words) && strings.HasPrefix(words[index], "-") {
				switch strings.ToLower(words[index]) {
				case "-k", "-s", "--signal", "--kill-after":
					index += 2
				default:
					index++
				}
			}
			// 再跳过 timeout 的时长参数。
			if index < len(words) {
				index++
			}
			words = words[index:]
		case "env":
			index := 1
			for index < len(words) &&
				(strings.HasPrefix(words[index], "-") || strings.Contains(words[index], "=")) {
				index++
			}
			words = words[index:]
		case "nohup", "command", "exec":
			words = words[1:]
		default:
			return words
		}
	}
	return words
}

func isDurationLike(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') &&
			char != '.' && char != 's' && char != 'm' && char != 'h' &&
			char != 'd' && char != 'w' {
			return false
		}
	}
	return true
}

func isNetworkInfoCommand(words []string) bool {
	for _, word := range words {
		switch strings.ToLower(strings.TrimSpace(word)) {
		case "-h", "--help", "-v", "--version", "-V":
			return true
		}
	}
	return false
}

func isCatastrophicCommand(command string) bool {
	normalized := strings.Join(strings.Fields(strings.ToLower(command)), " ")
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(
			`\brm\s+(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+(?:/\*|/(?:\s|$)|/(?:etc|var|usr|home|root)(?:/|\s|$))`,
		),
		regexp.MustCompile(`\bkubectl\s+delete\s+namespace\b`),
		regexp.MustCompile(`\bkubectl\s+delete\s+.*--all\b`),
		regexp.MustCompile(`\bkubectl\s+delete\s+nodes?\b`),
		regexp.MustCompile(`\bdrop\s+(database|schema)\b`),
		regexp.MustCompile(`\bdd\s+.*\bof=/dev/(sd|nvme|vd|mmcblk)`),
		regexp.MustCompile(`\b(shutdown|reboot|poweroff|halt)\b`),
		regexp.MustCompile(`\bchmod\s+-R\s+777\s+/(?:\s|$)`),
		regexp.MustCompile(`\bchown\s+-R\s+\S+\s+/(?:\s|$)`),
	} {
		if pattern.MatchString(normalized) {
			return true
		}
	}
	return false
}

func AnalyzePythonScript(script string) CommandAnalysis {
	return AnalyzePythonScriptInWorkspace(script, "")
}

func AnalyzePythonScriptInWorkspace(script string, workspace string) CommandAnalysis {
	script = strings.TrimSpace(script)
	if script == "" {
		return CommandAnalysis{
			Capability: CapabilityDestructive,
			Reason:     "空 Python 脚本无法判定安全级别",
		}
	}
	lower := strings.ToLower(script)
	targets, importedNetwork := extractPythonTargetsInWorkspace(script, workspace)
	networkScript := pythonNetworkPattern.MatchString(script) || importedNetwork
	for _, marker := range []string{
		"os.remove", "os.unlink", "os.rmdir", "shutil.rmtree", "unlink(",
		"remove(", "drop table", "delete from", "truncate", "rm -rf",
		"kubectl delete",
	} {
		if strings.Contains(lower, marker) {
			return CommandAnalysis{
				Capability: CapabilityDestructive,
				Reason:     "Python 脚本包含删除或破坏数据操作",
				Delete:     true,
			}
		}
	}
	for _, marker := range []string{
		"subprocess", "os.system", "popen(", "socket", "requests.post",
		"requests.put", "requests.patch", "insert into",
		"update ", "alter table", "create table",
	} {
		if strings.Contains(lower, marker) {
			return CommandAnalysis{
				Capability: CapabilityDestructive,
				Reason:     "Python 脚本包含写入、修改或执行外部命令的操作",
			}
		}
	}
	for _, marker := range []string{
		".write(", ".writelines(", "file_put_contents",
		"mode='w", `mode="w`, "mode='a", `mode="a`, "mode='x", `mode="x`,
	} {
		if strings.Contains(lower, marker) {
			return CommandAnalysis{
				Capability: CapabilityDestructive,
				Reason:     "Python 脚本包含文件写入或修改操作",
			}
		}
	}
	if pythonWriteOpenPattern.MatchString(script) {
		return CommandAnalysis{
			Capability: CapabilityDestructive,
			Reason:     "Python 脚本包含文件写入或修改操作",
		}
	}
	if networkScript || len(targets) > 0 {
		capability := CapabilityRead
		reason := "Python 脚本发起只读网络请求"
		for _, marker := range []string{
			"requests.post", "requests.put", "requests.patch", "requests.delete",
			"httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
		} {
			if strings.Contains(lower, marker) {
				capability = CapabilityDestructive
				reason = "Python 脚本发起写入或数据变更请求"
				break
			}
		}
		return CommandAnalysis{
			Capability:       capability,
			Reason:           reason,
			Targets:          targets,
			UnresolvedTarget: len(targets) == 0,
		}
	}
	return CommandAnalysis{
		Capability: CapabilityRead,
		Reason:     "Python 脚本未检测到写入、删除或系统执行操作",
	}
}

func extractPythonTargets(script string) []string {
	targets, _ := extractPythonTargetsInWorkspace(script, "")
	return targets
}

func extractPythonTargetsInWorkspace(script string, workspace string) ([]string, bool) {
	targets := map[string]bool{}
	networkScript := scanPythonSourceTargets(script, targets)
	if root, ok := resolvePythonWorkspace(workspace); ok {
		walker := &pythonImportWalker{
			root:    root,
			visited: map[string]bool{},
		}
		walker.collectImports(script, 0, targets)
		if walker.network {
			networkScript = true
		}
	}
	out := make([]string, 0, len(targets))
	for target := range targets {
		out = append(out, target)
	}
	sort.Strings(out)
	return out, networkScript
}

func scanPythonSourceTargets(source string, targets map[string]bool) bool {
	networkScript := pythonNetworkPattern.MatchString(source)
	for _, match := range pythonURLPattern.FindAllString(source, -1) {
		parsed, err := url.Parse(strings.TrimSpace(match))
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		if host := normalizeHeaderTarget(parsed.Hostname()); host != "" {
			targets[host] = true
		}
	}
	if !networkScript {
		// Local file processing often contains dotted filenames such as
		// "Kingdee.BOS.FileServer.App.Core.il". Without an actual network
		// operation these are artifacts, not authorization targets. Explicit
		// http(s) URLs above remain traceable across imported modules.
		return false
	}
	for _, literal := range pythonStringPattern.FindAllString(source, -1) {
		if pythonSQLLiteralPattern.MatchString(literal) {
			continue
		}
		hostLiteral := pythonURLPattern.ReplaceAllString(literal, " ")
		for _, match := range pythonHostPattern.FindAllString(hostLiteral, -1) {
			host := strings.ToLower(strings.TrimSpace(match))
			if isScopeAssetHostLiteral(host) && isPlausiblePythonTarget(host) {
				targets[host] = true
			}
		}
		for _, match := range literalIPv4Pattern.FindAllString(literal, -1) {
			if ip := net.ParseIP(match); ip != nil {
				targets[ip.String()] = true
			}
		}
	}
	return true
}

func isScopeAssetHostLiteral(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return true
	}
	return strings.HasSuffix(host, ".com") || strings.HasSuffix(host, ".cn")
}

func isPlausiblePythonTarget(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || isLikelyLocalPath(host) || !isHostLike(host) ||
		isSQLObjectName(host) {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	suffix, icann := publicsuffix.PublicSuffix(host)
	if suffix != "" && suffix != host && (icann || strings.Contains(suffix, ".")) {
		return true
	}
	for _, suffix := range internalDomainSuffixes {
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true
		}
	}
	return false
}

func isSQLObjectName(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if strings.Contains(value, ".dbo.") || strings.HasPrefix(value, "dbo.") {
		return true
	}
	first := strings.SplitN(value, ".", 2)[0]
	switch first {
	case "information_schema", "master", "model", "msdb", "mysql",
		"pg_catalog", "postgres", "sys", "tempdb":
		return true
	default:
		return false
	}
}

type pythonImportWalker struct {
	root    string
	visited map[string]bool
	files   int
	network bool
}

func (w *pythonImportWalker) collectImports(
	source string,
	depth int,
	targets map[string]bool,
) {
	if w == nil || depth >= maxPythonImportDepth || w.files >= maxPythonImportFiles {
		return
	}
	for _, module := range pythonImportedModules(source) {
		path, ok := resolvePythonModule(w.root, module)
		if !ok || w.visited[path] {
			continue
		}
		w.visited[path] = true
		w.files++
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		moduleSource := string(raw)
		if scanPythonSourceTargets(moduleSource, targets) {
			w.network = true
		}
		w.collectImports(moduleSource, depth+1, targets)
	}
}

func pythonImportedModules(source string) []string {
	found := map[string]bool{}
	for _, match := range pythonImportLinePattern.FindAllStringSubmatch(source, -1) {
		if len(match) < 2 {
			continue
		}
		for _, item := range strings.Split(match[1], ",") {
			fields := strings.Fields(strings.TrimSpace(item))
			if len(fields) == 0 {
				continue
			}
			module := strings.TrimSpace(fields[0])
			if validPythonModuleName(module) {
				found[module] = true
			}
		}
	}
	for _, match := range pythonFromImportLinePattern.FindAllStringSubmatch(source, -1) {
		if len(match) >= 2 && validPythonModuleName(match[1]) {
			found[match[1]] = true
		}
	}
	result := make([]string, 0, len(found))
	for module := range found {
		result = append(result, module)
	}
	sort.Strings(result)
	return result
}

func validPythonModuleName(module string) bool {
	parts := strings.Split(strings.TrimSpace(module), ".")
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if !pythonModulePartPattern.MatchString(part) {
			return false
		}
	}
	return true
}

func resolvePythonWorkspace(workspace string) (string, bool) {
	workspace = strings.TrimSpace(workspace)
	if workspace == "" {
		return "", false
	}
	absolute, err := filepath.Abs(workspace)
	if err != nil {
		return "", false
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.IsDir() {
		return "", false
	}
	root, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", false
	}
	return filepath.Clean(root), true
}

func resolvePythonModule(root string, module string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(module), ".")
	if len(parts) == 0 {
		return "", false
	}
	for _, part := range parts {
		if !pythonModulePartPattern.MatchString(part) {
			return "", false
		}
	}
	base := filepath.Join(append([]string{root}, parts...)...)
	for _, candidate := range []string{
		base + ".py",
		filepath.Join(base, "__init__.py"),
	} {
		if path, ok := safePythonModuleFile(root, candidate); ok {
			return path, true
		}
	}
	return "", false
}

func safePythonModuleFile(root string, candidate string) (string, bool) {
	info, err := os.Lstat(candidate)
	if err != nil || info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() || info.Size() > maxPythonModuleBytes {
		return "", false
	}
	realPath, err := filepath.EvalSymlinks(candidate)
	if err != nil || !pathWithinRoot(root, realPath) {
		return "", false
	}
	return realPath, true
}

func pathWithinRoot(root string, target string) bool {
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func isDeleteSegment(program string, words []string) bool {
	lowerWords := make([]string, len(words))
	for index, word := range words {
		lowerWords[index] = strings.ToLower(word)
	}
	switch program {
	case "rm", "rmdir", "shred", "truncate":
		return true
	case "dd":
		for _, word := range lowerWords[1:] {
			if strings.HasPrefix(word, "of=") {
				return true
			}
		}
	case "find":
		if stringInWords(lowerWords, "-delete") {
			return true
		}
	case "xargs":
		if stringInWords(lowerWords, "rm") {
			return true
		}
	case "kubectl":
		return stringInWords(lowerWords, "delete")
	case "helm":
		return stringInWords(lowerWords, "uninstall")
	case "terraform":
		return stringInWords(lowerWords, "destroy")
	case "docker":
		return stringInWords(lowerWords, "rm", "rmi", "prune")
	case "pip", "pip3":
		return stringInWords(lowerWords, "uninstall")
	case "apt", "apt-get":
		return stringInWords(lowerWords, "remove", "purge")
	case "curl", "wget":
		return stringInWords(lowerWords, "delete")
	}
	if isDatabaseProgram(program) {
		for _, word := range lowerWords[1:] {
			if strings.Contains(word, "delete") ||
				strings.Contains(word, "drop") ||
				strings.Contains(word, "truncate") {
				return true
			}
		}
	}
	return false
}

func classifySegment(program string, words []string) (Capability, string) {
	lowerWords := make([]string, len(words))
	for index, word := range words {
		lowerWords[index] = strings.ToLower(word)
	}
	has := func(value string) bool {
		for _, word := range lowerWords[1:] {
			if word == value {
				return true
			}
		}
		return false
	}
	contains := func(value string) bool {
		for _, word := range lowerWords[1:] {
			if strings.Contains(word, value) {
				return true
			}
		}
		return false
	}

	switch program {
	case "rm", "rmdir", "shred", "dd", "truncate", "mkfs", "fdisk",
		"parted", "mkswap", "wipefs", "kill", "pkill", "killall",
		"iptables", "nft", "ufw", "chmod", "chown", "chattr", "mount",
		"umount", "crontab", "useradd", "userdel", "passwd", "visudo":
		return CapabilityDestructive, "命令会修改系统、文件或进程状态"
	case "mv", "cp":
		return CapabilityDestructive, "命令会写入或移动文件"
	}

	switch program {
	case "ls", "cat", "head", "tail", "grep", "rg", "stat", "ps",
		"uname", "id", "whoami", "pwd", "env", "printenv", "df", "du",
		"ss", "netstat", "wc", "file", "strings", "which", "type",
		"echo", "printf", "true", "false", "test", "date", "hostname",
		"basename", "dirname", "realpath", "readlink", "sort", "uniq",
		"cut", "tr", "seq", "cd", "export", "set", "unset", "source",
		"local", "read", "shift", "wait", "for", "while", "until", "if",
		"case", "done", "fi", "esac", "[", "]":
		return CapabilityRead, "命令为只读本地查询"
	}
	// 解释器/运行时的版本与帮助查询是只读操作；执行脚本本身仍按动态执行处理。
	if program == "python" || program == "python3" || program == "node" ||
		program == "ruby" || program == "perl" || program == "php" {
		if len(words) <= 1 || isNetworkInfoCommand(words) ||
			stringInWords(lowerWords[1:], "-v", "--version", "-version") {
			return CapabilityRead, "运行时版本或帮助查询"
		}
		return CapabilityDestructive, "执行脚本或动态代码，无法静态证明安全"
	}
	if program == "find" {
		if has("-delete") || has("-exec") {
			return CapabilityDestructive, "find 命令包含删除或执行动作"
		}
		return CapabilityRead, "find 仅查询文件"
	}
	if program == "sed" {
		if has("-i") {
			return CapabilityDestructive, "sed 会原地修改文件"
		}
		return CapabilityRead, "sed 仅读取并输出内容"
	}
	if program == "git" {
		if stringInWords(lowerWords, "reset", "--hard") ||
			stringInWords(lowerWords, "clean", "-fd", "-f") {
			return CapabilityDestructive, "git 命令会销毁工作区改动"
		}
		if stringInWords(lowerWords, "push", "merge", "rebase", "checkout") {
			return CapabilityDestructive, "git 命令会修改仓库状态"
		}
		return CapabilityRead, "git 命令为只读查询"
	}
	if program == "curl" || program == "wget" {
		if contains("post") || contains("put") || contains("patch") ||
			contains("delete") || contains("--data") || contains("-d") ||
			contains("--form") || contains("-f") || contains("--upload-file") {
			return CapabilityDestructive, "网络命令包含写入或数据变更请求"
		}
		return CapabilityRead, "网络命令为只读请求"
	}
	if program == "ping" || program == "ping6" || program == "traceroute" ||
		program == "traceroute6" || program == "telnet" {
		if len(words) <= 1 || isNetworkInfoCommand(words) {
			return CapabilityRead, "网络连通性查询"
		}
		return CapabilityIntrusive, "命令会对目标发起网络探测"
	}
	if program == "openssl" {
		if len(words) > 1 && strings.EqualFold(strings.TrimSpace(words[1]), "s_client") {
			return CapabilityIntrusive, "OpenSSL 会对目标建立 TLS 连接"
		}
		return CapabilityRead, "OpenSSL 本地证书/编码操作"
	}
	if program == "kubectl" {
		if stringInWords(lowerWords, "get", "describe", "logs", "top", "explain", "api-resources", "version") {
			return CapabilityRead, "kubectl 为只读查询"
		}
		return CapabilityDestructive, "kubectl 命令包含写入或删除动作"
	}
	if program == "helm" {
		if stringInWords(lowerWords, "uninstall", "upgrade", "rollback") {
			return CapabilityDestructive, "helm 命令会修改集群资源"
		}
		return CapabilityRead, "helm 命令为只读查询"
	}
	if program == "terraform" {
		if stringInWords(lowerWords, "apply", "destroy", "import", "state") {
			return CapabilityDestructive, "terraform 命令会修改基础设施"
		}
		return CapabilityRead, "terraform 命令为只读操作"
	}
	if isDatabaseProgram(program) {
		if contains("drop") || contains("delete") || contains("truncate") ||
			contains("update") || contains("insert") || contains("alter") ||
			contains("create") || contains("grant") || contains("revoke") {
			return CapabilityDestructive, "数据库命令包含写入或删除动作"
		}
		return CapabilityRead, "数据库命令为只读查询"
	}
	if isKnownIntrusiveTool(program) {
		return CapabilityIntrusive, "工具会对目标执行主动测试"
	}
	if program == "xargs" && contains("rm") {
		return CapabilityDestructive, "xargs 会批量执行删除"
	}
	return CapabilityDestructive, "命令包含未知程序，无法静态证明安全"
}

func hasDynamicExecution(lower string) bool {
	for _, marker := range []string{
		"$(", "`", "eval ", "sh -c", "bash -c", "zsh -c",
		"python -c", "python3 -c", "perl -e", "ruby -e", "node -e",
		"base64 -d", "base64 --decode", "| sh", "| bash",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func splitShellCommands(command string) []string {
	parts := make([]string, 0, 4)
	var current strings.Builder
	var quote rune
	escaped := false
	runes := []rune(command)
	for index := 0; index < len(runes); index++ {
		char := runes[index]
		if escaped {
			current.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' {
			current.WriteRune(char)
			escaped = true
			continue
		}
		if quote != 0 {
			current.WriteRune(char)
			if char == quote {
				quote = 0
			}
			continue
		}
		switch char {
		case '\'', '"':
			quote = char
			current.WriteRune(char)
		case '\n', ';':
			if strings.TrimSpace(current.String()) != "" {
				parts = append(parts, strings.TrimSpace(current.String()))
			}
			current.Reset()
		case '|':
			if strings.TrimSpace(current.String()) != "" {
				parts = append(parts, strings.TrimSpace(current.String()))
			}
			current.Reset()
		default:
			current.WriteRune(char)
		}
	}
	if strings.TrimSpace(current.String()) != "" {
		parts = append(parts, strings.TrimSpace(current.String()))
	}
	return parts
}

func shellWords(value string) []string {
	var words []string
	var current strings.Builder
	var quote rune
	escaped := false
	for _, char := range value {
		if escaped {
			current.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				current.WriteRune(char)
			}
			continue
		}
		switch char {
		case '\'', '"':
			quote = char
		case ' ', '\t':
			if current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(char)
		}
	}
	if current.Len() > 0 {
		words = append(words, current.String())
	}
	return words
}

func stringInWords(words []string, values ...string) bool {
	for _, word := range words {
		for _, value := range values {
			if strings.EqualFold(word, value) {
				return true
			}
		}
	}
	return false
}

func isDatabaseProgram(program string) bool {
	switch program {
	case "mysql", "psql", "sqlite3", "mongo", "mongosh", "redis-cli":
		return true
	default:
		return false
	}
}

func extractTargets(program string, words []string) []string {
	// 只从真正会发起网络请求的程序中提取目标；本地命令里的文件名、
	// 日志片段和测试字符串不应被误判为未授权目标。
	if !isNetworkProgram(program, words) {
		return nil
	}
	targets := map[string]bool{}
	for index, word := range words {
		word = strings.Trim(strings.TrimSpace(word), `"'`)
		// --request-target 是请求行 Payload，不是实际网络目的地。
		if strings.HasPrefix(strings.ToLower(word), "--request-target=") {
			continue
		}
		// curl --resolve host:port:address：host 是实际请求目标。
		if index > 0 && strings.EqualFold(strings.TrimSpace(words[index-1]), "--resolve") {
			if resolved := resolveOptionTargets(word); len(resolved) > 0 {
				for _, target := range resolved {
					targets[target] = true
				}
				continue
			}
		}
		// curl -H 'Host: x' / 'Referer: x' 的 host 值属于请求目标边界。
		if headerName, headerValue, ok := strings.Cut(word, ":"); ok {
			switch strings.ToLower(strings.TrimSpace(headerName)) {
			case "host":
				if host := normalizeHeaderTarget(headerValue); host != "" {
					targets[host] = true
					continue
				}
			case "referer":
				if parsed, err := url.Parse(strings.TrimSpace(headerValue)); err == nil {
					if host := normalizeHeaderTarget(parsed.Hostname()); host != "" {
						targets[host] = true
						continue
					}
				}
			}
		}
		if strings.HasPrefix(word, "-") {
			continue
		}
		if isNetworkOptionValue(words, index) {
			continue
		}
		// 去掉 URL 尾部的 shell 变量（如 http://host$path），只校验可静态确认的 host。
		staticWord := stripShellExpansion(word)
		if parsed, err := url.Parse(staticWord); err == nil && parsed.Hostname() != "" {
			host := strings.ToLower(parsed.Hostname())
			if isHostLike(host) {
				targets[host] = true
			}
			continue
		}
		if isLikelyLocalPath(word) {
			continue
		}
		host := word
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
		host = strings.Trim(strings.TrimSpace(host), "[]")
		if isHostLike(host) {
			targets[strings.ToLower(host)] = true
		}
	}
	out := make([]string, 0, len(targets))
	for target := range targets {
		out = append(out, target)
	}
	return out
}

func stripShellExpansion(value string) string {
	if index := strings.IndexAny(value, "$`"); index >= 0 {
		return strings.TrimRight(value[:index], "/?&=;")
	}
	return value
}

func resolveOptionTargets(value string) []string {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	if value == "" {
		return nil
	}
	// --resolve 的格式是 host:port:address，host 与 address 都必须通过授权校验。
	hostPart := value
	addressPart := ""
	if strings.HasPrefix(value, "[") {
		if end := strings.Index(value, "]"); end > 0 {
			hostPart = value[1:end]
			rest := strings.TrimPrefix(value[end+1:], ":")
			if fields := strings.SplitN(rest, ":", 2); len(fields) == 2 {
				addressPart = strings.Trim(fields[1], "[]")
			}
		}
	} else if fields := strings.SplitN(value, ":", 3); len(fields) == 3 {
		hostPart = fields[0]
		addressPart = fields[2]
	}
	targets := make([]string, 0, 2)
	if host := strings.ToLower(strings.TrimSpace(hostPart)); isHostLike(host) {
		targets = append(targets, host)
	}
	if address := strings.Trim(strings.TrimSpace(addressPart), "[]"); net.ParseIP(address) != nil {
		targets = append(targets, address)
	}
	return targets
}

func normalizeHeaderTarget(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = strings.Trim(host, "[]")
	}
	if isHostLike(value) {
		return value
	}
	return ""
}

func isNetworkOptionValue(words []string, index int) bool {
	if index <= 0 || index >= len(words) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(words[index-1])) {
	case "-o", "-O", "--output", "--output-document", "-i", "--input-file",
		"--post-file", "--cert", "--key", "--cacert", "--config",
		"--request-target", "-servername", "--servername":
		return true
	case "-h", "--header":
		// 请求头里的 Host/Referer 也是授权边界的一部分，不能被当作普通参数跳过。
		lower := strings.ToLower(strings.TrimSpace(words[index]))
		return !strings.HasPrefix(lower, "host:") && !strings.HasPrefix(lower, "referer:")
	default:
		return false
	}
}

func isLikelyLocalPath(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if strings.Contains(lower, "/") || strings.Contains(lower, `\\`) {
		return true
	}
	extension := strings.TrimPrefix(filepath.Ext(lower), ".")
	return localFileExtensions[extension]
}

var localFileExtensions = map[string]bool{
	"7z": true, "apk": true, "asp": true, "aspx": true, "bin": true,
	"bak": true, "bmp": true, "class": true, "conf": true, "crt": true, "css": true,
	"csv": true, "dll": true, "doc": true, "docx": true, "dylib": true,
	"exe": true, "gif": true, "gz": true, "go": true, "html": true,
	"ico": true, "ini": true, "ipa": true, "jar": true, "jpeg": true,
	"jpg": true, "js": true, "json": true, "jsp": true, "jspx": true,
	"key": true, "log": true, "md": true, "new": true, "old": true,
	"out": true, "pem": true, "pdf": true, "pid": true,
	"php": true, "png": true, "ppt": true, "pptx": true, "py": true,
	"rar": true, "sh": true, "so": true, "sql": true, "svg": true,
	"swp": true, "tar": true, "tmp": true, "toml": true, "ts": true, "txt": true, "war": true,
	"webp": true, "xls": true, "xlsx": true, "xml": true, "yaml": true,
	"yml": true, "zip": true,
}

func isHostLike(value string) bool {
	if ip := net.ParseIP(value); ip != nil {
		return true
	}
	return hostPattern.MatchString(value)
}
