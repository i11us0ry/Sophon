package toolrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"sophon/internal/policy"
)

const defaultMaxOutputBytes = 256 * 1024

// defaultRunTimeout 是 runner 全局默认超时上限；工具可用 timeout_seconds 收紧。
const defaultRunTimeout = 900 * time.Second

type Executor struct {
	Timeout        time.Duration
	MaxOutputBytes int
	WorkspaceRoot  string
}

type Result struct {
	Command     string
	ExitCode    int
	Output      string
	TimedOut    bool
	CPUSeconds  float64
	BudgetToken string
}

// Run 按工具定义拼装参数并执行外部命令，返回输出与退出码。
func (e *Executor) Run(ctx context.Context, item Tool, args map[string]any) (*Result, error) {
	command := strings.TrimSpace(item.Command)
	if command == "" {
		return nil, fmt.Errorf("工具 %s 未配置命令", item.Name)
	}
	if item.Name == "exec" {
		if raw := strings.TrimSpace(stringMapValue(args, "command")); policy.ContainsDetachedBackground(raw) {
			return nil, fmt.Errorf("禁止通过 nohup、setsid、disown 或后台 & 启动进程；请使用 job(action=start) 分步执行")
		}
	}
	if item.Name == "execute-python-script" &&
		policy.ContainsDetachedLauncher(stringMapValue(args, "script")) {
		return nil, fmt.Errorf("禁止 Python 脚本通过 setsid 或 start_new_session 脱离 Worker 进程组")
	}
	cpuSeconds := intMapValue(args, "_sophon_max_cpu_seconds")
	maxProcesses := intMapValue(args, "_sophon_max_processes")
	budgetToken := strings.TrimSpace(stringMapValue(args, "_sophon_budget_token"))
	preparedArgs, workspace, conversationWorkspace, err := e.prepareWorkspace(args)
	if err != nil {
		return nil, err
	}
	built, err := BuildArgs(item, preparedArgs)
	if err != nil {
		return nil, err
	}
	timeout := e.resolveTimeout(item)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// nmap 的 scan_type 会整段替换默认扫描参数，与 CS AI 行为保持一致。
	baseArgs := item.Args
	if item.Name == "nmap" {
		if raw, ok := args["scan_type"].(string); ok && strings.TrimSpace(raw) != "" {
			baseArgs = nil
		}
	}
	full := append(append([]string(nil), baseArgs...), built...)
	cmd := exec.CommandContext(runCtx, command, full...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		return os.ErrProcessDone
	}
	cmd.WaitDelay = 2 * time.Second
	if workspace != "" {
		cmd.Dir = workspace
		cmd.Env = workspaceEnvironment(workspace, conversationWorkspace)
	}
	output := newBoundedOutputBuffer(e.maxOutputBytes())
	cmd.Stdout = output
	cmd.Stderr = output
	runErr := cmd.Start()
	started := runErr == nil
	var budgetWatch *processBudgetWatch
	if started {
		budgetWatch = startProcessBudgetWatch(cmd.Process.Pid, cpuSeconds, maxProcesses)
		runErr = cmd.Wait()
	}
	budgetReason := ""
	if budgetWatch != nil {
		budgetReason = budgetWatch.Stop()
	}
	leftoverProcesses := false
	if started {
		leftoverProcesses = cleanupProcessGroup(cmd.Process.Pid)
	}

	cpuSecondsUsed := 0.0
	if started && cmd.ProcessState != nil {
		cpuSecondsUsed = processCPUSeconds(cmd.ProcessState)
	}
	result := &Result{
		Command:     commandLine(command, full),
		Output:      output.String(),
		CPUSeconds:  cpuSecondsUsed,
		BudgetToken: budgetToken,
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		result.TimedOut = true
		result.ExitCode = -1
		return result, fmt.Errorf("工具执行超时（%s）", timeout)
	}
	if budgetReason != "" {
		result.ExitCode = -1
		return result, fmt.Errorf("工具进程组超出预算：%s", budgetReason)
	}
	if leftoverProcesses {
		result.ExitCode = -1
		return result, fmt.Errorf("命令主进程退出后仍有后台子进程，已终止整个进程组")
	}
	if runErr == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		if allowedExitCode(item, result.ExitCode) {
			return result, nil
		}
		return result, fmt.Errorf("命令退出码 %d", result.ExitCode)
	}
	return result, fmt.Errorf("执行 %s 失败: %w", command, runErr)
}

// resolveTimeout 计算单次执行超时：全局上限优先，工具级 timeout_seconds 只收紧不放宽。
func (e *Executor) resolveTimeout(item Tool) time.Duration {
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = defaultRunTimeout
	}
	if item.TimeoutSeconds > 0 {
		if toolTimeout := time.Duration(item.TimeoutSeconds) * time.Second; toolTimeout < timeout {
			timeout = toolTimeout
		}
	}
	return timeout
}

func (e *Executor) prepareWorkspace(
	args map[string]any,
) (map[string]any, string, string, error) {
	prepared := make(map[string]any, len(args))
	for key, value := range args {
		prepared[key] = value
	}
	workspace := strings.TrimSpace(stringMapValue(prepared, "_sophon_workspace"))
	if workspace == "" {
		workspace = strings.TrimSpace(stringMapValue(prepared, "workdir"))
	}
	if workspace == "" && strings.TrimSpace(e.WorkspaceRoot) != "" {
		workspace = filepath.Join(filepath.Clean(e.WorkspaceRoot), "default")
	}
	if workspace == "" {
		return prepared, "", "", nil
	}
	absolute, err := e.resolveWorkspace(workspace)
	if err != nil {
		return nil, "", "", err
	}
	conversationWorkspace := strings.TrimSpace(stringMapValue(prepared, "_sophon_conversation_workspace"))
	if conversationWorkspace == "" {
		conversationWorkspace = workspace
	}
	conversationAbsolute, err := e.resolveWorkspace(conversationWorkspace)
	if err != nil {
		return nil, "", "", err
	}
	for key, value := range prepared {
		if strings.HasPrefix(key, "_sophon_") {
			continue
		}
		prepared[key] = rewriteWorkspaceValue(value, absolute)
	}
	delete(prepared, "_sophon_workspace")
	delete(prepared, "_sophon_conversation_workspace")
	delete(prepared, "_sophon_conversation_id")
	delete(prepared, "_sophon_max_cpu_seconds")
	delete(prepared, "_sophon_max_processes")
	delete(prepared, "_sophon_budget_token")
	return prepared, absolute, conversationAbsolute, nil
}

func (e *Executor) resolveWorkspace(workspace string) (string, error) {
	absolute, err := filepath.Abs(workspace)
	if err != nil {
		return "", fmt.Errorf("解析会话工作区失败: %w", err)
	}
	if root := strings.TrimSpace(e.WorkspaceRoot); root != "" {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			return "", fmt.Errorf("解析工作区根目录失败: %w", err)
		}
		lexicalRelative, err := filepath.Rel(rootAbs, absolute)
		if err != nil ||
			lexicalRelative == ".." ||
			strings.HasPrefix(lexicalRelative, ".."+string(filepath.Separator)) ||
			filepath.IsAbs(lexicalRelative) {
			return "", fmt.Errorf("会话工作区超出允许目录")
		}
		if err := os.MkdirAll(rootAbs, 0o700); err != nil {
			return "", fmt.Errorf("创建工作区根目录失败: %w", err)
		}
		if err := os.MkdirAll(absolute, 0o700); err != nil {
			return "", fmt.Errorf("创建会话工作区失败: %w", err)
		}
		realRoot, err := filepath.EvalSymlinks(rootAbs)
		if err != nil {
			return "", fmt.Errorf("读取工作区根目录失败: %w", err)
		}
		realWorkspace, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return "", fmt.Errorf("读取会话工作区失败: %w", err)
		}
		relative, err := filepath.Rel(realRoot, realWorkspace)
		if err != nil ||
			relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) ||
			filepath.IsAbs(relative) {
			return "", fmt.Errorf("会话工作区超出允许目录")
		}
	} else if err := os.MkdirAll(absolute, 0o700); err != nil {
		return "", fmt.Errorf("创建会话工作区失败: %w", err)
	}
	return absolute, nil
}

func stringMapValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func intMapValue(values map[string]any, key string) int {
	switch value := values[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case json.Number:
		parsed, _ := value.Int64()
		return int(parsed)
	default:
		return 0
	}
}

type processBudgetWatch struct {
	once   sync.Once
	stop   chan struct{}
	done   chan struct{}
	mu     sync.Mutex
	reason string
}

func newProcessBudgetWatch() *processBudgetWatch {
	return &processBudgetWatch{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
}

func (w *processBudgetWatch) setReason(reason string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	if w.reason == "" {
		w.reason = strings.TrimSpace(reason)
	}
	w.mu.Unlock()
}

func (w *processBudgetWatch) Stop() string {
	if w == nil {
		return ""
	}
	w.once.Do(func() { close(w.stop) })
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reason
}

func workspaceEnvironment(workspace string, conversationWorkspace string) []string {
	values := map[string]string{
		"HOME":                          workspace,
		"SOPHON_WORKSPACE":              workspace,
		"SOPHON_CONVERSATION_WORKSPACE": conversationWorkspace,
		"TMP":                           workspace,
		"TEMP":                          workspace,
		"TMPDIR":                        workspace,
		"XDG_CACHE_HOME":                filepath.Join(workspace, ".cache"),
		"XDG_CONFIG_HOME":               filepath.Join(workspace, ".config"),
		"XDG_DATA_HOME":                 filepath.Join(workspace, ".local", "share"),
	}
	env := os.Environ()
	for key, value := range values {
		env = setEnvironmentValue(env, key, value)
	}
	return env
}

func setEnvironmentValue(env []string, key string, value string) []string {
	prefix := key + "="
	for index, item := range env {
		if strings.HasPrefix(item, prefix) {
			env[index] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func rewriteWorkspaceValue(value any, workspace string) any {
	switch typed := value.(type) {
	case string:
		return rewriteTemporaryPaths(typed, workspace)
	case []string:
		result := make([]string, len(typed))
		for index, item := range typed {
			result[index] = rewriteTemporaryPaths(item, workspace)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = rewriteWorkspaceValue(item, workspace)
		}
		return result
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = rewriteWorkspaceValue(item, workspace)
		}
		return result
	default:
		return value
	}
}

var temporaryPathPattern = regexp.MustCompile(`/tmp(?:/[^\s"'` + "`" + `;|&<>()]*)?`)

func rewriteTemporaryPaths(value string, workspace string) string {
	if strings.TrimSpace(value) == "" {
		return value
	}
	matches := temporaryPathPattern.FindAllStringIndex(value, -1)
	if len(matches) == 0 {
		return value
	}
	var builder strings.Builder
	last := 0
	for _, match := range matches {
		start, end := match[0], match[1]
		if start > 0 && isPathTokenByte(value[start-1]) {
			continue
		}
		if end < len(value) && isPathTokenByte(value[end]) {
			continue
		}
		builder.WriteString(value[last:start])
		suffix := strings.TrimPrefix(value[start:end], "/tmp")
		builder.WriteString(workspace + suffix)
		last = end
	}
	if last == 0 {
		return value
	}
	builder.WriteString(value[last:])
	return builder.String()
}

func isPathTokenByte(value byte) bool {
	return value == '/' ||
		value == '\\' ||
		value == '.' ||
		value == '-' ||
		value == '_' ||
		(value >= 'a' && value <= 'z') ||
		(value >= 'A' && value <= 'Z') ||
		(value >= '0' && value <= '9')
}

func (e *Executor) maxOutputBytes() int {
	if e.MaxOutputBytes > 0 {
		return e.MaxOutputBytes
	}
	return defaultMaxOutputBytes
}

type boundedOutputBuffer struct {
	mu    sync.Mutex
	limit int
	total int64
	data  bytes.Buffer
}

func newBoundedOutputBuffer(limit int) *boundedOutputBuffer {
	if limit <= 0 {
		limit = defaultMaxOutputBytes
	}
	return &boundedOutputBuffer{limit: limit}
}

func (b *boundedOutputBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := len(value)
	b.total += int64(written)
	if remaining := b.limit - b.data.Len(); remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = b.data.Write(value)
	}
	return written, nil
}

func (b *boundedOutputBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.total <= int64(b.limit) {
		return b.data.String()
	}
	return b.data.String() + fmt.Sprintf(
		"\n...(输出超过 %d 字节，已截断)",
		b.limit,
	)
}

// BuildArgs 按 YAML 定义把模型参数转为命令行参数。
func BuildArgs(item Tool, args map[string]any) ([]string, error) {
	values := make(map[string]any, len(args)+len(item.Parameters))
	for key, value := range args {
		values[key] = value
	}
	for _, param := range item.Parameters {
		if _, ok := values[param.Name]; !ok && param.Default != nil {
			values[param.Name] = param.Default
		}
	}

	// 没有参数定义时使用固定参数 + --key value 的通用拼装。
	if len(item.Parameters) == 0 {
		out := make([]string, 0, len(values))
		for key, value := range values {
			if key == "_tool_name" || value == nil {
				continue
			}
			out = append(out, "--"+key, scalarText(value))
		}
		return out, nil
	}

	var flags []string
	positional := map[int]string{}
	maxPosition := 0
	for _, param := range item.Parameters {
		if specialParam(param.Name) {
			continue
		}
		value, ok, err := paramValue(param, values)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if strings.EqualFold(param.Type, "bool") && param.Position == nil {
			if truthy(value) && param.Flag != "" {
				flags = append(flags, param.Flag)
			}
			continue
		}
		formatted := formatValue(param, value)
		if strings.TrimSpace(formatted) == "" {
			continue
		}
		if param.Position != nil {
			position := *param.Position
			positional[position] = formatted
			if position > maxPosition {
				maxPosition = position
			}
			continue
		}
		flags = append(flags, formatFlag(param, formatted)...)
	}

	out := make([]string, 0, len(flags)+maxPosition+2)
	if value, ok := positional[0]; ok {
		out = append(out, value)
	}
	out = append(out, flags...)
	for index := 1; index <= maxPosition; index++ {
		if value, ok := positional[index]; ok {
			out = append(out, value)
		}
	}
	if raw, ok := values["additional_args"].(string); ok && strings.TrimSpace(raw) != "" {
		out = append(out, parseAdditionalArgs(raw)...)
	}
	if raw, ok := values["scan_type"].(string); ok && strings.TrimSpace(raw) != "" {
		extra := parseAdditionalArgs(raw)
		if len(extra) > 0 {
			if item.Name == "nmap" {
				out = append(extra, out...)
			} else {
				out = insertBeforeLastPositional(out, extra)
			}
		}
	}
	return out, nil
}

func paramValue(param Parameter, values map[string]any) (any, bool, error) {
	if value, ok := values[param.Name]; ok && value != nil {
		if text, isText := value.(string); !isText || strings.TrimSpace(text) != "" {
			return value, true, nil
		}
	}
	if param.Default != nil {
		return param.Default, true, nil
	}
	if param.Required {
		return nil, false, fmt.Errorf("缺少必需参数 %s", param.Name)
	}
	return nil, false, nil
}

func formatFlag(param Parameter, value string) []string {
	format := strings.ToLower(strings.TrimSpace(param.Format))
	if format == "" {
		format = "flag"
	}
	switch format {
	case "combined":
		if param.Flag == "" {
			return []string{value}
		}
		return []string{param.Flag + "=" + value}
	case "template":
		if param.Template == "" {
			if param.Flag == "" {
				return []string{value}
			}
			return []string{param.Flag, value}
		}
		expanded := strings.NewReplacer(
			"{flag}", param.Flag,
			"{value}", value,
			"{name}", param.Name,
		).Replace(param.Template)
		return strings.Fields(expanded)
	case "positional":
		return []string{value}
	default:
		if param.Flag == "" {
			return []string{value}
		}
		return []string{param.Flag, value}
	}
}

func formatValue(param Parameter, value any) string {
	switch strings.ToLower(strings.TrimSpace(param.Type)) {
	case "array":
		switch items := value.(type) {
		case []any:
			parts := make([]string, 0, len(items))
			for _, entry := range items {
				parts = append(parts, scalarText(entry))
			}
			return strings.Join(parts, ",")
		case []string:
			return strings.Join(items, ",")
		}
	case "object":
		// 模型常把 object 参数直接传成 JSON 字符串，此时原样透传，避免二次编码。
		if text, ok := value.(string); ok {
			trimmed := strings.TrimSpace(text)
			if trimmed == "" {
				return ""
			}
			if json.Valid([]byte(trimmed)) {
				return trimmed
			}
			return text
		}
		if raw, err := json.Marshal(value); err == nil {
			return string(raw)
		}
	case "int", "integer":
		if number, ok := value.(float64); ok {
			return strconv.FormatInt(int64(number), 10)
		}
	case "bool":
		if truthy(value) {
			return "true"
		}
		return "false"
	}
	text := scalarText(value)
	if param.Name == "ports" {
		text = strings.ReplaceAll(text, " ", "")
	}
	return text
}

func scalarText(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprintf("%v", value)
}

func truthy(value any) bool {
	switch item := value.(type) {
	case bool:
		return item
	case float64:
		return item != 0
	case int:
		return item != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(item)) {
		case "true", "1", "yes", "on":
			return true
		}
	}
	return false
}

func specialParam(name string) bool {
	switch name {
	case "additional_args", "scan_type", "action", "shell", "workdir":
		return true
	}
	return false
}

// parseAdditionalArgs 按空格切分额外参数，保留引号内的空格。
func parseAdditionalArgs(input string) []string {
	runes := []rune(input)
	out := make([]string, 0, 4)
	var current strings.Builder
	var quote rune
	for index := 0; index < len(runes); index++ {
		char := runes[index]
		if char == '\\' && index+1 < len(runes) && (runes[index+1] == '"' || runes[index+1] == '\'') {
			index++
			current.WriteRune(runes[index])
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
				continue
			}
			current.WriteRune(char)
			continue
		}
		switch char {
		case '"', '\'':
			quote = char
		case ' ', '\t', '\n':
			if current.Len() > 0 {
				out = append(out, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(char)
		}
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}

// insertBeforeLastPositional 把额外参数插到最后一个位置参数之前（scan_type 用）。
func insertBeforeLastPositional(args []string, extra []string) []string {
	index := len(args)
	for position := len(args) - 1; position >= 0; position-- {
		if !strings.HasPrefix(args[position], "-") {
			index = position
			break
		}
	}
	out := make([]string, 0, len(args)+len(extra))
	out = append(out, args[:index]...)
	out = append(out, extra...)
	out = append(out, args[index:]...)
	return out
}

func allowedExitCode(item Tool, code int) bool {
	for _, allowed := range item.AllowedExitCodes {
		if allowed == code {
			return true
		}
	}
	return false
}

func truncateOutput(output string, limit int) string {
	if limit <= 0 || len(output) <= limit {
		return output
	}
	cut := output[:limit]
	return cut + fmt.Sprintf("\n...(输出超过 %d 字节，已截断)", limit)
}

func commandLine(command string, args []string) string {
	parts := append([]string{command}, args...)
	return strings.Join(parts, " ")
}
