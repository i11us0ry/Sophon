package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	einojsonschema "github.com/eino-contrib/jsonschema"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"sophon/internal/execctx"
)

type ExecutionRecorder interface {
	StartToolExecution(
		ctx context.Context,
		conversationID string,
		userID string,
		toolName string,
		args map[string]interface{},
	) string
	FinishToolExecution(ctx context.Context, id, result string, invokeErr error)
}

type ToolInterceptor func(
	ctx context.Context,
	serverName string,
	toolName string,
	args map[string]interface{},
) error

type toolInterceptorContextKey struct{}

func WithToolInterceptor(ctx context.Context, interceptor ToolInterceptor) context.Context {
	return context.WithValue(ctx, toolInterceptorContextKey{}, interceptor)
}

type Client struct {
	serverName     string
	command        string
	args           []string
	env            []string
	connectTimeout time.Duration
	callTimeout    time.Duration
	session        *sdkmcp.ClientSession
	sessionCancel  context.CancelFunc
	recorder       ExecutionRecorder
	limiter        *ConcurrencyLimiter
}

type bridgeTool struct {
	session     *sdkmcp.ClientSession
	recorder    ExecutionRecorder
	serverName  string
	name        string
	info        *schema.ToolInfo
	callTimeout time.Duration
	limiter     *ConcurrencyLimiter
}

func New(command string, args []string, connectTimeout, callTimeout time.Duration) *Client {
	if connectTimeout <= 0 {
		connectTimeout = 20 * time.Second
	}
	if callTimeout <= 0 {
		callTimeout = 30 * time.Second
	}
	return &Client{
		command:        strings.TrimSpace(command),
		args:           append([]string(nil), args...),
		connectTimeout: connectTimeout,
		callTimeout:    callTimeout,
	}
}

func (c *Client) Connect(ctx context.Context) error {
	if c.session != nil {
		return nil
	}
	if c.command == "" {
		return fmt.Errorf("MCP command is empty")
	}

	sessionCtx, cancel := context.WithCancel(context.Background())
	type result struct {
		session *sdkmcp.ClientSession
		err     error
	}
	resultCh := make(chan result, 1)

	go func() {
		client := sdkmcp.NewClient(&sdkmcp.Implementation{
			Name:    "sophon-backend",
			Version: "0.1.0",
		}, nil)
		command := exec.Command(c.command, c.args...)
		if len(c.env) > 0 {
			command.Env = append(os.Environ(), c.env...)
		}
		session, err := client.Connect(
			sessionCtx,
			&sdkmcp.CommandTransport{
				Command: command,
			},
			nil,
		)
		if err != nil {
			resultCh <- result{err: err}
			return
		}
		select {
		case resultCh <- result{session: session}:
		case <-sessionCtx.Done():
			_ = session.Close()
		}
	}()

	select {
	case connectResult := <-resultCh:
		if connectResult.err != nil {
			cancel()
			return fmt.Errorf("connect MCP server: %w", connectResult.err)
		}
		c.session = connectResult.session
		c.sessionCancel = cancel
		return nil
	case <-time.After(c.connectTimeout):
		cancel()
		return fmt.Errorf("connect MCP server timeout")
	case <-ctx.Done():
		cancel()
		return ctx.Err()
	}
}

func (c *Client) Close() error {
	if c.sessionCancel != nil {
		c.sessionCancel()
		c.sessionCancel = nil
	}
	if c.session == nil {
		return nil
	}
	err := c.session.Close()
	c.session = nil
	return err
}

func (c *Client) SetExecutionRecorder(recorder ExecutionRecorder) {
	c.recorder = recorder
}

func (c *Client) SetServerName(serverName string) {
	c.serverName = strings.TrimSpace(serverName)
}

func (c *Client) SetEnv(env []string) {
	c.env = append([]string(nil), env...)
}

func (c *Client) SetLimiter(limiter *ConcurrencyLimiter) {
	c.limiter = limiter
}

func (c *Client) EinoTools(ctx context.Context) ([]tool.BaseTool, error) {
	if c.session == nil {
		return nil, fmt.Errorf("MCP server is not connected")
	}

	listCtx, cancel := context.WithTimeout(ctx, c.callTimeout)
	defer cancel()
	result, err := c.session.ListTools(listCtx, nil)
	if err != nil {
		return nil, fmt.Errorf("MCP tools/list: %w", err)
	}

	tools := make([]tool.BaseTool, 0, len(result.Tools))
	for _, definition := range result.Tools {
		info, err := toEinoToolInfo(definition)
		if err != nil {
			return nil, fmt.Errorf("convert MCP tool %q: %w", definition.Name, err)
		}
		tools = append(tools, &bridgeTool{
			session:     c.session,
			recorder:    c.recorder,
			serverName:  c.serverName,
			name:        definition.Name,
			info:        info,
			callTimeout: c.callTimeout,
			limiter:     c.limiter,
		})
	}
	return tools, nil
}

func (t *bridgeTool) Info(_ context.Context) (*schema.ToolInfo, error) {
	return t.info, nil
}

// MCPServerName 返回工具所属 MCP 服务名，供上层建立 server__tool 限定名索引。
func (t *bridgeTool) MCPServerName() string {
	return t.serverName
}

func (t *bridgeTool) InvokableRun(
	ctx context.Context,
	argumentsInJSON string,
	_ ...tool.Option,
) (string, error) {
	arguments := map[string]interface{}{}
	if strings.TrimSpace(argumentsInJSON) != "" && argumentsInJSON != "null" {
		if err := json.Unmarshal([]byte(argumentsInJSON), &arguments); err != nil {
			return "", fmt.Errorf("parse arguments for %s: %w", t.name, err)
		}
	}

	if interceptor, ok := ctx.Value(toolInterceptorContextKey{}).(ToolInterceptor); ok && interceptor != nil {
		if err := interceptor(ctx, t.serverName, t.name, arguments); err != nil {
			return "", err
		}
	}

	executionID := ""
	if t.recorder != nil {
		executionID = t.recorder.StartToolExecution(
			ctx,
			execctx.ConversationID(ctx),
			execctx.UserID(ctx),
			t.name,
			arguments,
		)
	}

	release, err := t.limiter.acquire(ctx, t.callTimeout)
	if err != nil {
		if t.recorder != nil {
			t.recorder.FinishToolExecution(ctx, executionID, "", err)
		}
		return "", err
	}
	defer release()

	callCtx, cancel := context.WithTimeout(ctx, t.callTimeout)
	defer cancel()
	result, err := t.session.CallTool(callCtx, &sdkmcp.CallToolParams{
		Name:      t.name,
		Arguments: arguments,
	})
	if err != nil {
		if t.recorder != nil {
			t.recorder.FinishToolExecution(ctx, executionID, "", err)
		}
		return "", fmt.Errorf("call MCP tool %s: %w", t.name, err)
	}
	text, err := resultText(result)
	if err != nil {
		if t.recorder != nil {
			t.recorder.FinishToolExecution(ctx, executionID, "", err)
		}
		return "", err
	}
	if result.IsError {
		failure := fmt.Errorf("MCP tool %s failed: %s", t.name, text)
		if t.recorder != nil {
			t.recorder.FinishToolExecution(ctx, executionID, text, failure)
		}
		return text, failure
	}
	if t.recorder != nil {
		t.recorder.FinishToolExecution(ctx, executionID, text, nil)
	}
	return text, nil
}

func toEinoToolInfo(definition *sdkmcp.Tool) (*schema.ToolInfo, error) {
	raw, err := json.Marshal(definition.InputSchema)
	if err != nil {
		return nil, err
	}
	var inputSchema einojsonschema.Schema
	if err := json.Unmarshal(raw, &inputSchema); err != nil {
		return nil, err
	}
	if inputSchema.Type == "" {
		inputSchema.Type = string(schema.Object)
	}
	return &schema.ToolInfo{
		Name:        definition.Name,
		Desc:        definition.Description,
		ParamsOneOf: schema.NewParamsOneOfByJSONSchema(&inputSchema),
	}, nil
}

func resultText(result *sdkmcp.CallToolResult) (string, error) {
	if result == nil {
		return "", nil
	}
	parts := make([]string, 0, len(result.Content))
	for _, content := range result.Content {
		if text, ok := content.(*sdkmcp.TextContent); ok {
			parts = append(parts, text.Text)
			continue
		}
		raw, err := json.Marshal(content)
		if err != nil {
			return "", err
		}
		parts = append(parts, string(raw))
	}
	if len(parts) > 0 {
		return strings.Join(parts, "\n"), nil
	}
	if result.StructuredContent == nil {
		return "", nil
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
