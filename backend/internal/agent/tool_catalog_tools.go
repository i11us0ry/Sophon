package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

func newToolCatalogTools(service *Service) []tool.BaseTool {
	return []tool.BaseTool{
		&jsonTool{
			name: "tool_catalog_status",
			desc: "查询平台全部工具定义的来源和可用状态；不传 name 返回全部工具。只有带固定下载产物的工具支持安装。",
			params: map[string]*schema.ParameterInfo{
				"name": stringParam("工具名称，例如 suo5；留空返回全部"),
			},
			run: func(ctx context.Context, raw string) (string, error) {
				var request struct {
					Name string `json:"name"`
				}
				if err := decodeToolArgs(raw, &request); err != nil {
					return "", err
				}
				if service == nil || service.catalog == nil {
					return "", fmt.Errorf("Tool Catalog 未配置")
				}
				if request.Name != "" {
					status, err := service.catalog.Status(ctx, request.Name)
					if err != nil {
						return "", err
					}
					return marshalToolCatalogResult(status)
				}
				items, err := service.catalog.List(ctx)
				if err != nil {
					return "", err
				}
				return marshalToolCatalogResult(items)
			},
		},
		&jsonTool{
			name: "tool_catalog_install",
			desc: "从平台固定 Tool Catalog 下载二进制或构建受控 GitHub 源码工具。系统命令、平台打包和内置工具不能通过此工具安装；禁止传入 URL、命令或目标路径。",
			params: map[string]*schema.ParameterInfo{
				"name":    stringParam("Tool Catalog 中的工具名称，例如 suo5", true),
				"confirm": &schema.ParameterInfo{Type: schema.Boolean, Desc: "只有用户明确同意安装后才传 true", Required: true},
				"force":   &schema.ParameterInfo{Type: schema.Boolean, Desc: "已安装时是否强制重装，默认 false"},
			},
			run: func(ctx context.Context, raw string) (string, error) {
				var request struct {
					Name    string `json:"name"`
					Confirm bool   `json:"confirm"`
					Force   bool   `json:"force"`
				}
				if err := decodeToolArgs(raw, &request); err != nil {
					return "", err
				}
				if !request.Confirm {
					return "", fmt.Errorf("安装 Tool Catalog 工具前需要用户明确确认")
				}
				if service == nil || service.catalog == nil {
					return "", fmt.Errorf("Tool Catalog 未配置")
				}
				status, err := service.catalog.Install(ctx, request.Name, request.Force)
				if err != nil {
					return "", err
				}
				return marshalToolCatalogResult(status)
			},
		},
		&jsonTool{
			name: "tool_catalog_verify",
			desc: "验证 Tool Catalog 二进制或源码构建产物的存在性、SHA256、权限和健康检查命令。",
			params: map[string]*schema.ParameterInfo{
				"name": stringParam("Tool Catalog 中的工具名称", true),
			},
			run: func(ctx context.Context, raw string) (string, error) {
				var request struct {
					Name string `json:"name"`
				}
				if err := decodeToolArgs(raw, &request); err != nil {
					return "", err
				}
				if service == nil || service.catalog == nil {
					return "", fmt.Errorf("Tool Catalog 未配置")
				}
				status, err := service.catalog.Verify(ctx, request.Name)
				if err != nil {
					return "", err
				}
				return marshalToolCatalogResult(status)
			},
		},
		&jsonTool{
			name: "tool_catalog_ensure",
			desc: "Agent 发现工具缺失后的快速补齐：检查系统 PATH 和 Catalog，若 Catalog 支持则安装并验证。Catalog 不是限制，未收录时 Agent 仍可自行下载、构建和 tool_register。",
			params: map[string]*schema.ParameterInfo{
				"name":  stringParam("工具名称，例如 nuclei", true),
				"force": &schema.ParameterInfo{Type: schema.Boolean, Desc: "强制重新安装，默认 false"},
			},
			run: func(ctx context.Context, raw string) (string, error) {
				var request struct {
					Name  string `json:"name"`
					Force bool   `json:"force"`
				}
				if err := decodeToolArgs(raw, &request); err != nil {
					return "", err
				}
				if service == nil || service.catalog == nil {
					return "", fmt.Errorf("Tool Catalog 未配置")
				}
				_, userID, _, _ := service.currentProject(ctx)
				status, err := service.catalog.Status(ctx, request.Name)
				if err != nil {
					return "", err
				}
				if status.Installed && !request.Force {
					service.auditToolProvisioning(ctx, userID, "tool.catalog.ensure", request.Name, "success", "action=already_available")
					return marshalToolCatalogResult(map[string]any{
						"action": "already_available",
						"status": status,
					})
				}
				if !status.Installable {
					service.auditToolProvisioning(ctx, userID, "tool.catalog.ensure", request.Name, "skipped", "action=not_installable")
					return marshalToolCatalogResult(map[string]any{
						"action": "not_installable",
						"status": status,
						"next":   "可继续使用 exec 自行下载或构建，并通过 tool_register 注册",
					})
				}
				installed, err := service.catalog.Install(ctx, request.Name, request.Force)
				if err != nil {
					return "", err
				}
				verified, verifyErr := service.catalog.Verify(ctx, request.Name)
				result := "success"
				if verifyErr != nil {
					result = "failed"
				}
				service.auditToolProvisioning(
					ctx,
					userID,
					"tool.catalog.ensure",
					request.Name,
					result,
					"action=installed",
				)
				return marshalToolCatalogResult(map[string]any{
					"action":       "installed",
					"status":       installed,
					"verified":     verifyErr == nil && verified.Installed,
					"verification": verified,
					"error":        errorString(verifyErr),
				})
			},
		},
	}
}

func marshalToolCatalogResult(value any) (string, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
