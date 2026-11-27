package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

func (s *Service) nextAssetsTool() tool.BaseTool {
	return &jsonTool{
		name: "project_next_assets",
		desc: "读取当前项目的资产工作队列和调度状态。",
		params: map[string]*schema.ParameterInfo{
			"limit":  integerParam("最多返回多少项，默认 20，最大 50"),
			"offset": integerParam("分页偏移，默认 0"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Limit  flexInt `json:"limit"`
				Offset flexInt `json:"offset"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			items, err := s.db.ListProjectAssetWork(ctx, projectID, userID)
			if err != nil {
				return "", err
			}
			limit := int(request.Limit)
			if limit <= 0 {
				limit = 20
			}
			if limit > 50 {
				limit = 50
			}
			offset := max(0, int(request.Offset))
			if len(items) == 0 {
				return "当前项目没有资产工作项。", nil
			}
			var builder strings.Builder
			builder.WriteString("资产工作队列：\n")
			printed := 0
			for index, item := range items {
				if index < offset {
					continue
				}
				if printed >= limit {
					builder.WriteString(fmt.Sprintf("- …（另有 %d 项）\n", len(items)-index))
					break
				}
				printed++
				builder.WriteString(fmt.Sprintf(
					"- %s（%s，%s）asset_id=%s authorization=%s work=%s priority=%d reason=%s\n",
					item.AssetName,
					item.AssetKind,
					item.AssetValue,
					item.AssetID,
					item.AuthorizationState,
					item.WorkState,
					item.Priority,
					orDefaultProjectToolValue(item.StateReason, "-"),
				))
			}
			return capProjectOutput(&builder), nil
		},
	}
}

func (s *Service) assetCloseoutTool() tool.BaseTool {
	return &jsonTool{
		name: "project_asset_closeout",
		desc: "检查指定资产是否满足服务端关闭门禁；只读，不直接改变资产状态。",
		params: map[string]*schema.ParameterInfo{
			"asset_id": stringParam("资产 id；留空时使用当前 Planner 资产焦点"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				AssetID string `json:"asset_id"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			assetID := strings.TrimSpace(request.AssetID)
			if assetID == "" {
				assetID = currentAssetID(ctx)
			}
			if assetID == "" {
				return "", fmt.Errorf("asset_id 不能为空，且当前没有资产焦点")
			}
			status, err := s.db.AssetCloseoutStatus(ctx, projectID, userID, assetID)
			if err != nil {
				return "", err
			}
			var builder strings.Builder
			builder.WriteString("资产关闭门禁：\n")
			builder.WriteString(fmt.Sprintf(
				"- asset_id=%s can_close=%t tests=%d/%d required_open=%d required_blocked=%d suspicious=%d evidence_gaps=%d\n",
				status.AssetID,
				status.CanClose,
				status.TestsCovered,
				status.TestsTotal,
				status.RequiredOpen,
				status.RequiredBlocked,
				status.RequiredSuspect,
				status.EvidenceGaps,
			))
			if len(status.Missing) == 0 {
				builder.WriteString("- 缺失项：无\n")
			} else {
				builder.WriteString("- 缺失项：\n")
				for _, item := range status.Missing {
					builder.WriteString("- " + item + "\n")
				}
			}
			return capProjectOutput(&builder), nil
		},
	}
}
