package agent

import (
	"context"
	"fmt"
	"strings"

	"sophon/internal/database"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

const (
	assetCardFactLimit    = 8
	assetCardTestLimit    = 8
	assetCardFindingLimit = 5
	assetCardNodeLimit    = 8
	assetCardTotalRunes   = 5000
)

func (s *Service) assetCardTool() tool.BaseTool {
	return &jsonTool{
		name: "project_asset_card",
		desc: "读取单个资产的完整任务上下文：画像事实、测试假设、漏洞、覆盖状态和图谱关联。",
		params: map[string]*schema.ParameterInfo{
			"asset_id": stringParam("资产 id；当前对话已绑定资产时可留空"),
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
				return "", fmt.Errorf("asset_id 不能为空，且当前对话未绑定资产")
			}
			return s.renderProjectAssetCard(ctx, projectID, userID, assetID)
		},
	}
}

func (s *Service) renderProjectAssetCard(
	ctx context.Context,
	projectID string,
	userID string,
	assetID string,
) (string, error) {
	asset, err := s.db.GetAsset(ctx, strings.TrimSpace(assetID), userID)
	if err != nil {
		return "", fmt.Errorf("读取资产失败: %w", err)
	}
	if asset.ProjectID != projectID {
		return "", fmt.Errorf("资产不属于当前项目")
	}

	testCoverage, err := s.db.AggregateProjectTestCoverage(ctx, projectID)
	if err != nil {
		return "", fmt.Errorf("读取资产测试覆盖失败: %w", err)
	}
	tests, err := s.db.ListProjectTestResultsByAsset(
		ctx,
		projectID,
		asset.ID,
		assetCardTestLimit*3,
	)
	if err != nil {
		return "", fmt.Errorf("读取资产测试失败: %w", err)
	}
	facts, err := s.db.ListProjectFactsByAsset(ctx, projectID, asset.ID)
	if err != nil {
		return "", fmt.Errorf("读取资产事实失败: %w", err)
	}
	findings, _, err := s.db.ListVulnerabilitiesFiltered(ctx, database.VulnerabilityFilter{
		OwnerUserID: userID,
		ProjectID:   projectID,
		AssetID:     asset.ID,
		Limit:       assetCardFindingLimit * 2,
	})
	if err != nil {
		return "", fmt.Errorf("读取资产漏洞失败: %w", err)
	}
	nodes, err := s.db.ListProjectGraphNodesByAsset(ctx, projectID, asset.ID)
	if err != nil {
		return "", fmt.Errorf("读取资产图谱失败: %w", err)
	}

	state := testCoverage[asset.ID]
	observed := state.TestsTotal > 0
	evidenceFacts := make([]database.ProjectFact, 0, len(facts))
	for _, fact := range facts {
		if fact.Tainted || strings.TrimSpace(fact.ContradictedBy) != "" || isCredentialFact(fact) {
			continue
		}
		evidenceFacts = append(evidenceFacts, fact)
		if strings.TrimSpace(fact.Evidence) != "" {
			observed = true
		}
	}
	for _, finding := range findings {
		if strings.TrimSpace(finding.Evidence) != "" || len(finding.EvidenceRefs) > 0 {
			observed = true
		}
	}

	coverageStatus := "untested"
	if observed {
		switch {
		case state.RequiredTotal > 0 && state.RequiredCovered == state.RequiredTotal:
			coverageStatus = "covered"
		case state.RequiredBlocked > 0:
			coverageStatus = "blocked"
		case state.RequiredSuspicious > 0:
			coverageStatus = "suspicious"
		default:
			coverageStatus = "partial"
		}
	}

	var builder strings.Builder
	builder.WriteString("当前资产卡片：\n")
	builder.WriteString(fmt.Sprintf(
		"- 资产：%s（id=%s，kind=%s，value=%s）\n",
		asset.Name,
		asset.ID,
		asset.Kind,
		asset.Value,
	))
	builder.WriteString(fmt.Sprintf(
		"- 属性：status=%s，criticality=%s，risk=%d\n",
		asset.Status,
		asset.Criticality,
		asset.RiskScore,
	))
	builder.WriteString(fmt.Sprintf(
		"- 覆盖：status=%s，tests=%d/%d，required-open=%d，blocked=%d，suspicious=%d\n",
		coverageStatus,
		state.TestsCovered,
		state.TestsTotal,
		state.RequiredOpen,
		state.RequiredBlocked,
		state.RequiredSuspicious,
	))

	rankedFacts := s.rankProjectFacts(ctx, "", evidenceFacts)
	builder.WriteString("资产画像事实：\n")
	if len(rankedFacts) == 0 {
		builder.WriteString("- 无\n")
	} else {
		for index, ranked := range rankedFacts {
			if index >= assetCardFactLimit {
				builder.WriteString(fmt.Sprintf("- …（另有 %d 条）\n", len(rankedFacts)-assetCardFactLimit))
				break
			}
			fact := ranked.Fact
			builder.WriteString(fmt.Sprintf(
				"- [%s] %s: %s（confidence=%d）\n",
				orDefaultProjectToolValue(fact.MemoryKind, "general"),
				fact.Key,
				truncateProjectText(projectFactSummary(fact), situationTextRune),
				fact.Confidence,
			))
		}
	}

	builder.WriteString("当前测试与假设：\n")
	if len(tests) == 0 {
		builder.WriteString("- 无，需要先建立测试计划\n")
	} else {
		for index, item := range tests {
			if index >= assetCardTestLimit {
				builder.WriteString(fmt.Sprintf("- …（另有 %d 条）\n", len(tests)-assetCardTestLimit))
				break
			}
			builder.WriteString(fmt.Sprintf(
				"- [%s] %s/%s（id=%s，priority=%d）\n",
				item.Status,
				item.Dimension,
				orDefaultProjectToolValue(item.Technique, "-"),
				item.ID,
				item.Priority,
			))
		}
	}

	builder.WriteString("最近资产漏洞：\n")
	if len(findings) == 0 {
		builder.WriteString("- 无\n")
	} else {
		for index, item := range findings {
			if index >= assetCardFindingLimit {
				builder.WriteString(fmt.Sprintf("- …（另有 %d 条）\n", len(findings)-assetCardFindingLimit))
				break
			}
			builder.WriteString(fmt.Sprintf(
				"- [%s/%s] %s（id=%s）\n",
				item.Severity,
				item.Status,
				truncateProjectText(item.Title, situationTextRune),
				item.ID,
			))
		}
	}

	builder.WriteString("资产图谱节点：\n")
	if len(nodes) == 0 {
		builder.WriteString("- 无\n")
	} else {
		limited := 0
		for _, node := range nodes {
			if strings.TrimSpace(node.AssetID) == "" {
				continue
			}
			if limited >= assetCardNodeLimit {
				builder.WriteString("- …（更多节点请调用 project_get resource=graph_node）\n")
				break
			}
			builder.WriteString(fmt.Sprintf(
				"- [%s/%s] %s（id=%s）\n",
				node.Kind,
				node.Status,
				truncateProjectText(node.Title, situationTextRune),
				node.ID,
			))
			limited++
		}
	}

	return truncateProjectText(builder.String(), assetCardTotalRunes), nil
}
