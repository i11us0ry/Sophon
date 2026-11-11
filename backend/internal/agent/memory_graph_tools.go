package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/database"
)

func (s *Service) upsertMemoryEntityTool() tool.BaseTool {
	return &jsonTool{
		name: "project_upsert_entity",
		desc: "幂等写入结构化记忆实体，例如 asset/service/endpoint/parameter/credential/finding/intent/goal。",
		params: map[string]*schema.ParameterInfo{
			"entity_type":   stringParam("实体类型", true),
			"entity_key":    stringParam("实体稳定标识", true),
			"label":         stringParam("展示名称"),
			"summary":       stringParam("实体摘要"),
			"metadata":      stringParam("JSON 元数据"),
			"source_ref_id": stringParam("来源对象 id"),
			"evidence":      stringParam("证据摘要"),
			"evidence_refs": stringArrayParam("证据引用；" + evidenceReferenceFormatHint),
			"confidence":    integerParam("置信度 0-100"),
			"priority":      integerParam("优先级 0-100"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				EntityType   string   `json:"entity_type"`
				EntityKey    string   `json:"entity_key"`
				Label        string   `json:"label"`
				Summary      string   `json:"summary"`
				Metadata     string   `json:"metadata"`
				SourceRefID  string   `json:"source_ref_id"`
				Evidence     string   `json:"evidence"`
				EvidenceRefs []string `json:"evidence_refs"`
				Confidence   flexInt  `json:"confidence"`
				Priority     flexInt  `json:"priority"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			if err := s.validateMemorySourceRef(
				ctx,
				projectID,
				userID,
				request.EntityType,
				request.SourceRefID,
			); err != nil {
				return "", err
			}
			entity, err := s.db.UpsertProjectMemoryEntity(ctx, database.ProjectMemoryEntity{
				ProjectID:    projectID,
				EntityType:   request.EntityType,
				EntityKey:    request.EntityKey,
				Label:        request.Label,
				Summary:      request.Summary,
				Metadata:     request.Metadata,
				SourceRefID:  request.SourceRefID,
				Evidence:     request.Evidence,
				EvidenceRefs: request.EvidenceRefs,
				Confidence:   int(request.Confidence),
				Priority:     int(request.Priority),
				CreatedAt:    time.Now().UTC(),
			})
			if err != nil {
				return "", fmt.Errorf("写入记忆实体失败: %w", err)
			}
			return fmt.Sprintf("记忆实体已写入：%s/%s（id %s）", entity.EntityType, entity.EntityKey, entity.ID), nil
		},
	}
}

func (s *Service) linkMemoryEntitiesTool() tool.BaseTool {
	return &jsonTool{
		name: "project_link_entities",
		desc: "建立两个结构化记忆实体之间的关系，例如 finding found_on asset 或 endpoint has_parameter parameter。",
		params: map[string]*schema.ParameterInfo{
			"src_entity_id": stringParam("源实体 id", true),
			"relation":      stringParam("关系类型", true),
			"dst_entity_id": stringParam("目标实体 id", true),
			"fact_id":       stringParam("关联事实 id"),
			"confidence":    integerParam("置信度 0-100"),
			"evidence":      stringParam("证据摘要"),
			"evidence_refs": stringArrayParam("证据引用；" + evidenceReferenceFormatHint),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				SrcEntityID  string   `json:"src_entity_id"`
				Relation     string   `json:"relation"`
				DstEntityID  string   `json:"dst_entity_id"`
				FactID       string   `json:"fact_id"`
				Confidence   flexInt  `json:"confidence"`
				Evidence     string   `json:"evidence"`
				EvidenceRefs []string `json:"evidence_refs"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, _, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			if factID := strings.TrimSpace(request.FactID); factID != "" {
				if _, err := s.db.GetProjectFactByID(ctx, projectID, factID); err != nil {
					return "", fmt.Errorf("fact_id 不属于当前项目")
				}
			}
			relation, err := s.db.UpsertProjectMemoryRelation(ctx, database.ProjectMemoryRelation{
				ProjectID:    projectID,
				SrcEntityID:  request.SrcEntityID,
				Relation:     request.Relation,
				DstEntityID:  request.DstEntityID,
				FactID:       request.FactID,
				Confidence:   int(request.Confidence),
				Evidence:     request.Evidence,
				EvidenceRefs: request.EvidenceRefs,
				CreatedAt:    time.Now().UTC(),
			})
			if err != nil {
				return "", fmt.Errorf("写入记忆关系失败: %w", err)
			}
			return fmt.Sprintf("记忆关系已写入：%s -[%s]-> %s", relation.SrcEntityID, relation.Relation, relation.DstEntityID), nil
		},
	}
}

func (s *Service) listMemoryEntitiesTool() tool.BaseTool {
	return &jsonTool{
		name: "project_list_entities",
		desc: "列出当前项目的结构化记忆实体，可按实体类型过滤。",
		params: map[string]*schema.ParameterInfo{
			"entity_type": stringParam("实体类型，可选"),
			"query":       stringParam("按标签、摘要或实体键搜索"),
			"limit":       integerParam("返回条数，默认 50，最大 200"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				EntityType string  `json:"entity_type"`
				Query      string  `json:"query"`
				Limit      flexInt `json:"limit"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, _, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			limit := int(request.Limit)
			if limit <= 0 || limit > 200 {
				limit = 50
			}
			query := strings.ToLower(strings.TrimSpace(request.Query))
			fetchLimit := limit
			if query != "" {
				fetchLimit = 200
			}
			items, err := s.db.ListProjectMemoryEntities(ctx, projectID, request.EntityType, fetchLimit)
			if err != nil {
				return "", fmt.Errorf("读取记忆实体失败: %w", err)
			}
			if len(items) == 0 {
				return "当前项目没有匹配的结构化记忆实体。", nil
			}
			var builder strings.Builder
			matched := 0
			for _, item := range items {
				if query != "" && !projectTextMatches(query, item.Label, item.Summary, item.EntityKey, item.EntityType, item.ID) {
					continue
				}
				if matched >= limit {
					break
				}
				matched++
				builder.WriteString(fmt.Sprintf(
					"- [%s] %s: %s（confidence=%d，priority=%d，id=%s）\n",
					item.EntityType,
					item.Label,
					truncateProjectText(item.Summary, projectToolShortText),
					item.Confidence,
					item.Priority,
					item.ID,
				))
			}
			return capProjectOutput(&builder), nil
		},
	}
}

func (s *Service) memoryGraphTool() tool.BaseTool {
	return &jsonTool{
		name: "project_memory_graph",
		desc: "查看结构化记忆实体及其关系，可选择从某个实体开始。",
		params: map[string]*schema.ParameterInfo{
			"entity_id": stringParam("实体 id，可选"),
			"limit":     integerParam("返回关系条数，默认 50，最大 200"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				EntityID string  `json:"entity_id"`
				Limit    flexInt `json:"limit"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, _, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			limit := int(request.Limit)
			if limit <= 0 || limit > 200 {
				limit = 50
			}
			relations, err := s.db.ListProjectMemoryRelations(ctx, projectID, request.EntityID, limit)
			if err != nil {
				return "", fmt.Errorf("读取记忆图谱失败: %w", err)
			}
			if len(relations) == 0 {
				return "当前查询范围没有结构化记忆关系。", nil
			}
			var builder strings.Builder
			for _, relation := range relations {
				builder.WriteString(fmt.Sprintf(
					"- %s -[%s]-> %s（confidence=%d，fact=%s）\n",
					relation.SrcEntityID,
					relation.Relation,
					relation.DstEntityID,
					relation.Confidence,
					orDefaultProjectToolValue(relation.FactID, "-"),
				))
			}
			return capProjectOutput(&builder), nil
		},
	}
}

// newFactAuditTool 是事实审计工具的统一入口，按 action 分发到冲突列表、
// 冲突解决与历史版本三个动作；合并前它们是三个独立的直连工具。
func (s *Service) newFactAuditTool() tool.BaseTool {
	return &jsonTool{
		name: "project_fact_audit",
		desc: "事实审计：action=list 列出未解决的事实冲突；action=resolve 指定 winner/loser 解决冲突；" +
			"action=versions 查看某个事实的历史版本。",
		params: map[string]*schema.ParameterInfo{
			"action":    stringParam("操作：list（默认）| resolve | versions", true),
			"limit":     integerParam("list/versions 返回条数，默认 20，最大 100"),
			"winner_id": stringParam("resolve 时保留的事实 id"),
			"loser_id":  stringParam("resolve 时失效的事实 id"),
			"reason":    stringParam("resolve 时的解决依据"),
			"fact_id":   stringParam("versions 时的事实 id"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Action   string  `json:"action"`
				Limit    flexInt `json:"limit"`
				WinnerID string  `json:"winner_id"`
				LoserID  string  `json:"loser_id"`
				Reason   string  `json:"reason"`
				FactID   string  `json:"fact_id"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			switch strings.ToLower(strings.TrimSpace(request.Action)) {
			case "", "list":
				return s.runListFactConflicts(ctx, int(request.Limit))
			case "resolve":
				return s.runResolveFactConflict(ctx, request.WinnerID, request.LoserID, request.Reason)
			case "versions":
				return s.runListFactVersions(ctx, request.FactID, int(request.Limit))
			default:
				return "", fmt.Errorf("action 必须是 list、resolve 或 versions")
			}
		},
	}
}

func (s *Service) runListFactConflicts(ctx context.Context, limitIn int) (string, error) {
	_, _, projectID, err := s.currentProject(ctx)
	if err != nil {
		return "", err
	}
	limit := limitIn
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	items, err := s.db.ListProjectFactConflicts(ctx, projectID, limit)
	if err != nil {
		return "", fmt.Errorf("读取事实冲突失败: %w", err)
	}
	if len(items) == 0 {
		return "当前项目没有未解决的事实冲突。", nil
	}
	var builder strings.Builder
	for _, item := range items {
		builder.WriteString(fmt.Sprintf(
			"- %s：%s（contradictedBy=%s，priority=%d，id=%s）\n",
			item.Key,
			truncateProjectText(projectFactSummary(item), projectToolShortText),
			item.ContradictedBy,
			item.Priority,
			item.ID,
		))
		if item.ConflictReason != "" {
			builder.WriteString("  原因: " + truncateProjectText(item.ConflictReason, projectToolShortText) + "\n")
		}
	}
	return capProjectOutput(&builder), nil
}

func (s *Service) runResolveFactConflict(ctx context.Context, winnerID, loserID, reason string) (string, error) {
	_, _, projectID, err := s.currentProject(ctx)
	if err != nil {
		return "", err
	}
	winner, err := s.db.GetProjectFactByID(ctx, projectID, winnerID)
	if err != nil {
		return "", fmt.Errorf("winner 事实不存在")
	}
	loser, err := s.db.GetProjectFactByID(ctx, projectID, loserID)
	if err != nil {
		return "", fmt.Errorf("loser 事实不存在")
	}
	if err := s.db.RecordProjectFactVersion(ctx, *loser, "conflict-resolved-loser"); err != nil {
		return "", err
	}
	if err := s.db.ResolveProjectFactConflict(
		ctx,
		projectID,
		winner.ID,
		loser.ID,
		reason,
	); err != nil {
		return "", fmt.Errorf("解决事实冲突失败: %w", err)
	}
	return fmt.Sprintf("事实冲突已解决：保留 %s，失效 %s", winner.Key, loser.Key), nil
}

func (s *Service) runListFactVersions(ctx context.Context, factID string, limitIn int) (string, error) {
	_, _, projectID, err := s.currentProject(ctx)
	if err != nil {
		return "", err
	}
	if _, err := s.db.GetProjectFactByID(ctx, projectID, factID); err != nil {
		return "", fmt.Errorf("事实不存在")
	}
	limit := limitIn
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	items, err := s.db.ListProjectFactVersions(ctx, projectID, factID, limit)
	if err != nil {
		return "", fmt.Errorf("读取事实版本失败: %w", err)
	}
	if len(items) == 0 {
		return "该事实暂无历史版本。", nil
	}
	var builder strings.Builder
	for _, item := range items {
		builder.WriteString(fmt.Sprintf(
			"- v%d：%s（confidence=%d，reason=%s，时间=%s）\n",
			item.Version,
			truncateProjectText(item.Summary, projectToolShortText),
			item.Confidence,
			orDefaultProjectToolValue(item.Reason, "-"),
			item.CreatedAt.Format("2006-01-02 15:04:05"),
		))
	}
	return capProjectOutput(&builder), nil
}
