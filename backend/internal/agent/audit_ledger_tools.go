package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

const (
	auditSubjectScope      = "audit_scope"
	auditSubjectCell       = "audit_cell"
	auditSubjectCheckpoint = "audit_checkpoint"
	auditCoverageObject    = "coverage"
	maxAuditValues         = 32
)

var auditCoverageStatuses = map[string]bool{
	"tested":         true,
	"not_audited":    true,
	"not_applicable": true,
}

var auditConclusionStates = map[string]bool{
	"CONFIRMED":        true,
	"NEEDS_VALIDATION": true,
	"ENV_DEPENDENT":    true,
	"PATTERN":          true,
	"NOT_EXPLOITABLE":  true,
	"NOT_AUDITED":      true,
	"NOT_APPLICABLE":   true,
}

type auditRecordRequest struct {
	Action             string   `json:"action"`
	AssetID            string   `json:"asset_id"`
	IncludedCategories []string `json:"included_categories"`
	ExcludedCategories []string `json:"excluded_categories"`
	Service            string   `json:"service"`
	Entry              string   `json:"entry"`
	Shape              string   `json:"shape"`
	Surface            string   `json:"surface"`
	CoverageStatus     string   `json:"coverage_status"`
	ConclusionState    string   `json:"conclusion_state"`
	Result             string   `json:"result"`
	Evidence           string   `json:"evidence"`
	EvidenceRefs       []string `json:"evidence_refs"`
	FindingID          string   `json:"finding_id"`
	RescanSurfaces     []string `json:"rescan_surfaces"`
	NextAction         string   `json:"next_action"`
	ActiveHypothesisID string   `json:"active_hypothesis_id"`
	PendingDirections  []string `json:"pending_directions"`
	Confidence         flexInt  `json:"confidence"`
}

func (s *Service) recordAuditTool() tool.BaseTool {
	statuses := []string{"tested", "not_audited", "not_applicable"}
	conclusions := []string{
		"CONFIRMED", "NEEDS_VALIDATION", "ENV_DEPENDENT", "PATTERN",
		"NOT_EXPLOITABLE", "NOT_AUDITED", "NOT_APPLICABLE",
	}
	return &jsonTool{
		name: "project_record_audit",
		desc: "记录项目审计范围、服务入口覆盖矩阵和轮次断点。审计单元以 service × entry × shape × surface 表示；not_audited 单元格会自动进入未覆盖队列。",
		params: map[string]*schema.ParameterInfo{
			"action":               stringEnumParam("操作类型", []string{"scope", "cell", "checkpoint", "rescan"}, true),
			"asset_id":             stringParam("cell/rescan 必填的资产 id"),
			"included_categories":  stringArrayParam("scope：本次纳入审计的类别"),
			"excluded_categories":  stringArrayParam("scope：明确排除、不得报告为已审计的类别"),
			"service":              stringParam("服务类或组件名"),
			"entry":                stringParam("入口方法；同类全量回扫可写 *"),
			"shape":                stringParam("危险形态，例如 SQL-zero-parameter"),
			"surface":              stringParam("分发面，例如 kdsvc/asmx/ashx/kdma/WCF/ASPX"),
			"coverage_status":      stringEnumParam("覆盖状态", statuses),
			"conclusion_state":     stringEnumParam("结论状态", conclusions),
			"result":               stringParam("测试结果或 not_applicable 原因"),
			"evidence":             stringParam("证据摘要"),
			"evidence_refs":        stringArrayParam("证据引用数组；" + evidenceReferenceFormatHint),
			"finding_id":           stringParam("CONFIRMED 结论关联的漏洞 id"),
			"rescan_surfaces":      stringArrayParam("rescan：发现漏检形态后需要回扫的分发面列表"),
			"next_action":          stringParam("断点后的第一个动作"),
			"active_hypothesis_id": stringParam("当前活跃假设 id"),
			"pending_directions":   stringArrayParam("本轮已声明但未取证的方向"),
			"confidence":           integerParam("置信度 0-100"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request auditRecordRequest
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			switch strings.ToLower(strings.TrimSpace(request.Action)) {
			case "scope":
				fact, err := s.recordAuditScope(ctx, projectID, userID, request.IncludedCategories, request.ExcludedCategories, request.Evidence)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("已记录审计范围：%s（id %s）", fact.Summary, fact.ID), nil
			case "cell":
				fact, err := s.recordAuditCell(ctx, projectID, userID, request)
				if err != nil {
					return "", err
				}
				message := fmt.Sprintf("已记录审计单元：%s = %s（id %s）", fact.SubjectKey, fact.ObjectKey, fact.ID)
				if len(request.RescanSurfaces) > 0 {
					count, err := s.recordAuditRescan(ctx, projectID, userID, request)
					if err != nil {
						return "", err
					}
					message += fmt.Sprintf("；已加入 %d 个同类回扫单元", count)
				}
				return message, nil
			case "rescan":
				count, err := s.recordAuditRescan(ctx, projectID, userID, request)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("已加入 %d 个同类回扫未审计单元", count), nil
			case "checkpoint":
				fact, err := s.recordAuditCheckpoint(ctx, projectID, userID, request)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("已记录轮次断点：%s（id %s）", fact.Summary, fact.ID), nil
			default:
				return "", fmt.Errorf("action 必须是 scope/cell/rescan/checkpoint")
			}
		},
	}
}

func (s *Service) recordAuditScope(
	ctx context.Context,
	projectID string,
	userID string,
	included []string,
	excluded []string,
	evidence string,
) (*database.ProjectFact, error) {
	included = cleanAuditValues(included)
	excluded = cleanAuditValues(excluded)
	if len(included) == 0 {
		return nil, fmt.Errorf("included_categories 不能为空")
	}
	includedSet := make(map[string]bool, len(included))
	for _, value := range included {
		includedSet[strings.ToLower(value)] = true
	}
	for _, value := range excluded {
		if includedSet[strings.ToLower(value)] {
			return nil, fmt.Errorf("类别 %s 不能同时纳入和排除", value)
		}
	}
	if strings.TrimSpace(evidence) == "" {
		return nil, fmt.Errorf("审计范围必须提供用户要求或项目目标证据")
	}
	body, _ := json.Marshal(map[string]interface{}{
		"included": included,
		"excluded": excluded,
	})
	summary := "纳入=" + strings.Join(included, "、")
	if len(excluded) > 0 {
		summary += "；明确排除=" + strings.Join(excluded, "、")
	}
	return s.saveAuditFact(ctx, projectID, database.ProjectFact{
		AssetID:     "",
		FactType:    "scope",
		Key:         "business/audit-scope",
		Value:       summary,
		Summary:     summary,
		Body:        string(body),
		Evidence:    strings.TrimSpace(evidence),
		Confidence:  100,
		MemoryKind:  "scope",
		Priority:    100,
		Pinned:      true,
		SubjectType: auditSubjectScope,
		SubjectKey:  "project",
		Predicate:   "defines",
		ObjectType:  "categories",
		ObjectKey:   strings.Join(included, ","),
	}, userID)
}

func (s *Service) recordAuditCell(
	ctx context.Context,
	projectID string,
	userID string,
	request auditRecordRequest,
) (*database.ProjectFact, error) {
	assetID, err := s.validateProjectAsset(ctx, projectID, userID, request.AssetID)
	if err != nil {
		return nil, err
	}
	if assetID == "" {
		return nil, fmt.Errorf("asset_id 不能为空")
	}
	service := truncateProjectText(request.Service, projectToolShortText)
	entry := truncateProjectText(request.Entry, projectToolShortText)
	shape := truncateProjectText(request.Shape, projectToolShortText)
	surface := truncateProjectText(request.Surface, projectToolShortText)
	if service == "" || entry == "" || shape == "" || surface == "" {
		return nil, fmt.Errorf("service、entry、shape、surface 均不能为空")
	}
	coverage := strings.ToLower(strings.TrimSpace(request.CoverageStatus))
	if !auditCoverageStatuses[coverage] {
		return nil, fmt.Errorf("coverage_status 必须是 tested/not_audited/not_applicable")
	}
	conclusion := strings.ToUpper(strings.TrimSpace(request.ConclusionState))
	if conclusion == "" {
		switch coverage {
		case "not_audited":
			conclusion = "NOT_AUDITED"
		case "not_applicable":
			conclusion = "NOT_APPLICABLE"
		default:
			conclusion = "NEEDS_VALIDATION"
		}
	}
	if !auditConclusionStates[conclusion] {
		return nil, fmt.Errorf("conclusion_state 不合法")
	}
	switch coverage {
	case "not_audited":
		if conclusion != "NOT_AUDITED" {
			return nil, fmt.Errorf("not_audited 的 conclusion_state 必须是 NOT_AUDITED")
		}
	case "not_applicable":
		if conclusion != "NOT_APPLICABLE" {
			return nil, fmt.Errorf("not_applicable 的 conclusion_state 必须是 NOT_APPLICABLE")
		}
	case "tested":
		if conclusion == "NOT_AUDITED" || conclusion == "NOT_APPLICABLE" {
			return nil, fmt.Errorf("tested 单元格不能使用 %s", conclusion)
		}
	}
	result := truncateProjectText(request.Result, projectToolLongText)
	evidence := truncateProjectText(request.Evidence, projectToolLongText)
	refs := append([]string(nil), request.EvidenceRefs...)
	if coverage == "not_applicable" && result == "" {
		return nil, fmt.Errorf("not_applicable 必须说明理由")
	}
	if coverage == "tested" && result == "" {
		return nil, fmt.Errorf("tested 单元格必须提供 result")
	}
	if conclusion == "CONFIRMED" {
		if strings.TrimSpace(request.FindingID) == "" {
			return nil, fmt.Errorf("CONFIRMED 必须关联 finding_id")
		}
		if _, err := s.validateProjectFindingID(ctx, projectID, userID, request.FindingID); err != nil {
			return nil, err
		}
	}
	if (conclusion == "CONFIRMED" || conclusion == "NOT_EXPLOITABLE") &&
		evidence == "" && len(cleanAuditValues(refs)) == 0 {
		return nil, fmt.Errorf("%s 必须提供证据", conclusion)
	}
	if len(cleanAuditValues(refs)) > 0 {
		if err := s.validateEvidenceReferences(ctx, projectID, userID, refs, "medium"); err != nil {
			return nil, err
		}
	}
	confidence := int(request.Confidence)
	if confidence <= 0 {
		switch conclusion {
		case "CONFIRMED":
			confidence = 95
		case "NOT_EXPLOITABLE":
			confidence = 85
		case "NOT_AUDITED":
			confidence = 0
		default:
			confidence = 70
		}
	}
	body, _ := json.Marshal(map[string]interface{}{
		"service":          service,
		"entry":            entry,
		"shape":            shape,
		"surface":          surface,
		"coverage_status":  coverage,
		"conclusion_state": conclusion,
		"result":           result,
		"finding_id":       strings.TrimSpace(request.FindingID),
		"evidence_refs":    refs,
		"next_action":      strings.TrimSpace(request.NextAction),
	})
	subjectKey := strings.Join([]string{service, entry, shape, surface}, " × ")
	key := "business/audit-cell-" + shortAuditHash(projectID, assetID, subjectKey)
	return s.saveAuditFact(ctx, projectID, database.ProjectFact{
		AssetID:     assetID,
		FactType:    "constraint",
		Key:         key,
		Value:       coverage,
		Summary:     subjectKey + " = " + coverage + " / " + conclusion,
		Body:        string(body),
		Evidence:    evidence,
		Confidence:  confidence,
		MemoryKind:  "constraint",
		Priority:    90,
		SubjectType: auditSubjectCell,
		SubjectKey:  subjectKey,
		Predicate:   auditCoverageObject,
		ObjectType:  auditCoverageObject,
		ObjectKey:   coverage,
	}, userID)
}

func (s *Service) recordAuditRescan(
	ctx context.Context,
	projectID string,
	userID string,
	request auditRecordRequest,
) (int, error) {
	surfaces := cleanAuditValues(request.RescanSurfaces)
	if len(surfaces) == 0 {
		return 0, fmt.Errorf("rescan_surfaces 不能为空")
	}
	service := truncateProjectText(request.Service, projectToolShortText)
	shape := truncateProjectText(request.Shape, projectToolShortText)
	if service == "" || shape == "" {
		return 0, fmt.Errorf("rescan 需要 service 和 shape")
	}
	for _, surface := range surfaces {
		request.Entry = "*"
		request.Surface = surface
		request.CoverageStatus = "not_audited"
		request.ConclusionState = "NOT_AUDITED"
		request.Result = "发现同类漏检形态，等待跨分发面回扫"
		request.Evidence = ""
		request.EvidenceRefs = nil
		request.FindingID = ""
		if request.NextAction == "" {
			request.NextAction = "回扫 " + service + " 在 " + surface + " 上的 " + shape
		}
		if _, err := s.recordAuditCell(ctx, projectID, userID, request); err != nil {
			return 0, err
		}
	}
	return len(surfaces), nil
}

func (s *Service) recordAuditCheckpoint(
	ctx context.Context,
	projectID string,
	userID string,
	request auditRecordRequest,
) (*database.ProjectFact, error) {
	nextAction := truncateProjectText(request.NextAction, projectToolLongText)
	if nextAction == "" {
		return nil, fmt.Errorf("next_action 不能为空")
	}
	hypothesisID := strings.TrimSpace(request.ActiveHypothesisID)
	if hypothesisID != "" {
		if _, err := s.db.GetProjectTestResultByID(ctx, projectID, hypothesisID); err != nil {
			return nil, fmt.Errorf("active_hypothesis_id 不属于当前项目: %w", err)
		}
	}
	pending := cleanAuditValues(request.PendingDirections)
	body, _ := json.Marshal(map[string]interface{}{
		"active_hypothesis_id": hypothesisID,
		"pending_directions":   pending,
		"next_action":          nextAction,
	})
	conversationID := execctx.ConversationID(ctx)
	return s.saveAuditFact(ctx, projectID, database.ProjectFact{
		FactType:    "note",
		Key:         "note/round-checkpoint-" + shortAuditHash(projectID, conversationID),
		Value:       nextAction,
		Summary:     nextAction,
		Body:        string(body),
		Confidence:  100,
		MemoryKind:  "note",
		Priority:    100,
		SubjectType: auditSubjectCheckpoint,
		SubjectKey:  conversationID,
		Predicate:   "resume_from",
		ObjectType:  "next_action",
		ObjectKey:   shortAuditHash(nextAction),
	}, userID)
}

func (s *Service) saveAuditFact(
	ctx context.Context,
	projectID string,
	fact database.ProjectFact,
	userID string,
) (*database.ProjectFact, error) {
	now := time.Now().UTC()
	fact.ProjectID = projectID
	fact.SourceType = "conversation"
	fact.SourceID = execctx.ConversationID(ctx)
	fact.ObservedAt = now
	fact.CreatedAt = now
	fact.UpdatedAt = now
	if fact.ID == "" {
		fact.ID = randomID()
	}
	decision, err := s.consolidateFact(ctx, projectID, fact)
	if err != nil {
		return nil, err
	}
	if decision.Fact == nil {
		return nil, fmt.Errorf("审计记录保存失败")
	}
	if userID != "" {
		s.syncProjectGraph(ctx, projectID, userID)
	}
	return decision.Fact, nil
}

func cleanAuditValues(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = truncateProjectText(value, projectToolShortText)
		key := strings.ToLower(value)
		if value == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, value)
		if len(result) >= maxAuditValues {
			break
		}
	}
	return result
}

func shortAuditHash(values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return hex.EncodeToString(sum[:6])
}
