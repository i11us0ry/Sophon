package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

const evidenceReferenceFormatHint = "证据引用格式：tool:<工具执行ID>、fact:<事实ID或key>、" +
	"artifact:<artifact目录内文件路径>、conversation:<会话ID>；" +
	"示例：tool:0f3c...，artifact:/opt/sophon/data/conversation_artifacts/<conversation_id>/tool_results/result.txt"

const evidenceCandidateLimit = 5

func (s *Service) validateEvidenceReferences(
	ctx context.Context,
	projectID string,
	userID string,
	refs []string,
	severity string,
) error {
	validStructured := 0
	for _, item := range refs {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, ":", 2)
		if len(parts) != 2 {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}
		switch kind {
		case "tool":
			execution, err := s.db.GetToolExecution(ctx, value)
			if err != nil || execution.UserID != userID || execution.Status != "completed" {
				return s.invalidEvidenceReference(
					ctx,
					projectID,
					userID,
					"证据工具执行无效或不属于当前用户",
					kind,
					item,
				)
			}
			conversation, err := s.db.GetConversation(ctx, execution.ConversationID, userID)
			if err != nil || conversation.ProjectID != projectID {
				return s.invalidEvidenceReference(
					ctx,
					projectID,
					userID,
					"证据工具执行不属于当前项目",
					kind,
					item,
				)
			}
			validStructured++
		case "fact":
			assetID := strings.TrimSpace(execctx.AssetID(ctx))
			fact, err := s.db.GetProjectFactByID(ctx, projectID, value)
			if err != nil {
				fact, err = s.db.GetProjectFactByKey(ctx, projectID, assetID, value)
			}
			if err != nil || fact == nil {
				return s.invalidEvidenceReference(
					ctx,
					projectID,
					userID,
					"证据事实不存在或不属于当前项目",
					kind,
					item,
				)
			}
			validStructured++
		case "artifact", "file":
			if !s.artifactPathAllowed(value) {
				return s.invalidEvidenceReference(
					ctx,
					projectID,
					userID,
					"证据文件不在允许的 artifact 目录",
					kind,
					item,
				)
			}
			validStructured++
		case "conversation":
			conversation, err := s.db.GetConversation(ctx, value, userID)
			if err != nil || conversation.ProjectID != projectID {
				return s.invalidEvidenceReference(
					ctx,
					projectID,
					userID,
					"证据会话不属于当前项目",
					kind,
					item,
				)
			}
			validStructured++
		default:
			return fmt.Errorf("无法识别证据引用类型 %s；%s", item, evidenceReferenceFormatHint)
		}
	}
	if strings.EqualFold(severity, "critical") || strings.EqualFold(severity, "high") {
		if validStructured == 0 {
			return fmt.Errorf("%s 漏洞至少需要一个有效的 tool/file/artifact/fact 证据引用；%s", severity, evidenceReferenceFormatHint)
		}
	}
	return nil
}

func (s *Service) invalidEvidenceReference(
	ctx context.Context,
	projectID string,
	userID string,
	reason string,
	kind string,
	item string,
) error {
	value := ""
	if parts := strings.SplitN(item, ":", 2); len(parts) == 2 {
		value = strings.TrimSpace(parts[1])
	}
	hint := s.evidenceReferenceCandidates(ctx, projectID, userID, kind, value)
	if hint == "" {
		return fmt.Errorf("%s: %s；%s", reason, item, evidenceReferenceFormatHint)
	}
	return fmt.Errorf(
		"%s: %s；可恢复候选：%s；%s",
		reason,
		item,
		hint,
		evidenceReferenceFormatHint,
	)
}

func (s *Service) evidenceReferenceCandidates(
	ctx context.Context,
	projectID string,
	userID string,
	kind string,
	value string,
) string {
	if s == nil || s.db == nil {
		return ""
	}
	switch kind {
	case "tool":
		return s.toolEvidenceCandidates(ctx, userID)
	case "fact":
		return s.factEvidenceCandidates(ctx, projectID, value)
	case "artifact", "file":
		return s.artifactEvidenceCandidates(ctx)
	case "conversation":
		if conversationID := strings.TrimSpace(execctx.ConversationID(ctx)); conversationID != "" {
			return "conversation:" + conversationID
		}
	}
	return ""
}

func (s *Service) toolEvidenceCandidates(ctx context.Context, userID string) string {
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	if conversationID == "" {
		return ""
	}
	items, err := s.db.ListToolExecutions(ctx, userID, 50)
	if err != nil {
		return ""
	}
	candidates := make([]string, 0, evidenceCandidateLimit)
	for _, item := range items {
		if item.ConversationID != conversationID || item.Status != "completed" {
			continue
		}
		candidates = append(candidates, fmt.Sprintf(
			"tool:%s（%s）",
			item.ID,
			truncateProjectText(item.ToolName, projectToolShortText),
		))
		if len(candidates) >= evidenceCandidateLimit {
			break
		}
	}
	return strings.Join(candidates, "、")
}

func (s *Service) factEvidenceCandidates(
	ctx context.Context,
	projectID string,
	value string,
) string {
	facts, _, err := s.db.ListProjectFactsPageByAsset(
		ctx,
		projectID,
		execctx.AssetID(ctx),
		100,
		0,
	)
	if err != nil || len(facts) == 0 {
		return ""
	}
	sort.SliceStable(facts, func(i, j int) bool {
		return factEvidenceMatchScore(facts[i], value) > factEvidenceMatchScore(facts[j], value)
	})
	if len(facts) > evidenceCandidateLimit {
		facts = facts[:evidenceCandidateLimit]
	}
	candidates := make([]string, 0, len(facts))
	for _, fact := range facts {
		candidates = append(candidates, fmt.Sprintf(
			"fact:%s（key=%s）",
			fact.ID,
			truncateProjectText(fact.Key, projectToolShortText),
		))
	}
	return strings.Join(candidates, "、")
}

func factEvidenceMatchScore(fact database.ProjectFact, value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if strings.EqualFold(fact.ID, value) {
		return 4
	}
	if strings.EqualFold(fact.Key, value) {
		return 3
	}
	valueToken := normalizeEvidenceToken(value)
	keyToken := normalizeEvidenceToken(fact.Key)
	if len([]rune(valueToken)) < 2 || len([]rune(keyToken)) < 2 {
		return 0
	}
	if valueToken == keyToken {
		return 2
	}
	if strings.Contains(keyToken, valueToken) || strings.Contains(valueToken, keyToken) {
		return 1
	}
	return 0
}

func normalizeEvidenceToken(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func (s *Service) artifactEvidenceCandidates(ctx context.Context) string {
	root := strings.TrimSpace(s.configSnapshot().Storage.ArtifactRoot)
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	if root == "" || conversationID == "" ||
		filepath.Base(conversationID) != conversationID ||
		conversationID == "." || conversationID == ".." {
		return ""
	}
	dir := filepath.Join(
		root,
		"data",
		"conversation_artifacts",
		conversationID,
		"tool_results",
	)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	type artifactCandidate struct {
		path     string
		modified time.Time
	}
	files := make([]artifactCandidate, 0, evidenceCandidateLimit)
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil || !info.Mode().IsRegular() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if !s.artifactPathAllowed(path) {
			continue
		}
		files = append(files, artifactCandidate{path: path, modified: info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].modified.After(files[j].modified)
	})
	if len(files) > evidenceCandidateLimit {
		files = files[:evidenceCandidateLimit]
	}
	candidates := make([]string, 0, len(files))
	for _, file := range files {
		candidates = append(candidates, "artifact:"+file.path)
	}
	return strings.Join(candidates, "、")
}

func (s *Service) artifactPathAllowed(value string) bool {
	value = strings.TrimSpace(value)
	root := strings.TrimSpace(s.configSnapshot().Storage.ArtifactRoot)
	if value == "" || root == "" {
		return false
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return false
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, absolute)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false
	}
	info, err := os.Stat(absolute)
	return err == nil && !info.IsDir()
}

func (s *Service) validateProjectFindingID(
	ctx context.Context,
	projectID string,
	userID string,
	findingID string,
) (*database.Vulnerability, error) {
	findingID = strings.TrimSpace(findingID)
	if findingID == "" {
		return nil, fmt.Errorf("finding_id 不能为空")
	}
	finding, err := s.db.GetVulnerability(ctx, findingID, userID)
	if err != nil || finding.ProjectID != projectID {
		return nil, fmt.Errorf("finding_id 不属于当前项目")
	}
	return finding, nil
}

func (s *Service) validateCampaignAssetScope(ctx context.Context, assetID string) error {
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		return nil
	}
	campaignID, _, _, err := s.currentCampaign(ctx, "")
	if err != nil {
		return err
	}
	if campaignID == "" {
		return nil
	}
	allowed, err := s.db.CampaignContainsAsset(ctx, campaignID, assetID)
	if err != nil {
		return fmt.Errorf("校验 Campaign 资产范围失败: %w", err)
	}
	if !allowed {
		return fmt.Errorf("资产 %s 不属于当前 Campaign 授权范围", assetID)
	}
	return nil
}

func graphAssetScopeCompatible(targetAssetID string, sourceAssetID string) bool {
	targetAssetID = strings.TrimSpace(targetAssetID)
	sourceAssetID = strings.TrimSpace(sourceAssetID)
	return targetAssetID == "" || sourceAssetID == "" || targetAssetID == sourceAssetID
}

func (s *Service) loadActiveFactSource(
	ctx context.Context,
	projectID string,
	targetAssetID string,
	factID string,
) (*database.ProjectFact, error) {
	fact, err := s.db.GetActiveProjectFactByID(ctx, projectID, factID)
	if err != nil || fact == nil {
		return nil, fmt.Errorf("source_fact_id 不存在、已失效或不属于当前项目")
	}
	if !graphAssetScopeCompatible(targetAssetID, fact.AssetID) {
		return nil, fmt.Errorf("source_fact_id 与目标 intent 不属于同一资产")
	}
	if err := s.validateCampaignAssetScope(ctx, fact.AssetID); err != nil {
		return nil, err
	}
	return fact, nil
}

func (s *Service) loadActiveFindingSource(
	ctx context.Context,
	projectID string,
	userID string,
	targetAssetID string,
	findingID string,
) (*database.Vulnerability, error) {
	finding, err := s.validateProjectFindingID(ctx, projectID, userID, findingID)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(finding.Status)) {
	case "open", "confirmed":
	default:
		return nil, fmt.Errorf("source_finding_id 对应的漏洞状态为 %s，不能作为活跃链路来源", finding.Status)
	}
	if !graphAssetScopeCompatible(targetAssetID, finding.AssetID) {
		return nil, fmt.Errorf("source_finding_id 与目标 intent 不属于同一资产")
	}
	if err := s.validateCampaignAssetScope(ctx, finding.AssetID); err != nil {
		return nil, err
	}
	return finding, nil
}

func (s *Service) validateProjectIntentID(
	ctx context.Context,
	projectID string,
	intentID string,
) error {
	intentID = strings.TrimSpace(intentID)
	if intentID == "" {
		return nil
	}
	node, err := s.db.GetProjectGraphNode(ctx, intentID, projectID)
	if err != nil || node.Kind != "intent" {
		return fmt.Errorf("intent_id 不属于当前项目或不是意图节点")
	}
	return nil
}

func (s *Service) validateMemorySourceRef(
	ctx context.Context,
	projectID string,
	userID string,
	entityType string,
	sourceRefID string,
) error {
	sourceRefID = strings.TrimSpace(sourceRefID)
	if sourceRefID == "" {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(entityType)) {
	case "asset":
		_, err := s.validateProjectAsset(ctx, projectID, userID, sourceRefID)
		return err
	case "finding":
		_, err := s.validateProjectFindingID(ctx, projectID, userID, sourceRefID)
		return err
	default:
		return nil
	}
}
