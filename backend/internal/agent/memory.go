package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

const (
	// 语义合并阈值：仅在同类型且高度相似时才并入已有记忆，避免误合并。
	memorySemanticMergeThreshold = 0.90
	// 可能相关阈值：达到该值仍单独新增，但在审计里记录相似度便于复盘。
	memoryRelatedThreshold  = 0.60
	memoryDefaultImportance = 60
	memoryDefaultPriority   = 50
	memoryAuditCellKind     = "audit_cell"
	memoryAuditCellPriority = 60
)

// memoryDecision 描述一次记忆写决策，用于审计与工具回执。
type memoryDecision struct {
	Action     string
	Fact       *database.ProjectFact
	Similarity float64
	Reason     string
}

func normalizeMemoryText(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.Join(strings.Fields(value), " ")
}

func orDefaultText(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func importanceFromConfidence(confidence int) int {
	if confidence <= 0 {
		return memoryDefaultImportance
	}
	if confidence > 100 {
		return 100
	}
	return confidence
}

func memoryActionLabel(action string) string {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "ADD":
		return "已新增"
	case "UPDATE":
		return "已更新"
	case "NONE":
		return "无变化（同 key 同内容）"
	case "SUPERSEDE":
		return "已失效"
	default:
		return "已记录"
	}
}

// memoryContentEqual 判断新旧记忆在语义字段上是否等价；空字段按“保持原值”处理。
func memoryContentEqual(existing, incoming database.ProjectFact) bool {
	if normalizeMemoryText(existing.Summary) != normalizeMemoryText(incoming.Summary) {
		return false
	}
	if body := normalizeMemoryText(incoming.Body); body != "" &&
		body != normalizeMemoryText(existing.Body) {
		return false
	}
	if evidence := normalizeMemoryText(incoming.Evidence); evidence != "" &&
		evidence != normalizeMemoryText(existing.Evidence) {
		return false
	}
	if relation := normalizeMemoryText(incoming.Relation); relation != "" &&
		relation != normalizeMemoryText(existing.Relation) {
		return false
	}
	return true
}

// consolidateFact 幂等写入项目记忆：
// 同 key 内容一致 → NONE；同 key 有变化 → UPDATE；
// 不同 key 但同类型且高度相似 → 合并进已有记忆（UPDATE）；否则 ADD。
func (s *Service) consolidateFact(
	ctx context.Context,
	projectID string,
	source database.ProjectFact,
) (memoryDecision, error) {
	if s.db == nil {
		return memoryDecision{}, fmt.Errorf("数据库不可用")
	}
	source.SourceType = orDefaultText(source.SourceType, "agent")
	source.SourceID = orDefaultText(source.SourceID, execctx.ConversationID(ctx))
	if source.Importance <= 0 {
		source.Importance = memoryDefaultImportance
	}
	if strings.TrimSpace(source.ID) == "" {
		source.ID = randomID()
	}
	// 不可信内容检测：命中注入特征的事实保留（侦查价值），但打污点标记并排除自动注入。
	taintPatterns := scanInjectionPatterns(strings.Join(
		[]string{source.Summary, source.Body, source.Evidence},
		"\n",
	))
	if len(taintPatterns) > 0 {
		source.Tainted = true
		source.TaintReason = strings.Join(taintPatterns, ",")
	}
	fingerprint := factFingerprint(
		projectID,
		source.AssetID,
		source.Key,
		source.SubjectKey,
		source.Predicate,
	)
	if fingerprintExisting, fingerprintErr := s.db.GetProjectFactByFingerprint(
		ctx,
		projectID,
		source.AssetID,
		fingerprint,
	); fingerprintErr == nil && fingerprintExisting != nil {
		source.ID = fingerprintExisting.ID
		source.Key = fingerprintExisting.Key
		fingerprint = factFingerprint(
			projectID,
			source.AssetID,
			source.Key,
			source.SubjectKey,
			source.Predicate,
		)
	}

	existing, err := s.db.GetProjectFactByKey(ctx, projectID, source.AssetID, source.Key)
	if err != nil {
		return memoryDecision{}, err
	}
	if existing != nil && existing.ValidTo.IsZero() {
		if memoryContentEqual(*existing, source) {
			_ = s.db.TouchProjectFact(ctx, existing.ID)
			s.recordMemoryWrite(ctx, projectID, existing.ID, "NONE", "exact-key-identical",
				existing.Key, source.Key, "", existing.Summary, source.Summary, source, 1)
			return memoryDecision{
				Action:     "NONE",
				Fact:       existing,
				Similarity: 1,
				Reason:     "exact-key-identical",
			}, nil
		}
		// 低置信且无新证据的覆盖请求直接拒绝，避免记忆被错误/恶意内容改写。
		if source.Evidence == "" && source.Confidence < existing.Confidence {
			s.recordMemoryWrite(ctx, projectID, existing.ID, "NONE", "rejected-lower-confidence",
				existing.Key, source.Key, "", existing.Summary, source.Summary, source, 1)
			return memoryDecision{
				Action:     "NONE",
				Fact:       existing,
				Similarity: 1,
				Reason:     "rejected-lower-confidence",
			}, nil
		}
		source.ID = existing.ID
		_ = s.db.RecordProjectFactVersion(ctx, *existing, "exact-key-changed")
		if existing.Tainted && !source.Tainted {
			// 污点保持粘性：旧内容仍可能残留在未覆盖字段中。
			source.Tainted = true
			source.TaintReason = existing.TaintReason
		}
		saved, upsertErr := s.db.UpsertProjectFact(ctx, source)
		if upsertErr != nil {
			return memoryDecision{}, upsertErr
		}
		_ = s.db.SetProjectFactFingerprint(ctx, saved.ID, fingerprint)
		s.recordMemoryWrite(ctx, projectID, saved.ID, "UPDATE", "exact-key-changed",
			existing.Key, saved.Key, "", existing.Summary, saved.Summary, source, 1)
		s.recordFactTaint(ctx, projectID, saved)
		return memoryDecision{Action: "UPDATE", Fact: saved, Similarity: 1, Reason: "exact-key-changed"}, nil
	}

	// 无同 key 记忆：尝试语义合并到已有事实。
	if candidates, searchErr := s.searchProjectMemories(ctx, projectID, source.AssetID, source.Summary, 5); searchErr == nil {
		for index := range candidates {
			candidate := candidates[index]
			sameStructuredIdentity := structuredFactIdentityEqual(source, candidate)
			sameFactType := strings.EqualFold(
				strings.TrimSpace(candidate.FactType),
				strings.TrimSpace(source.FactType),
			)
			sameFactFamily := projectFactFamily(source) != "" &&
				strings.EqualFold(projectFactFamily(source), projectFactFamily(candidate))
			if !sameStructuredIdentity && !sameFactType {
				continue
			}
			if sameStructuredIdentity && !sameFactType && !sameFactFamily {
				continue
			}
			if structuredFactsConflict(source, candidate) {
				continue
			}
			similarity := memorySimilarity(source.Summary, candidate.Summary)
			threshold := memorySemanticMergeThreshold
			if sameStructuredIdentity {
				threshold = 0.75
			}
			if similarity < threshold {
				continue
			}
			// 语义合并同样要求新证据或更高置信度，避免覆盖可信记忆。
			if source.Evidence == "" && source.Confidence < candidate.Confidence {
				continue
			}
			source.ID = candidate.ID
			source.Key = candidate.Key
			_ = s.db.RecordProjectFactVersion(ctx, candidate, "semantic-merge")
			if candidate.Tainted && !source.Tainted {
				source.Tainted = true
				source.TaintReason = candidate.TaintReason
			}
			if source.Confidence < candidate.Confidence {
				source.Confidence = candidate.Confidence
			}
			if source.Importance < candidate.Importance {
				source.Importance = candidate.Importance
			}
			saved, upsertErr := s.db.UpsertProjectFact(ctx, source)
			if upsertErr != nil {
				return memoryDecision{}, upsertErr
			}
			_ = s.db.SetProjectFactFingerprint(ctx, saved.ID, fingerprint)
			s.recordMemoryWrite(ctx, projectID, saved.ID, "UPDATE", "semantic-merge",
				candidate.Key, saved.Key, "", candidate.Summary, saved.Summary, source, similarity)
			s.recordFactTaint(ctx, projectID, saved)
			return memoryDecision{
				Action:     "UPDATE",
				Fact:       saved,
				Similarity: similarity,
				Reason:     "semantic-merge",
			}, nil
		}
	}

	saved, err := s.db.UpsertProjectFact(ctx, source)
	if err != nil {
		return memoryDecision{}, err
	}
	_ = s.db.SetProjectFactFingerprint(ctx, saved.ID, fingerprint)
	if conflict, conflictErr := s.findStructuredFactConflict(ctx, projectID, saved); conflictErr == nil && conflict != nil {
		if err := s.db.MarkProjectFactConflict(
			ctx,
			projectID,
			saved.ID,
			conflict.ID,
			fmt.Sprintf("主体 %s/%s 的谓词 %s 出现不同对象", saved.SubjectType, saved.SubjectKey, saved.Predicate),
		); err != nil {
			return memoryDecision{}, err
		}
		saved.ContradictedBy = conflict.ID
		saved.ConflictReason = "结构化事实冲突"
	}
	s.recordFactTaint(ctx, projectID, saved)
	reason := "new-key"
	similarity := 0.0
	if related, score := s.bestRelatedFact(ctx, projectID, source); related != nil {
		reason = "possibly-related"
		similarity = score
	}
	s.recordMemoryWrite(ctx, projectID, saved.ID, "ADD", reason,
		"", saved.Key, "", "", saved.Summary, source, similarity)
	return memoryDecision{Action: "ADD", Fact: saved, Similarity: similarity, Reason: reason}, nil
}

func structuredFactsConflict(left, right database.ProjectFact) bool {
	if strings.TrimSpace(left.SubjectType) == "" ||
		strings.TrimSpace(left.SubjectKey) == "" ||
		strings.TrimSpace(left.Predicate) == "" {
		return false
	}
	leftObject := strings.TrimSpace(left.ObjectKey)
	if leftObject == "" {
		leftObject = strings.TrimSpace(left.Summary)
	}
	rightObject := strings.TrimSpace(right.ObjectKey)
	if rightObject == "" {
		rightObject = strings.TrimSpace(right.Summary)
	}
	return strings.EqualFold(left.SubjectType, right.SubjectType) &&
		strings.EqualFold(left.SubjectKey, right.SubjectKey) &&
		strings.EqualFold(left.Predicate, right.Predicate) &&
		!strings.EqualFold(leftObject, rightObject)
}

func structuredFactIdentityEqual(left, right database.ProjectFact) bool {
	if strings.TrimSpace(left.SubjectType) == "" ||
		strings.TrimSpace(left.SubjectKey) == "" ||
		strings.TrimSpace(left.Predicate) == "" ||
		strings.TrimSpace(right.SubjectType) == "" ||
		strings.TrimSpace(right.SubjectKey) == "" ||
		strings.TrimSpace(right.Predicate) == "" {
		return false
	}
	return strings.EqualFold(left.SubjectType, right.SubjectType) &&
		strings.EqualFold(left.SubjectKey, right.SubjectKey) &&
		strings.EqualFold(left.Predicate, right.Predicate)
}

func projectFactFamily(fact database.ProjectFact) string {
	key := strings.ToLower(strings.TrimSpace(fact.Key))
	if index := strings.Index(key, "/"); index > 0 {
		return key[:index]
	}
	return strings.ToLower(strings.TrimSpace(fact.FactType))
}

func isAuditCellFact(fact database.ProjectFact) bool {
	return strings.EqualFold(strings.TrimSpace(fact.MemoryKind), memoryAuditCellKind) ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(fact.Key)), "business/audit-cell-")
}

func (s *Service) findStructuredFactConflict(
	ctx context.Context,
	projectID string,
	source *database.ProjectFact,
) (*database.ProjectFact, error) {
	if s == nil || s.db == nil || source == nil {
		return nil, nil
	}
	if strings.TrimSpace(source.SubjectType) == "" ||
		strings.TrimSpace(source.SubjectKey) == "" ||
		strings.TrimSpace(source.Predicate) == "" {
		return nil, nil
	}
	items, err := s.db.ListProjectFactsByAsset(ctx, projectID, source.AssetID)
	if err != nil {
		return nil, err
	}
	sourceObject := strings.TrimSpace(source.ObjectKey)
	if sourceObject == "" {
		sourceObject = strings.TrimSpace(source.Summary)
	}
	for index := range items {
		item := items[index]
		if item.ID == source.ID || !item.ValidTo.IsZero() || item.Tainted {
			continue
		}
		itemObject := strings.TrimSpace(item.ObjectKey)
		if itemObject == "" {
			itemObject = strings.TrimSpace(item.Summary)
		}
		if strings.EqualFold(item.SubjectType, source.SubjectType) &&
			strings.EqualFold(item.SubjectKey, source.SubjectKey) &&
			strings.EqualFold(item.Predicate, source.Predicate) &&
			!strings.EqualFold(itemObject, sourceObject) {
			copy := item
			return &copy, nil
		}
	}
	return nil, nil
}

// bestRelatedFact 找出与新记忆相关但未达到合并阈值的已有事实，仅用于审计。
func (s *Service) bestRelatedFact(
	ctx context.Context,
	projectID string,
	source database.ProjectFact,
) (*database.ProjectFact, float64) {
	candidates, err := s.searchProjectMemories(ctx, projectID, source.AssetID, source.Summary, 3)
	if err != nil || len(candidates) == 0 {
		return nil, 0
	}
	best := candidates[0]
	score := memorySimilarity(source.Summary, best.Summary)
	if score < memoryRelatedThreshold {
		return nil, score
	}
	return &best, score
}

// supersedeFact 标记旧记忆被新记忆替代（valid_to + superseded_by）。
func (s *Service) supersedeFact(
	ctx context.Context,
	projectID string,
	assetID string,
	oldKey string,
	replacement *database.ProjectFact,
) error {
	if s.db == nil || strings.TrimSpace(oldKey) == "" {
		return nil
	}
	old, err := s.db.GetProjectFactByKey(ctx, projectID, assetID, strings.TrimSpace(oldKey))
	if err != nil || old == nil {
		return err
	}
	// 失效可信记忆需要证据或更高置信度，防止被注入内容随意作废真实结论。
	if replacement != nil && replacement.Evidence == "" && replacement.Confidence < old.Confidence {
		return fmt.Errorf("替代事实证据不足：需提供 evidence 或不低于旧的 confidence")
	}
	replacementID := ""
	after := ""
	if replacement != nil {
		replacementID = replacement.ID
		after = replacement.Summary
	}
	if err := s.db.SupersedeProjectFact(ctx, old.ID, replacementID); err != nil {
		return err
	}
	source := database.ProjectFact{SourceType: "agent", SourceID: execctx.ConversationID(ctx)}
	s.recordMemoryWrite(ctx, projectID, old.ID, "SUPERSEDE", "explicit-supersede",
		old.Key, "", replacementID, old.Summary, after, source, 0)
	return nil
}

var conclusionNegationMarkers = []string{
	"不可复现", "无法复现", "未复现", "不复现", "不可利用", "无法利用",
	"未发现", "不存在", "不成立", "已修复", "已关闭", "not reproducible",
	"not vulnerable", "false positive", "not exploitable",
}

// factConclusionConflict 判断两条自由文本结论是否在“同一主题”上互相否定。
// 不依赖结构化 subject/predicate，覆盖模型用不同 key 记录同一结论的场景。
func factConclusionConflict(source, existing database.ProjectFact) bool {
	left := normalizeMemoryText(source.Summary)
	right := normalizeMemoryText(existing.Summary)
	if left == "" || right == "" || left == right {
		return false
	}
	similarity := memorySimilarity(source.Summary, existing.Summary)
	// 冲突检测比普通相关性更宽容：原文中出现明确相反结论标记时，
	// 只要主题词有约一半重合就应要求显式解决，不能静默并存。
	if similarity < 0.5 {
		return false
	}
	leftNegated := textHasConclusionNegation(left)
	rightNegated := textHasConclusionNegation(right)
	return leftNegated != rightNegated
}

func textHasConclusionNegation(text string) bool {
	for _, marker := range conclusionNegationMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func (s *Service) findConclusionConflict(
	ctx context.Context,
	projectID string,
	source database.ProjectFact,
) (*database.ProjectFact, error) {
	candidates, err := s.searchProjectMemories(ctx, projectID, source.AssetID, source.Summary, 8)
	if err != nil {
		return nil, err
	}
	for index := range candidates {
		candidate := candidates[index]
		if candidate.ID == source.ID || !candidate.ValidTo.IsZero() || candidate.Tainted {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(candidate.FactType), strings.TrimSpace(source.FactType)) {
			continue
		}
		if factConclusionConflict(source, candidate) {
			copy := candidate
			return &copy, nil
		}
	}
	return nil, nil
}

type factConclusionConflictError struct {
	Fact *database.ProjectFact
	Key  string
}

func (e *factConclusionConflictError) Error() string {
	if e == nil || e.Fact == nil {
		return "事实结论存在冲突"
	}
	return fmt.Sprintf(
		"事实结论与已有事实冲突：new=%s，existing=%s（id=%s，confidence=%d，summary=%s）。"+
			"确认新结论成立且已有新证据时，重新调用 project_record_fact 并设置 supersedes=%s、同时提供 evidence，"+
			"让旧结论保留历史版本并失效；如果只是复核旧结论，请直接返回已有结论，不要并存两个相反结论。",
		e.Key,
		e.Fact.Key,
		e.Fact.ID,
		e.Fact.Confidence,
		truncateProjectText(e.Fact.Summary, projectToolShortText),
		e.Fact.Key,
	)
}

func (s *Service) recordMemoryWrite(
	ctx context.Context,
	projectID string,
	factID string,
	action string,
	reason string,
	beforeKey string,
	afterKey string,
	relatedFactID string,
	before string,
	after string,
	source database.ProjectFact,
	similarity float64,
) {
	if s.db == nil {
		return
	}
	_ = s.db.AddMemoryWrite(ctx, database.MemoryWrite{
		ID:            randomID(),
		ProjectID:     projectID,
		FactID:        factID,
		Action:        action,
		Reason:        reason,
		BeforeKey:     beforeKey,
		AfterKey:      afterKey,
		RelatedFactID: relatedFactID,
		BeforeSummary: before,
		AfterSummary:  after,
		SourceType:    source.SourceType,
		SourceID:      source.SourceID,
		Similarity:    similarity,
		CreatedAt:     time.Now().UTC(),
	})
}

// recordFactTaint 为污点事实写入注入事件审计（只在持久化路径记录，避免每轮上下文构建刷屏）。
func (s *Service) recordFactTaint(ctx context.Context, projectID string, fact *database.ProjectFact) {
	if s.db == nil || fact == nil || !fact.Tainted {
		return
	}
	_ = s.db.AddInjectionEvent(ctx, database.InjectionEvent{
		ID:             randomID(),
		ConversationID: execctx.ConversationID(ctx),
		ProjectID:      projectID,
		SourceType:     "fact",
		SourceID:       fact.Key,
		Patterns:       fact.TaintReason,
		Action:         "tainted",
		CreatedAt:      time.Now().UTC(),
	})
}
