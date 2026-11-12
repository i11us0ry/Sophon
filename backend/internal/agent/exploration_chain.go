package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sophon/internal/database"
)

const (
	unlimitedActiveGraphNodeSlots = 1 << 30
	maxProjectGraphNodes          = 20000
	maxBlockedAlternativesPerRun  = 20
)

func (s *Service) activeGraphNodeCapacity(
	ctx context.Context,
	projectID string,
	kind string,
	assetID string,
) (int, string, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	assetID = strings.TrimSpace(assetID)
	slots := unlimitedActiveGraphNodeSlots
	total, err := s.db.CountProjectGraphNodes(ctx, projectID)
	if err != nil {
		return 0, "", err
	}
	if total >= maxProjectGraphNodes {
		return 0, fmt.Sprintf(
			"项目图谱节点总数已达到上限 %d；请先清理冷节点或归档旧链路。",
			maxProjectGraphNodes,
		), nil
	}
	if limit := activeProjectGraphNodeLimit(kind); limit > 0 {
		active, err := s.db.CountActiveProjectGraphNodesByKind(ctx, projectID, kind)
		if err != nil {
			return 0, "", err
		}
		if active >= limit {
			return 0, fmt.Sprintf(
				"%s 项目级活跃数量已达到上限 %d；请先完成或合并现有节点，不要继续新增。",
				kind,
				limit,
			), nil
		}
		if remaining := limit - active; remaining < slots {
			slots = remaining
		}
	}
	if limit := activeGraphNodeLimit(kind); limit > 0 {
		active, err := s.db.CountActiveProjectGraphNodes(ctx, projectID, kind, assetID)
		if err != nil {
			return 0, "", err
		}
		if active >= limit {
			target := assetID
			if target == "" {
				target = "项目级"
			}
			return 0, fmt.Sprintf(
				"%s 在 %s 的活跃数量已达到上限 %d；请先完成或合并现有节点，不要继续新增。",
				kind,
				target,
				limit,
			), nil
		}
		if remaining := limit - active; remaining < slots {
			slots = remaining
		}
	}
	return slots, "", nil
}

func (s *Service) linkGraphEdge(
	ctx context.Context,
	projectID string,
	srcID string,
	dstID string,
	rel string,
) error {
	srcID = strings.TrimSpace(srcID)
	dstID = strings.TrimSpace(dstID)
	rel = strings.TrimSpace(rel)
	if srcID == "" || dstID == "" || rel == "" || srcID == dstID {
		return nil
	}
	return s.db.CreateProjectGraphEdge(ctx, database.GraphEdge{
		ID:        randomID(),
		ProjectID: projectID,
		SrcID:     srcID,
		DstID:     dstID,
		Rel:       rel,
		CreatedAt: time.Now().UTC(),
	})
}

func (s *Service) validateGraphNodeKind(
	ctx context.Context,
	projectID string,
	nodeID string,
	kind string,
) (*database.GraphNode, error) {
	node, err := s.db.GetProjectGraphNode(ctx, strings.TrimSpace(nodeID), projectID)
	if err != nil || node == nil || node.Kind != kind {
		return nil, fmt.Errorf("%s 节点不存在或不属于当前项目", kind)
	}
	return node, nil
}

func (s *Service) materializeIntentFactNode(
	ctx context.Context,
	projectID string,
	fact *database.ProjectFact,
) (*database.GraphNode, error) {
	if fact == nil {
		return nil, fmt.Errorf("事实为空")
	}
	detail := strings.TrimSpace(fact.Body)
	if detail == "" {
		detail = fact.Summary
	}
	now := time.Now().UTC()
	return s.db.UpsertProjectGraphNode(ctx, database.GraphNode{
		ID:          randomID(),
		ProjectID:   projectID,
		Kind:        "fact",
		Title:       fact.Key,
		Detail:      truncateProjectText(detail, projectToolLongText),
		Status:      "confirmed",
		Confidence:  fact.Confidence,
		AssetID:     fact.AssetID,
		Source:      "agent",
		SourceRefID: fact.ID,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
}

func (s *Service) materializeFindingNode(
	ctx context.Context,
	projectID string,
	finding *database.Vulnerability,
) (*database.GraphNode, error) {
	if finding == nil {
		return nil, fmt.Errorf("漏洞为空")
	}
	now := time.Now().UTC()
	return s.db.UpsertProjectGraphNode(ctx, database.GraphNode{
		ID:          randomID(),
		ProjectID:   projectID,
		Kind:        "finding",
		Title:       finding.Title,
		Detail:      truncateProjectText(finding.Description, projectToolLongText),
		Status:      "confirmed",
		Confidence:  90,
		Severity:    finding.Severity,
		AssetID:     finding.AssetID,
		Source:      "agent",
		SourceRefID: finding.ID,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
}

func appendFactIntentRelation(relation string, intentID string) string {
	intentID = strings.TrimSpace(intentID)
	if intentID == "" {
		return relation
	}
	marker := "intent:" + intentID
	if strings.Contains(relation, marker) {
		return relation
	}
	if strings.TrimSpace(relation) == "" {
		return marker
	}
	return relation + " " + marker
}

func (s *Service) latestIntentSourceRootID(
	ctx context.Context,
	projectID string,
	assetID string,
) string {
	nodes, err := s.db.ListProjectGraphNodesByAsset(ctx, projectID, assetID)
	if err != nil {
		return ""
	}
	var latestGoal *database.GraphNode
	var latestBegin *database.GraphNode
	for index := range nodes {
		node := nodes[index]
		if !graphAssetScopeCompatible(assetID, node.AssetID) {
			continue
		}
		switch {
		case node.Kind == "goal" && node.Status == "open":
			if latestGoal == nil ||
				node.UpdatedAt.After(latestGoal.UpdatedAt) ||
				(node.UpdatedAt.Equal(latestGoal.UpdatedAt) && node.ID > latestGoal.ID) {
				latestGoal = &node
			}
		case node.Kind == "begin":
			if latestBegin == nil ||
				node.UpdatedAt.After(latestBegin.UpdatedAt) ||
				(node.UpdatedAt.Equal(latestBegin.UpdatedAt) && node.ID > latestBegin.ID) {
				latestBegin = &node
			}
		}
	}
	if latestGoal != nil {
		return latestGoal.ID
	}
	if latestBegin != nil {
		return latestBegin.ID
	}
	return ""
}

// spawnFindingFollowUpIntents 把漏洞后续验证方向固化为 intent 节点，
// 并建立 finding --derived_from--> intent 链路。
func (s *Service) spawnFindingFollowUpIntents(
	ctx context.Context,
	projectID string,
	finding *database.Vulnerability,
) error {
	if missionSuppressesAutomaticFollowUps(ctx) {
		return nil
	}
	if finding == nil || strings.TrimSpace(finding.AssetID) == "" {
		return nil
	}
	if !shouldGenerateFollowUps(*finding) {
		return nil
	}
	findingNode, err := s.materializeFindingNode(ctx, projectID, finding)
	if err != nil {
		return err
	}
	s.graphWriteMu.Lock()
	defer s.graphWriteMu.Unlock()
	hypotheses := buildFollowUpHypotheses(*finding)
	slots, limitMessage, err := s.activeGraphNodeCapacity(
		ctx,
		projectID,
		"intent",
		finding.AssetID,
	)
	if err != nil {
		return err
	}
	if limitMessage != "" || slots <= 0 {
		return nil
	}
	if len(hypotheses) > slots {
		hypotheses = hypotheses[:slots]
	}
	now := time.Now().UTC()
	for _, candidate := range hypotheses {
		title := normalizeGraphNodeTitle(fmt.Sprintf(
			"[后续] %s/%s：%s",
			candidate.Dimension,
			orDefaultProjectToolValue(candidate.Technique, "验证"),
			candidate.Rationale,
		))
		if title == "" {
			continue
		}
		sourceRefID := "finding:" + finding.ID + ":" +
			strings.ToLower(strings.TrimSpace(candidate.Dimension)) + ":" +
			strings.ToLower(strings.TrimSpace(candidate.Technique))
		if existing, lookupErr := s.db.GetProjectGraphNodeBySourceRef(
			ctx,
			projectID,
			"intent",
			finding.AssetID,
			sourceRefID,
		); lookupErr == nil && existing != nil {
			if err := s.linkGraphEdge(ctx, projectID, findingNode.ID, existing.ID, "derived_from"); err != nil {
				return err
			}
			continue
		}
		intent, err := s.db.UpsertProjectGraphNode(ctx, database.GraphNode{
			ID:          randomID(),
			ProjectID:   projectID,
			Kind:        "intent",
			Title:       title,
			Detail:      truncateProjectText(candidate.Expected, projectToolLongText),
			Status:      "open",
			Confidence:  70,
			AssetID:     finding.AssetID,
			Source:      "finding-follow-up",
			SourceRefID: sourceRefID,
			CreatedAt:   now,
			UpdatedAt:   now,
		})
		if err != nil {
			return err
		}
		if err := s.linkGraphEdge(ctx, projectID, findingNode.ID, intent.ID, "derived_from"); err != nil {
			return err
		}
	}
	return nil
}

// spawnBlockedIntentAlternatives 为 blocked intent 派生一条替代路径。
// 派生边始终是 blocked intent --derived_from--> replacement intent。
func (s *Service) spawnBlockedIntentAlternatives(
	ctx context.Context,
	projectID string,
	intent *database.GraphNode,
) (int, error) {
	if intent == nil ||
		intent.Kind != "intent" ||
		(intent.Status != "blocked" && intent.Status != "capacity_blocked") {
		return 0, nil
	}
	s.graphWriteMu.Lock()
	defer s.graphWriteMu.Unlock()
	hasOpen, err := s.hasOpenDerivedIntent(ctx, projectID, intent.ID)
	if err != nil {
		return 0, err
	}
	if hasOpen {
		return 0, nil
	}
	slots, limitMessage, err := s.activeGraphNodeCapacity(
		ctx,
		projectID,
		"intent",
		intent.AssetID,
	)
	if err != nil {
		return 0, err
	}
	if limitMessage != "" || slots <= 0 {
		intent.Status = "capacity_blocked"
		intent.Detail = appendGraphDetail(
			intent.Detail,
			"【替代路径状态：capacity_blocked】当前没有可用的活跃 intent 容量，暂不继续派生。",
		)
		intent.UpdatedAt = time.Now().UTC()
		if err := s.db.UpdateProjectGraphNode(ctx, *intent); err != nil {
			return 0, err
		}
		return 0, nil
	}
	title := normalizeGraphNodeTitle("[替代] " + intent.Title)
	if title == "" {
		return 0, nil
	}
	sourceRefID := "blocked:" + intent.ID + ":alternative"
	if existing, lookupErr := s.db.GetProjectGraphNodeBySourceRef(
		ctx,
		projectID,
		"intent",
		intent.AssetID,
		sourceRefID,
	); lookupErr == nil && existing != nil {
		if existing.Status == "open" || existing.Status == "running" {
			if err := s.linkGraphEdge(ctx, projectID, intent.ID, existing.ID, "derived_from"); err != nil {
				return 0, err
			}
			return 0, nil
		}
		sourceRefID = sourceRefID + ":" + randomID()
	}
	now := time.Now().UTC()
	alternative, err := s.db.UpsertProjectGraphNode(ctx, database.GraphNode{
		ID:        randomID(),
		ProjectID: projectID,
		Kind:      "intent",
		Title:     title,
		Detail: truncateProjectText(appendGraphDetail(
			intent.Detail,
			"【阻塞替代】原意图 blocked。请换用不同入口、参数、身份、协议或资产后重新验证，禁止重复同一失败路径。",
		), projectToolLongText),
		Status:      "open",
		Confidence:  65,
		AssetID:     intent.AssetID,
		Source:      "blocked-follow-up",
		SourceRefID: sourceRefID,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		return 0, err
	}
	if err := s.linkGraphEdge(ctx, projectID, intent.ID, alternative.ID, "derived_from"); err != nil {
		return 0, err
	}
	intent.Detail = appendGraphDetail(
		intent.Detail,
		fmt.Sprintf("【已派生替代意图】%s", alternative.ID),
	)
	intent.UpdatedAt = now
	if err := s.db.UpdateProjectGraphNode(ctx, *intent); err != nil {
		return 0, err
	}
	return 1, nil
}

func (s *Service) ensureBlockedIntentAlternatives(
	ctx context.Context,
	projectID string,
) (int, error) {
	nodes, err := s.db.ListProjectGraphNodes(ctx, projectID)
	if err != nil {
		return 0, err
	}
	created := 0
	processed := 0
	for index := range nodes {
		node := nodes[index]
		if node.Kind != "intent" ||
			(node.Status != "blocked" && node.Status != "capacity_blocked") {
			continue
		}
		hasOpen, err := s.hasOpenDerivedIntent(ctx, projectID, node.ID)
		if err != nil {
			return created, err
		}
		if hasOpen {
			continue
		}
		processed++
		count, err := s.spawnBlockedIntentAlternatives(ctx, projectID, &node)
		if err != nil {
			return created, err
		}
		created += count
		if processed >= maxBlockedAlternativesPerRun {
			break
		}
	}
	return created, nil
}

func (s *Service) hasOpenDerivedIntent(
	ctx context.Context,
	projectID string,
	intentID string,
) (bool, error) {
	edges, err := s.db.ListProjectGraphEdgesFromNode(ctx, projectID, intentID)
	if err != nil {
		return false, err
	}
	for _, edge := range edges {
		if edge.Rel != "derived_from" {
			continue
		}
		child, childErr := s.db.GetProjectGraphNode(ctx, edge.DstID, projectID)
		if childErr == nil &&
			child.Kind == "intent" &&
			(child.Status == "open" || child.Status == "running") {
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) RecoverBlockedIntentAlternatives(ctx context.Context) (int, error) {
	projectIDs, err := s.db.ListActiveProjectIDs(ctx)
	if err != nil {
		return 0, err
	}
	created := 0
	for _, projectID := range projectIDs {
		if err := ctx.Err(); err != nil {
			return created, err
		}
		count, err := s.ensureBlockedIntentAlternatives(ctx, projectID)
		if err != nil {
			return created, err
		}
		created += count
		if count > 0 {
			_ = s.db.AddAuditLog(ctx, database.AuditLog{
				UserID:       "system",
				Username:     "system",
				Action:       "recover_blocked_intent_alternatives",
				ResourceType: "project",
				ResourceID:   projectID,
				Result:       "success",
				Detail:       fmt.Sprintf("已派生 %d 条 blocked intent 替代路径", count),
			})
		}
	}
	return created, nil
}

func appendGraphDetail(detail string, addition string) string {
	detail = strings.TrimSpace(detail)
	addition = strings.TrimSpace(addition)
	if addition == "" || strings.Contains(detail, addition) {
		return detail
	}
	if detail == "" {
		return addition
	}
	return detail + "\n\n" + addition
}
