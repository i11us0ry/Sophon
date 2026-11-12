package database

import (
	"context"
	"sort"
	"strings"
	"time"
)

// GraphSyncResult 汇总一次攻击路径补全的变更数量。
type GraphSyncResult struct {
	CreatedNodes int `json:"createdNodes"`
	UpdatedNodes int `json:"updatedNodes"`
	CreatedEdges int `json:"createdEdges"`
}

const (
	maxProjectGoalNodes            = 5
	maxGraphNodeTitleRun           = 200
	maxMaterializedFactsPerAsset   = 3
	maxMaterializedFactsPerProject = 200
)

// SyncProjectGraph 为项目补齐攻击路径骨架并回填既有事实/漏洞（幂等，可重复调用）：
//   - 起点（begin）+ 项目目标（goal）节点与 begin→goal 连线
//   - project_facts 回填为 fact 节点
//   - vulnerabilities 回填为 finding 节点
//   - 为 intent/fact/finding/hint 节点补入边（优先意图→目标→起点）
func (db *DB) SyncProjectGraph(ctx context.Context, project Project) (GraphSyncResult, error) {
	result := GraphSyncResult{}
	existingNodes, err := db.ListProjectGraphNodes(ctx, project.ID)
	if err != nil {
		return result, err
	}
	existingEdges, err := db.ListProjectGraphEdges(ctx, project.ID)
	if err != nil {
		return result, err
	}

	allNodes := make([]*GraphNode, 0, len(existingNodes))
	byKey := make(map[string]*GraphNode, len(existingNodes))
	for index := range existingNodes {
		node := existingNodes[index]
		allNodes = append(allNodes, &node)
		byKey[graphNodeKey(node.Kind, node.Title, node.SourceRefID, node.AssetID)] = &node
	}
	edgeSet := make(map[string]bool, len(existingEdges))
	for _, edge := range existingEdges {
		edgeSet[graphEdgeKey(edge.SrcID, edge.DstID, edge.Rel)] = true
	}
	now := time.Now().UTC()

	ensureNode := func(
		kind string,
		title string,
		detail string,
		status string,
		severity string,
		assetID string,
		confidence int,
		sourceRefID string,
	) (*GraphNode, error) {
		title = strings.TrimSpace(title)
		if title == "" {
			return nil, nil
		}
		key := graphNodeKey(kind, title, sourceRefID, assetID)
		existing, ok := byKey[key]
		if !ok && assetID != "" {
			legacyKey := graphNodeKey(kind, title, sourceRefID, "")
			if legacy, legacyOK := byKey[legacyKey]; legacyOK && legacy.AssetID == "" {
				existing = legacy
				ok = true
				delete(byKey, legacyKey)
				byKey[key] = legacy
			}
		}
		if ok {
			changed := false
			if detail != "" && existing.Detail != detail {
				existing.Detail = detail
				changed = true
			}
			if status != "" && existing.Status != status {
				existing.Status = status
				changed = true
			}
			if severity != "" && existing.Severity != severity {
				existing.Severity = severity
				changed = true
			}
			if assetID != "" && existing.AssetID != assetID {
				existing.AssetID = assetID
				changed = true
			}
			if confidence > 0 && existing.Confidence != confidence {
				existing.Confidence = confidence
				changed = true
			}
			if changed {
				existing.UpdatedAt = now
				if err := db.UpdateProjectGraphNode(ctx, *existing); err != nil {
					return nil, err
				}
				result.UpdatedNodes++
			}
			return existing, nil
		}
		source := "auto-sync"
		if sourceRefID != "" {
			source = "vulnerability"
		}
		node := &GraphNode{
			ID:          newID(),
			ProjectID:   project.ID,
			Kind:        kind,
			Title:       title,
			Detail:      detail,
			Status:      status,
			Confidence:  confidence,
			Severity:    severity,
			AssetID:     assetID,
			Source:      source,
			SourceRefID: sourceRefID,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		saved, err := db.UpsertProjectGraphNode(ctx, *node)
		if err != nil {
			return nil, err
		}
		byKey[key] = saved
		allNodes = append(allNodes, saved)
		// 并发同步下 upsert 可能命中已存在的节点（id 不同），此时不计入新增。
		if saved.ID == node.ID {
			result.CreatedNodes++
		}
		return saved, nil
	}

	latestOfKind := func(assetID string, kinds ...string) *GraphNode {
		want := make(map[string]bool, len(kinds))
		for _, kind := range kinds {
			want[kind] = true
		}
		var latest *GraphNode
		for _, node := range allNodes {
			if !want[node.Kind] {
				continue
			}
			if assetID != "" && node.AssetID != "" && node.AssetID != assetID {
				continue
			}
			if latest == nil || node.CreatedAt.After(latest.CreatedAt) ||
				(node.CreatedAt.Equal(latest.CreatedAt) && node.ID > latest.ID) {
				latest = node
			}
		}
		return latest
	}

	ensureEdge := func(src, dst *GraphNode, rel string) error {
		if src == nil || dst == nil || src.ID == "" || dst.ID == "" || src.ID == dst.ID {
			return nil
		}
		key := graphEdgeKey(src.ID, dst.ID, rel)
		if edgeSet[key] {
			return nil
		}
		edge := GraphEdge{
			ID:        newID(),
			ProjectID: project.ID,
			SrcID:     src.ID,
			DstID:     dst.ID,
			Rel:       rel,
			CreatedAt: now,
		}
		if err := db.CreateProjectGraphEdge(ctx, edge); err != nil {
			return err
		}
		edgeSet[key] = true
		result.CreatedEdges++
		return nil
	}

	begin, err := ensureNode("begin", "外部攻击者", strings.TrimSpace(project.Scope), "open", "", "", 90, "")
	if err != nil {
		return result, err
	}
	for _, title := range splitProjectGoals(project.Goals) {
		goal, err := ensureNode("goal", title, "", "open", "", "", 80, "")
		if err != nil {
			return result, err
		}
		if err := ensureEdge(begin, goal, "aims"); err != nil {
			return result, err
		}
	}

	facts, err := db.ListProjectFacts(ctx, project.ID)
	if err != nil {
		return result, err
	}
	for _, fact := range projectFactsForGraph(facts) {
		detail := strings.TrimSpace(fact.Body)
		if detail == "" {
			detail = strings.TrimSpace(fact.Summary)
		}
		if detail == "" {
			detail = fact.Value
		}
		if _, err := ensureNode(
			"fact",
			fact.Key,
			detail,
			"confirmed",
			"",
			fact.AssetID,
			fact.Confidence,
			fact.ID,
		); err != nil {
			return result, err
		}
	}

	vulnerabilities, _, err := db.ListVulnerabilitiesFiltered(ctx, VulnerabilityFilter{
		OwnerUserID: project.OwnerUserID,
		ProjectID:   project.ID,
		Limit:       1000,
	})
	if err != nil {
		return result, err
	}
	for _, item := range vulnerabilities {
		if _, err := ensureNode(
			"finding",
			item.Title,
			item.Description,
			graphFindingStatus(item.Status),
			item.Severity,
			item.AssetID,
			90,
			item.ID,
		); err != nil {
			return result, err
		}
	}

	// 补入边：优先挂到意图，其次目标，最后起点。
	for _, node := range allNodes {
		var rel string
		var anchor *GraphNode
		switch node.Kind {
		case "intent":
			rel, anchor = "plans", latestOfKind(node.AssetID, "goal")
		case "fact":
			if hasIncomingGraphEdge(edgeSet, node.ID, "yields") {
				continue
			}
			rel, anchor = "yields", latestOfKind(node.AssetID, "intent", "goal")
		case "finding":
			if hasIncomingGraphEdge(edgeSet, node.ID, "proves") {
				continue
			}
			rel, anchor = "proves", latestOfKind(node.AssetID, "intent", "goal")
		case "hint":
			if hasIncomingGraphEdge(edgeSet, node.ID, "hints") {
				continue
			}
			rel, anchor = "hints", latestOfKind(node.AssetID, "goal", "intent")
		default:
			continue
		}
		if anchor == nil {
			anchor = begin
		}
		if err := ensureEdge(anchor, node, rel); err != nil {
			return result, err
		}
	}
	return result, nil
}

// pruneProjectGraphSingleEdges 让 intent/fact/finding/hint 各自只保留一条
// 来自当前锚点的关系边，避免历史同步不断追加导致边数无限增长。
func (db *DB) pruneProjectGraphSingleEdges(ctx context.Context, projectID string) error {
	_, err := db.ExecContext(
		ctx,
		`DELETE FROM project_graph_edges
		 WHERE project_id = ?
		   AND rel IN ('plans', 'yields', 'proves', 'hints')
		   AND rowid NOT IN (
			SELECT MAX(rowid) FROM project_graph_edges
			WHERE project_id = ?
			  AND rel IN ('plans', 'yields', 'proves', 'hints')
			GROUP BY rel, dst_id
		   )`,
		projectID,
		projectID,
	)
	return err
}

// projectFactsForGraph 只把高价值事实物化到攻击路径：
// 固定事实、chain/exploit/poc 上下文、显式关联意图或漏洞的事实，
// 以及每个资产按优先级排序的前 3 条事实。其余事实保留在黑板索引中。
func projectFactsForGraph(facts []ProjectFact) []ProjectFact {
	grouped := make(map[string][]ProjectFact)
	order := make([]string, 0)
	for _, fact := range facts {
		key := strings.TrimSpace(fact.AssetID)
		if _, exists := grouped[key]; !exists {
			order = append(order, key)
		}
		grouped[key] = append(grouped[key], fact)
	}
	type candidate struct {
		fact      ProjectFact
		highValue bool
	}
	candidates := make([]candidate, 0, len(facts))
	for _, assetID := range order {
		items := grouped[assetID]
		sort.SliceStable(items, func(i, j int) bool {
			leftHigh := factMaterializationValue(items[i])
			rightHigh := factMaterializationValue(items[j])
			if leftHigh != rightHigh {
				return leftHigh
			}
			if items[i].Priority != items[j].Priority {
				return items[i].Priority > items[j].Priority
			}
			if items[i].Confidence != items[j].Confidence {
				return items[i].Confidence > items[j].Confidence
			}
			return items[i].UpdatedAt.After(items[j].UpdatedAt)
		})
		limit := maxMaterializedFactsPerAsset
		if len(items) < limit {
			limit = len(items)
		}
		for index := 0; index < limit; index++ {
			candidates = append(candidates, candidate{
				fact:      items[index],
				highValue: factMaterializationValue(items[index]),
			})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].highValue != candidates[j].highValue {
			return candidates[i].highValue
		}
		if candidates[i].fact.Priority != candidates[j].fact.Priority {
			return candidates[i].fact.Priority > candidates[j].fact.Priority
		}
		return candidates[i].fact.Confidence > candidates[j].fact.Confidence
	})
	if len(candidates) > maxMaterializedFactsPerProject {
		candidates = candidates[:maxMaterializedFactsPerProject]
	}
	result := make([]ProjectFact, 0, len(candidates))
	for _, item := range candidates {
		result = append(result, item.fact)
	}
	return result
}

func factMaterializationValue(fact ProjectFact) bool {
	return fact.Pinned ||
		hasFactKeyPrefix(fact.Key, "chain/", "exploit/", "poc/", "finding/") ||
		strings.Contains(strings.ToLower(fact.Relation), "intent:") ||
		strings.Contains(strings.ToLower(fact.Relation), "finding:")
}

func hasFactKeyPrefix(key string, prefixes ...string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, prefix := range prefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func graphNodeKey(kind, title, sourceRefID, assetID string) string {
	identity := "title:" + strings.TrimSpace(title)
	if sourceRefID = strings.TrimSpace(sourceRefID); sourceRefID != "" {
		identity = "ref:" + sourceRefID
	}
	return strings.ToLower(strings.TrimSpace(kind)) + "\x00" + identity + "\x00asset:" + strings.TrimSpace(assetID)
}

// graphFindingStatus 把漏洞状态映射为攻击路径 finding 节点状态（前端仅支持 confirmed/dismissed）。
func graphFindingStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "fixed", "ignored", "false_positive":
		return "dismissed"
	default:
		return "confirmed"
	}
}

func graphEdgeKey(srcID, dstID, rel string) string {
	return srcID + "\x00" + dstID + "\x00" + rel
}

func hasIncomingGraphEdge(edgeSet map[string]bool, dstID string, rel string) bool {
	suffix := "\x00" + dstID + "\x00" + rel
	for key := range edgeSet {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

// splitProjectGoals 把项目目标文本拆成最多 maxProjectGoalNodes 个目标标题。
func splitProjectGoals(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case '\n', '\r', ';', '；':
			return true
		}
		return false
	})
	goals := make([]string, 0, len(fields))
	seen := make(map[string]bool, len(fields))
	for _, field := range fields {
		title := strings.TrimSpace(field)
		if runes := []rune(title); len(runes) > maxGraphNodeTitleRun {
			title = string(runes[:maxGraphNodeTitleRun]) + "…"
		}
		if title == "" || seen[title] {
			continue
		}
		seen[title] = true
		goals = append(goals, title)
		if len(goals) >= maxProjectGoalNodes {
			break
		}
	}
	if len(goals) == 0 {
		return []string{"完成项目目标"}
	}
	return goals
}
