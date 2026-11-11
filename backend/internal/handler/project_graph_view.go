package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"sophon/internal/database"
)

type attackChainView struct {
	Nodes []database.GraphNode
	Edges []database.GraphEdge
}

type graphDigestGroup struct {
	key     string
	kind    string
	assetID string
	nodes   []database.GraphNode
}

const maxAttackChainViewNodes = 4000

func buildAttackChainView(
	nodes []database.GraphNode,
	edges []database.GraphEdge,
	assets []database.Asset,
	chains []database.CampaignChain,
	assetID string,
) attackChainView {
	assetID = strings.TrimSpace(assetID)
	nodeByID := make(map[string]database.GraphNode, len(nodes))
	visible := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		nodeByID[node.ID] = node
		if chainViewNodeVisible(node) {
			visible[node.ID] = true
		}
	}

	// 把与前沿直接相连的事实和提示保留在链路中，避免折叠掉关键证据。
	for pass := 0; pass < 2; pass++ {
		for _, edge := range edges {
			src, srcOK := nodeByID[edge.SrcID]
			dst, dstOK := nodeByID[edge.DstID]
			if !srcOK || !dstOK {
				continue
			}
			if visible[src.ID] && chainViewSupportingKind(dst.Kind) {
				visible[dst.ID] = true
			}
			if visible[dst.ID] && chainViewSupportingKind(src.Kind) {
				visible[src.ID] = true
			}
		}
	}
	coreVisible := 0
	supporting := make([]database.GraphNode, 0)
	for _, node := range nodes {
		if !visible[node.ID] {
			continue
		}
		if chainViewSupportingKind(node.Kind) {
			supporting = append(supporting, node)
		} else {
			coreVisible++
		}
	}
	if len(visible) > maxAttackChainViewNodes {
		limit := maxAttackChainViewNodes - coreVisible
		if limit < 0 {
			limit = 0
		}
		sort.SliceStable(supporting, func(i, j int) bool {
			return supporting[i].UpdatedAt.After(supporting[j].UpdatedAt)
		})
		for index := limit; index < len(supporting); index++ {
			delete(visible, supporting[index].ID)
		}
	}

	coldGroups := make(map[string]*graphDigestGroup)
	nodeGroup := make(map[string]string)
	for _, node := range nodes {
		if visible[node.ID] {
			continue
		}
		groupKey := node.Kind + "\x00" + node.AssetID
		group := coldGroups[groupKey]
		if group == nil {
			group = &graphDigestGroup{
				key:     groupKey,
				kind:    node.Kind,
				assetID: node.AssetID,
			}
			coldGroups[groupKey] = group
		}
		group.nodes = append(group.nodes, node)
		nodeGroup[node.ID] = groupKey
	}

	now := time.Now().UTC()
	viewNodes := make([]database.GraphNode, 0, len(nodes)+len(coldGroups)+len(chains))
	for _, node := range nodes {
		if visible[node.ID] {
			viewNodes = append(viewNodes, node)
		}
	}
	groupKeys := make([]string, 0, len(coldGroups))
	for key := range coldGroups {
		groupKeys = append(groupKeys, key)
	}
	sort.Strings(groupKeys)
	digestByGroup := make(map[string]string, len(groupKeys))
	for _, key := range groupKeys {
		group := coldGroups[key]
		digestID := syntheticGraphID("digest", key)
		digestByGroup[key] = digestID
		viewNodes = append(viewNodes, database.GraphNode{
			ID:          digestID,
			Kind:        "digest",
			Title:       fmt.Sprintf("已折叠 %d 个%s", len(group.nodes), graphKindLabel(group.kind)),
			Detail:      graphDigestDetail(group.nodes),
			Status:      "cold",
			AssetID:     group.assetID,
			Source:      "synthetic",
			SourceRefID: group.key,
			CreatedAt:   now,
			UpdatedAt:   now,
		})
	}

	viewEdges := make([]database.GraphEdge, 0, len(edges)+len(chains)*3)
	edgeSeen := make(map[string]bool)
	addEdge := func(srcID, dstID, rel string, originalID string) {
		srcID = strings.TrimSpace(srcID)
		dstID = strings.TrimSpace(dstID)
		rel = strings.TrimSpace(rel)
		if srcID == "" || dstID == "" || srcID == dstID || rel == "" {
			return
		}
		key := srcID + "\x00" + dstID + "\x00" + rel
		if edgeSeen[key] {
			return
		}
		edgeSeen[key] = true
		if originalID == "" {
			originalID = syntheticGraphID("edge", srcID, dstID, rel)
		}
		viewEdges = append(viewEdges, database.GraphEdge{
			ID:        originalID,
			SrcID:     srcID,
			DstID:     dstID,
			Rel:       rel,
			CreatedAt: now,
		})
	}

	for _, edge := range edges {
		srcVisible := visible[edge.SrcID]
		dstVisible := visible[edge.DstID]
		switch {
		case srcVisible && dstVisible:
			addEdge(edge.SrcID, edge.DstID, edge.Rel, edge.ID)
		case srcVisible && nodeGroup[edge.DstID] != "":
			addEdge(edge.SrcID, digestByGroup[nodeGroup[edge.DstID]], "digest", "")
		case dstVisible && nodeGroup[edge.SrcID] != "":
			addEdge(digestByGroup[nodeGroup[edge.SrcID]], edge.DstID, "digest", "")
		case nodeGroup[edge.SrcID] != "" && nodeGroup[edge.DstID] != "":
			addEdge(
				digestByGroup[nodeGroup[edge.SrcID]],
				digestByGroup[nodeGroup[edge.DstID]],
				"digest",
				"",
			)
		}
	}

	assetByID := make(map[string]database.Asset, len(assets))
	for _, asset := range assets {
		assetByID[asset.ID] = asset
	}
	for _, chain := range chains {
		if assetID != "" &&
			chain.EntryAssetID != assetID &&
			chain.TargetAssetID != assetID {
			continue
		}
		entryAssetID := ensureSyntheticAssetNode(&viewNodes, assetByID, chain.EntryAssetID, now)
		targetAssetID := ensureSyntheticAssetNode(&viewNodes, assetByID, chain.TargetAssetID, now)
		chainNodeID := syntheticGraphID("chain", chain.ID)
		viewNodes = append(viewNodes, database.GraphNode{
			ID:          chainNodeID,
			Kind:        "chain",
			Title:       chain.Title,
			Detail:      campaignChainDetail(chain),
			Status:      chain.Status,
			Confidence:  chain.Confidence,
			AssetID:     chain.TargetAssetID,
			Source:      "synthetic",
			SourceRefID: chain.ID,
			CreatedAt:   chain.CreatedAt,
			UpdatedAt:   chain.UpdatedAt,
		})
		if entryAssetID != "" {
			addEdge(entryAssetID, chainNodeID, "spawns", "")
		}
		if targetAssetID != "" {
			addEdge(chainNodeID, targetAssetID, "proves", "")
		}
		if sourceFindingID := graphNodeIDBySourceRef(
			nodes,
			"finding",
			chain.SrcFindingID,
			chain.EntryAssetID,
		); sourceFindingID != "" {
			if visible[sourceFindingID] {
				addEdge(sourceFindingID, chainNodeID, "yields", "")
			} else if groupKey := nodeGroup[sourceFindingID]; groupKey != "" {
				addEdge(digestByGroup[groupKey], chainNodeID, "yields", "")
			}
		}
	}

	return attackChainView{Nodes: viewNodes, Edges: viewEdges}
}

func chainViewNodeVisible(node database.GraphNode) bool {
	switch node.Kind {
	case "begin", "goal":
		return true
	case "intent":
		switch node.Status {
		case "open", "running", "blocked", "capacity_blocked":
			return true
		}
	case "finding":
		return node.Status == "confirmed"
	case "hint":
		return node.Status == "active"
	}
	return false
}

func chainViewSupportingKind(kind string) bool {
	return kind == "fact" || kind == "hint"
}

func graphDigestDetail(nodes []database.GraphNode) string {
	if len(nodes) == 0 {
		return ""
	}
	statuses := make(map[string]int)
	for _, node := range nodes {
		statuses[node.Status]++
	}
	statusKeys := make([]string, 0, len(statuses))
	for status := range statuses {
		statusKeys = append(statusKeys, status)
	}
	sort.Strings(statusKeys)
	parts := make([]string, 0, len(statusKeys)+8)
	for _, status := range statusKeys {
		parts = append(parts, fmt.Sprintf("%s=%d", status, statuses[status]))
	}
	limit := len(nodes)
	if limit > 8 {
		limit = 8
	}
	lines := make([]string, 0, limit+1)
	lines = append(lines, "状态："+strings.Join(parts, "，"))
	for _, node := range nodes[:limit] {
		lines = append(lines, "- "+node.Title)
	}
	if len(nodes) > limit {
		lines = append(lines, fmt.Sprintf("- 另有 %d 个节点", len(nodes)-limit))
	}
	return strings.Join(lines, "\n")
}

func graphKindLabel(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "begin":
		return "起点"
	case "goal":
		return "目标"
	case "intent":
		return "意图"
	case "fact":
		return "事实"
	case "finding":
		return "漏洞"
	case "hint":
		return "提示"
	default:
		return "节点"
	}
}

func ensureSyntheticAssetNode(
	nodes *[]database.GraphNode,
	assets map[string]database.Asset,
	assetID string,
	now time.Time,
) string {
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		return ""
	}
	nodeID := syntheticGraphID("asset", assetID)
	for _, node := range *nodes {
		if node.ID == nodeID {
			return nodeID
		}
	}
	title := assetID
	value := ""
	if asset, ok := assets[assetID]; ok {
		if strings.TrimSpace(asset.Name) != "" {
			title = asset.Name
		} else if strings.TrimSpace(asset.Value) != "" {
			title = asset.Value
		}
		value = asset.Value
	}
	detail := value
	if detail != "" && detail != title {
		detail = "资产标识：" + value
	}
	*nodes = append(*nodes, database.GraphNode{
		ID:          nodeID,
		Kind:        "asset",
		Title:       title,
		Detail:      detail,
		Status:      "active",
		AssetID:     assetID,
		Source:      "synthetic",
		SourceRefID: assetID,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	return nodeID
}

func campaignChainDetail(chain database.CampaignChain) string {
	lines := []string{
		fmt.Sprintf("攻击链类型：%s，状态：%s，优先级：%d", chain.Kind, chain.Status, chain.Priority),
	}
	for _, step := range chain.Steps {
		summary := strings.TrimSpace(step.Summary)
		if summary == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("- %s：%s", step.Kind, summary))
	}
	return strings.Join(lines, "\n")
}

func graphNodeIDBySourceRef(
	nodes []database.GraphNode,
	kind string,
	sourceRefID string,
	assetID string,
) string {
	sourceRefID = strings.TrimSpace(sourceRefID)
	assetID = strings.TrimSpace(assetID)
	if sourceRefID == "" {
		return ""
	}
	for _, node := range nodes {
		if node.Kind == kind &&
			node.SourceRefID == sourceRefID &&
			(assetID == "" || node.AssetID == "" || node.AssetID == assetID) {
			return node.ID
		}
	}
	return ""
}

func syntheticGraphID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "view-" + hex.EncodeToString(sum[:])[:20]
}
