package handler

import (
	"testing"
	"time"

	"sophon/internal/database"
)

func TestBuildAttackChainViewFoldsColdNodes(t *testing.T) {
	now := time.Now().UTC()
	nodes := []database.GraphNode{
		{ID: "goal-1", Kind: "goal", Title: "达成目标", Status: "met", CreatedAt: now, UpdatedAt: now},
		{ID: "intent-open", Kind: "intent", Title: "继续验证", Status: "open", CreatedAt: now, UpdatedAt: now},
		{ID: "fact-1", Kind: "fact", Title: "关键事实", Status: "confirmed", CreatedAt: now, UpdatedAt: now},
		{ID: "intent-done-1", Kind: "intent", Title: "已完成方向一", Status: "done", CreatedAt: now, UpdatedAt: now},
		{ID: "intent-done-2", Kind: "intent", Title: "已完成方向二", Status: "done", CreatedAt: now, UpdatedAt: now},
		{ID: "finding-1", Kind: "finding", Title: "最终漏洞", Status: "confirmed", CreatedAt: now, UpdatedAt: now},
	}
	edges := []database.GraphEdge{
		{ID: "edge-1", SrcID: "goal-1", DstID: "intent-open", Rel: "spawns"},
		{ID: "edge-2", SrcID: "intent-open", DstID: "fact-1", Rel: "yields"},
		{ID: "edge-3", SrcID: "intent-done-1", DstID: "finding-1", Rel: "proves"},
		{ID: "edge-4", SrcID: "intent-done-2", DstID: "finding-1", Rel: "proves"},
	}
	view := buildAttackChainView(nodes, edges, nil, nil, "")
	if !hasViewNode(view.Nodes, "intent-open") ||
		!hasViewNode(view.Nodes, "fact-1") ||
		!hasViewNode(view.Nodes, "finding-1") {
		t.Fatalf("链路视图不应折叠前沿节点: %+v", view.Nodes)
	}
	digestID := ""
	for _, node := range view.Nodes {
		if node.Kind == "digest" {
			digestID = node.ID
			break
		}
	}
	if digestID == "" {
		t.Fatalf("冷 intent 应折叠为 digest: %+v", view.Nodes)
	}
	if !hasViewEdge(view.Edges, digestID, "finding-1", "digest") {
		t.Fatalf("digest 应桥接冷节点到最终漏洞: %+v", view.Edges)
	}
	if hasViewNode(view.Nodes, "intent-done-1") || hasViewNode(view.Nodes, "intent-done-2") {
		t.Fatalf("冷 intent 不应继续展开: %+v", view.Nodes)
	}
}

func TestBuildAttackChainViewAddsCampaignChains(t *testing.T) {
	now := time.Now().UTC()
	nodes := []database.GraphNode{
		{
			ID:          "finding-source",
			Kind:        "finding",
			Title:       "凭据泄露",
			Status:      "confirmed",
			SourceRefID: "vuln-1",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
	assets := []database.Asset{
		{ID: "asset-a", Name: "入口资产", Value: "https://a.example.com"},
		{ID: "asset-b", Name: "目标资产", Value: "https://b.example.com"},
	}
	chains := []database.CampaignChain{
		{
			ID:            "chain-1",
			Title:         "凭据复用横向移动",
			Kind:          "credential_reuse",
			Status:        "verified",
			Priority:      90,
			Confidence:    88,
			EntryAssetID:  "asset-a",
			TargetAssetID: "asset-b",
			SrcFindingID:  "vuln-1",
			CreatedAt:     now,
			UpdatedAt:     now,
			Steps: []database.CampaignChainStep{
				{Kind: "entry", AssetID: "asset-a", Summary: "获取有效凭据"},
				{Kind: "pivot", AssetID: "asset-b", Summary: "复用凭据进入目标资产"},
			},
		},
	}
	view := buildAttackChainView(nodes, nil, assets, chains, "")
	if countViewKind(view.Nodes, "chain") != 1 {
		t.Fatalf("应注入攻击链节点: %+v", view.Nodes)
	}
	if countViewKind(view.Nodes, "asset") != 2 {
		t.Fatalf("应注入跨资产节点: %+v", view.Nodes)
	}
	chainNodeID := firstViewNodeID(view.Nodes, "chain")
	entryNodeID := viewNodeIDBySourceRef(view.Nodes, "asset", "asset-a")
	targetNodeID := viewNodeIDBySourceRef(view.Nodes, "asset", "asset-b")
	if !hasViewEdge(view.Edges, entryNodeID, chainNodeID, "spawns") ||
		!hasViewEdge(view.Edges, chainNodeID, targetNodeID, "proves") ||
		!hasViewEdge(view.Edges, "finding-source", chainNodeID, "yields") {
		t.Fatalf("跨资产攻击链连线不完整: %+v", view.Edges)
	}
}

func hasViewNode(nodes []database.GraphNode, id string) bool {
	for _, node := range nodes {
		if node.ID == id {
			return true
		}
	}
	return false
}

func hasViewEdge(edges []database.GraphEdge, srcID, dstID, rel string) bool {
	if srcID == "" || dstID == "" {
		return false
	}
	for _, edge := range edges {
		if edge.SrcID == srcID && edge.DstID == dstID && edge.Rel == rel {
			return true
		}
	}
	return false
}

func countViewKind(nodes []database.GraphNode, kind string) int {
	count := 0
	for _, node := range nodes {
		if node.Kind == kind {
			count++
		}
	}
	return count
}

func firstViewNodeID(nodes []database.GraphNode, kind string) string {
	for _, node := range nodes {
		if node.Kind == kind {
			return node.ID
		}
	}
	return ""
}

func viewNodeIDBySourceRef(nodes []database.GraphNode, kind, sourceRefID string) string {
	for _, node := range nodes {
		if node.Kind == kind && node.SourceRefID == sourceRefID {
			return node.ID
		}
	}
	return ""
}
