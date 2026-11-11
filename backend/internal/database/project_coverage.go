package database

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// CoverageTarget 表示未覆盖队列中的一项（资产 / 意图 / 证据缺口）。
type CoverageTarget struct {
	Kind   string `json:"kind"`
	RefID  string `json:"refId"`
	Label  string `json:"label"`
	Reason string `json:"reason"`
	Score  int    `json:"score"`
}

// AssetCoverageState 描述单个资产基于当前测试计划得到的完整覆盖状态。
type AssetCoverageState struct {
	AssetID            string `json:"assetId"`
	Label              string `json:"label"`
	Status             string `json:"status"`
	TestsTotal         int    `json:"testsTotal"`
	TestsCovered       int    `json:"testsCovered"`
	RequiredOpen       int    `json:"requiredOpen"`
	RequiredBlocked    int    `json:"requiredBlocked"`
	RequiredSuspicious int    `json:"requiredSuspicious"`
	Findings           int    `json:"findings"`
}

// ProjectCoverage 汇总项目覆盖率与未覆盖队列，用于看板展示与 Agent 下一步决策。
type ProjectCoverage struct {
	AssetsTotal             int                  `json:"assetsTotal"`
	AssetsTested            int                  `json:"assetsTested"`
	AssetsCovered           int                  `json:"assetsCovered"`
	AssetsPartial           int                  `json:"assetsPartial"`
	AssetsBlocked           int                  `json:"assetsBlocked"`
	AssetsSuspicious        int                  `json:"assetsSuspicious"`
	AssetsUntested          int                  `json:"assetsUntested"`
	TestsTotal              int                  `json:"testsTotal"`
	TestsCovered            int                  `json:"testsCovered"`
	TestsConfirmed          int                  `json:"testsConfirmed"`
	TestsSuspicious         int                  `json:"testsSuspicious"`
	TestsOpen               int                  `json:"testsOpen"`
	TestsOpenRequired       int                  `json:"testsOpenRequired"`
	TestsOpenOptional       int                  `json:"testsOpenOptional"`
	TestsBlocked            int                  `json:"testsBlocked"`
	TestCoverageRatio       float64              `json:"testCoverageRatio"`
	FindingsTotal           int                  `json:"findingsTotal"`
	FindingsConfirmed       int                  `json:"findingsConfirmed"`
	FindingsWithoutEvidence int                  `json:"findingsWithoutEvidence"`
	FactsTotal              int                  `json:"factsTotal"`
	FactsWithoutEvidence    int                  `json:"factsWithoutEvidence"`
	IntentsOpen             int                  `json:"intentsOpen"`
	IntentsRunning          int                  `json:"intentsRunning"`
	CoverageRatio           float64              `json:"coverageRatio"`
	FullCoverageRatio       float64              `json:"fullCoverageRatio"`
	AssetCoverage           []AssetCoverageState `json:"assetCoverage"`
	UntestedAssets          []Asset              `json:"untestedAssets"`
	NextTargets             []CoverageTarget     `json:"nextTargets"`
}

const (
	coverageUntestedAssetLimit = 50
	coverageNextTargetLimit    = 20
)

// ProjectCoverage 计算项目覆盖情况：
// 资产"已测试"= 被漏洞(asset_id/target)、事实(relation=asset:<id>)或攻击路径节点锚定。
func (db *DB) ProjectCoverage(
	ctx context.Context,
	projectID string,
	ownerUserID string,
) (*ProjectCoverage, error) {
	projectID = strings.TrimSpace(projectID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	if projectID == "" || ownerUserID == "" {
		return nil, fmt.Errorf("项目或用户不能为空")
	}
	// 先校验归属，避免任何跨租户读取。
	if _, err := db.GetProject(ctx, projectID, ownerUserID); err != nil {
		return nil, err
	}

	assets, err := db.ListProjectAssets(ctx, projectID, ownerUserID)
	if err != nil {
		return nil, err
	}
	findingCoverage, err := db.AggregateProjectVulnerabilityCoverage(
		ctx,
		projectID,
		ownerUserID,
	)
	if err != nil {
		return nil, err
	}
	findingSamples, _, err := db.ListVulnerabilitiesFiltered(ctx, VulnerabilityFilter{
		OwnerUserID: ownerUserID,
		ProjectID:   projectID,
		Limit:       500,
	})
	if err != nil {
		return nil, err
	}
	facts, err := db.ListProjectFacts(ctx, projectID)
	if err != nil {
		return nil, err
	}
	testCoverage, err := db.AggregateProjectTestCoverage(ctx, projectID)
	if err != nil {
		return nil, err
	}
	// 列表只用于生成可执行的测试目标；覆盖统计全部使用上面的全量聚合结果。
	testResults, err := db.ListProjectTestResults(ctx, projectID, 500)
	if err != nil {
		return nil, err
	}

	coverage := &ProjectCoverage{
		FindingsTotal:           findingCoverage.FindingsTotal,
		FindingsConfirmed:       findingCoverage.FindingsConfirmed,
		FindingsWithoutEvidence: findingCoverage.FindingsWithoutEvidence,
		FactsTotal:              len(facts),
		AssetCoverage:           make([]AssetCoverageState, 0, len(assets)),
		UntestedAssets:          make([]Asset, 0),
		NextTargets:             make([]CoverageTarget, 0),
	}
	for _, item := range testCoverage {
		coverage.TestsTotal += item.TestsTotal
		coverage.TestsCovered += item.TestsCovered
		coverage.TestsConfirmed += item.TestsConfirmed
		coverage.TestsOpen += item.TestsOpen
		coverage.TestsOpenRequired += item.RequiredOpen
		coverage.TestsOpenOptional += item.TestsOpen - item.RequiredOpen
		coverage.TestsBlocked += item.TestsBlocked
		coverage.TestsSuspicious += item.TestsSuspicious
	}
	targets := make([]CoverageTarget, 0, 32)
	observedAssets := map[string]bool{}
	targetedAssets := map[string]bool{}

	for _, test := range testResults {
		status := strings.ToLower(strings.TrimSpace(test.Status))
		switch status {
		case "suspicious":
			targetedAssets[test.AssetID] = true
			targets = append(targets, CoverageTarget{
				Kind:   "test",
				RefID:  test.ID,
				Label:  coverageTestLabel(test),
				Reason: coverageTestReason(test, "可疑结果待验证"),
				Score:  coverageTestScore(test, 90),
			})
		case "running", "untested":
			targetedAssets[test.AssetID] = true
			targets = append(targets, CoverageTarget{
				Kind:   "test",
				RefID:  test.ID,
				Label:  coverageTestLabel(test),
				Reason: coverageTestReason(test, "测试未完成"),
				Score:  coverageTestScore(test, 75),
			})
		case "blocked":
			targetedAssets[test.AssetID] = true
			targets = append(targets, CoverageTarget{
				Kind:   "test",
				RefID:  test.ID,
				Label:  coverageTestLabel(test),
				Reason: coverageTestReason(test, "测试被阻断"),
				Score:  coverageTestScore(test, 55),
			})
		}
	}
	if coverage.TestsTotal > 0 {
		coverage.TestCoverageRatio = float64(coverage.TestsCovered) / float64(coverage.TestsTotal)
	}

	nodes, err := db.ListProjectGraphNodes(ctx, projectID)
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		if node.Kind != "intent" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(node.Status)) {
		case "running":
			coverage.IntentsRunning++
			targets = append(targets, CoverageTarget{
				Kind:   "intent",
				RefID:  node.ID,
				Label:  node.Title,
				Reason: "进行中意图",
				Score:  80,
			})
		case "open":
			coverage.IntentsOpen++
			targets = append(targets, CoverageTarget{
				Kind:   "intent",
				RefID:  node.ID,
				Label:  node.Title,
				Reason: "待办意图",
				Score:  70,
			})
		}
	}

	for _, item := range findingSamples {
		hasEvidence := strings.TrimSpace(item.Evidence) != "" || len(item.EvidenceRefs) > 0
		if !hasEvidence {
			targets = append(targets, CoverageTarget{
				Kind:   "evidence",
				RefID:  item.ID,
				Label:  item.Title,
				Reason: "漏洞缺证据",
				Score:  60 + coverageSeverityWeight(item.Severity),
			})
		}
	}

	for _, fact := range facts {
		if fact.SubjectType == "audit_scope" || fact.SubjectType == "audit_checkpoint" {
			continue
		}
		if fact.SubjectType == "audit_cell" && fact.Predicate == "coverage" {
			switch strings.ToLower(strings.TrimSpace(fact.ObjectKey)) {
			case "not_audited":
				targets = append(targets, CoverageTarget{
					Kind:   "audit_cell",
					RefID:  fact.ID,
					Label:  fact.SubjectKey,
					Reason: "审计覆盖矩阵仍有 not_audited 单元格",
					Score:  88,
				})
			case "tested":
				if assetID := coverageFactAssetID(fact); assetID != "" {
					observedAssets[assetID] = true
				}
			}
			continue
		}
		if strings.TrimSpace(fact.Evidence) != "" {
			if assetID := coverageFactAssetID(fact); assetID != "" {
				observedAssets[assetID] = true
			}
			continue
		}
		coverage.FactsWithoutEvidence++
		reason := "事实缺证据"
		if fact.Tainted {
			reason = "污点事实待复核"
		}
		score := 50
		if fact.Importance > 0 {
			score = 40 + fact.Importance/2
		}
		targets = append(targets, CoverageTarget{
			Kind:   "evidence",
			RefID:  fact.ID,
			Label:  fact.Key,
			Reason: reason,
			Score:  score,
		})
	}

	for _, asset := range assets {
		coverage.AssetsTotal++
		testState := testCoverage[asset.ID]
		findingState := findingCoverage.ByAsset[asset.ID]
		observed := testState.TestsTotal > 0 ||
			findingState.WithEvidence > 0 ||
			findingCoverage.EvidenceBackedTargets[coverageNormalizeValue(asset.Value)] ||
			observedAssets[asset.ID]

		status := "untested"
		if observed {
			coverage.AssetsTested++
			switch {
			case testState.RequiredTotal > 0 &&
				testState.RequiredCovered == testState.RequiredTotal:
				status = "covered"
				coverage.AssetsCovered++
			case testState.RequiredBlocked > 0:
				status = "blocked"
			case testState.RequiredSuspicious > 0:
				status = "suspicious"
			default:
				status = "partial"
			}
			if status != "covered" {
				coverage.AssetsPartial++
			}
			if testState.RequiredBlocked > 0 {
				coverage.AssetsBlocked++
			}
			if testState.RequiredSuspicious > 0 {
				coverage.AssetsSuspicious++
			}
		} else {
			if len(coverage.UntestedAssets) < coverageUntestedAssetLimit {
				coverage.UntestedAssets = append(coverage.UntestedAssets, asset)
			}
			targets = append(targets, CoverageTarget{
				Kind:   "asset",
				RefID:  asset.ID,
				Label:  coverageAssetLabel(asset),
				Reason: "未测试",
				Score:  coverageCriticalityWeight(asset.Criticality) + asset.RiskScore,
			})
		}

		coverage.AssetCoverage = append(coverage.AssetCoverage, AssetCoverageState{
			AssetID:            asset.ID,
			Label:              coverageAssetLabel(asset),
			Status:             status,
			TestsTotal:         testState.TestsTotal,
			TestsCovered:       testState.TestsCovered,
			RequiredOpen:       testState.RequiredOpen,
			RequiredBlocked:    testState.RequiredBlocked,
			RequiredSuspicious: testState.RequiredSuspicious,
			Findings:           findingState.FindingsTotal,
		})
		if observed && status != "covered" && !targetedAssets[asset.ID] {
			reason := "已有观察但测试计划不完整"
			switch status {
			case "blocked":
				reason = fmt.Sprintf("必选测试被阻断 %d 项", testState.RequiredBlocked)
			case "suspicious":
				reason = fmt.Sprintf("必选测试结果可疑 %d 项", testState.RequiredSuspicious)
			}
			targets = append(targets, CoverageTarget{
				Kind:   "asset",
				RefID:  asset.ID,
				Label:  coverageAssetLabel(asset),
				Reason: reason,
				Score: coverageCriticalityWeight(asset.Criticality) +
					asset.RiskScore + 15,
			})
		}
	}
	coverage.AssetsUntested = coverage.AssetsTotal - coverage.AssetsTested
	if coverage.AssetsTotal > 0 {
		coverage.CoverageRatio = float64(coverage.AssetsTested) / float64(coverage.AssetsTotal)
		coverage.FullCoverageRatio = float64(coverage.AssetsCovered) / float64(coverage.AssetsTotal)
	}

	sort.SliceStable(targets, func(i, j int) bool {
		if targets[i].Score != targets[j].Score {
			return targets[i].Score > targets[j].Score
		}
		if targets[i].Kind != targets[j].Kind {
			return targets[i].Kind < targets[j].Kind
		}
		return targets[i].Label < targets[j].Label
	})
	if len(targets) > coverageNextTargetLimit {
		targets = targets[:coverageNextTargetLimit]
	}
	coverage.NextTargets = targets
	return coverage, nil
}

func coverageNormalizeValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimRight(value, "/")
	return value
}

func coverageFactAssetID(fact ProjectFact) string {
	if assetID := strings.TrimSpace(fact.AssetID); assetID != "" {
		return assetID
	}
	for _, prefix := range []string{"asset:", "asset_id:"} {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(fact.Relation)), prefix) {
			return strings.TrimSpace(fact.Relation[len(prefix):])
		}
	}
	if strings.EqualFold(strings.TrimSpace(fact.SubjectType), "asset") {
		return strings.TrimSpace(fact.SubjectKey)
	}
	return ""
}

func coverageCriticalityWeight(criticality string) int {
	switch strings.ToLower(strings.TrimSpace(criticality)) {
	case "critical":
		return 100
	case "high":
		return 80
	case "medium":
		return 60
	case "low":
		return 40
	default:
		return 50
	}
}

func coverageSeverityWeight(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 40
	case "high":
		return 30
	case "medium":
		return 20
	case "low":
		return 10
	default:
		return 15
	}
}

func coverageAssetLabel(asset Asset) string {
	name := strings.TrimSpace(asset.Name)
	value := strings.TrimSpace(asset.Value)
	switch {
	case name == "":
		return value
	case value == "" || value == name:
		return name
	default:
		return name + "（" + value + "）"
	}
}

func coverageTestLabel(item ProjectTestResult) string {
	label := strings.TrimSpace(item.Dimension)
	if technique := strings.TrimSpace(item.Technique); technique != "" {
		label += "/" + technique
	}
	if assetID := strings.TrimSpace(item.AssetID); assetID != "" {
		label += "（" + assetID + "）"
	}
	return label
}

func coverageTestReason(item ProjectTestResult, fallback string) string {
	if rationale := strings.TrimSpace(item.Rationale); rationale != "" {
		return fallback + "：" + rationale
	}
	return fallback
}

func coverageTestScore(item ProjectTestResult, fallback int) int {
	if item.Priority > 0 {
		return item.Priority
	}
	return fallback
}
