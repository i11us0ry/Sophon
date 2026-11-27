package database

import (
	"context"
	"fmt"
	"strings"
)

type AssetCloseoutStatus struct {
	AssetID          string   `json:"assetId"`
	CanClose         bool     `json:"canClose"`
	Missing          []string `json:"missing"`
	TestsTotal       int      `json:"testsTotal"`
	TestsCovered     int      `json:"testsCovered"`
	TestsOpen        int      `json:"testsOpen"`
	TestsBlocked     int      `json:"testsBlocked"`
	TestsSuspicious  int      `json:"testsSuspicious"`
	RequiredOpen     int      `json:"requiredOpen"`
	RequiredBlocked  int      `json:"requiredBlocked"`
	RequiredSuspect  int      `json:"requiredSuspicious"`
	OpenIntents      int      `json:"openIntents"`
	EvidenceGaps     int      `json:"evidenceGaps"`
	Authorization    string   `json:"authorizationState"`
	CurrentWorkState string   `json:"currentWorkState"`
}

// AssetCloseoutStatus is the deterministic gate used before an asset can be
// marked complete. The model may suggest closing an asset, but this function is
// the server-side source of truth.
func (db *DB) AssetCloseoutStatus(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	assetID string,
) (*AssetCloseoutStatus, error) {
	projectID = strings.TrimSpace(projectID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	assetID = strings.TrimSpace(assetID)
	if projectID == "" || ownerUserID == "" || assetID == "" {
		return nil, fmt.Errorf("项目、用户、资产不能为空")
	}
	project, err := db.GetProject(ctx, projectID, ownerUserID)
	if err != nil {
		return nil, err
	}
	asset, err := db.GetAsset(ctx, assetID, ownerUserID)
	if err != nil {
		return nil, err
	}
	if asset == nil || asset.ProjectID != projectID {
		return nil, fmt.Errorf("资产不属于当前项目")
	}
	if err := db.SyncProjectAssetWork(ctx, projectID, ownerUserID); err != nil {
		return nil, err
	}
	work, err := db.GetProjectAssetWork(ctx, projectID, ownerUserID, assetID)
	if err != nil {
		return nil, err
	}
	status := &AssetCloseoutStatus{
		AssetID:  assetID,
		Missing:  make([]string, 0),
		CanClose: true,
	}
	if work != nil {
		status.Authorization = work.AuthorizationState
		status.CurrentWorkState = work.WorkState
	}
	if !assetTestingEligible(project.Scope, *asset) {
		status.CanClose = false
		status.Missing = append(status.Missing, "资产类型、状态或质量不允许进入关闭流程")
	}
	if status.Authorization != AssetAuthorizationAuthorized {
		status.CanClose = false
		status.Missing = append(status.Missing, "资产尚未获得项目测试授权")
	}

	coverage, err := db.ProjectCoverage(ctx, projectID, ownerUserID)
	if err != nil {
		return nil, err
	}
	for _, item := range coverage.AssetCoverage {
		if item.AssetID != assetID {
			continue
		}
		status.TestsTotal = item.TestsTotal
		status.TestsCovered = item.TestsCovered
		status.TestsOpen = item.TestsOpen
		status.TestsBlocked = item.TestsBlocked
		status.TestsSuspicious = item.TestsSuspicious
		status.RequiredOpen = item.RequiredOpen
		status.RequiredBlocked = item.RequiredBlocked
		status.RequiredSuspect = item.RequiredSuspicious
		status.EvidenceGaps += item.FindingsWithoutEvidence
		break
	}
	if status.TestsTotal == 0 {
		status.CanClose = false
		status.Missing = append(status.Missing, "尚未建立可验证的测试计划")
	}
	if status.RequiredOpen > 0 {
		status.CanClose = false
		status.Missing = append(status.Missing, fmt.Sprintf("仍有 %d 项必选测试未完成", status.RequiredOpen))
	}
	if status.RequiredBlocked > 0 {
		status.CanClose = false
		status.Missing = append(status.Missing, fmt.Sprintf("仍有 %d 项必选测试被阻断", status.RequiredBlocked))
	}
	if status.RequiredSuspect > 0 {
		status.CanClose = false
		status.Missing = append(status.Missing, fmt.Sprintf("仍有 %d 项必选测试结果可疑", status.RequiredSuspect))
	}
	if status.TestsOpen > 0 {
		status.CanClose = false
		status.Missing = append(status.Missing, fmt.Sprintf("仍有 %d 项测试未收敛", status.TestsOpen))
	}
	if status.TestsBlocked > 0 {
		status.CanClose = false
		status.Missing = append(status.Missing, fmt.Sprintf("仍有 %d 项测试被阻断", status.TestsBlocked))
	}
	if status.TestsSuspicious > 0 {
		status.CanClose = false
		status.Missing = append(status.Missing, fmt.Sprintf("仍有 %d 项测试结果可疑", status.TestsSuspicious))
	}

	nodes, err := db.ListProjectGraphNodesByAsset(ctx, projectID, assetID)
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		if node.AssetID != assetID {
			continue
		}
		if strings.EqualFold(node.Kind, "intent") {
			switch strings.ToLower(strings.TrimSpace(node.Status)) {
			case "open", "running", "paused", "blocked", "capacity_blocked":
				status.OpenIntents++
			}
		}
	}
	// Graph intents are retained for history and may predate the current
	// hypothesis model. Test execution state below is the blocking authority.

	facts, err := db.ListProjectFactsByAsset(ctx, projectID, assetID)
	if err != nil {
		return nil, err
	}
	for _, fact := range facts {
		if fact.AssetID == assetID &&
			strings.TrimSpace(fact.Evidence) == "" &&
			!strings.EqualFold(fact.SubjectType, "audit_scope") &&
			!strings.EqualFold(fact.SubjectType, "audit_checkpoint") {
			status.EvidenceGaps++
		}
	}
	if status.EvidenceGaps > 0 {
		status.CanClose = false
		status.Missing = append(status.Missing, fmt.Sprintf("仍有 %d 条资产级证据缺口", status.EvidenceGaps))
	}
	return status, nil
}
