package database

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateEvidenceReferencesRejectsFakeAndCrossProjectRefs(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "evidence-references.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-evidence", OwnerUserID: "user-1", Name: "证据项目",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateProject(ctx, Project{
		ID: "project-other", OwnerUserID: "user-2", Name: "其他项目",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建其他项目失败: %v", err)
	}
	validFact, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID: "fact-valid", ProjectID: "project-evidence", FactType: "general",
		Key: "valid-fact", Summary: "真实事实", Value: "真实事实",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("创建事实失败: %v", err)
	}
	if _, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID: "fact-other", ProjectID: "project-other", FactType: "general",
		Key: "other-fact", Summary: "其他项目事实", Value: "其他项目事实",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建其他项目事实失败: %v", err)
	}

	for name, refs := range map[string][]string{
		"普通字符串":   {"garbage"},
		"不存在的键":   {"fact:not-found"},
		"跨项目事实ID": {"fact:fact-other"},
	} {
		err := db.ValidateEvidenceReferences(ctx, EvidenceReferenceOptions{
			ProjectID: "project-evidence", UserID: "user-1", Refs: refs,
			RequireStructured: true,
		})
		if !errors.Is(err, ErrInvalidVulnerabilityEvidence) {
			t.Fatalf("%s应被拒绝，实际 err=%v", name, err)
		}
	}

	if err := db.ValidateEvidenceReferences(ctx, EvidenceReferenceOptions{
		ProjectID: "project-evidence", UserID: "user-1",
		Refs: []string{"fact:" + validFact.ID}, RequireStructured: true,
	}); err != nil {
		t.Fatalf("真实事实引用应通过: %v", err)
	}
}

func TestValidateEvidenceReferencesChecksToolConversationAndArtifactOwnership(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "evidence-ownership.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-owner", OwnerUserID: "user-1", Name: "证据归属",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conversation-owner", OwnerUserID: "user-1",
		ProjectID: "project-owner", Title: "证据会话",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	executionID := db.StartToolExecution(
		ctx,
		"conversation-owner",
		"user-1",
		"nmap",
		map[string]interface{}{"target": "example.com"},
	)
	db.FinishToolExecution(ctx, executionID, "open", nil)

	artifactRoot := t.TempDir()
	artifactPath := filepath.Join(
		artifactRoot,
		"data",
		"conversation_artifacts",
		"conversation-owner",
		"tool_results",
		"scan.txt",
	)
	if err := os.MkdirAll(filepath.Dir(artifactPath), 0o750); err != nil {
		t.Fatalf("创建 artifact 目录失败: %v", err)
	}
	if err := os.WriteFile(artifactPath, []byte("scan result"), 0o600); err != nil {
		t.Fatalf("写入 artifact 失败: %v", err)
	}
	outsidePath := filepath.Join(artifactRoot, "config.yml")
	if err := os.WriteFile(outsidePath, []byte("secret"), 0o600); err != nil {
		t.Fatalf("写入目录外文件失败: %v", err)
	}

	for _, ref := range []string{
		"tool:" + executionID,
		"conversation:conversation-owner",
		"file:" + artifactPath,
	} {
		if err := db.ValidateEvidenceReferences(ctx, EvidenceReferenceOptions{
			ProjectID: "project-owner", UserID: "user-1",
			Refs: []string{ref}, ArtifactRoot: artifactRoot,
			RequireStructured: true,
		}); err != nil {
			t.Fatalf("有效证据引用 %s 应通过: %v", ref, err)
		}
	}

	for _, ref := range []string{
		"tool:not-found",
		"conversation:not-found",
		"file:" + outsidePath,
		"file:/etc/passwd",
	} {
		err := db.ValidateEvidenceReferences(ctx, EvidenceReferenceOptions{
			ProjectID: "project-owner", UserID: "user-1",
			Refs: []string{ref}, ArtifactRoot: artifactRoot,
			RequireStructured: true,
		})
		if !errors.Is(err, ErrInvalidVulnerabilityEvidence) {
			t.Fatalf("无效证据引用 %s 应被拒绝，实际 err=%v", ref, err)
		}
	}
}
