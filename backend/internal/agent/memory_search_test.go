package agent

import (
	"context"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestRankProjectFactsPrefersRelevant(t *testing.T) {
	now := time.Now().UTC()
	facts := []database.ProjectFact{
		{
			ID:         "fact-db",
			Key:        "数据库版本",
			Summary:    "MySQL 8.0.32 存在已知漏洞",
			FactType:   "service",
			Importance: 70,
			UpdatedAt:  now.Add(-48 * time.Hour),
		},
		{
			ID:         "fact-web",
			Key:        "Web 框架",
			Summary:    "目标使用 Spring Boot 2.3",
			FactType:   "service",
			Importance: 95,
			UpdatedAt:  now,
		},
	}
	service := &Service{}
	ranked := service.rankProjectFacts(context.Background(), "数据库 MySQL 版本漏洞", facts)
	if len(ranked) != 2 {
		t.Fatalf("应返回全部有效记忆，实际 %d", len(ranked))
	}
	if ranked[0].Fact.ID != "fact-db" {
		t.Fatalf("与查询相关的记忆应排第一，实际 %s", ranked[0].Fact.ID)
	}

	empty := service.rankProjectFacts(context.Background(), "", facts)
	if empty[0].Fact.ID != "fact-web" {
		t.Fatalf("无查询时应按重要度排序，实际 %s", empty[0].Fact.ID)
	}
}

func TestRankProjectFactsSkipsSuperseded(t *testing.T) {
	now := time.Now().UTC()
	facts := []database.ProjectFact{
		{ID: "active", Key: "a", Summary: "目标端口 22 开放", UpdatedAt: now},
		{ID: "invalid", Key: "b", Summary: "目标端口 22 开放", UpdatedAt: now, ValidTo: now},
	}
	service := &Service{}
	ranked := service.rankProjectFacts(context.Background(), "端口", facts)
	if len(ranked) != 1 || ranked[0].Fact.ID != "active" {
		t.Fatalf("失效记忆不应参与排序: %+v", ranked)
	}
}

func TestEmbeddingEncodeDecodeRoundTrip(t *testing.T) {
	vector := []float64{0.1, -0.25, 0.75, 1}
	decoded := decodeEmbedding(encodeEmbedding(vector), len(vector))
	if len(decoded) != len(vector) {
		t.Fatalf("向量长度不一致: %d", len(decoded))
	}
	for index := range vector {
		if diff := decoded[index] - vector[index]; diff > 1e-6 || diff < -1e-6 {
			t.Fatalf("第 %d 位不一致: %f vs %f", index, decoded[index], vector[index])
		}
	}
	if score := cosineSimilarity(vector, vector); score < 0.999 {
		t.Fatalf("同向量余弦应为 1，实际 %.3f", score)
	}
}
