package knowledge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"sophon/internal/database"
)

type Service struct {
	db       *database.DB
	embedder Embedder
}

type SearchResult struct {
	ItemID     string  `json:"itemId"`
	Title      string  `json:"title"`
	Category   string  `json:"category"`
	Content    string  `json:"content"`
	Score      float64 `json:"score"`
	ChunkIndex int     `json:"chunkIndex"`
}

func NewService(db *database.DB, embedder Embedder) *Service {
	return &Service{
		db:       db,
		embedder: embedder,
	}
}

func (s *Service) Mode() string {
	if s.embedder == nil {
		return "disabled"
	}
	return s.embedder.Mode()
}

func (s *Service) Dimensions() int {
	if s.embedder == nil {
		return 0
	}
	return s.embedder.Dimensions()
}

// Embed 暴露嵌入能力给记忆检索使用；mock/disabled 模式返回错误，调用方自动退回关键词检索。
func (s *Service) Embed(ctx context.Context, texts []string) ([][]float64, error) {
	if s == nil || s.embedder == nil {
		return nil, fmt.Errorf("embedding disabled")
	}
	mode := strings.ToLower(strings.TrimSpace(s.embedder.Mode()))
	if mode == "" || mode == "mock" || mode == "disabled" {
		return nil, fmt.Errorf("embedding mode %s unavailable", mode)
	}
	return s.embedder.Embed(ctx, texts)
}

func (s *Service) CreateItem(
	ctx context.Context,
	ownerUserID string,
	category string,
	title string,
	content string,
) (*database.KnowledgeItem, error) {
	if strings.TrimSpace(title) == "" {
		return nil, fmt.Errorf("title is required")
	}
	if strings.TrimSpace(content) == "" {
		return nil, fmt.Errorf("content is required")
	}

	now := time.Now().UTC()
	item := database.KnowledgeItem{
		ID:          newID(),
		OwnerUserID: ownerUserID,
		Category:    defaultString(category, "general"),
		Title:       strings.TrimSpace(title),
		Content:     strings.TrimSpace(content),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.db.CreateKnowledgeItem(ctx, item); err != nil {
		return nil, err
	}
	if err := s.indexItem(ctx, item); err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *Service) UpdateItem(
	ctx context.Context,
	ownerUserID string,
	id string,
	category string,
	title string,
	content string,
) (*database.KnowledgeItem, error) {
	if strings.TrimSpace(title) == "" {
		return nil, fmt.Errorf("title is required")
	}
	if strings.TrimSpace(content) == "" {
		return nil, fmt.Errorf("content is required")
	}
	item, err := s.db.GetKnowledgeItem(ctx, id, ownerUserID)
	if err != nil {
		return nil, err
	}
	item.Category = defaultString(category, item.Category)
	item.Title = strings.TrimSpace(title)
	item.Content = strings.TrimSpace(content)
	item.UpdatedAt = time.Now().UTC()
	chunks := splitChunks(item.Content, 1200, 120)
	vectors, err := s.embedder.Embed(ctx, chunks)
	if err != nil {
		return nil, err
	}
	if err := s.db.UpdateKnowledgeItem(ctx, *item); err != nil {
		return nil, err
	}
	if err := s.storeChunks(ctx, item.ID, chunks, vectors); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *Service) DeleteItem(ctx context.Context, ownerUserID, id string) error {
	if _, err := s.db.GetKnowledgeItem(ctx, id, ownerUserID); err != nil {
		return err
	}
	return s.db.DeleteKnowledgeItem(ctx, id, ownerUserID)
}

func (s *Service) Search(
	ctx context.Context,
	ownerUserID string,
	query string,
	limit int,
) ([]SearchResult, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return []SearchResult{}, nil
	}
	if limit <= 0 || limit > 20 {
		limit = 5
	}
	vectors, err := s.embedder.Embed(ctx, []string{query})
	if err != nil || len(vectors) == 0 {
		return nil, err
	}
	queryVector := vectors[0]
	chunks, err := s.db.ListKnowledgeChunks(ctx, ownerUserID)
	if err != nil {
		return nil, err
	}

	results := make([]SearchResult, 0, len(chunks))
	seenItems := map[string]bool{}
	for _, chunk := range chunks {
		score := cosine(queryVector, chunk.Embedding)
		if score <= 0 || seenItems[chunk.ItemID] {
			continue
		}
		seenItems[chunk.ItemID] = true
		results = append(results, SearchResult{
			ItemID:     chunk.ItemID,
			Title:      chunk.ItemTitle,
			Category:   chunk.Category,
			Content:    chunk.Content,
			Score:      score,
			ChunkIndex: chunk.ChunkIndex,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (s *Service) indexItem(ctx context.Context, item database.KnowledgeItem) error {
	chunks := splitChunks(item.Content, 1200, 120)
	if len(chunks) == 0 {
		return nil
	}
	vectors, err := s.embedder.Embed(ctx, chunks)
	if err != nil {
		return err
	}
	return s.storeChunks(ctx, item.ID, chunks, vectors)
}

func (s *Service) storeChunks(
	ctx context.Context,
	itemID string,
	chunks []string,
	vectors [][]float64,
) error {
	stored := make([]database.KnowledgeChunk, 0, len(chunks))
	for index, chunk := range chunks {
		var vector []float64
		if index < len(vectors) {
			vector = vectors[index]
		}
		stored = append(stored, database.KnowledgeChunk{
			ID:         newID(),
			ItemID:     itemID,
			ChunkIndex: index,
			Content:    chunk,
			Embedding:  vector,
			UpdatedAt:  time.Now().UTC(),
		})
	}
	return s.db.ReplaceKnowledgeChunks(ctx, itemID, stored)
}

func splitChunks(content string, size, overlap int) []string {
	runes := []rune(strings.TrimSpace(content))
	if len(runes) == 0 {
		return nil
	}
	if len(runes) <= size {
		return []string{string(runes)}
	}
	result := make([]string, 0)
	for start := 0; start < len(runes); {
		end := start + size
		if end > len(runes) {
			end = len(runes)
		}
		result = append(result, string(runes[start:end]))
		if end == len(runes) {
			break
		}
		start = end - overlap
	}
	return result
}

func cosine(left, right []float64) float64 {
	if len(left) == 0 || len(right) == 0 {
		return 0
	}
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}
	var dot, leftNorm, rightNorm float64
	for index := 0; index < limit; index++ {
		dot += left[index] * right[index]
		leftNorm += left[index] * left[index]
		rightNorm += right[index] * right[index]
	}
	if leftNorm == 0 || rightNorm == 0 {
		return 0
	}
	return dot / (math.Sqrt(leftNorm) * math.Sqrt(rightNorm))
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func newID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("id_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}
