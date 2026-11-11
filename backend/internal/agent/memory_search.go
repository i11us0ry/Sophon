package agent

import (
	"context"
	"encoding/binary"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"

	"sophon/internal/database"
)

const (
	memorySearchDefaultLimit = 12
	memoryKeywordWeight      = 0.45
	memoryImportanceWeight   = 0.15
	memoryRecencyWeight      = 0.10
	memoryPriorityWeight     = 0.20
	memoryEvidenceWeight     = 0.10
	memoryVectorKeyword      = 0.25
	memoryVectorCosine       = 0.30
	memoryVectorImportance   = 0.10
	memoryVectorRecency      = 0.10
	memoryVectorPriority     = 0.15
	memoryVectorEvidence     = 0.10
	memoryHalfLifeDays       = 14.0
)

type rankedFact struct {
	Fact  database.ProjectFact
	Score float64
}

// memoryTokens 生成检索 token：ASCII 单词 + 中日韩单字与双字组合。
func memoryTokens(text string) map[string]struct{} {
	tokens := map[string]struct{}{}
	runes := []rune(strings.ToLower(strings.TrimSpace(text)))
	word := make([]rune, 0, 16)
	flush := func() {
		if len(word) == 0 {
			return
		}
		tokens["w:"+string(word)] = struct{}{}
		word = word[:0]
	}
	isWide := func(r rune) bool {
		return unicode.Is(unicode.Han, r) ||
			unicode.Is(unicode.Hiragana, r) ||
			unicode.Is(unicode.Katakana, r) ||
			unicode.Is(unicode.Hangul, r)
	}
	for index, r := range runes {
		switch {
		case r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)):
			word = append(word, r)
		case isWide(r):
			flush()
			tokens["c:"+string(r)] = struct{}{}
			if index+1 < len(runes) && isWide(runes[index+1]) {
				tokens["c:"+string(r)+string(runes[index+1])] = struct{}{}
			}
		default:
			flush()
		}
	}
	flush()
	return tokens
}

// memorySimilarity 使用 Dice 系数衡量两段文本的 token 重合度（0~1）。
func memorySimilarity(left, right string) float64 {
	a := memoryTokens(left)
	b := memoryTokens(right)
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	overlap := 0
	for token := range a {
		if _, ok := b[token]; ok {
			overlap++
		}
	}
	return float64(2*overlap) / float64(len(a)+len(b))
}

func memoryRecencyScore(updated, now time.Time) float64 {
	if updated.IsZero() {
		return 0
	}
	ageDays := now.Sub(updated).Hours() / 24
	if ageDays < 0 {
		ageDays = 0
	}
	return math.Pow(0.5, ageDays/memoryHalfLifeDays)
}

// rankProjectFacts 按 相关度/重要度/时间衰减（+可选向量余弦）对有效记忆排序。
func (s *Service) rankProjectFacts(
	ctx context.Context,
	query string,
	facts []database.ProjectFact,
) []rankedFact {
	now := time.Now().UTC()
	queryTokens := memoryTokens(query)
	vectorScores := map[string]float64{}
	useVector := false

	if s != nil && s.knowledge != nil && len(queryTokens) > 0 {
		if vectors, err := s.knowledge.Embed(ctx, []string{query}); err == nil && len(vectors) > 0 {
			queryVector := vectors[0]
			if len(queryVector) > 0 {
				useVector = true
				for _, fact := range facts {
					if len(fact.Embedding) == 0 {
						continue
					}
					vector := decodeEmbedding(fact.Embedding, len(queryVector))
					if len(vector) != len(queryVector) {
						continue
					}
					vectorScores[fact.ID] = cosineSimilarity(queryVector, vector)
				}
			}
		}
	}

	ranked := make([]rankedFact, 0, len(facts))
	for _, fact := range facts {
		// 污点事实（疑似注入内容）保留在库中供显式查看，但不参与自动注入。
		if fact.Tainted {
			continue
		}
		if strings.TrimSpace(fact.ContradictedBy) != "" {
			continue
		}
		if !fact.ValidTo.IsZero() {
			continue
		}
		importance := float64(fact.Importance) / 100
		if importance <= 0 {
			importance = 0.5
		}
		recency := memoryRecencyScore(fact.UpdatedAt, now)
		priority := float64(fact.Priority) / 100
		if priority <= 0 {
			priority = importance
		}
		evidence := memoryEvidenceScore(fact)
		kind := memoryKindScore(fact)
		var score float64
		switch {
		case len(queryTokens) == 0:
			score = 0.35*importance + 0.20*recency + 0.30*priority + 0.10*evidence + 0.05*kind
		case useVector:
			text := strings.Join([]string{fact.Key, fact.Summary, fact.Body}, " ")
			match := memorySimilarity(query, text)
			score = memoryVectorKeyword*match +
				memoryVectorCosine*vectorScores[fact.ID] +
				memoryVectorImportance*importance +
				memoryVectorRecency*recency +
				memoryVectorPriority*priority +
				memoryVectorEvidence*evidence
		default:
			text := strings.Join([]string{fact.Key, fact.Summary, fact.Body}, " ")
			match := memorySimilarity(query, text)
			score = memoryKeywordWeight*match +
				memoryImportanceWeight*importance +
				memoryRecencyWeight*recency +
				memoryPriorityWeight*priority +
				memoryEvidenceWeight*evidence
		}
		if fact.Pinned {
			score += 1
		}
		score += kind * 0.05
		ranked = append(ranked, rankedFact{Fact: fact, Score: score})
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if math.Abs(ranked[i].Score-ranked[j].Score) > 1e-9 {
			return ranked[i].Score > ranked[j].Score
		}
		if !ranked[i].Fact.UpdatedAt.Equal(ranked[j].Fact.UpdatedAt) {
			return ranked[i].Fact.UpdatedAt.After(ranked[j].Fact.UpdatedAt)
		}
		return ranked[i].Fact.Key < ranked[j].Fact.Key
	})
	return ranked
}

func memoryEvidenceScore(fact database.ProjectFact) float64 {
	score := 0.0
	if strings.TrimSpace(fact.Evidence) != "" {
		score += 0.6
	}
	if strings.TrimSpace(fact.Relation) != "" {
		score += 0.2
	}
	if fact.SourceID != "" || fact.SourceType != "" {
		score += 0.2
	}
	if score > 1 {
		return 1
	}
	return score
}

func memoryKindScore(fact database.ProjectFact) float64 {
	switch strings.ToLower(strings.TrimSpace(fact.MemoryKind)) {
	case "scope", "constraint", "credential":
		return 1
	case "finding":
		return 0.9
	case "topology", "asset", "service", "endpoint":
		return 0.7
	default:
		return 0.4
	}
}

// searchProjectMemories 返回按相关度排序的 top-k 有效记忆。
func (s *Service) searchProjectMemories(
	ctx context.Context,
	projectID string,
	assetID string,
	query string,
	limit int,
) ([]database.ProjectFact, error) {
	if s == nil || s.db == nil || strings.TrimSpace(projectID) == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = memorySearchDefaultLimit
	}
	facts, err := s.db.ListProjectFactsByAsset(ctx, projectID, assetID)
	if err != nil || len(facts) == 0 {
		return nil, err
	}
	ranked := s.rankProjectFacts(ctx, query, facts)
	if len(ranked) > limit {
		ranked = ranked[:limit]
	}
	result := make([]database.ProjectFact, 0, len(ranked))
	for _, item := range ranked {
		result = append(result, item.Fact)
	}
	return result, nil
}

// touchMemoryUsage 记录记忆被召回（后台 best-effort，不阻塞请求）。
func (s *Service) touchMemoryUsage(facts []database.ProjectFact) {
	if s == nil || s.db == nil || len(facts) == 0 {
		return
	}
	ids := make([]string, 0, len(facts))
	for _, fact := range facts {
		if strings.TrimSpace(fact.ID) != "" {
			ids = append(ids, fact.ID)
		}
	}
	if len(ids) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for _, id := range ids {
			_ = s.db.TouchProjectFact(ctx, id)
		}
	}()
}

func encodeEmbedding(vector []float64) []byte {
	if len(vector) == 0 {
		return nil
	}
	raw := make([]byte, 4*len(vector))
	for index, value := range vector {
		binary.LittleEndian.PutUint32(raw[index*4:], math.Float32bits(float32(value)))
	}
	return raw
}

func decodeEmbedding(raw []byte, dimensions int) []float64 {
	if dimensions <= 0 || len(raw) < dimensions*4 {
		return nil
	}
	vector := make([]float64, dimensions)
	for index := 0; index < dimensions; index++ {
		bits := binary.LittleEndian.Uint32(raw[index*4:])
		vector[index] = float64(math.Float32frombits(bits))
	}
	return vector
}

func cosineSimilarity(left, right []float64) float64 {
	if len(left) == 0 || len(left) != len(right) {
		return 0
	}
	var dot, leftNorm, rightNorm float64
	for index := range left {
		dot += left[index] * right[index]
		leftNorm += left[index] * left[index]
		rightNorm += right[index] * right[index]
	}
	if leftNorm == 0 || rightNorm == 0 {
		return 0
	}
	return dot / (math.Sqrt(leftNorm) * math.Sqrt(rightNorm))
}
