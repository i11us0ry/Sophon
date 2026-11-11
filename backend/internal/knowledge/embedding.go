package knowledge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net/http"
	"strings"
	"time"

	"sophon/internal/config"
)

type Embedder interface {
	Embed(ctx context.Context, texts []string) ([][]float64, error)
	Dimensions() int
	Mode() string
}

func NewEmbedder(cfg config.Config) (Embedder, error) {
	if cfg.EmbeddingMock || strings.TrimSpace(cfg.EmbeddingAPIKey) == "" {
		return &mockEmbedder{dimensions: cfg.EmbeddingDimensions}, nil
	}
	client, err := cfg.Proxy.HTTPClient(
		time.Duration(cfg.EmbeddingTimeout) * time.Second,
	)
	if err != nil {
		return nil, err
	}
	return &openAIEmbedder{
		baseURL:    strings.TrimRight(cfg.EmbeddingBaseURL, "/"),
		apiKey:     cfg.EmbeddingAPIKey,
		model:      cfg.EmbeddingModel,
		dimensions: cfg.EmbeddingDimensions,
		client:     client,
	}, nil
}

type mockEmbedder struct {
	dimensions int
}

func (m *mockEmbedder) Dimensions() int {
	if m.dimensions <= 0 {
		return 256
	}
	return m.dimensions
}

func (m *mockEmbedder) Mode() string {
	return "mock"
}

func (m *mockEmbedder) Embed(_ context.Context, texts []string) ([][]float64, error) {
	result := make([][]float64, len(texts))
	for index, text := range texts {
		result[index] = mockVector(text, m.Dimensions())
	}
	return result, nil
}

type openAIEmbedder struct {
	baseURL    string
	apiKey     string
	model      string
	dimensions int
	client     *http.Client
}

func (o *openAIEmbedder) Dimensions() int {
	return o.dimensions
}

func (o *openAIEmbedder) Mode() string {
	return "openai-compatible"
}

func (o *openAIEmbedder) Embed(ctx context.Context, texts []string) ([][]float64, error) {
	body := map[string]interface{}{
		"model": o.model,
		"input": texts,
	}
	if o.dimensions > 0 {
		body["dimensions"] = o.dimensions
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		o.baseURL+"/embeddings",
		bytes.NewReader(raw),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+o.apiKey)
	request.Header.Set("Content-Type", "application/json")

	response, err := o.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("embedding request failed: %s", response.Status)
	}

	var payload struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nil, err
	}
	result := make([][]float64, len(texts))
	for _, item := range payload.Data {
		if item.Index >= 0 && item.Index < len(result) {
			result[item.Index] = item.Embedding
		}
	}
	return result, nil
}

func mockVector(text string, dimensions int) []float64 {
	vector := make([]float64, dimensions)
	tokens := tokenize(text)
	for _, token := range tokens {
		hash := fnv.New64a()
		_, _ = hash.Write([]byte(token))
		value := hash.Sum64()
		index := int(value % uint64(dimensions))
		sign := 1.0
		if value&(1<<63) != 0 {
			sign = -1
		}
		vector[index] += sign
	}
	normalize(vector)
	return vector
}

func tokenize(text string) []string {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return nil
	}
	parts := strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == ',' || r == '.' || r == '，' || r == '。'
	})
	tokens := make([]string, 0, len(parts)*2)
	for _, part := range parts {
		if part == "" {
			continue
		}
		tokens = append(tokens, part)
		runes := []rune(part)
		for index := 0; index+1 < len(runes); index++ {
			sum := sha256.Sum256([]byte(string(runes[index : index+2])))
			tokens = append(tokens, string(sum[:4]))
		}
	}
	return tokens
}

func normalize(vector []float64) {
	var sum float64
	for _, value := range vector {
		sum += value * value
	}
	if sum == 0 {
		return
	}
	length := math.Sqrt(sum)
	for index := range vector {
		vector[index] /= length
	}
}

func float64FromBytes(value []byte) float64 {
	bits := binary.LittleEndian.Uint64(value)
	return math.Float64frombits(bits)
}
