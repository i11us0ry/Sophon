package toolwire

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

const StructuredContentMarker = "[sophon_structured_content]"

var structuredContentKey = newStructuredContentKey()

// AppendStructured 把 MCP StructuredContent 作为独立块附在文本结果后。
// 结构化值只接受 JSON 对象，避免把协议约定扩展成任意 JSON 类型。
func AppendStructured(text string, structured any) (string, error) {
	if structured == nil {
		return text, nil
	}
	raw, err := json.Marshal(structured)
	if err != nil {
		return "", fmt.Errorf("encode structured content: %w", err)
	}
	if string(raw) == "null" {
		return text, nil
	}
	if !isJSONObject(raw) {
		return "", fmt.Errorf("structured content must be a JSON object")
	}
	body := strings.TrimRight(text, "\n")
	signature := signStructuredContent(body, raw)
	if body == "" {
		return StructuredContentMarker + "\nhmac=" + signature + "\n" + string(raw), nil
	}
	return body + "\n\n" + StructuredContentMarker + "\nhmac=" + signature + "\n" + string(raw), nil
}

// SplitStructured 只解析最后一个完整结构化块。
// 文本正文中包含同名普通字符串时保持原样，非法 JSON 也不会被提升为结构化数据。
func SplitStructured(text string) (string, json.RawMessage) {
	index := strings.LastIndex(text, StructuredContentMarker)
	if index < 0 {
		return text, nil
	}
	candidate := strings.TrimSpace(text[index+len(StructuredContentMarker):])
	signatureLine, candidate, ok := strings.Cut(candidate, "\n")
	if !ok || !strings.HasPrefix(signatureLine, "hmac=") {
		return text, nil
	}
	signature := strings.TrimSpace(strings.TrimPrefix(signatureLine, "hmac="))
	candidate = strings.TrimSpace(candidate)
	if !isJSONObject([]byte(candidate)) {
		return text, nil
	}
	body := strings.TrimRight(text[:index], "\n")
	if !hmac.Equal([]byte(signature), []byte(signStructuredContent(body, []byte(candidate)))) {
		return text, nil
	}
	return body, json.RawMessage(append([]byte(nil), []byte(candidate)...))
}

func isJSONObject(raw []byte) bool {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	return value != nil
}

func signStructuredContent(body string, raw []byte) string {
	mac := hmac.New(sha256.New, structuredContentKey[:])
	_, _ = mac.Write([]byte(body))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(raw)
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func newStructuredContentKey() [32]byte {
	var key [32]byte
	if _, err := rand.Read(key[:]); err == nil {
		return key
	}
	return sha256.Sum256([]byte("sophon-toolwire-fallback-key"))
}
