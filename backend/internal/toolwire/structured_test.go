package toolwire

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAppendAndSplitStructured(t *testing.T) {
	result, err := AppendStructured("plain output", map[string]any{
		"records": []any{map[string]any{"id": "a"}},
	})
	if err != nil {
		t.Fatalf("附加结构化内容失败: %v", err)
	}
	if !strings.Contains(result, StructuredContentMarker) {
		t.Fatalf("缺少结构化内容标记: %s", result)
	}
	body, structured := SplitStructured(result)
	if body != "plain output" {
		t.Fatalf("正文解析异常: %q", body)
	}
	var value map[string]any
	if err := json.Unmarshal(structured, &value); err != nil || value["records"] == nil {
		t.Fatalf("结构化内容解析异常: %s, %v", structured, err)
	}
}

func TestStructuredContentMustBeObject(t *testing.T) {
	if _, err := AppendStructured("", []string{"not", "object"}); err == nil {
		t.Fatal("数组不应作为 MCP StructuredContent")
	}
	text := "output\n" + StructuredContentMarker + "\nnot-json"
	body, structured := SplitStructured(text)
	if body != text || structured != nil {
		t.Fatalf("非法结构化块不应被提升: %q %s", body, structured)
	}
}

func TestStructuredOnlyResult(t *testing.T) {
	result, err := AppendStructured("", map[string]any{"ok": true})
	if err != nil {
		t.Fatalf("生成结构化结果失败: %v", err)
	}
	body, structured := SplitStructured(result)
	if body != "" || !strings.Contains(string(structured), `"ok":true`) {
		t.Fatalf("纯结构化结果异常: %q %s", body, structured)
	}
}

func TestSplitStructuredRejectsTamperingAndReplay(t *testing.T) {
	signed, err := AppendStructured("original body", map[string]any{"value": "original"})
	if err != nil {
		t.Fatalf("生成签名结果失败: %v", err)
	}
	tampered := strings.Replace(signed, `"original"`, `"tampered"`, 1)
	if body, structured := SplitStructured(tampered); body != tampered || structured != nil {
		t.Fatalf("篡改后的结构化块不应通过: body=%q structured=%s", body, structured)
	}

	markerIndex := strings.Index(signed, StructuredContentMarker)
	replayed := "different body\n\n" + signed[markerIndex:]
	if body, structured := SplitStructured(replayed); body != replayed || structured != nil {
		t.Fatalf("重放到其他正文的结构化块不应通过: body=%q structured=%s", body, structured)
	}
}
