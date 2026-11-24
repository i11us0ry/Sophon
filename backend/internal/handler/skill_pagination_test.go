package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sophon/internal/skillaudit"

	"github.com/gin-gonic/gin"
)

func TestListSkillsPaginatesSearchesAndSorts(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"alpha", "beta", "gamma"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("创建技能目录失败: %v", err)
		}
		content := "---\ndescription: " + name + "\ntags: [" + name + "]\n---\n# " + name
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(content), 0o600); err != nil {
			t.Fatalf("创建技能文件失败: %v", err)
		}
	}
	handler := &BusinessHandler{skillsDir: root}
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(
		http.MethodGet,
		"/api/skills?limit=1&offset=1&sort=name_desc",
		nil,
	)
	handler.ListSkills(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("技能分页失败: %d %s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("解析技能响应失败: %v", err)
	}
	if result.Total != 3 || len(result.Items) != 1 || result.Items[0].Name != "beta" {
		t.Fatalf("技能分页排序异常: %+v", result)
	}

	recorder = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(
		http.MethodGet,
		"/api/skills?limit=20&offset=0&search=gamma",
		nil,
	)
	handler.ListSkills(ctx)
	if recorder.Code != http.StatusOK ||
		!containsJSONString(recorder.Body.Bytes(), "gamma") {
		t.Fatalf("技能搜索失败: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestSkillTemplateUsesMethodologySections(t *testing.T) {
	content := skillTemplate("demo-skill", "demo methodology")
	result := skillaudit.AuditContent("demo-skill", content, "skills/demo-skill/SKILL.md")
	if !result.Compliant {
		t.Fatalf("新建 Skill 默认模板不符合方法论标准: %+v", result.Issues)
	}
	for _, want := range []string{
		"## 适用场景",
		"## 核心判断",
		"## 证据标准",
		"## 决策树",
		"## 可选工具与示例",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("方法论模板缺少 %q:\n%s", want, content)
		}
	}
}

func containsJSONString(body []byte, value string) bool {
	return strings.Contains(string(body), `"name":"`+value+`"`)
}
