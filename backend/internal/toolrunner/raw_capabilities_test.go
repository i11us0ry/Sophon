package toolrunner

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadDirNormalizesRequiredCapabilities(t *testing.T) {
	dir := t.TempDir()
	definition := `name: raw-scanner
command: /usr/bin/raw-scanner
enabled: true
requires_capabilities:
  - cap_net_raw
  - " cap_net_raw "
  - cap_net_admin
parameters: []
`
	if err := os.WriteFile(
		filepath.Join(dir, "raw-scanner.yaml"),
		[]byte(definition),
		0o600,
	); err != nil {
		t.Fatalf("写入工具定义失败: %v", err)
	}
	tools, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("加载工具定义失败: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("工具数量错误: %d", len(tools))
	}
	want := []string{"cap_net_raw", "cap_net_admin"}
	if !reflect.DeepEqual(tools[0].RequiresCapabilities, want) {
		t.Fatalf("capability 依赖归一化错误: %#v", tools[0].RequiresCapabilities)
	}
}
