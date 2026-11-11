package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestUpdateFileConcurrentUpdatesDoNotLoseFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("agent:\n  mock: true\n"), 0o600); err != nil {
		t.Fatalf("写入测试配置失败: %v", err)
	}
	var wait sync.WaitGroup
	for _, update := range []FieldUpdate{
		{Path: []string{"agent", "mock"}, Value: false},
		{Path: []string{"proxy", "enabled"}, Value: true},
		{Path: []string{"proxy", "host"}, Value: "127.0.0.1"},
		{Path: []string{"proxy", "port"}, Value: 7890},
	} {
		wait.Add(1)
		go func(item FieldUpdate) {
			defer wait.Done()
			if err := UpdateFile(path, []FieldUpdate{item}); err != nil {
				t.Errorf("并发更新失败: %v", err)
			}
		}(update)
	}
	wait.Wait()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	var root map[string]interface{}
	if err := yaml.Unmarshal(raw, &root); err != nil {
		t.Fatalf("解析配置失败: %v", err)
	}
	proxy := root["proxy"].(map[string]interface{})
	if proxy["enabled"] != true || proxy["host"] != "127.0.0.1" || proxy["port"] != 7890 {
		t.Fatalf("并发更新丢失字段: %+v", proxy)
	}
}

func TestUpdateFilePrunesOldBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("version: test\n"), 0o600); err != nil {
		t.Fatalf("写入测试配置失败: %v", err)
	}
	for index := 0; index < maxConfigBackups+5; index++ {
		if err := UpdateFile(path, []FieldUpdate{
			{Path: []string{"version"}, Value: string(rune('a' + index%26))},
		}); err != nil {
			t.Fatalf("更新配置失败: %v", err)
		}
	}
	backups, err := filepath.Glob(path + ".bak.*")
	if err != nil {
		t.Fatalf("查找备份失败: %v", err)
	}
	if len(backups) != maxConfigBackups {
		t.Fatalf("备份数量应为 %d，实际 %d", maxConfigBackups, len(backups))
	}
}
