package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type FieldUpdate struct {
	Path  []string
	Value interface{}
}

type UpdateOptions struct {
	SkipBackup bool
}

const maxConfigBackups = 20

var configWriteMu sync.Mutex

// UpdateFile 在保留注释的前提下更新 YAML 字段，写入前自动备份原文件。
func UpdateFile(path string, updates []FieldUpdate) error {
	return UpdateFileWithOptions(path, updates, UpdateOptions{})
}

// UpdateFileWithOptions 按调用方要求更新配置；敏感配置可跳过明文备份。
func UpdateFileWithOptions(path string, updates []FieldUpdate, options UpdateOptions) error {
	configWriteMu.Lock()
	defer configWriteMu.Unlock()

	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("未找到 config.yml，无法保存在线修改")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}
	if len(root.Content) == 0 {
		root.Kind = yaml.DocumentNode
		root.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	doc := root.Content[0]
	if doc.Kind == 0 {
		doc.Kind = yaml.MappingNode
		doc.Tag = "!!map"
	}
	if doc.Kind != yaml.MappingNode {
		return fmt.Errorf("配置文件根节点不是映射结构")
	}

	for _, update := range updates {
		if len(update.Path) == 0 {
			continue
		}
		if err := setYAMLValue(doc, update.Path, update.Value); err != nil {
			return err
		}
	}

	out, err := yaml.Marshal(&root)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	if !options.SkipBackup {
		backup := fmt.Sprintf(
			"%s.bak.%s",
			path,
			time.Now().UTC().Format("20060102150405.000000000"),
		)
		if err := os.WriteFile(backup, raw, 0o600); err != nil {
			return fmt.Errorf("备份配置文件失败: %w", err)
		}
		pruneConfigBackups(path)
	}

	tempFile, err := os.CreateTemp(
		filepath.Dir(path),
		filepath.Base(path)+".tmp-*",
	)
	if err != nil {
		return fmt.Errorf("创建临时配置文件失败: %w", err)
	}
	temp := tempFile.Name()
	defer func() { _ = os.Remove(temp) }()
	if err := tempFile.Chmod(0o600); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("设置临时配置文件权限失败: %w", err)
	}
	if _, err := tempFile.Write(out); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("写入配置文件失败: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("同步配置文件失败: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("关闭临时配置文件失败: %w", err)
	}
	if err := os.Rename(temp, path); err != nil {
		return fmt.Errorf("替换配置文件失败: %w", err)
	}
	return nil
}

func pruneConfigBackups(path string) {
	matches, err := filepath.Glob(path + ".bak.*")
	if err != nil || len(matches) <= maxConfigBackups {
		return
	}
	sort.Strings(matches)
	for _, item := range matches[:len(matches)-maxConfigBackups] {
		_ = os.Remove(item)
	}
}

func setYAMLValue(node *yaml.Node, path []string, value interface{}) error {
	if len(path) == 0 {
		return nil
	}
	key := path[0]
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("配置节点 %s 不是映射结构", key)
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value != key {
			continue
		}
		child := node.Content[index+1]
		if len(path) == 1 {
			if err := child.Encode(value); err != nil {
				return fmt.Errorf("设置 %s 失败: %w", key, err)
			}
			return nil
		}
		if child.Kind != yaml.MappingNode {
			child.Kind = yaml.MappingNode
			child.Tag = "!!map"
			child.Value = ""
			child.Content = nil
		}
		return setYAMLValue(child, path[1:], value)
	}

	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valueNode := &yaml.Node{}
	if len(path) == 1 {
		if err := valueNode.Encode(value); err != nil {
			return fmt.Errorf("设置 %s 失败: %w", key, err)
		}
		node.Content = append(node.Content, keyNode, valueNode)
		return nil
	}
	valueNode.Kind = yaml.MappingNode
	valueNode.Tag = "!!map"
	node.Content = append(node.Content, keyNode, valueNode)
	return setYAMLValue(valueNode, path[1:], value)
}

// EnvLocked 判断某个配置项是否被环境变量覆盖（覆盖后写文件也不会生效）。
func EnvLocked(envKey string) bool {
	return strings.TrimSpace(os.Getenv(envKey)) != ""
}

// MaskSecret 对密钥打码，仅保留头 3 位与末 4 位。
func MaskSecret(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return "****"
	}
	return value[:3] + "****" + value[len(value)-4:]
}
