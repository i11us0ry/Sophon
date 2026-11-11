package storage

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
)

const (
	CategoryKindDatabase   = "db"
	CategoryKindTextColumn = "text_column"
	CategoryKindDirectory  = "dir"
)

type Category struct {
	Name       string
	Label      string
	Kind       string
	Table      string
	TimeColumn string
	ExtraWhere string
	Path       string
	ZeroColumn string
}

var Categories = []Category{
	{Name: "audit_logs", Label: "审计日志", Kind: CategoryKindDatabase, Table: "audit_logs", TimeColumn: "created_at"},
	{Name: "tool_executions", Label: "工具执行记录", Kind: CategoryKindDatabase, Table: "tool_executions", TimeColumn: "started_at"},
	{Name: "tool_jobs", Label: "受控后台 Job", Kind: CategoryKindDatabase, Table: "tool_jobs", TimeColumn: "updated_at"},
	{Name: "token_usage", Label: "Token 用量", Kind: CategoryKindDatabase, Table: "token_usage", TimeColumn: "created_at"},
	{
		Name:       "hitl_requests",
		Label:      "人工审批记录",
		Kind:       CategoryKindDatabase,
		Table:      "hitl_requests",
		TimeColumn: "created_at",
		ExtraWhere: "status <> 'pending'",
	},
	{Name: "process_details", Label: "工具过程明细", Kind: CategoryKindDatabase, Table: "process_details", TimeColumn: "created_at"},
	{Name: "context_compactions", Label: "上下文压缩记录", Kind: CategoryKindDatabase, Table: "context_compactions", TimeColumn: "created_at"},
	{Name: "memory_writes", Label: "记忆写入审计", Kind: CategoryKindDatabase, Table: "memory_writes", TimeColumn: "created_at"},
	{
		Name:       "reasoning_content",
		Label:      "推理内容",
		Kind:       CategoryKindTextColumn,
		Table:      "messages",
		TimeColumn: "created_at",
		ZeroColumn: "reasoning_content",
		ExtraWhere: "TRIM(reasoning_content) <> ''",
	},
	{Name: "workspace", Label: "Agent 工作区", Kind: CategoryKindDirectory, Path: "tmp/workspace"},
	{Name: "reduction", Label: "工具输出缓存", Kind: CategoryKindDirectory, Path: "tmp/reduction"},
	{Name: "conversation_artifacts", Label: "会话产物", Kind: CategoryKindDirectory, Path: "data/conversation_artifacts"},
	{Name: "chat_uploads", Label: "对话上传文件", Kind: CategoryKindDirectory, Path: "chat_uploads"},
}

var safeCategoryPaths = map[string]string{
	"workspace":              "tmp/workspace",
	"reduction":              "tmp/reduction",
	"conversation_artifacts": "data/conversation_artifacts",
	"chat_uploads":           "chat_uploads",
}

// ConversationScopedCategories 是按会话 ID 建子目录的存储类别：
// 删除对话或项目时必须连同目录一起清理，否则工作空间会残留已删除会话的数据。
var ConversationScopedCategories = []string{
	"workspace",
	"reduction",
	"conversation_artifacts",
	"chat_uploads",
}

type PreviewItem struct {
	Name          string `json:"name"`
	Label         string `json:"label"`
	Kind          string `json:"kind"`
	Path          string `json:"path,omitempty"`
	Enabled       bool   `json:"enabled"`
	RetentionDays int    `json:"retentionDays"`
	// 数据库类别使用 Expired，目录类别使用 Files + Bytes，均为立即清理将删除的总量。
	Expired int   `json:"expired"`
	Files   int   `json:"files"`
	Bytes   int64 `json:"bytes"`
}

func CategoryByName(name string) (Category, bool) {
	for _, category := range Categories {
		if category.Name == name {
			return category, true
		}
	}
	return Category{}, false
}

type Service struct {
	mu           sync.RWMutex
	db           *database.DB
	config       config.StorageConfig
	artifactRoot string
	dataDir      string
}

func NewService(db *database.DB, storageConfig config.StorageConfig, dataDir string) *Service {
	if len(storageConfig.Categories) == 0 {
		storageConfig.Categories = map[string]config.StorageCategoryConfig{}
	}
	if storageConfig.IntervalMinutes < 5 {
		storageConfig.IntervalMinutes = 60
	}
	if storageConfig.ActiveGraceHours < 0 {
		storageConfig.ActiveGraceHours = 0
	}
	service := &Service{
		db:           db,
		config:       storageConfig,
		artifactRoot: filepath.Clean(storageConfig.ArtifactRoot),
		dataDir:      filepath.Clean(dataDir),
	}
	service.EnsureDirectories()
	return service
}

func (s *Service) Config() config.StorageConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneStorageConfig(s.config)
}

func (s *Service) ArtifactRoot() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.artifactRoot
}

func (s *Service) CategoryDir(name string) (string, error) {
	cfg, root, _ := s.snapshot()
	name = strings.TrimSpace(name)
	settings, ok := cfg.Categories[name]
	if !ok || strings.TrimSpace(settings.Path) == "" {
		return "", fmt.Errorf("storage category %s not configured", name)
	}
	return resolveCategoryDir(root, name, settings.Path)
}

// RemoveConversationDirs 删除给定会话在各存储类别下的目录，返回清理成功的目录数。
// 会话 ID 必须是不含路径分隔符的单层名称，越界路径与符号链接一律跳过。
func (s *Service) RemoveConversationDirs(conversationIDs []string) int {
	if s == nil || len(conversationIDs) == 0 {
		return 0
	}
	removed := 0
	for _, category := range ConversationScopedCategories {
		root, err := s.CategoryDir(category)
		if err != nil {
			continue
		}
		for _, conversationID := range conversationIDs {
			name := strings.TrimSpace(conversationID)
			if name == "" || name == "." || name == ".." ||
				filepath.Base(name) != name ||
				strings.ContainsAny(name, `/\`) {
				continue
			}
			target := filepath.Join(root, name)
			if !withinRoot(root, target) {
				continue
			}
			info, err := os.Lstat(target)
			if err != nil || !info.IsDir() {
				continue
			}
			if err := os.RemoveAll(target); err == nil {
				removed++
			}
		}
	}
	return removed
}

// withinRoot 判断 target 是否位于 root 之下（先取绝对路径再比较）。
func withinRoot(root, target string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return false
	}
	return relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(os.PathSeparator)) &&
		!filepath.IsAbs(relative)
}

func (s *Service) ActiveGraceHours() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.ActiveGraceHours
}

func (s *Service) snapshot() (config.StorageConfig, string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneStorageConfig(s.config), s.artifactRoot, s.dataDir
}

func cloneStorageConfig(value config.StorageConfig) config.StorageConfig {
	result := value
	result.Categories = make(map[string]config.StorageCategoryConfig, len(value.Categories))
	for name, item := range value.Categories {
		result.Categories[name] = item
	}
	return result
}

// EnsureDirectories 为启用的目录类别创建目录；失败只记录日志。
func (s *Service) EnsureDirectories() {
	cfg, root, _ := s.snapshot()
	for _, category := range Categories {
		if category.Kind != CategoryKindDirectory {
			continue
		}
		settings, ok := cfg.Categories[category.Name]
		if !ok || !settings.Enabled || strings.TrimSpace(settings.Path) == "" {
			continue
		}
		dir, err := resolveCategoryDir(root, category.Name, settings.Path)
		if err != nil {
			log.Printf("storage: 类别 %s 路径不合法: %v", category.Name, err)
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Printf("storage: 创建目录 %s 失败: %v", dir, err)
		}
	}
}

func (s *Service) Preview(ctx context.Context) ([]PreviewItem, error) {
	cfg, root, _ := s.snapshot()
	items := make([]PreviewItem, 0, len(Categories))
	for _, category := range Categories {
		settings, ok := cfg.Categories[category.Name]
		if !ok {
			continue
		}
		item := PreviewItem{
			Name:          category.Name,
			Label:         category.Label,
			Kind:          category.Kind,
			Enabled:       settings.Enabled,
			RetentionDays: settings.RetentionDays,
		}
		if category.Kind == CategoryKindDirectory {
			item.Path = settings.Path
		}
		if !settings.Enabled {
			items = append(items, item)
			continue
		}
		if category.Kind == CategoryKindDirectory {
			dir, err := resolveCategoryDir(root, category.Name, settings.Path)
			if err != nil {
				log.Printf("storage: 跳过类别 %s: %v", category.Name, err)
				items = append(items, item)
				continue
			}
			// 手动清理忽略保留期，预览展示的是立即清理将删除的总量。
			files, bytes, err := previewDir(dir, time.Time{}, true)
			if err != nil {
				return nil, err
			}
			item.Files = files
			item.Bytes = bytes
		} else {
			count, err := s.db.CountRows(ctx, category.Table, category.ExtraWhere)
			if err != nil {
				return nil, err
			}
			item.Expired = count
		}
		items = append(items, item)
	}
	return items, nil
}

type CleanResult struct {
	Deleted map[string]int   `json:"deleted"`
	Bytes   map[string]int64 `json:"bytes"`
}

// Clean 按保留期清理；force 为 true 时忽略保留期与活动宽限期，
// 清空所选类别的全部数据（仍遵守 ExtraWhere 安全条件与 enabled 开关）。
func (s *Service) Clean(ctx context.Context, names []string, force bool) (CleanResult, error) {
	cfg, root, _ := s.snapshot()
	targets := names
	if len(targets) == 0 {
		targets = make([]string, 0, len(Categories))
		for _, category := range Categories {
			targets = append(targets, category.Name)
		}
	}

	now := time.Now().UTC()
	result := CleanResult{Deleted: map[string]int{}, Bytes: map[string]int64{}}
	for _, name := range targets {
		category, ok := CategoryByName(name)
		if !ok {
			continue
		}
		settings, ok := cfg.Categories[name]
		if !ok || !settings.Enabled {
			continue
		}
		if !force && settings.RetentionDays <= 0 {
			continue
		}
		cutoff := time.Time{}
		if !force {
			cutoff = cutoffTime(cfg.ActiveGraceHours, settings.RetentionDays, now)
		}
		if category.Kind == CategoryKindDirectory {
			dir, err := resolveCategoryDir(root, name, settings.Path)
			if err != nil {
				return result, fmt.Errorf("类别 %s 路径不合法: %w", name, err)
			}
			files, bytes, err := cleanDir(dir, cutoff, force)
			if err != nil {
				return result, err
			}
			result.Deleted[name] = files
			result.Bytes[name] = bytes
			continue
		}
		if category.Kind == CategoryKindTextColumn {
			cutoffUnix := int64(0)
			if !force {
				cutoffUnix = cutoff.Unix()
			}
			cleared, err := s.db.ClearTextColumn(
				ctx,
				category.Table,
				category.ZeroColumn,
				category.TimeColumn,
				category.ExtraWhere,
				cutoffUnix,
			)
			if err != nil {
				return result, err
			}
			result.Deleted[name] = cleared
			result.Bytes[name] = 0
			continue
		}
		var deleted int
		var err error
		if force {
			deleted, err = s.db.DeleteAllRows(ctx, category.Table, category.ExtraWhere)
		} else {
			deleted, err = s.db.DeleteExpiredRows(
				ctx,
				category.Table,
				category.TimeColumn,
				category.ExtraWhere,
				cutoff.Unix(),
			)
		}
		if err != nil {
			return result, err
		}
		result.Deleted[name] = deleted
	}
	return result, nil
}

func (s *Service) UpdateConfig(storageConfig config.StorageConfig) error {
	if storageConfig.IntervalMinutes < 5 {
		storageConfig.IntervalMinutes = 60
	}
	root := filepath.Clean(storageConfig.ArtifactRoot)
	if err := ValidateArtifactRoot(root); err != nil {
		return err
	}
	s.mu.RLock()
	dataDir := s.dataDir
	s.mu.RUnlock()
	if dataDir != "" && root == dataDir {
		return fmt.Errorf("artifact_root 不能设置为数据目录")
	}
	for name, item := range storageConfig.Categories {
		category, ok := CategoryByName(name)
		if !ok {
			return fmt.Errorf("未知的清理类别: %s", name)
		}
		if category.Kind != CategoryKindDirectory {
			continue
		}
		if err := ValidateCategoryPath(root, name, item.Path); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.config = storageConfig
	if strings.TrimSpace(storageConfig.ArtifactRoot) != "" {
		s.artifactRoot = root
	}
	s.mu.Unlock()
	s.EnsureDirectories()
	return nil
}

// Start 在开启自动清理时启动后台定时任务；间隔与开关变更需重启生效。
func (s *Service) Start(ctx context.Context) {
	cfg, _, _ := s.snapshot()
	if !cfg.AutoClean || cfg.IntervalMinutes <= 0 {
		return
	}
	interval := time.Duration(cfg.IntervalMinutes) * time.Minute
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		log.Printf("storage: 自动清理已开启，间隔 %s", interval)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				result, err := s.Clean(ctx, nil, false)
				if err != nil {
					log.Printf("storage: 自动清理失败: %v", err)
					continue
				}
				log.Printf("storage: 自动清理完成 %v", result.Deleted)
			}
		}
	}()
}

func cutoffTime(activeGraceHours, retentionDays int, now time.Time) time.Time {
	cutoff := now.AddDate(0, 0, -retentionDays)
	if activeGraceHours > 0 {
		graceCutoff := now.Add(-time.Duration(activeGraceHours) * time.Hour)
		if graceCutoff.Before(cutoff) {
			cutoff = graceCutoff
		}
	}
	return cutoff
}

func ValidateArtifactRoot(root string) error {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "" || root == "." || !filepath.IsAbs(root) {
		return fmt.Errorf("artifact_root 必须是绝对路径")
	}
	if root == string(filepath.Separator) {
		return fmt.Errorf("artifact_root 不允许使用文件系统根目录")
	}
	if info, err := os.Lstat(root); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("artifact_root 不允许使用符号链接")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ValidateCategoryPath 校验目录类别只能使用预设的安全相对路径。
func ValidateCategoryPath(artifactRoot, categoryName, relative string) error {
	if err := ValidateArtifactRoot(artifactRoot); err != nil {
		return err
	}
	expected, ok := safeCategoryPaths[strings.TrimSpace(categoryName)]
	if !ok {
		return fmt.Errorf("类别 %s 不支持目录路径", categoryName)
	}
	cleaned := filepath.Clean(strings.TrimSpace(relative))
	if cleaned != expected {
		return fmt.Errorf("类别 %s 路径必须是 %s", categoryName, expected)
	}
	return nil
}

func resolveCategoryDir(root, categoryName, relative string) (string, error) {
	if err := ValidateCategoryPath(root, categoryName, relative); err != nil {
		return "", err
	}
	full := filepath.Join(root, filepath.Clean(relative))
	if err := checkNoSymlink(root, filepath.Clean(relative)); err != nil {
		return "", err
	}
	return full, nil
}

// checkNoSymlink 逐级检查路径，拒绝符号链接跳转。
func checkNoSymlink(root, relative string) error {
	current := filepath.Clean(root)
	for _, segment := range strings.Split(relative, string(os.PathSeparator)) {
		if segment == "" || segment == "." {
			continue
		}
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("路径包含符号链接，已拒绝: %s", current)
		}
	}
	return nil
}

func previewDir(dir string, cutoff time.Time, ignoreAge bool) (int, int64, error) {
	files := 0
	var bytes int64
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if entry == nil || entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if !ignoreAge && !info.ModTime().Before(cutoff) {
			return nil
		}
		files++
		bytes += info.Size()
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return 0, 0, err
	}
	return files, bytes, nil
}

func cleanDir(dir string, cutoff time.Time, ignoreAge bool) (int, int64, error) {
	files := 0
	var bytes int64
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if entry == nil || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if !ignoreAge && !info.ModTime().Before(cutoff) {
			return nil
		}
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		files++
		bytes += info.Size()
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return files, bytes, err
	}
	removeEmptyDirs(dir)
	return files, bytes, nil
}

// removeEmptyDirs 回收空子目录，但保留类别根目录本身。
func removeEmptyDirs(root string) {
	dirs := make([]string, 0)
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry == nil || !entry.IsDir() {
			return nil
		}
		if path != root {
			dirs = append(dirs, path)
		}
		return nil
	})
	for index := len(dirs) - 1; index >= 0; index-- {
		_ = os.Remove(dirs[index])
	}
}
