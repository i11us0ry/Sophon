package toolcatalog

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	archivepath "path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	maxArtifactBytes = 256 * 1024 * 1024
	stateDirName     = ".catalog"
)

type Artifact struct {
	URL             string   `yaml:"url" json:"url"`
	SHA256          string   `yaml:"sha256" json:"sha256"`
	Destination     string   `yaml:"destination" json:"destination"`
	Mode            string   `yaml:"mode" json:"mode,omitempty"`
	Archive         string   `yaml:"archive" json:"archive,omitempty"`
	Member          string   `yaml:"member" json:"member,omitempty"`
	Directory       bool     `yaml:"directory" json:"directory,omitempty"`
	Entry           string   `yaml:"entry" json:"entry,omitempty"`
	StripComponents int      `yaml:"strip_components" json:"stripComponents,omitempty"`
	Capabilities    []string `yaml:"capabilities" json:"capabilities,omitempty"`
}

type Manifest struct {
	Name           string              `yaml:"name" json:"name"`
	Version        string              `yaml:"version" json:"version"`
	Description    string              `yaml:"description" json:"description"`
	License        string              `yaml:"license" json:"license,omitempty"`
	ToolDefinition string              `yaml:"tool_definition" json:"toolDefinition"`
	Artifacts      map[string]Artifact `yaml:"artifacts" json:"artifacts"`
	Build          *BuildSpec          `yaml:"build,omitempty" json:"build,omitempty"`
	VerifyArgs     []string            `yaml:"verify_args" json:"verifyArgs,omitempty"`
}

type Status struct {
	Name                 string `json:"name"`
	Version              string `json:"version"`
	Description          string `json:"description"`
	License              string `json:"license,omitempty"`
	Architecture         string `json:"architecture"`
	Source               string `json:"source"`
	Installable          bool   `json:"installable"`
	InstalledVersion     string `json:"installedVersion,omitempty"`
	Installed            bool   `json:"installed"`
	Executable           bool   `json:"executable"`
	ToolDefinitionExists bool   `json:"toolDefinitionExists"`
	State                string `json:"state"`
	Detail               string `json:"detail,omitempty"`
	SHA256               string `json:"sha256,omitempty"`
}

type installState struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	SHA256          string `json:"sha256"`
	InstalledSHA256 string `json:"installedSHA256,omitempty"`
	Installed       string `json:"installedAt"`
}

type Catalog struct {
	catalogDir  string
	installRoot string
	toolsDir    string
	client      *http.Client
	proxyEnv    []string
}

func New(catalogDir, installRoot, toolsDir string, clients ...*http.Client) *Catalog {
	client := &http.Client{
		Timeout: 5 * time.Minute,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Scheme == "https" || isLoopbackHTTP(req.URL) {
				return nil
			}
			return fmt.Errorf("Tool Catalog 下载重定向必须保持 HTTPS")
		},
	}
	if len(clients) > 0 && clients[0] != nil {
		cloned := *clients[0]
		previousRedirect := cloned.CheckRedirect
		cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" && !isLoopbackHTTP(req.URL) {
				return fmt.Errorf("Tool Catalog 下载重定向必须保持 HTTPS")
			}
			if previousRedirect != nil {
				return previousRedirect(req, via)
			}
			return nil
		}
		client = &cloned
	}
	return &Catalog{
		catalogDir:  strings.TrimSpace(catalogDir),
		installRoot: strings.TrimSpace(installRoot),
		toolsDir:    strings.TrimSpace(toolsDir),
		client:      client,
	}
}

func (c *Catalog) SetProxyEnvironment(env []string) {
	c.proxyEnv = append([]string(nil), env...)
}

func CurrentArchitecture() string {
	return "linux-" + runtime.GOARCH
}

func (c *Catalog) List(ctx context.Context) ([]Status, error) {
	manifests, err := c.loadManifests()
	if err != nil {
		return nil, err
	}
	definitions, err := c.loadToolDefinitions()
	if err != nil {
		return nil, err
	}
	manifestNames := make(map[string]bool, len(manifests))
	items := make([]Status, 0, len(manifests)+len(definitions))
	for _, manifest := range manifests {
		manifestNames[strings.ToLower(manifest.Name)] = true
		item, statusErr := c.statusFor(ctx, manifest)
		if statusErr != nil {
			item = Status{
				Name:                 manifest.Name,
				Version:              manifest.Version,
				Description:          manifest.Description,
				License:              manifest.License,
				Architecture:         CurrentArchitecture(),
				Source:               SourceArtifact,
				Installable:          true,
				ToolDefinitionExists: c.toolDefinitionExists(manifest),
				State:                "error",
				Detail:               statusErr.Error(),
			}
		}
		items = append(items, item)
	}
	for _, definition := range definitions {
		if manifestNames[strings.ToLower(definition.Name)] {
			continue
		}
		item, statusErr := c.statusForDefinition(ctx, definition)
		if statusErr != nil {
			item = Status{
				Name:                 definition.Name,
				Description:          definition.Summary(),
				Architecture:         CurrentArchitecture(),
				Source:               c.definitionSource(definition),
				ToolDefinitionExists: true,
				State:                "error",
				Detail:               statusErr.Error(),
			}
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items, nil
}

func (c *Catalog) Status(ctx context.Context, name string) (Status, error) {
	manifest, err := c.loadManifestByName(name)
	if err == nil {
		return c.statusFor(ctx, manifest)
	}
	definition, definitionErr := c.loadDefinitionByName(name)
	if definitionErr != nil {
		return Status{}, err
	}
	return c.statusForDefinition(ctx, definition)
}

func (c *Catalog) Install(ctx context.Context, name string, force bool) (Status, error) {
	manifest, err := c.loadManifestByName(name)
	if err != nil {
		if definition, definitionErr := c.loadDefinitionByName(name); definitionErr == nil {
			return Status{}, fmt.Errorf(
				"工具 %s 来源为 %s，不支持从 Tool Catalog 下载安装",
				definition.Name,
				c.definitionSource(definition),
			)
		}
		return Status{}, err
	}
	if manifest.Build != nil {
		return c.installBuild(ctx, manifest, force)
	}
	artifact, err := c.artifactFor(manifest)
	if err != nil {
		return Status{}, err
	}
	destination, err := c.resolveDestination(artifact.Destination)
	if err != nil {
		return Status{}, err
	}
	if !force {
		if info, statErr := os.Stat(destination); statErr == nil &&
			info.IsDir() == artifact.Directory {
			return c.statusFor(ctx, manifest)
		}
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return Status{}, fmt.Errorf("创建安装目录失败: %w", err)
	}
	if err := c.downloadArtifact(ctx, manifest, artifact, destination); err != nil {
		return Status{}, err
	}
	if err := applyCapabilities(ctx, destination, artifact.Capabilities); err != nil {
		return Status{}, err
	}
	installedSHA256, err := installedPathSHA256(artifact, destination)
	if err != nil {
		return Status{}, fmt.Errorf("计算安装文件 SHA256 失败: %w", err)
	}
	if err := c.writeInstallState(manifest, artifact, installedSHA256); err != nil {
		return Status{}, err
	}
	return c.statusFor(ctx, manifest)
}

func (c *Catalog) Verify(ctx context.Context, name string) (Status, error) {
	status, err := c.Status(ctx, name)
	if err != nil {
		return Status{}, err
	}
	if status.State == "disabled" {
		return status, nil
	}
	if !status.Installed {
		return status, nil
	}
	manifest, err := c.loadManifestByName(name)
	if err != nil {
		definition, definitionErr := c.loadDefinitionByName(name)
		if definitionErr != nil {
			return status, definitionErr
		}
		status, err = c.statusForDefinition(ctx, definition)
		if err == nil && status.State == "installed" {
			status.Detail = "命令和声明依赖验证通过"
		}
		return status, err
	}
	if manifest.Build != nil {
		return c.verifyBuild(ctx, manifest, status)
	}
	artifact, err := c.artifactFor(manifest)
	if err != nil {
		return status, err
	}
	destination, err := c.resolveDestination(artifact.Destination)
	if err != nil {
		return status, err
	}
	actual, err := installedPathSHA256(artifact, destination)
	if err != nil {
		return status, err
	}
	expected := artifact.SHA256
	if state, stateErr := c.readInstallState(manifest.Name); stateErr == nil &&
		strings.TrimSpace(state.InstalledSHA256) != "" {
		expected = state.InstalledSHA256
	} else if !strings.EqualFold(strings.TrimSpace(artifact.Archive), "") {
		// 压缩包哈希不能直接用于校验解包后的文件；没有安装记录时继续做健康检查。
		expected = ""
	}
	if expected != "" && !strings.EqualFold(actual, expected) {
		status.State = "checksum_mismatch"
		status.Detail = "安装文件 SHA256 与安装记录不一致"
		return status, nil
	}
	if len(manifest.VerifyArgs) > 0 {
		verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		executable := destination
		if artifact.Directory {
			executable = filepath.Join(destination, filepath.Clean(artifact.Entry))
		}
		if err := runVerifiedCommand(verifyCtx, executable, manifest.VerifyArgs); err != nil {
			status.State = "verify_failed"
			status.Detail = err.Error()
			return status, nil
		}
	}
	status.State = "installed"
	status.Detail = "SHA256 和可执行文件验证通过"
	return status, nil
}

func (c *Catalog) statusFor(ctx context.Context, manifest Manifest) (Status, error) {
	status := Status{
		Name:                 manifest.Name,
		Version:              manifest.Version,
		Description:          manifest.Description,
		License:              manifest.License,
		Architecture:         CurrentArchitecture(),
		Source:               SourceArtifact,
		Installable:          true,
		ToolDefinitionExists: c.toolDefinitionExists(manifest),
	}
	if manifest.Build != nil {
		return c.statusForBuild(ctx, manifest, status)
	}
	if runtimeStatus, ok := c.installedRuntimeStatus(ctx, manifest.Name); ok {
		return runtimeStatus, nil
	}
	artifact, err := c.artifactFor(manifest)
	if err != nil {
		if definition, definitionErr := c.loadDefinitionByName(manifest.Name); definitionErr == nil {
			fallback, fallbackErr := c.statusForDefinition(ctx, definition)
			if fallbackErr == nil {
				fallback.Installable = false
				fallback.Detail = appendDetail(fallback.Detail, err.Error())
				return fallback, nil
			}
		}
		status.State = "unsupported"
		status.Detail = err.Error()
		return status, nil
	}
	status.SHA256 = artifact.SHA256
	destination, err := c.resolveDestination(artifact.Destination)
	if err != nil {
		return status, err
	}
	info, statErr := os.Stat(destination)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			status.State = "missing"
			status.Detail = "工具文件尚未安装"
			return status, nil
		}
		return status, statErr
	}
	if info.IsDir() != artifact.Directory {
		return status, fmt.Errorf("安装目标不是文件: %s", destination)
	}
	status.Installed = true
	executableInfo := info
	if artifact.Directory {
		entry := strings.TrimSpace(artifact.Entry)
		if entry == "" || filepath.IsAbs(entry) {
			return status, fmt.Errorf("目录安装目标缺少有效入口")
		}
		executableInfo, statErr = os.Stat(filepath.Join(destination, filepath.Clean(entry)))
		if statErr != nil {
			status.State = "missing"
			status.Detail = "工具入口文件不存在"
			return status, nil
		}
		if executableInfo.IsDir() {
			return status, fmt.Errorf("工具入口不是文件: %s", filepath.Join(destination, entry))
		}
	}
	if runtime.GOOS != "windows" {
		status.Executable = executableInfo.Mode()&0o111 != 0
	} else {
		status.Executable = true
	}
	state, _ := c.readInstallState(manifest.Name)
	status.InstalledVersion = state.Version
	switch {
	case !status.Executable:
		status.State = "not_executable"
		status.Detail = "工具文件存在但不可执行"
	case state.Version != "" && state.Version != manifest.Version:
		status.State = "update_required"
		status.Detail = "已安装版本与目录版本不一致"
	case state.SHA256 != "" && !strings.EqualFold(state.SHA256, artifact.SHA256):
		status.State = "update_required"
		status.Detail = "已安装文件的记录哈希与目录不一致"
	default:
		status.State = "installed"
		status.Detail = "工具已安装"
	}
	return status, nil
}

func appendDetail(existing, extra string) string {
	existing = strings.TrimSpace(existing)
	extra = strings.TrimSpace(extra)
	switch {
	case existing == "":
		return extra
	case extra == "":
		return existing
	default:
		return existing + "；" + extra
	}
}

func (c *Catalog) loadManifests() ([]Manifest, error) {
	if c.catalogDir == "" {
		return nil, fmt.Errorf("Tool Catalog 目录未配置")
	}
	entries, err := os.ReadDir(c.catalogDir)
	if err != nil {
		return nil, fmt.Errorf("读取 Tool Catalog: %w", err)
	}
	items := make([]Manifest, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(c.catalogDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var manifest Manifest
		if err := yaml.Unmarshal(raw, &manifest); err != nil {
			return nil, fmt.Errorf("解析 %s: %w", entry.Name(), err)
		}
		if strings.TrimSpace(manifest.Name) == "" || strings.TrimSpace(manifest.Version) == "" {
			continue
		}
		items = append(items, manifest)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items, nil
}

func (c *Catalog) loadManifestByName(name string) (Manifest, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Manifest{}, fmt.Errorf("工具名称不能为空")
	}
	items, err := c.loadManifests()
	if err != nil {
		return Manifest{}, err
	}
	for _, item := range items {
		if strings.EqualFold(item.Name, name) {
			return item, nil
		}
	}
	return Manifest{}, fmt.Errorf("Tool Catalog 中不存在工具 %s", name)
}

func (c *Catalog) artifactFor(manifest Manifest) (Artifact, error) {
	arch := CurrentArchitecture()
	artifact, ok := manifest.Artifacts[arch]
	if !ok {
		return Artifact{}, fmt.Errorf("工具 %s 不支持当前架构 %s", manifest.Name, arch)
	}
	if strings.TrimSpace(artifact.URL) == "" ||
		strings.TrimSpace(artifact.SHA256) == "" ||
		strings.TrimSpace(artifact.Destination) == "" {
		return Artifact{}, fmt.Errorf("工具 %s 的产物清单不完整", manifest.Name)
	}
	parsed, err := url.Parse(artifact.URL)
	if err != nil || (parsed.Scheme != "https" && !isLoopbackHTTP(parsed)) {
		return Artifact{}, fmt.Errorf("工具 %s 的下载地址必须使用 HTTPS", manifest.Name)
	}
	if len(artifact.SHA256) != 64 {
		return Artifact{}, fmt.Errorf("工具 %s 的 SHA256 格式错误", manifest.Name)
	}
	if _, err := hex.DecodeString(artifact.SHA256); err != nil {
		return Artifact{}, fmt.Errorf("工具 %s 的 SHA256 格式错误", manifest.Name)
	}
	if artifact.Directory {
		if !strings.EqualFold(strings.TrimSpace(artifact.Archive), "zip") {
			return Artifact{}, fmt.Errorf("目录型工具当前只支持 zip")
		}
		if strings.TrimSpace(artifact.Entry) == "" || filepath.IsAbs(artifact.Entry) {
			return Artifact{}, fmt.Errorf("工具 %s 缺少有效的目录入口", manifest.Name)
		}
		if artifact.StripComponents < 0 {
			return Artifact{}, fmt.Errorf("工具 %s 的 strip_components 无效", manifest.Name)
		}
	}
	for _, capability := range artifact.Capabilities {
		if !validBuildCapability(capability) {
			return Artifact{}, fmt.Errorf("工具 %s 包含不支持的 capability: %s", manifest.Name, capability)
		}
	}
	return artifact, nil
}

func (c *Catalog) resolveDestination(relative string) (string, error) {
	if c.installRoot == "" {
		return "", fmt.Errorf("安装根目录未配置")
	}
	relative = strings.TrimSpace(relative)
	if relative == "" || filepath.IsAbs(relative) {
		return "", fmt.Errorf("安装目标必须是相对路径")
	}
	root, err := filepath.Abs(c.installRoot)
	if err != nil {
		return "", err
	}
	destination, err := filepath.Abs(filepath.Join(root, filepath.Clean(relative)))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, destination)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("安装目标越出 thirdTools 目录")
	}
	return destination, nil
}

func (c *Catalog) downloadArtifact(
	ctx context.Context,
	manifest Manifest,
	artifact Artifact,
	destination string,
) error {
	data, err := c.downloadBytes(ctx, artifact.URL)
	if err != nil {
		return fmt.Errorf("下载 %s 失败: %w", manifest.Name, err)
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actual, artifact.SHA256) {
		return fmt.Errorf("下载 %s 的 SHA256 校验失败", manifest.Name)
	}
	mode := os.FileMode(0o755)
	if strings.TrimSpace(artifact.Mode) != "" {
		parsed, err := strconv.ParseUint(strings.TrimSpace(artifact.Mode), 8, 32)
		if err != nil {
			return fmt.Errorf("安装文件权限格式错误")
		}
		mode = os.FileMode(parsed)
	}
	if artifact.Directory {
		return installZIPDirectory(data, artifact, destination)
	}
	switch strings.ToLower(strings.TrimSpace(artifact.Archive)) {
	case "":
		return atomicWriteFile(destination, data, mode)
	case "tar.gz":
		return installTarGZ(data, artifact.Member, destination, mode)
	case "zip":
		return installZIP(data, artifact.Member, destination, mode)
	default:
		return fmt.Errorf("不支持的归档格式: %s", artifact.Archive)
	}
}

func (c *Catalog) downloadBytes(ctx context.Context, sourceURL string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
		if err != nil {
			return nil, err
		}
		response, err := c.client.Do(request)
		if err != nil {
			lastErr = err
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, maxArtifactBytes+1))
		closeErr := response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			lastErr = fmt.Errorf("HTTP %d", response.StatusCode)
			if !retryableDownloadStatus(response.StatusCode) {
				return nil, lastErr
			}
			continue
		}
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if closeErr != nil {
			lastErr = closeErr
			continue
		}
		if len(data) > maxArtifactBytes {
			return nil, fmt.Errorf("下载内容超过大小限制")
		}
		return data, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("下载失败")
	}
	return nil, lastErr
}

func retryableDownloadStatus(status int) bool {
	return status == http.StatusRequestTimeout ||
		status == http.StatusTooEarly ||
		status == http.StatusTooManyRequests ||
		status >= http.StatusInternalServerError
}

func installTarGZ(data []byte, member, destination string, mode os.FileMode) error {
	if strings.TrimSpace(member) == "" {
		return fmt.Errorf("tar.gz 产物必须指定 member")
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("解压 tar.gz 失败: %w", err)
	}
	defer reader.Close()
	archive := tar.NewReader(reader)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取 tar.gz 失败: %w", err)
		}
		if filepath.Clean(header.Name) != filepath.Clean(member) {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return fmt.Errorf("目标 member 不是普通文件")
		}
		content, err := io.ReadAll(io.LimitReader(archive, maxArtifactBytes+1))
		if err != nil {
			return err
		}
		if len(content) > maxArtifactBytes {
			return fmt.Errorf("解压文件超过大小限制")
		}
		return atomicWriteFile(destination, content, mode)
	}
	return fmt.Errorf("tar.gz 中未找到 %s", member)
}

func installZIP(data []byte, member, destination string, mode os.FileMode) error {
	if strings.TrimSpace(member) == "" {
		return fmt.Errorf("zip 产物必须指定 member")
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("解压 zip 失败: %w", err)
	}
	for _, file := range reader.File {
		if filepath.Clean(file.Name) != filepath.Clean(member) {
			continue
		}
		if file.FileInfo().IsDir() {
			return fmt.Errorf("目标 member 不是普通文件")
		}
		source, err := file.Open()
		if err != nil {
			return err
		}
		content, readErr := io.ReadAll(io.LimitReader(source, maxArtifactBytes+1))
		closeErr := source.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(content) > maxArtifactBytes {
			return fmt.Errorf("解压文件超过大小限制")
		}
		return atomicWriteFile(destination, content, mode)
	}
	return fmt.Errorf("zip 中未找到 %s", member)
}

func installZIPDirectory(data []byte, artifact Artifact, destination string) error {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("解压 zip 失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	tempDir, err := os.MkdirTemp(filepath.Dir(destination), ".catalog-dir-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	var total int64
	for _, file := range reader.File {
		name := archivepath.Clean(file.Name)
		if name == "." {
			continue
		}
		if archivepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("zip 包含越界路径: %s", file.Name)
		}
		parts := strings.Split(name, "/")
		if len(parts) <= artifact.StripComponents {
			continue
		}
		relative := filepath.Join(parts[artifact.StripComponents:]...)
		target := filepath.Join(tempDir, relative)
		if !pathWithin(tempDir, target) {
			return fmt.Errorf("zip 包含越界路径: %s", file.Name)
		}

		info := file.FileInfo()
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("zip 不允许符号链接: %s", file.Name)
		}
		if info.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("zip 包含不支持的文件类型: %s", file.Name)
		}
		if file.UncompressedSize64 > maxArtifactBytes {
			return fmt.Errorf("解压文件超过大小限制: %s", file.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		source, err := file.Open()
		if err != nil {
			return err
		}
		perm := info.Mode().Perm()
		if perm == 0 {
			perm = 0o644
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
		if err != nil {
			_ = source.Close()
			return err
		}
		written, copyErr := io.Copy(
			output,
			io.LimitReader(source, maxArtifactBytes-total+1),
		)
		closeOutputErr := output.Close()
		closeSourceErr := source.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeOutputErr != nil {
			return closeOutputErr
		}
		if closeSourceErr != nil {
			return closeSourceErr
		}
		total += written
		if total > maxArtifactBytes {
			return fmt.Errorf("解压内容超过大小限制")
		}
	}

	entry := filepath.Join(tempDir, filepath.Clean(artifact.Entry))
	if !pathWithin(tempDir, entry) {
		return fmt.Errorf("目录入口越出安装目录")
	}
	entryInfo, err := os.Stat(entry)
	if err != nil || entryInfo.IsDir() {
		return fmt.Errorf("zip 中未找到目录入口 %s", artifact.Entry)
	}
	if entryInfo.Mode()&0o111 == 0 {
		if err := os.Chmod(entry, entryInfo.Mode().Perm()|0o755); err != nil {
			return err
		}
	}
	return replaceDirectory(destination, tempDir)
}

func replaceDirectory(destination, tempDir string) error {
	backupPath, err := os.MkdirTemp(filepath.Dir(destination), ".catalog-backup-*")
	if err != nil {
		return err
	}
	if err := os.Remove(backupPath); err != nil {
		return err
	}
	_, statErr := os.Lstat(destination)
	existed := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}
	if existed {
		if err := os.Rename(destination, backupPath); err != nil {
			return err
		}
	}
	if err := os.Rename(tempDir, destination); err != nil {
		if existed {
			_ = os.Rename(backupPath, destination)
		}
		return err
	}
	if existed {
		return os.RemoveAll(backupPath)
	}
	return nil
}

func atomicWriteFile(destination string, data []byte, mode os.FileMode) error {
	temp, err := os.CreateTemp(filepath.Dir(destination), ".catalog-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, destination)
}

func (c *Catalog) toolDefinitionExists(manifest Manifest) bool {
	name := strings.TrimSpace(manifest.ToolDefinition)
	if name == "" || c.toolsDir == "" {
		return false
	}
	if filepath.IsAbs(name) {
		name = filepath.Base(name)
	}
	info, err := os.Stat(filepath.Join(c.toolsDir, filepath.Clean(name)))
	return err == nil && !info.IsDir()
}

func (c *Catalog) statePath(name string) string {
	return filepath.Join(c.installRoot, stateDirName, name+".json")
}

func (c *Catalog) writeInstallState(manifest Manifest, artifact Artifact, installedSHA256 string) error {
	return c.writeInstallStateRecord(
		manifest.Name,
		manifest.Version,
		artifact.SHA256,
		installedSHA256,
	)
}

func (c *Catalog) writeInstallStateRecord(
	name string,
	version string,
	sourceSHA256 string,
	installedSHA256 string,
) error {
	path := c.statePath(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	payload := installState{
		Name:            name,
		Version:         version,
		SHA256:          sourceSHA256,
		InstalledSHA256: installedSHA256,
		Installed:       time.Now().UTC().Format(time.RFC3339),
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(raw, '\n'), 0o600)
}

func (c *Catalog) readInstallState(name string) (installState, error) {
	raw, err := os.ReadFile(c.statePath(name))
	if err != nil {
		return installState{}, err
	}
	var state installState
	if err := json.Unmarshal(raw, &state); err != nil {
		return installState{}, err
	}
	return state, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maxArtifactBytes+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func installedPathSHA256(artifact Artifact, destination string) (string, error) {
	if artifact.Directory {
		return directorySHA256(destination)
	}
	return fileSHA256(destination)
}

func directorySHA256(root string) (string, error) {
	hash := sha256.New()
	var total int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if info.IsDir() && ignoredRuntimeTreeDirectory(info.Name()) {
			return filepath.SkipDir
		}
		if !info.IsDir() && ignoredRuntimeTreeFile(info.Name()) {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			target := filepath.Clean(filepath.Join(filepath.Dir(path), link))
			if filepath.IsAbs(link) || !pathWithin(root, target) {
				return fmt.Errorf("安装目录包含越界符号链接: %s", path)
			}
			_, _ = fmt.Fprintf(hash, "l\x00%s\x00%s\x00", relative, filepath.ToSlash(link))
			return nil
		}
		if info.IsDir() {
			_, _ = fmt.Fprintf(hash, "d\x00%s\x00%o\x00", relative, info.Mode().Perm())
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("安装目录包含不支持的文件: %s", path)
		}
		_, _ = fmt.Fprintf(hash, "f\x00%s\x00%o\x00", relative, info.Mode().Perm())
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		written, copyErr := io.Copy(
			hash,
			io.LimitReader(file, maxArtifactBytes-total+1),
		)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		total += written
		if total > maxArtifactBytes {
			return fmt.Errorf("安装目录超过大小限制")
		}
		_, _ = hash.Write([]byte{0})
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func ignoredRuntimeTreeDirectory(name string) bool {
	switch name {
	case "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache":
		return true
	default:
		return false
	}
}

func ignoredRuntimeTreeFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".pyc") || strings.HasSuffix(lower, ".pyo")
}

func runVerifiedCommand(ctx context.Context, executable string, args []string) error {
	cmd := execCommandContext(ctx, executable, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("验证命令失败: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func isLoopbackHTTP(value *url.URL) bool {
	if value == nil || value.Scheme != "http" || value.Hostname() == "" {
		return false
	}
	ip := net.ParseIP(value.Hostname())
	return ip != nil && ip.IsLoopback()
}
