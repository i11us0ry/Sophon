package toolcatalog

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	archivepath "path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	BuildRecipeCopy   = "copy"
	BuildRecipeGo     = "go"
	BuildRecipeHydra  = "hydra"
	BuildRecipeJohn   = "john"
	BuildRecipeRuby   = "ruby"
	SourceSourceBuild = "source"
)

type BuildSpec struct {
	URL               string   `yaml:"url" json:"url"`
	SHA256            string   `yaml:"sha256" json:"sha256"`
	Archive           string   `yaml:"archive" json:"archive"`
	StripComponents   int      `yaml:"strip_components" json:"stripComponents,omitempty"`
	SourceEntry       string   `yaml:"source_entry" json:"sourceEntry,omitempty"`
	Recipe            string   `yaml:"recipe" json:"recipe"`
	Destination       string   `yaml:"destination" json:"destination"`
	Directory         bool     `yaml:"directory" json:"directory,omitempty"`
	Entry             string   `yaml:"entry" json:"entry,omitempty"`
	Package           string   `yaml:"package" json:"package,omitempty"`
	RequireExecutable bool     `yaml:"require_executable" json:"requireExecutable,omitempty"`
	Capabilities      []string `yaml:"capabilities" json:"capabilities,omitempty"`
	StatikSource      string   `yaml:"statik_source" json:"statikSource,omitempty"`
	Command           string   `yaml:"command" json:"command,omitempty"`
	CommandMode       string   `yaml:"command_mode" json:"commandMode,omitempty"`
	CommandTarget     string   `yaml:"command_target" json:"commandTarget,omitempty"`
}

func (c *Catalog) installBuild(ctx context.Context, manifest Manifest, force bool) (Status, error) {
	build := manifest.Build
	if err := validateBuildSpec(manifest); err != nil {
		return Status{}, err
	}
	destination, err := c.resolveDestination(build.Destination)
	if err != nil {
		return Status{}, err
	}
	if !force {
		if info, statErr := os.Stat(destination); statErr == nil &&
			info.IsDir() == build.Directory {
			return c.statusFor(ctx, manifest)
		}
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return Status{}, fmt.Errorf("创建源码构建目录失败: %w", err)
	}
	data, err := c.downloadBuildSource(ctx, manifest)
	if err != nil {
		return Status{}, err
	}
	workRoot, err := os.MkdirTemp(filepath.Dir(c.installRoot), ".catalog-build-*")
	if err != nil {
		return Status{}, err
	}
	defer os.RemoveAll(workRoot)
	sourceDir := filepath.Join(workRoot, "source")
	if err := extractBuildSource(data, build, sourceDir); err != nil {
		return Status{}, err
	}
	if err := c.runBuildRecipe(ctx, manifest, sourceDir, destination, workRoot); err != nil {
		return Status{}, err
	}
	if err := c.installBuildCommand(build, destination); err != nil {
		return Status{}, err
	}
	if err := applyBuildCapabilities(ctx, build, destination); err != nil {
		return Status{}, err
	}
	installedSHA256, err := buildPathSHA256(build, destination)
	if err != nil {
		return Status{}, fmt.Errorf("计算构建产物 SHA256 失败: %w", err)
	}
	if err := c.writeBuildInstallState(manifest, installedSHA256); err != nil {
		return Status{}, err
	}
	return c.statusFor(ctx, manifest)
}

func (c *Catalog) statusForBuild(ctx context.Context, manifest Manifest, status Status) (Status, error) {
	build := manifest.Build
	if err := validateBuildSpec(manifest); err != nil {
		status.State = "error"
		status.Detail = err.Error()
		return status, nil
	}
	status.Source = SourceSourceBuild
	status.Installable = true
	status.SHA256 = build.SHA256
	if command := strings.TrimSpace(build.Command); command != "" {
		if commandPath, lookupErr := exec.LookPath(command); lookupErr == nil {
			status.Installed = true
			status.Executable = true
			status.State = "installed"
			status.Installable = false
			if pathWithin(c.installRoot, commandPath) {
				status.Source = SourceSourceBuild
				status.Detail = "使用 thirdTools/bin 中的源码构建命令"
			} else {
				status.Source = SourceSystem
				status.Detail = "使用系统 PATH 中的命令"
			}
			return status, nil
		}
	}
	if runtimeStatus, ok := c.installedRuntimeStatus(ctx, manifest.Name); ok {
		return runtimeStatus, nil
	}
	destination, err := c.resolveDestination(build.Destination)
	if err != nil {
		return status, err
	}
	info, statErr := os.Stat(destination)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			status.State = "missing"
			status.Detail = "源码工具尚未构建"
			return status, nil
		}
		return status, statErr
	}
	if info.IsDir() != build.Directory {
		return status, fmt.Errorf("构建产物类型与清单不一致: %s", destination)
	}
	status.Installed = true
	entryInfo := info
	if build.Directory {
		entryInfo, statErr = os.Stat(filepath.Join(destination, filepath.Clean(build.Entry)))
		if statErr != nil || entryInfo.IsDir() {
			status.State = "missing"
			status.Detail = "构建产物入口文件不存在"
			return status, nil
		}
	}
	requireExecutable := !build.Directory || build.RequireExecutable
	status.Executable = runtime.GOOS == "windows" ||
		!requireExecutable || entryInfo.Mode()&0o111 != 0
	state, _ := c.readInstallState(manifest.Name)
	status.InstalledVersion = state.Version
	switch {
	case !status.Executable:
		status.State = "not_executable"
		status.Detail = "构建产物入口不可执行"
	case state.Version != "" && state.Version != manifest.Version:
		status.State = "update_required"
		status.Detail = "已构建版本与源码清单版本不一致"
	case state.SHA256 != "" && !strings.EqualFold(state.SHA256, build.SHA256):
		status.State = "update_required"
		status.Detail = "已构建版本的源码哈希与清单不一致"
	default:
		status.State = "installed"
		status.Detail = "源码构建产物已安装"
	}
	return status, nil
}

func (c *Catalog) installBuildCommand(build *BuildSpec, destination string) error {
	command := strings.TrimSpace(build.Command)
	if command == "" {
		return nil
	}
	if strings.ContainsAny(command, `/\`) || strings.TrimSpace(build.CommandTarget) == "" {
		return fmt.Errorf("源码工具命令配置无效")
	}
	target := filepath.Join(destination, filepath.Clean(build.CommandTarget))
	if !build.Directory {
		target = destination
	}
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("源码工具命令目标不存在: %w", err)
	}
	binDir := filepath.Join(c.installRoot, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	var script string
	switch strings.ToLower(strings.TrimSpace(build.CommandMode)) {
	case "", "exec":
		script = "#!/bin/sh\nexec " + shellQuote(target) + ` "$@"` + "\n"
	case "python":
		interpreter := filepath.Join(filepath.Dir(c.installRoot), "venv", "bin", "python")
		if info, err := os.Stat(interpreter); err != nil || info.IsDir() {
			interpreter = "python3"
		}
		script = "#!/bin/sh\nPYTHONPATH=" + shellQuote(destination) +
			`${PYTHONPATH:+:$PYTHONPATH}` + "\nexport PYTHONPATH\nexec " +
			shellQuote(interpreter) + " " + shellQuote(target) + ` "$@"` + "\n"
	default:
		return fmt.Errorf("不支持的源码工具命令模式: %s", build.CommandMode)
	}
	return atomicWriteFile(
		filepath.Join(binDir, command),
		[]byte(script),
		0o755,
	)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func (c *Catalog) verifyBuild(ctx context.Context, manifest Manifest, status Status) (Status, error) {
	build := manifest.Build
	if status.Source == SourceSystem && strings.TrimSpace(build.Command) != "" {
		executable, err := exec.LookPath(build.Command)
		if err != nil {
			return status, err
		}
		if len(manifest.VerifyArgs) > 0 {
			verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if err := runVerifiedCommand(verifyCtx, executable, manifest.VerifyArgs); err != nil {
				status.State = "verify_failed"
				status.Detail = err.Error()
				return status, nil
			}
		}
		status.State = "installed"
		status.Detail = "系统 PATH 命令验证通过"
		return status, nil
	}
	destination, err := c.resolveDestination(build.Destination)
	if err != nil {
		return status, err
	}
	actual, err := buildPathSHA256(build, destination)
	if err != nil {
		return status, err
	}
	state, stateErr := c.readInstallState(manifest.Name)
	if stateErr == nil && strings.TrimSpace(state.InstalledSHA256) != "" &&
		!strings.EqualFold(actual, state.InstalledSHA256) {
		status.State = "checksum_mismatch"
		status.Detail = "构建产物 SHA256 与安装记录不一致"
		return status, nil
	}
	executable := destination
	if build.Directory {
		executable = filepath.Join(destination, filepath.Clean(build.Entry))
	}
	if len(manifest.VerifyArgs) > 0 {
		verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := runVerifiedCommand(verifyCtx, executable, manifest.VerifyArgs); err != nil {
			status.State = "verify_failed"
			status.Detail = err.Error()
			return status, nil
		}
	}
	status.State = "installed"
	status.Detail = "源码构建产物和入口验证通过"
	return status, nil
}

func (c *Catalog) runBuildRecipe(
	ctx context.Context,
	manifest Manifest,
	sourceDir string,
	destination string,
	workRoot string,
) error {
	build := manifest.Build
	switch strings.ToLower(strings.TrimSpace(build.Recipe)) {
	case BuildRecipeCopy, BuildRecipeRuby:
		return replaceDirectory(destination, sourceDir)
	case BuildRecipeGo:
		output := filepath.Join(workRoot, "artifact")
		if statikSource := strings.TrimSpace(build.StatikSource); statikSource != "" {
			if err := c.runNetworkBuildCommand(
				ctx,
				sourceDir,
				"go",
				"run",
				"github.com/rakyll/statik@v0.1.7",
				"-src="+statikSource,
			); err != nil {
				return err
			}
		}
		target := strings.TrimSpace(build.Package)
		if target == "" {
			target = "."
		}
		if err := c.runNetworkBuildCommand(ctx, sourceDir, "go", "build", "-trimpath", "-o", output, target); err != nil {
			return err
		}
		return installBuiltFile(output, destination)
	case BuildRecipeHydra:
		if err := buildAutotools(ctx, sourceDir, workRoot, "hydra"); err != nil {
			return err
		}
		return installBuiltFile(filepath.Join(sourceDir, "hydra"), destination)
	case BuildRecipeJohn:
		buildDir := sourceDir
		if _, err := os.Stat(filepath.Join(sourceDir, "src", "configure")); err == nil {
			buildDir = filepath.Join(sourceDir, "src")
		}
		if err := configureAndMake(ctx, buildDir, workRoot, "--disable-simd"); err != nil {
			return err
		}
		return replaceDirectory(destination, filepath.Join(sourceDir, "run"))
	default:
		return fmt.Errorf("不支持的源码构建配方: %s", build.Recipe)
	}
}

func (c *Catalog) runNetworkBuildCommand(ctx context.Context, dir, name string, args ...string) error {
	cmd := execCommandContext(ctx, name, args...)
	cmd.Dir = dir
	env := os.Environ()
	for _, value := range c.proxyEnv {
		key, raw, ok := strings.Cut(value, "=")
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		env = setBuildEnvironmentValue(env, strings.TrimSpace(key), raw)
	}
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	text := strings.TrimSpace(string(output))
	if len(text) > 4000 {
		text = text[len(text)-4000:]
	}
	return fmt.Errorf("%s 构建失败: %s", name, text)
}

func setBuildEnvironmentValue(env []string, key, value string) []string {
	prefix := key + "="
	for index, item := range env {
		if strings.HasPrefix(item, prefix) {
			env[index] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func buildAutotools(ctx context.Context, sourceDir, workRoot, binary string) error {
	if err := configureAndMake(ctx, sourceDir, workRoot); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(sourceDir, binary)); err != nil {
		return fmt.Errorf("构建完成但未找到 %s", binary)
	}
	return nil
}

func applyBuildCapabilities(ctx context.Context, build *BuildSpec, destination string) error {
	target := destination
	if build.Directory {
		target = filepath.Join(destination, filepath.Clean(build.Entry))
	}
	return applyCapabilities(ctx, target, build.Capabilities)
}

func applyCapabilities(ctx context.Context, target string, capabilities []string) error {
	for _, capability := range capabilities {
		if err := runBuildCommand(
			ctx,
			filepath.Dir(target),
			"setcap",
			strings.TrimSpace(capability)+"+ep",
			target,
		); err != nil {
			return err
		}
	}
	return nil
}

func validBuildCapability(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "cap_net_bind_service", "cap_net_admin", "cap_net_raw":
		return true
	default:
		return false
	}
}

func configureAndMake(ctx context.Context, sourceDir, workRoot string, extraArgs ...string) error {
	if _, err := os.Stat(filepath.Join(sourceDir, "configure")); err != nil {
		if err := runBuildCommand(ctx, sourceDir, "autoreconf", "-fi"); err != nil {
			return err
		}
	}
	prefix := filepath.Join(workRoot, "prefix")
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		return err
	}
	configureArgs := []string{"--prefix", prefix}
	configureArgs = append(configureArgs, extraArgs...)
	if err := runBuildCommand(ctx, sourceDir, "./configure", configureArgs...); err != nil {
		return err
	}
	jobs := runtime.NumCPU()
	if jobs < 1 {
		jobs = 1
	}
	if jobs > 4 {
		jobs = 4
	}
	return runBuildCommand(ctx, sourceDir, "make", "-j"+strconv.Itoa(jobs))
}

func runBuildCommand(ctx context.Context, dir, name string, args ...string) error {
	cmd := execCommandContext(ctx, name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	text := strings.TrimSpace(string(output))
	if len(text) > 4000 {
		text = text[len(text)-4000:]
	}
	return fmt.Errorf("%s 构建失败: %s", name, text)
}

func installBuiltFile(source, destination string) error {
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	return atomicWriteFile(destination, raw, 0o755)
}

func buildPathSHA256(build *BuildSpec, destination string) (string, error) {
	if build.Directory {
		return directorySHA256(destination)
	}
	return fileSHA256(destination)
}

func validateBuildSpec(manifest Manifest) error {
	build := manifest.Build
	if build == nil {
		return fmt.Errorf("缺少源码构建清单")
	}
	if strings.TrimSpace(build.URL) == "" ||
		strings.TrimSpace(build.SHA256) == "" ||
		strings.TrimSpace(build.Destination) == "" ||
		strings.TrimSpace(build.Recipe) == "" {
		return fmt.Errorf("工具 %s 的源码构建清单不完整", manifest.Name)
	}
	if len(build.SHA256) != 64 {
		return fmt.Errorf("工具 %s 的源码 SHA256 格式错误", manifest.Name)
	}
	if _, err := hex.DecodeString(build.SHA256); err != nil {
		return fmt.Errorf("工具 %s 的源码 SHA256 格式错误", manifest.Name)
	}
	parsed, err := url.Parse(build.URL)
	if err != nil || (parsed.Scheme != "https" && !isLoopbackHTTP(parsed)) {
		return fmt.Errorf("工具 %s 的源码下载地址必须使用 HTTPS", manifest.Name)
	}
	archive := strings.ToLower(strings.TrimSpace(build.Archive))
	if archive != "tar.gz" && archive != "zip" {
		return fmt.Errorf("工具 %s 的源码归档必须是 tar.gz 或 zip", manifest.Name)
	}
	if build.StripComponents < 0 {
		return fmt.Errorf("工具 %s 的源码 strip_components 无效", manifest.Name)
	}
	switch strings.ToLower(strings.TrimSpace(build.Recipe)) {
	case BuildRecipeCopy, BuildRecipeGo, BuildRecipeHydra, BuildRecipeJohn, BuildRecipeRuby:
	default:
		return fmt.Errorf("工具 %s 使用未知源码构建配方", manifest.Name)
	}
	if archive == "zip" && strings.TrimSpace(build.SourceEntry) == "" {
		return fmt.Errorf("工具 %s 的 ZIP 源码缺少 source_entry", manifest.Name)
	}
	if build.Directory {
		if strings.TrimSpace(build.Entry) == "" || filepath.IsAbs(build.Entry) {
			return fmt.Errorf("工具 %s 缺少有效的构建产物入口", manifest.Name)
		}
	}
	command := strings.TrimSpace(build.Command)
	if command != "" {
		if strings.ContainsAny(command, `/\`) || strings.TrimSpace(build.CommandTarget) == "" {
			return fmt.Errorf("工具 %s 的源码构建命令配置无效", manifest.Name)
		}
		target := filepath.Clean(build.CommandTarget)
		if filepath.IsAbs(target) || target == ".." || strings.HasPrefix(target, ".."+string(filepath.Separator)) {
			return fmt.Errorf("工具 %s 的源码构建命令目标越界", manifest.Name)
		}
		switch strings.ToLower(strings.TrimSpace(build.CommandMode)) {
		case "", "exec", "python":
		default:
			return fmt.Errorf("工具 %s 的源码构建命令模式无效", manifest.Name)
		}
	} else if strings.TrimSpace(build.CommandTarget) != "" || strings.TrimSpace(build.CommandMode) != "" {
		return fmt.Errorf("工具 %s 的命令配置缺少 command", manifest.Name)
	}
	for _, capability := range build.Capabilities {
		if !validBuildCapability(capability) {
			return fmt.Errorf("工具 %s 包含不支持的 capability: %s", manifest.Name, capability)
		}
	}
	return nil
}

func (c *Catalog) downloadBuildSource(ctx context.Context, manifest Manifest) ([]byte, error) {
	build := manifest.Build
	if data, err := c.readSourceCache(build); err == nil {
		return data, nil
	}
	data, err := c.downloadBytes(ctx, build.URL)
	if err != nil {
		return nil, fmt.Errorf("下载 %s 源码失败: %w", manifest.Name, err)
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), build.SHA256) {
		return nil, fmt.Errorf("下载 %s 源码的 SHA256 校验失败", manifest.Name)
	}
	_ = c.writeSourceCache(build, data)
	return data, nil
}

func (c *Catalog) sourceCachePath(sha256Value string) string {
	return filepath.Join(
		filepath.Dir(c.installRoot),
		"data",
		"tool-catalog-cache",
		strings.ToLower(strings.TrimSpace(sha256Value))+".tar.gz",
	)
}

func (c *Catalog) readSourceCache(build *BuildSpec) ([]byte, error) {
	path := c.sourceCachePath(build.SHA256)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() || info.Size() > maxArtifactBytes {
		return nil, fmt.Errorf("源码缓存无效")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), build.SHA256) {
		return nil, fmt.Errorf("源码缓存 SHA256 不匹配")
	}
	return data, nil
}

func (c *Catalog) writeSourceCache(build *BuildSpec, data []byte) error {
	path := c.sourceCachePath(build.SHA256)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

func extractBuildSource(data []byte, build *BuildSpec, destination string) error {
	switch strings.ToLower(strings.TrimSpace(build.Archive)) {
	case "zip":
		artifact := Artifact{
			Archive:         "zip",
			Directory:       true,
			Entry:           build.SourceEntry,
			StripComponents: build.StripComponents,
		}
		if artifact.Entry == "" {
			artifact.Entry = firstBuildSourceEntry(build)
		}
		return installZIPDirectory(data, artifact, destination)
	case "tar.gz":
		return installTarGZDirectory(data, build, destination)
	default:
		return fmt.Errorf("不支持的源码归档格式: %s", build.Archive)
	}
}

func firstBuildSourceEntry(build *BuildSpec) string {
	switch strings.ToLower(strings.TrimSpace(build.Recipe)) {
	case BuildRecipeGo:
		return "go.mod"
	default:
		return "README.md"
	}
}

func installTarGZDirectory(data []byte, build *BuildSpec, destination string) error {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("解压源码 tar.gz 失败: %w", err)
	}
	defer reader.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	tempDir, err := os.MkdirTemp(filepath.Dir(destination), ".catalog-src-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	archive := tar.NewReader(reader)
	var total int64
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取源码 tar.gz 失败: %w", err)
		}
		name := archivepath.Clean(header.Name)
		if name == "." {
			continue
		}
		if archivepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("源码包包含越界路径: %s", header.Name)
		}
		parts := strings.Split(name, "/")
		if len(parts) <= build.StripComponents {
			continue
		}
		target := filepath.Join(tempDir, filepath.Join(parts[build.StripComponents:]...))
		if !pathWithin(tempDir, target) {
			return fmt.Errorf("源码包包含越界路径: %s", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			source := io.LimitReader(archive, maxArtifactBytes-total+1)
			file, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode)&0o777)
			if err != nil {
				return err
			}
			written, copyErr := io.Copy(file, source)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			total += written
			if total > maxArtifactBytes {
				return fmt.Errorf("源码解压后超过大小限制")
			}
		case tar.TypeSymlink, tar.TypeLink:
			// 源码构建不跟随归档内链接，避免构建脚本通过链接逃出临时目录。
			continue
		default:
			return fmt.Errorf("源码包包含不支持的文件类型: %s", header.Name)
		}
	}
	return replaceDirectory(destination, tempDir)
}

func (c *Catalog) writeBuildInstallState(manifest Manifest, installedSHA256 string) error {
	return c.writeInstallStateRecord(
		manifest.Name,
		manifest.Version,
		manifest.Build.SHA256,
		installedSHA256,
	)
}
