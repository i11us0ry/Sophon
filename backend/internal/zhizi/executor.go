package zhizi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"sophon/internal/database"

	"golang.org/x/crypto/ssh"
)

const (
	DefaultTTL       = 5 * time.Minute
	maxOutputBytes   = 256 * 1024
	maxTransferBytes = 32 * 1024 * 1024
)

type ExecResult struct {
	ExitCode   int    `json:"exitCode"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	Truncated  bool   `json:"truncated"`
	DurationMS int64  `json:"durationMs"`
}

type HostKeyProbe struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
}

type Executor struct {
	db *database.DB
}

func NewExecutor(db *database.DB) *Executor {
	return &Executor{db: db}
}

func (e *Executor) ExecConversation(
	ctx context.Context,
	conversationID string,
	ownerUserID string,
	command string,
	timeout time.Duration,
) (ExecResult, error) {
	client, node, lease, err := e.clientForConversation(ctx, conversationID, ownerUserID)
	if err != nil {
		return ExecResult{}, err
	}
	defer client.Close()
	timeout = normalizeTimeout(timeout)
	workspace, err := remoteWorkspace(node, conversationID)
	if err != nil {
		return ExecResult{}, err
	}
	script := "umask 077; mkdir -p " + shellQuote(workspace) +
		" && cd " + shellQuote(workspace) + " && " + command
	remoteCommand := "timeout --signal=KILL " + strconv.Itoa(int(timeout.Seconds())) +
		" /bin/sh -lc " + shellQuote(script)
	result, err := runSSH(ctx, client, remoteCommand, nil)
	if err == nil || isSSHExitError(err) {
		_ = e.db.RenewZhiziLease(ctx, lease.ID, DefaultTTL)
	}
	return result, normalizeRunError(err)
}

func (e *Executor) RunPythonConversation(
	ctx context.Context,
	conversationID string,
	ownerUserID string,
	script string,
	timeout time.Duration,
) (ExecResult, error) {
	client, node, lease, err := e.clientForConversation(ctx, conversationID, ownerUserID)
	if err != nil {
		return ExecResult{}, err
	}
	defer client.Close()
	timeout = normalizeTimeout(timeout)
	workspace, err := remoteWorkspace(node, conversationID)
	if err != nil {
		return ExecResult{}, err
	}
	filename := "zhizi-" + randomSuffix() + ".py"
	writeCommand := "umask 077; mkdir -p " + shellQuote(workspace) +
		" && cat > " + shellQuote(path.Join(workspace, filename))
	if _, err := runSSH(ctx, client, writeCommand, strings.NewReader(script)); err != nil {
		return ExecResult{}, err
	}
	runCommand := "cd " + shellQuote(workspace) + " && timeout --signal=KILL " +
		strconv.Itoa(int(timeout.Seconds())) + " python3 " + shellQuote(filename)
	result, err := runSSH(ctx, client, runCommand, nil)
	if err == nil || isSSHExitError(err) {
		_ = e.db.RenewZhiziLease(ctx, lease.ID, DefaultTTL)
	}
	return result, normalizeRunError(err)
}

func (e *Executor) UploadConversation(
	ctx context.Context,
	conversationID string,
	ownerUserID string,
	remotePath string,
	content []byte,
) error {
	if len(content) > maxTransferBytes {
		return fmt.Errorf("上传文件不能超过 %d MiB", maxTransferBytes/(1024*1024))
	}
	relative, err := safeRelativePath(remotePath)
	if err != nil {
		return err
	}
	client, node, lease, err := e.clientForConversation(ctx, conversationID, ownerUserID)
	if err != nil {
		return err
	}
	defer client.Close()
	workspace, err := remoteWorkspace(node, conversationID)
	if err != nil {
		return err
	}
	target := path.Join(workspace, relative)
	command := "umask 077; mkdir -p " + shellQuote(path.Dir(target)) +
		" && cat > " + shellQuote(target)
	if _, err := runSSH(ctx, client, command, bytes.NewReader(content)); err != nil {
		return err
	}
	_ = e.db.RenewZhiziLease(ctx, lease.ID, DefaultTTL)
	return nil
}

func (e *Executor) DownloadConversation(
	ctx context.Context,
	conversationID string,
	ownerUserID string,
	remotePath string,
) ([]byte, error) {
	relative, err := safeRelativePath(remotePath)
	if err != nil {
		return nil, err
	}
	client, node, lease, err := e.clientForConversation(ctx, conversationID, ownerUserID)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	workspace, err := remoteWorkspace(node, conversationID)
	if err != nil {
		return nil, err
	}
	target := path.Join(workspace, relative)
	var output limitedBuffer
	output.limit = maxTransferBytes
	err = runSSHWithWriters(ctx, client, "cat -- "+shellQuote(target), nil, &output, io.Discard)
	if err != nil {
		return nil, err
	}
	if output.truncated {
		return nil, fmt.Errorf("远端文件不能超过 %d MiB", maxTransferBytes/(1024*1024))
	}
	_ = e.db.RenewZhiziLease(ctx, lease.ID, DefaultTTL)
	return output.Bytes(), nil
}

func (e *Executor) TestNode(ctx context.Context, nodeID string) error {
	node, secret, err := e.db.GetZhiziNodeSecret(ctx, nodeID)
	if err != nil {
		return err
	}
	client, err := dial(ctx, *node, secret)
	if err != nil {
		return err
	}
	defer client.Close()
	_, err = runSSH(ctx, client, "true", nil)
	return normalizeRunError(err)
}

func (e *Executor) RunNodeCommand(
	ctx context.Context,
	nodeID string,
	command string,
) (ExecResult, error) {
	node, secret, err := e.db.GetZhiziNodeSecret(ctx, nodeID)
	if err != nil {
		return ExecResult{}, err
	}
	client, err := dial(ctx, *node, secret)
	if err != nil {
		return ExecResult{}, err
	}
	defer client.Close()
	return runSSH(ctx, client, command, nil)
}

func (e *Executor) RunNodeScript(
	ctx context.Context,
	nodeID string,
	script string,
) (ExecResult, error) {
	return e.RunNodeCommand(ctx, nodeID, "bash -lc "+shellQuote(script))
}

func (e *Executor) ProbeHosts(ctx context.Context, hosts []string, port int) ([]HostKeyProbe, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("SSH 端口不合法")
	}
	items := make([]HostKeyProbe, 0, len(hosts))
	for _, host := range hosts {
		item, err := probeHostKey(ctx, strings.TrimSpace(host), port)
		if err != nil {
			return nil, fmt.Errorf("探测 %s 主机指纹失败: %w", host, err)
		}
		items = append(items, item)
	}
	return items, nil
}

func (e *Executor) clientForConversation(
	ctx context.Context,
	conversationID string,
	ownerUserID string,
) (*ssh.Client, database.ZhiziNode, *database.ZhiziLease, error) {
	if e == nil || e.db == nil {
		return nil, database.ZhiziNode{}, nil, fmt.Errorf("智子分身服务不可用")
	}
	lease, err := e.db.GetActiveZhiziLease(ctx, conversationID, ownerUserID)
	if err != nil {
		return nil, database.ZhiziNode{}, nil, err
	}
	if lease == nil {
		return nil, database.ZhiziNode{}, nil, database.ErrZhiziNoCapacity
	}
	node, secret, err := e.db.GetZhiziNodeSecret(ctx, lease.NodeID)
	if err != nil {
		return nil, database.ZhiziNode{}, nil, err
	}
	client, err := dial(ctx, *node, secret)
	if err != nil {
		return nil, database.ZhiziNode{}, nil, err
	}
	return client, *node, lease, nil
}

func dial(ctx context.Context, node database.ZhiziNode, secret database.ZhiziNodeSecret) (*ssh.Client, error) {
	expectedFingerprint := strings.TrimSpace(node.HostKeyFingerprint)
	if expectedFingerprint == "" {
		return nil, fmt.Errorf("节点未确认 SSH 主机指纹")
	}
	hostKeyCallback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		actual := ssh.FingerprintSHA256(key)
		if !strings.EqualFold(actual, expectedFingerprint) {
			return fmt.Errorf("SSH 主机指纹不匹配：期望 %s，实际 %s", expectedFingerprint, actual)
		}
		return nil
	}
	authMethods := make([]ssh.AuthMethod, 0, 2)
	if strings.EqualFold(node.AuthType, "password") {
		if strings.TrimSpace(secret.Password) == "" {
			return nil, fmt.Errorf("节点缺少 SSH 密码")
		}
		authMethods = append(authMethods, ssh.Password(secret.Password))
		authMethods = append(authMethods, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for index := range answers {
					answers[index] = secret.Password
				}
				return answers, nil
			},
		))
	} else {
		if strings.TrimSpace(secret.PrivateKey) == "" {
			return nil, fmt.Errorf("节点缺少 SSH 私钥")
		}
		signer, err := ssh.ParsePrivateKey([]byte(secret.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("解析 SSH 私钥失败: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	address := net.JoinHostPort(node.Host, strconv.Itoa(node.Port))
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 20 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("连接 SSH 失败: %w", err)
	}
	config := &ssh.ClientConfig{
		User:            node.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}
	clientConn, channels, requests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SSH 握手失败: %w", err)
	}
	return ssh.NewClient(clientConn, channels, requests), nil
}

func probeHostKey(ctx context.Context, host string, port int) (HostKeyProbe, error) {
	result := HostKeyProbe{Host: host, Port: port}
	if strings.TrimSpace(host) == "" {
		return result, fmt.Errorf("主机不能为空")
	}
	var captured ssh.PublicKey
	config := &ssh.ClientConfig{
		User: "sophon-host-key-probe",
		Auth: []ssh.AuthMethod{ssh.Password("sophon-host-key-probe")},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return errHostKeyProbeComplete
		},
		Timeout: 10 * time.Second,
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return result, err
	}
	defer conn.Close()
	clientConn, _, _, err := ssh.NewClientConn(conn, address, config)
	if clientConn != nil {
		_ = clientConn.Close()
	}
	if captured == nil {
		return result, err
	}
	result.Algorithm = captured.Type()
	result.Fingerprint = ssh.FingerprintSHA256(captured)
	return result, nil
}

var errHostKeyProbeComplete = errors.New("SSH host key captured")

func runSSH(
	ctx context.Context,
	client *ssh.Client,
	command string,
	stdin io.Reader,
) (ExecResult, error) {
	started := time.Now()
	var stdout, stderr limitedBuffer
	stdout.limit = maxOutputBytes
	stderr.limit = maxOutputBytes
	err := runSSHWithWriters(ctx, client, command, stdin, &stdout, &stderr)
	result := ExecResult{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		Truncated:  stdout.truncated || stderr.truncated,
		DurationMS: time.Since(started).Milliseconds(),
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitStatus()
	}
	return result, err
}

func runSSHWithWriters(
	ctx context.Context,
	client *ssh.Client,
	command string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdin = stdin
	session.Stdout = stdout
	session.Stderr = stderr
	done := make(chan struct{})
	var closeOnce sync.Once
	go func() {
		select {
		case <-ctx.Done():
			closeOnce.Do(func() { _ = session.Close() })
		case <-done:
		}
	}()
	err = session.Run(command)
	closeOnce.Do(func() { close(done) })
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func remoteWorkspace(node database.ZhiziNode, conversationID string) (string, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" || path.Base(conversationID) != conversationID || conversationID == "." || conversationID == ".." {
		return "", fmt.Errorf("会话 ID 不合法")
	}
	root := path.Clean(strings.TrimSpace(node.WorkRoot))
	if !strings.HasPrefix(root, "/") || root == "/" || strings.HasPrefix(root, "/..") {
		return "", fmt.Errorf("远端工作目录不合法")
	}
	return path.Join(root, conversationID), nil
}

func safeRelativePath(value string) (string, error) {
	value = path.Clean(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"))
	if value == "." || value == "" || strings.HasPrefix(value, "/") ||
		value == ".." || strings.HasPrefix(value, "../") {
		return "", fmt.Errorf("远端路径必须是工作区内相对路径")
	}
	return value, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func normalizeTimeout(value time.Duration) time.Duration {
	if value <= 0 {
		return 120 * time.Second
	}
	if value < time.Second {
		return time.Second
	}
	if value > 10*time.Minute {
		return 10 * time.Minute
	}
	return value
}

func normalizeRunError(err error) error {
	if err == nil || isSSHExitError(err) {
		return nil
	}
	return err
}

func isSSHExitError(err error) bool {
	var exitErr *ssh.ExitError
	return errors.As(err, &exitErr)
}

func randomSuffix() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(raw)
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	if b.limit <= 0 {
		return original, nil
	}
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			_, _ = b.buffer.Write(value[:remaining])
			b.truncated = true
		} else {
			_, _ = b.buffer.Write(value)
		}
	} else {
		b.truncated = true
	}
	return original, nil
}

func (b *limitedBuffer) String() string {
	return b.buffer.String()
}

func (b *limitedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}
