package zhizi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"

	"golang.org/x/crypto/ssh"
)

func TestSafeRelativePathAndWorkspace(t *testing.T) {
	valid := []string{"a.txt", "dir/a.txt", "./dir/a.txt"}
	for _, value := range valid {
		if got, err := safeRelativePath(value); err != nil || got == "" {
			t.Fatalf("合法远端路径被拒绝 %q: %q %v", value, got, err)
		}
	}
	invalid := []string{"", ".", "..", "../a", "/etc/passwd", "dir/../../etc/passwd"}
	for _, value := range invalid {
		if _, err := safeRelativePath(value); err == nil {
			t.Fatalf("非法远端路径未被拒绝: %q", value)
		}
	}
	workspace, err := remoteWorkspace(database.ZhiziNode{WorkRoot: "/home/sophon/sophon"}, "conv-1")
	if err != nil || workspace != "/home/sophon/sophon/conv-1" {
		t.Fatalf("远端工作区错误: %q %v", workspace, err)
	}
	if _, err := remoteWorkspace(database.ZhiziNode{WorkRoot: "/"}, "conv-1"); err == nil {
		t.Fatalf("根目录不能作为远端工作区")
	}
}

func TestLimitedBufferMarksTruncation(t *testing.T) {
	var output limitedBuffer
	output.limit = 5
	if written, err := output.Write([]byte("12345678")); err != nil || written != 8 {
		t.Fatalf("limitedBuffer 写入返回值错误: %d %v", written, err)
	}
	if output.String() != "12345" || !output.truncated {
		t.Fatalf("limitedBuffer 截断错误: %q truncated=%v", output.String(), output.truncated)
	}
}

func TestShellQuoteEscapesSingleQuote(t *testing.T) {
	got := shellQuote("a'b")
	if got != "'a'\"'\"'b'" || !strings.Contains(got, `"'"`) {
		t.Fatalf("shellQuote 结果错误: %q", got)
	}
}

func TestExecutorConnectsToSSHServer(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成主机密钥失败: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("创建 SSH signer 失败: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听测试 SSH 失败: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if metadata.User() == "tester" && string(password) == "secret" {
				return nil, nil
			}
			return nil, errors.New("invalid credentials")
		},
	}
	serverConfig.AddHostKey(signer)
	go serveSSHConnections(listener, serverConfig)

	db, err := database.Open(filepath.Join(t.TempDir(), "executor.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	address := listener.Addr().String()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("解析监听地址失败: %v", err)
	}
	port, _ := strconv.Atoi(portText)
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer probeCancel()
	probes, err := NewExecutor(nil).ProbeHosts(probeCtx, []string{host}, port)
	if err != nil || len(probes) != 1 || probes[0].Fingerprint == "" {
		t.Fatalf("探测 SSH 主机指纹失败: probes=%+v err=%v", probes, err)
	}
	node, err := db.CreateZhiziNode(context.Background(), database.ZhiziNode{
		CreatedByUserID:    "user-1",
		Name:               "local-ssh",
		Host:               host,
		Port:               port,
		Username:           "tester",
		AuthType:           "password",
		HostKeyFingerprint: probes[0].Fingerprint,
		WorkRoot:           "/tmp/sophon-zhizi-test",
		MaxSlots:           1,
		Enabled:            true,
	}, database.ZhiziNodeSecret{Password: "secret"})
	if err != nil {
		t.Fatalf("创建测试节点失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := NewExecutor(db).TestNode(ctx, node.ID); err != nil {
		t.Fatalf("SSH 连接测试失败: %v", err)
	}
}

func serveSSHConnections(listener net.Listener, config *ssh.ServerConfig) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
			if err != nil {
				_ = conn.Close()
				return
			}
			defer serverConn.Close()
			go ssh.DiscardRequests(requests)
			for channel := range channels {
				if channel.ChannelType() != "session" {
					_ = channel.Reject(ssh.UnknownChannelType, "session only")
					continue
				}
				channelItem, channelRequests, err := channel.Accept()
				if err != nil {
					continue
				}
				go func() {
					defer channelItem.Close()
					for request := range channelRequests {
						switch request.Type {
						case "exec", "shell":
							_ = request.Reply(true, nil)
							_, _ = channelItem.SendRequest("exit-status", false, ssh.Marshal(struct {
								Status uint32
							}{Status: 0}))
							return
						default:
							_ = request.Reply(false, nil)
						}
					}
				}()
			}
		}()
	}
}
