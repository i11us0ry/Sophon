package policy

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
	"sophon/internal/intercept"
)

func TestDefaultCapabilityIsFailClosed(t *testing.T) {
	if got := DefaultCapability("exec"); got != CapabilityDestructive {
		t.Fatalf("exec 应为 destructive，实际 %s", got)
	}
	if got := DefaultCapability("nmap"); got != CapabilityIntrusive {
		t.Fatalf("nmap 应为 intrusive，实际 %s", got)
	}
	if got := DefaultCapability("project_list_facts"); got != CapabilityRead {
		t.Fatalf("项目查询应为 read，实际 %s", got)
	}
	if got := DefaultCapability("unknown-tool"); got != CapabilityDestructive {
		t.Fatalf("未知工具应失败关闭，实际 %s", got)
	}
}

func TestScopeAllowsWildcardAndSubdomains(t *testing.T) {
	scope := newScope([]database.Asset{
		{Value: "*.example.com"},
		{Value: "*lenxin.com"},
		{Value: "https://n9e.oa.example.com"},
		{Value: "10.0.0.0/24"},
	})
	cases := []struct {
		target string
		want   bool
	}{
		{"n9e.oa.example.com", true},
		{"example.com", false},
		{"lenxin.com", false},
		{"api.lenxin.com", true},
		{"evilexample.com", false},
		{"10.0.0.42", true},
		{"10.0.1.42", false},
	}
	for _, item := range cases {
		if got := scope.Allows(item.target); got != item.want {
			t.Fatalf("Allows(%q)=%v，期望 %v", item.target, got, item.want)
		}
	}
}

func TestAnalyzeCommandClassifiesReadIntrusiveAndDestructive(t *testing.T) {
	cases := []struct {
		command string
		want    Capability
	}{
		{"ls -la", CapabilityRead},
		{"curl https://target.example/a", CapabilityRead},
		{"curl -X POST https://target.example/a", CapabilityDestructive},
		{"nmap -sV target.example", CapabilityIntrusive},
		{"rm -rf /var/lib/data", CapabilityDestructive},
		{"kubectl get pods -n test", CapabilityRead},
		{"kubectl delete namespace prod", CapabilityDestructive},
		{"mysql -e 'DROP TABLE users'", CapabilityDestructive},
		{"echo hello | sh", CapabilityDestructive},
	}
	for _, testCase := range cases {
		got := AnalyzeCommand(testCase.command)
		if got.Capability != testCase.want {
			t.Fatalf("命令 %q 应为 %s，实际 %s（%s）",
				testCase.command, testCase.want, got.Capability, got.Reason)
		}
	}
}

func TestAnalyzeCommandIgnoresLocalArgumentsAsTargets(t *testing.T) {
	cases := []string{
		`grep "n9e.oa.example.com" evidence/probe1.out`,
		`echo "evil.example" > b.tmp`,
		`cat report.out | grep "crt.sh"`,
		`python3 process.py --input probe.out`,
	}
	for _, command := range cases {
		analysis := AnalyzeCommand(command)
		if len(analysis.Targets) != 0 {
			t.Fatalf("本地命令不应提取网络目标: %q -> %#v", command, analysis.Targets)
		}
		if analysis.UnresolvedTarget {
			t.Fatalf("本地命令不应标记为缺少网络目标: %q", command)
		}
	}
}

func TestAnalyzeCommandExtractsRealNetworkTargets(t *testing.T) {
	cases := []struct {
		command string
		target  string
	}{
		{`curl -sS https://n9e.oa.example.com/api/n9e/clusters`, "n9e.oa.example.com"},
		{`curl -H 'Host: n9e.oa.example.com' https://edge.example/a`, "n9e.oa.example.com"},
		{`nmap -sV target.example`, "target.example"},
		{`ping -c 1 target.example`, "target.example"},
	}
	for _, item := range cases {
		analysis := AnalyzeCommand(item.command)
		found := false
		for _, target := range analysis.Targets {
			if target == item.target {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("网络命令应提取目标 %s: %q -> %#v", item.target, item.command, analysis.Targets)
		}
	}
}

func TestAnalyzeCommandHandlesResolveAndShellVariableURL(t *testing.T) {
	command := `cd hostvar && for p in "/%61pi/n9e/clusters" "/api/n9e/./clusters"; do echo -n "80 $p => "; curl -sS -m 6 -o /dev/null -w '%{http_code}\n' --path-as-is --resolve eye.oa.example.com:80:198.51.100.10 "http://eye.oa.example.com$p" 2>&1; done`
	analysis := AnalyzeCommand(command)
	found := false
	foundResolveIP := false
	for _, target := range analysis.Targets {
		if target == "eye.oa.example.com" {
			found = true
		}
		if target == "198.51.100.10" {
			foundResolveIP = true
		}
	}
	if !found {
		t.Fatalf("--resolve 和变量拼接 URL 应提取目标: %#v", analysis.Targets)
	}
	if !foundResolveIP {
		t.Fatalf("--resolve 的落地 IP 也必须纳入授权校验: %#v", analysis.Targets)
	}
	if analysis.UnresolvedTarget {
		t.Fatal("已提取到 --resolve 目标时不应标记为未解析")
	}
}

func TestAnalyzeCommandHandlesTimeoutWrappedOpenSSL(t *testing.T) {
	command := `echo "=== cert"; echo | timeout 10 openssl s_client -connect 198.51.100.10:443 -servername eye.oa.example.com 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null`
	analysis := AnalyzeCommand(command)
	targets := map[string]bool{}
	for _, target := range analysis.Targets {
		targets[target] = true
	}
	if !targets["198.51.100.10"] {
		t.Fatalf("timeout 包裹的 openssl 应提取连接 IP: %#v", analysis.Targets)
	}
	if targets["eye.oa.example.com"] {
		t.Fatalf("-servername 是 SNI Payload，不应作为连接目标: %#v", analysis.Targets)
	}
	if analysis.UnresolvedTarget {
		t.Fatal("openssl x509 是本地的证书解析，不应被当成缺少网络目标")
	}
}

func TestAnalyzeCommandHandlesShellFunctionAndLoopVariables(t *testing.T) {
	command := `probe() { ip=$1; sni=$2; host=$3;
  printf 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' "$host" | timeout 12 openssl s_client -quiet -connect $ip:443 -servername "$sni" 2>/dev/null | head -14
}
for ip in 198.51.100.10 8.138.31.33; do
  probe $ip "eye.oa.example.com" "eye.oa.example.com" "baseline"
  probe $ip "sophon-sni-probe.invalid" "eye.oa.example.com" "unknown-sni"
done`
	analysis := AnalyzeCommand(command)
	targets := map[string]bool{}
	for _, target := range analysis.Targets {
		targets[target] = true
	}
	if !targets["198.51.100.10"] || !targets["8.138.31.33"] {
		t.Fatalf("for 循环中的字面 IP 应被提取: %#v", analysis.Targets)
	}
	if targets["sophon-sni-probe.invalid"] {
		t.Fatalf("-servername 是 TLS SNI Payload，不应作为网络目标: %#v", analysis.Targets)
	}
	if analysis.UnresolvedTarget {
		t.Fatal("已从循环字面值解析目标时不应标记为未解析")
	}
}

func TestAnalyzeCommandTreatsRequestTargetAsPayload(t *testing.T) {
	command := `curl -sS --resolve eye.oa.example.com:80:198.51.100.20 --request-target "http://evil.com/" http://eye.oa.example.com/`
	analysis := AnalyzeCommand(command)
	targets := map[string]bool{}
	for _, target := range analysis.Targets {
		targets[target] = true
	}
	if targets["evil.com"] {
		t.Fatalf("--request-target 的 Payload 不应被当成网络目标: %#v", analysis.Targets)
	}
	if !targets["eye.oa.example.com"] || !targets["198.51.100.20"] {
		t.Fatalf("实际连接目标应被提取: %#v", analysis.Targets)
	}
	if analysis.UnresolvedTarget {
		t.Fatal("已提取真实连接目标时不应标记为未解析")
	}
}

func TestAnalyzeCommandExpandsSimpleShellVariableInResolve(t *testing.T) {
	command := `ip=198.51.100.20
curl -sS --resolve eye.oa.example.com:80:$ip --request-target "http://evil.com/" http://eye.oa.example.com/`
	analysis := AnalyzeCommand(command)
	targets := map[string]bool{}
	for _, target := range analysis.Targets {
		targets[target] = true
	}
	if !targets["198.51.100.20"] || !targets["eye.oa.example.com"] {
		t.Fatalf("简单 shell 变量应被展开并校验: %#v", analysis.Targets)
	}
	if targets["evil.com"] {
		t.Fatalf("--request-target 的 Payload 不应被当成目标: %#v", analysis.Targets)
	}
}

func TestAnalyzePythonScriptExtractsNetworkTargets(t *testing.T) {
	analysis := AnalyzePythonScript("import requests\nrequests.get('https://n9e.oa.example.com/api/n9e/clusters')")
	if len(analysis.Targets) != 1 || analysis.Targets[0] != "n9e.oa.example.com" {
		t.Fatalf("Python 网络脚本应提取授权目标: %#v", analysis.Targets)
	}
	if analysis.UnresolvedTarget {
		t.Fatal("已提取到目标时不应标记为未解析")
	}

	unresolved := AnalyzePythonScript("import requests\nhost = input()\nrequests.get(f'https://{host}/api')")
	if !unresolved.UnresolvedTarget {
		t.Fatal("动态构造目标应标记为未解析")
	}

	localFile := AnalyzePythonScript("from pathlib import Path\ncontent = Path('notes.txt').read_text()\nprint(content)")
	if len(localFile.Targets) != 0 || localFile.UnresolvedTarget {
		t.Fatalf("纯本地脚本不应被当成网络访问: %#v", localFile)
	}
}

func TestAnalyzePythonScriptDoesNotTreatAttributesAsHosts(t *testing.T) {
	script := `
from http import client as H
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
HOST = "healthy.example.com"
PATH = "/api/n9e/self/profile"
def test(tok):
    c = H.HTTPSConnection(HOST, 443, timeout=10, context=ctx)
    c.request("GET", PATH, headers={"Authorization": "Bearer " + tok})
`
	analysis := AnalyzePythonScript(script)
	targets := map[string]bool{}
	for _, target := range analysis.Targets {
		targets[target] = true
	}
	if !targets["healthy.example.com"] {
		t.Fatalf("字符串中的真实域名应被提取: %#v", analysis.Targets)
	}
	if targets["ctx.check"] {
		t.Fatalf("Python 属性链不应被当成域名: %#v", analysis.Targets)
	}
}

func TestAnalyzePythonScriptDoesNotTreatSQLObjectsAsHosts(t *testing.T) {
	script := `
import jx
query = "SELECT CAST(COUNT(*) AS nvarchar(10)) FROM msdb.dbo.sysjobs WHERE name=N'jt1'"
history = "USE msdb; SELECT COUNT(*) FROM sysjobhistory"
`
	analysis := AnalyzePythonScript(script)
	if len(analysis.Targets) != 0 {
		t.Fatalf("SQL Server 对象名不应被识别为域名: %#v", analysis.Targets)
	}
}

func TestAnalyzePythonScriptDoesNotTreatLocalILFilesAsTargets(t *testing.T) {
	script := `
import os
files = [
    "Kingdee.BOS.FileServer.App.Core.il",
    "Kingdee.BOS.FileServer.Core.il",
    "Kingdee.BOS.FileServer.Web.il",
]
for name in files:
    path = os.path.join("/opt/sophon/tmp/workspace/evidence/idor", name)
    with open(path, encoding="utf-8") as handle:
        print(handle.read())
`
	analysis := AnalyzePythonScript(script)
	if len(analysis.Targets) != 0 {
		t.Fatalf("本地 IL 文件名不应被识别为域名: %#v", analysis.Targets)
	}
	if analysis.UnresolvedTarget {
		t.Fatal("纯本地 IL 读取不应产生未解析网络目标")
	}
}

func TestAnalyzePythonScriptAcceptsInternalDomainSuffix(t *testing.T) {
	analysis := AnalyzePythonScript(`requests.get("https://api.corp.local/health")`)
	targets := map[string]bool{}
	for _, target := range analysis.Targets {
		targets[target] = true
	}
	if !targets["api.corp.local"] {
		t.Fatalf("内网域名应被提取: %#v", analysis.Targets)
	}
}

func TestAnalyzePythonRuntimeAndFileModes(t *testing.T) {
	version := AnalyzeCommand(`python3 -V; ls -la; echo "---"; pwd`)
	if version.Capability != CapabilityRead {
		t.Fatalf("Python 版本查询应为只读，实际 %s：%s", version.Capability, version.Reason)
	}
	readFile := AnalyzePythonScript("open('notes.txt', 'r').read()")
	if readFile.Capability == CapabilityDestructive {
		t.Fatalf("读取文件不应被判定为破坏性: %s", readFile.Reason)
	}
	writeFile := AnalyzePythonScript("open('notes.txt', 'w').write('x')")
	if writeFile.Capability != CapabilityDestructive {
		t.Fatalf("写入文件应判定为破坏性: %s", writeFile.Reason)
	}
}

func TestAnalyzeCommandDoesNotTreatLocalArtifactsAsTargets(t *testing.T) {
	for _, command := range []string{
		"file index.jsp c0.png",
		"python3 scan.py --input index.jsp --output c0.png",
		"cat index.jsp",
		"strings c0.png",
	} {
		analysis := AnalyzeCommand(command)
		if len(analysis.Targets) != 0 {
			t.Fatalf("本地文件不应被识别为网络目标: command=%q targets=%v", command, analysis.Targets)
		}
	}
}

func TestEngineUsesConfiguredRulesForCommandSafety(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID: "project-policy", OwnerUserID: "user-1", Name: "Policy",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, database.Asset{
		ID: "asset-target", ProjectID: "project-policy", OwnerUserID: "user-1",
		Name: "目标", Kind: "url", Value: "http://127.0.0.1:8080",
		Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}

	engine := NewEngine(db)
	decide := func(tool string, args map[string]interface{}) Decision {
		t.Helper()
		decision, err := engine.Evaluate(
			ctx, "project-policy", "user-1", "sophon-tool-runner", tool, args,
		)
		if err != nil {
			t.Fatalf("Policy 评估失败: %v", err)
		}
		return decision
	}

	if decision := decide("exec", map[string]interface{}{"command": "ls -la"}); decision.Kind != DecisionAllow {
		t.Fatalf("本地只读命令应允许: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{"command": "rm test.txt"}); decision.Kind != DecisionAllow {
		t.Fatalf("未命中拦截规则时不应按删除关键字审批: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{"command": "rm -rf /"}); decision.Kind != DecisionDeny {
		t.Fatalf("内置拦截规则应拒绝递归强制删除: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "curl -s -m 20 -k -D - http://127.0.0.1:8080/",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("curl -D 仅导出响应头，不应被命令语义拦截: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "for p in /a /b; do curl -s http://127.0.0.1:8080$p; done",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("Shell 循环应按拦截规则判断，不应被当作未知程序: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": `curl -s -X POST -H 'Content-Type: application/json' -d '{"page":1,"page_size":1}' http://127.0.0.1:8080/query_all_system_list_with_page`,
	}); decision.Kind != DecisionAllow {
		t.Fatalf("未命中拦截规则的查询 POST 不应被审批: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": `printf '<svg xmlns="http://www.w3.org/2000/svg"></svg>' > rt.svg; curl http://127.0.0.1:8080/health; curl http://evil.example/`,
	}); decision.Kind != DecisionAllow {
		t.Fatalf("至少一个真实目标在授权范围内时应允许: %+v", decision)
	}
	if decision := decide("nmap", map[string]interface{}{
		"targets": []string{"127.0.0.1", "198.51.100.10"},
	}); decision.Kind != DecisionAllow {
		t.Fatalf("结构化目标至少一个授权时应允许: %+v", decision)
	}
	if decision := decide("nmap", map[string]interface{}{
		"targets": []string{"198.51.100.10", "203.0.113.20"},
	}); decision.Kind != DecisionDeny {
		t.Fatalf("全部目标均未授权时应拒绝: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "curl http://127.0.0.1:8080/health",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("授权目标只读请求应允许: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "curl http://127.0.0.1:8080/index.jsp -o c0.png",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("完整 URL 的目标应按 host 授权，输出文件不应被当作目标: %+v", decision)
	}
	if decision := decide("execute-python-script", map[string]interface{}{
		"script": "import requests\nrequests.get('http://127.0.0.1:8080/health')",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("Python 访问授权目标应允许: %+v", decision)
	}
	if decision := decide("execute-python-script", map[string]interface{}{
		"script": "import requests\nrequests.get('https://evil.example/secret')",
	}); decision.Kind != DecisionDeny || !strings.Contains(decision.Reason, "不在当前项目授权资产范围内") {
		t.Fatalf("Python 访问范围外目标应拒绝: %+v", decision)
	}
	if decision := decide("execute-python-script", map[string]interface{}{
		"script": `files=["Kingdee.BOS.FileServer.App.Core.il","Kingdee.BOS.FileServer.Core.il","Kingdee.BOS.FileServer.Web.il"]
for name in files:
    open("/opt/sophon/tmp/workspace/evidence/idor/"+name).read()`,
	}); decision.Kind != DecisionAllow {
		t.Fatalf("本地 IL 文件读取不应触发资产范围拦截: %+v", decision)
	}
	if decision := decide("execute-python-script", map[string]interface{}{
		"script": "import requests\nhost=input()\nrequests.get(f'https://{host}/api')",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("Python 动态目标解析失败时应默认放行: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": `curl "$url"`,
	}); decision.Kind != DecisionAllow {
		t.Fatalf("exec 目标解析失败时应默认放行: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": `nmap "$target"`,
	}); decision.Kind != DecisionAllow {
		t.Fatalf("主动测试目标解析失败时应默认放行: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "file index.jsp c0.png",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("本地 JSP/PNG 文件不应触发授权范围拒绝: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "curl index.jsp",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("缺少可校验目标的网络命令应默认放行: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "curl -X POST http://127.0.0.1:8080/api",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("非删除写请求应由基本设置决定审批: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": `curl -sk -X POST -H 'Content-Type: application/json' -d '{"page_size":1}' http://127.0.0.1:8080/falcon/user_info/user_info_query`,
	}); decision.Kind != DecisionAllow {
		t.Fatalf("授权目标上的最小化用户信息鉴权测试应允许: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "curl -sk -o /dev/null http://127.0.0.1:8080/falcon/user_info/user_info_query_download",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("授权目标上的下载类接口鉴权验证不应因路径语义被拒绝: %+v", decision)
	}
	if decision := decide("execute-python-script", map[string]interface{}{
		"script": "import requests\nrequests.post('http://127.0.0.1:8080/falcon/user_info/user_info_query', json={'page_size': 1})",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("Python 最小化用户信息查询应允许: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "kubectl delete pod nginx",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("未命中拦截规则的删除命令不应由命令语义审批: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "mysql -e 'INSERT INTO users(name) VALUES(\"a\")'",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("插入操作应由基本设置决定审批: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "mysql -e 'DELETE FROM users WHERE id=1'",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("未命中拦截规则的 SQL DELETE 不应由命令语义审批: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "kubectl apply -f deployment.yaml",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("非删除集群修改应由基本设置决定审批: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "kubectl delete pod demo -n test",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("未命中拦截规则的集群删除不应由命令语义审批: %+v", decision)
	}
	if decision := decide("exec", map[string]interface{}{
		"command": "curl http://unauthorized.example/api",
	}); decision.Kind != DecisionDeny || !strings.Contains(decision.Reason, "不在当前项目授权资产范围内") {
		t.Fatalf("项目内 exec 未授权目标应拒绝: %+v", decision)
	}
	if decision := decide("nmap", map[string]interface{}{
		"target": "127.0.0.1",
	}); decision.Kind != DecisionAllow {
		t.Fatalf("授权目标主动扫描应允许: %+v", decision)
	}
	if decision := decide("nmap", map[string]interface{}{
		"target": "198.51.100.10",
	}); decision.Kind != DecisionDeny {
		t.Fatalf("范围外扫描目标应拒绝: %+v", decision)
	}
	authorizedCtx := execctx.WithAuthorizedScopes(ctx, []string{"10.20.0.0/16"})
	decision, err := engine.Evaluate(
		authorizedCtx,
		"project-policy",
		"user-1",
		"sophon-tool-runner",
		"nmap",
		map[string]interface{}{"target": "10.20.30.10"},
	)
	if err != nil || decision.Kind != DecisionAllow {
		t.Fatalf("本轮授权 CIDR 内的目标应允许: decision=%+v err=%v", decision, err)
	}
	decision, err = engine.Evaluate(
		authorizedCtx,
		"project-policy",
		"user-1",
		"sophon-tool-runner",
		"nmap",
		map[string]interface{}{"target": "10.12.52.199"},
	)
	if err != nil || decision.Kind != DecisionDeny {
		t.Fatalf("本轮授权 CIDR 外的目标应拒绝: decision=%+v err=%v", decision, err)
	}
	if decision := decide("unknown-tool", map[string]interface{}{}); decision.Kind != DecisionAllow {
		t.Fatalf("未配置非删除工具应由基本设置决定审批: %+v", decision)
	}
}

func TestEngineAppliesConfiguredInterceptRules(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "intercept-policy.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID: "project-intercept", OwnerUserID: "user-1", Name: "intercept",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, database.Asset{
		ID: "asset-intercept", ProjectID: "project-intercept", OwnerUserID: "user-1",
		Name: "target", Kind: "domain", Value: "target.example.com",
		Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if err := db.CreateInterceptRule(ctx, database.InterceptRule{
		ID: "allow-exec", Name: "allow exec", Enabled: true, Priority: 100,
		MatchTarget: intercept.TargetToolName, MatchType: intercept.MatchString,
		Pattern: "exec", Action: intercept.ActionAllow, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("写入规则失败: %v", err)
	}
	engine := NewEngine(db)
	decision, err := engine.Evaluate(ctx, "project-intercept", "user-1", "sophon-tool-runner", "exec", map[string]interface{}{
		"command": "curl http://target.example.com/health",
	})
	if err != nil || decision.Kind != DecisionAllow {
		t.Fatalf("allow 规则应跳过能力审批: decision=%+v err=%v", decision, err)
	}
	decision, err = engine.Evaluate(ctx, "project-intercept", "user-1", "sophon-tool-runner", "exec", map[string]interface{}{
		"command": "curl http://evil.example/health",
	})
	if err != nil || decision.Kind != DecisionDeny || !strings.Contains(decision.Reason, "不在当前项目授权资产范围内") {
		t.Fatalf("allow 规则不能绕过项目授权范围: decision=%+v err=%v", decision, err)
	}
	decision, err = engine.Evaluate(ctx, "project-intercept", "user-1", "mcp-server", "nmap", map[string]interface{}{
		"target": "evil.example",
	})
	if err != nil || decision.Kind != DecisionDeny {
		t.Fatalf("MCP 工具也不能绕过项目授权范围: decision=%+v err=%v", decision, err)
	}
	if err := db.CreateInterceptRule(ctx, database.InterceptRule{
		ID: "ask-nmap", Name: "ask nmap", Enabled: true, Priority: 200,
		MatchTarget: intercept.TargetToolName, MatchType: intercept.MatchString,
		Pattern: "nmap", Action: intercept.ActionAsk, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("写入审批规则失败: %v", err)
	}
	decision, err = engine.Evaluate(ctx, "project-intercept", "user-1", "mcp-server", "nmap", map[string]interface{}{
		"target": "target.example.com",
	})
	if err != nil || decision.Kind != DecisionRequireApproval {
		t.Fatalf("ask 规则应要求人工审批: decision=%+v err=%v", decision, err)
	}
}

func TestEngineDoesNotApplyHiddenCampaignScope(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "policy-campaign.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID: "project-campaign-policy", OwnerUserID: "user-1", Name: "Campaign Policy",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	inAsset := database.Asset{
		ID: "asset-in-campaign", ProjectID: "project-campaign-policy",
		OwnerUserID: "user-1", Name: "授权内", Kind: "url",
		Value: "http://127.0.0.1:8080", Status: "active",
		CreatedAt: now, UpdatedAt: now,
	}
	outAsset := database.Asset{
		ID: "asset-out-campaign", ProjectID: "project-campaign-policy",
		OwnerUserID: "user-1", Name: "授权外", Kind: "url",
		Value: "http://198.51.100.10", Status: "active",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateAsset(ctx, outAsset); err != nil {
		t.Fatalf("创建范围外资产失败: %v", err)
	}
	const campaignID = "campaign-policy"
	if _, _, err := db.CreateConversationBatch(
		ctx,
		database.ConversationBatch{
			ID:                   campaignID,
			OwnerUserID:          "user-1",
			ProjectID:            "project-campaign-policy",
			ParentConversationID: "campaign-policy-parent",
			Title:                "Campaign Policy",
			Instruction:          "范围测试",
			Total:                1,
			CreatedAt:            now,
			UpdatedAt:            now,
		},
		database.Conversation{
			ID: "campaign-policy-parent", OwnerUserID: "user-1",
			ProjectID: "project-campaign-policy", Title: "Campaign Policy",
			CreatedAt: now, UpdatedAt: now,
		},
		[]database.ConversationBatchItem{{
			Asset: inAsset,
			Conversation: database.Conversation{
				ID: "campaign-policy-child", OwnerUserID: "user-1",
				ProjectID: "project-campaign-policy", Title: "授权内",
				CreatedAt: now, UpdatedAt: now,
			},
		}},
		"",
	); err != nil {
		t.Fatalf("创建 Campaign 失败: %v", err)
	}
	engine := NewEngine(db)
	campaignCtx := execctx.WithCampaignID(ctx, campaignID)

	decision, err := engine.Evaluate(
		campaignCtx,
		"project-campaign-policy",
		"user-1",
		"sophon-tool-runner",
		"exec",
		map[string]interface{}{"command": "curl http://198.51.100.10/"},
	)
	if err != nil {
		t.Fatalf("Campaign 范围评估失败: %v", err)
	}
	if decision.Kind != DecisionDeny || !strings.Contains(decision.Reason, "不在当前 Campaign 授权资产范围内") {
		t.Fatalf("Campaign 范围外目标应拒绝: %+v", decision)
	}

	task, err := db.CreateCampaignReviewTask(ctx, campaignID, "user-1", 1)
	if err != nil {
		t.Fatalf("创建复盘任务失败: %v", err)
	}
	reviewCtx := execctx.WithCampaignTaskID(campaignCtx, task.ID)
	decision, err = engine.Evaluate(
		reviewCtx,
		"project-campaign-policy",
		"user-1",
		"sophon-tool-runner",
		"nmap",
		map[string]interface{}{"target": "127.0.0.1"},
	)
	if err != nil {
		t.Fatalf("复盘任务评估失败: %v", err)
	}
	if decision.Kind != DecisionAllow {
		t.Fatalf("未命中拦截规则时不应由复盘任务隐式拒绝: %+v", decision)
	}
}
