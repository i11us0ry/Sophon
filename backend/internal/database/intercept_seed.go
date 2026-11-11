package database

import (
	"context"
	"fmt"
	"time"
)

type defaultInterceptRule struct {
	name      string
	target    string
	matchType string
	pattern   string
	action    string
	message   string
	priority  int
	enabled   bool
}

// ARTEX 内置规则全量移植：v1 系统/数据库/HTTP 破坏性操作、v2 安全兜底、
// v3 删除类接口路径。数据外泄管道保持 ARTEX 的默认停用状态。
var defaultInterceptRules = []defaultInterceptRule{
	{
		name: "[内置] 递归强制删除 rm -rf", target: "tool_input", matchType: "regex",
		pattern: `(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)`,
		action:  "deny", message: "禁止执行递归强制删除（rm -rf / rm --recursive），可能永久损坏系统或靶机环境",
		priority: 100, enabled: true,
	},
	{
		name: "[内置] 删除系统关键目录", target: "tool_input", matchType: "regex",
		pattern: `\brm\b[^"'\n]{0,60}["'\s](/|/etc|/bin|/usr|/boot|/var|/lib|/sys|/proc|/dev|/sbin|/root)`,
		action:  "deny", message: "禁止删除系统关键路径",
		priority: 100, enabled: true,
	},
	{
		name: "[内置] 磁盘格式化 mkfs", target: "tool_input", matchType: "regex",
		pattern: `\bmkfs\b`, action: "deny", message: "禁止格式化磁盘（mkfs）",
		priority: 100, enabled: true,
	},
	{
		name: "[内置] 覆写磁盘设备 dd", target: "tool_input", matchType: "regex",
		pattern: `\bdd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z]`,
		action:  "deny", message: "禁止使用 dd 覆写磁盘设备",
		priority: 100, enabled: true,
	},
	{
		name: "[内置] Fork 炸弹", target: "tool_input", matchType: "regex",
		pattern: `:\(\)\s*\{[^}]*:\|:`, action: "deny", message: "禁止执行 Fork 炸弹",
		priority: 100, enabled: true,
	},
	{
		name: "[内置] 关机 / 重启", target: "tool_input", matchType: "regex",
		pattern: `\b(?:shutdown|reboot|halt|poweroff|init\s+[06])\b`,
		action:  "deny", message: "禁止执行关机或重启命令",
		priority: 100, enabled: true,
	},
	{
		name: "[内置] 杀死全部进程", target: "tool_input", matchType: "regex",
		pattern: `\bkill\s+-9\s+-1\b|\bkillall\s+-9\b`,
		action:  "deny", message: "禁止 kill -9 -1 或 killall -9（杀死所有进程）",
		priority: 100, enabled: true,
	},
	{
		name: "[内置] 磁盘擦除 shred / wipe", target: "tool_input", matchType: "regex",
		pattern: `\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]`,
		action:  "deny", message: "禁止对磁盘设备执行 shred/wipe 擦除",
		priority: 100, enabled: true,
	},
	{
		name: "[内置] 清空防火墙规则", target: "tool_input", matchType: "regex",
		pattern: `\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b`,
		action:  "deny", message: "禁止清空防火墙规则（iptables -F / nft flush）",
		priority: 100, enabled: true,
	},
	{
		name: "[内置] SQL DROP DATABASE / TABLE / SCHEMA", target: "tool_input", matchType: "regex",
		pattern: `(?i)\bDROP\s+(?:DATABASE|TABLE|SCHEMA|INDEX|VIEW|TABLESPACE|USER|ROLE)\b`,
		action:  "deny", message: "禁止执行 DROP 操作，可能不可逆地销毁数据库对象",
		priority: 90, enabled: true,
	},
	{
		name: "[内置] SQL TRUNCATE", target: "tool_input", matchType: "regex",
		pattern: `(?i)\bTRUNCATE\s+(?:TABLE\s+)?\w`,
		action:  "deny", message: "禁止执行 TRUNCATE，可能清空数据表所有数据",
		priority: 90, enabled: true,
	},
	{
		name: "[内置] MongoDB drop / dropDatabase", target: "tool_input", matchType: "regex",
		pattern: `(?i)\.(?:dropDatabase|dropCollection|drop)\s*\(`,
		action:  "deny", message: "禁止执行 MongoDB drop 操作",
		priority: 90, enabled: true,
	},
	{
		name: "[内置] Redis FLUSHALL / FLUSHDB", target: "tool_input", matchType: "regex",
		pattern: `(?i)\b(?:FLUSHALL|FLUSHDB)\b`,
		action:  "deny", message: "禁止执行 Redis FLUSHALL / FLUSHDB，可能清空全部缓存数据",
		priority: 90, enabled: true,
	},
	{
		name: "[内置] curl / wget 发送 DELETE 请求", target: "tool_input", matchType: "regex",
		pattern: `(?i)\bcurl\b[^|\n&;"]{0,300}(?:-X\s*DELETE|--request\s+DELETE|-XDELETE)|\bwget\b[^|\n&;"]{0,300}--method[=\s]+DELETE`,
		action:  "deny", message: "禁止通过 curl/wget 发送 HTTP DELETE 请求，可能删除目标系统数据",
		priority: 80, enabled: true,
	},
	{
		name: "[内置] Python HTTP 客户端 DELETE（requests/httpx/aiohttp）", target: "tool_input", matchType: "regex",
		pattern: `(?i)\b(?:requests|httpx|aiohttp|urllib\.request)\.delete\s*\(|session\.delete\s*\(|client\.delete\s*\(`,
		action:  "deny", message: "禁止使用 Python HTTP 客户端发送 DELETE 请求",
		priority: 80, enabled: true,
	},
	{
		name: "[内置] 脚本中声明 HTTP DELETE 方法（JS/通用）", target: "tool_input", matchType: "regex",
		pattern: `(?i)axios\.delete\s*\(|method\s*[:=]\s*['"]DELETE['"]`,
		action:  "deny", message: "禁止在脚本中声明并发送 HTTP DELETE 请求",
		priority: 80, enabled: true,
	},
	{
		name: "[内置] 批量清空 / 清除接口路径", target: "tool_input", matchType: "regex",
		pattern: `(?i)/(?:clear|wipe|flush|purge|truncate|drop|destroy|factory[-_]reset|reset[-_]all)(?:[/?#"'\s]|$)`,
		action:  "deny", message: "禁止调用批量清空或销毁类接口（/clear /wipe /flush /purge 等）",
		priority: 80, enabled: true,
	},
	{
		name: "[内置] 破坏性系统命令", target: "tool_input", matchType: "regex",
		pattern: `(?i)\b(rm\s+-rf\s+/|mkfs|dd\s+if=|:\(\)\s*\{|shutdown|reboot|>\s*/dev/sd)`,
		action:  "deny", message: "破坏性命令被拒绝（rm -rf / / mkfs / dd / fork bomb / 关机重启 / 覆写磁盘设备）",
		priority: 100, enabled: true,
	},
	{
		name: "[内置] 数据外泄管道", target: "tool_input", matchType: "regex",
		pattern: `(?i)(curl|wget|nc|ncat)\b[^|]*\b(\|\s*(curl|wget|nc))`,
		action:  "deny", message: "疑似数据外泄管道被拒绝（命令输出经 curl/wget/nc 外传）",
		priority: 80, enabled: false,
	},
	{
		name: "[内置] 删除类接口路径", target: "tool_input", matchType: "regex",
		pattern: `(?i)/(?:(?:delete|remove|unlink|erase|destroy)[-\w]*|del)(?:[/?#"'\s]|$)`,
		action:  "deny", message: "禁止调用删除类接口（/delete /remove /unlink /erase 等），不论使用哪种 HTTP 方法——多数应用的删除接口用 GET/POST 就能触发，同样会真实删除目标数据",
		priority: 80, enabled: true,
	},
}

// seedDefaultInterceptRules 按名称幂等导入 ARTEX 内置规则；用户删除或改名后
// 重启会补回缺失的内置规则，但不会覆盖用户已经修改的同名规则。
func (db *DB) seedDefaultInterceptRules(ctx context.Context) error {
	now := time.Now().UTC()
	for _, item := range defaultInterceptRules {
		var existingID string
		err := db.QueryRowContext(
			ctx,
			`SELECT id FROM intercept_rules WHERE name = ? LIMIT 1`,
			item.name,
		).Scan(&existingID)
		if err == nil {
			continue
		}
		if !NoRows(err) {
			return err
		}
		if err := db.CreateInterceptRule(ctx, InterceptRule{
			ID:          newID(),
			Name:        item.name,
			Enabled:     item.enabled,
			Priority:    item.priority,
			MatchTarget: item.target,
			MatchType:   item.matchType,
			Pattern:     item.pattern,
			Action:      item.action,
			Message:     item.message,
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			return fmt.Errorf("seed intercept rule %q: %w", item.name, err)
		}
	}
	return nil
}
