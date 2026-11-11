#!/usr/bin/env python3
"""多用户 RBAC 与业务 CRUD 的端到端冒烟测试。

在运行 Sophon 的机器或容器内执行：

    SOPHON_ADMIN_PASSWORD=... python3 smoke-rbac.py
"""

import http.cookiejar
import http.server
import json
import os
import stat
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE_URL = os.environ.get("SOPHON_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
ADMIN_USER = os.environ.get("SOPHON_ADMIN_USERNAME", "admin")
ADMIN_PASS = os.environ.get("SOPHON_ADMIN_PASSWORD", "sophon-test-password")
TMP_USER = "smoke_%d" % int(time.time())
TMP_MANAGER = "smoke_mgr_%d" % int(time.time())
TMP_PASSWORD_USER = "smoke_pwd_%d" % int(time.time())
TMP_ROLE = "smoke_rbac_manager"
TMP_PASS = "smoke-password-123"


def fail(message):
    print("FAIL: %s" % message, file=sys.stderr)
    sys.exit(1)


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def csrf(self):
        for cookie in self.jar:
            if cookie.name == "sophon_csrf":
                return cookie.value
        return ""

    def request(self, method, path, body=None, csrf=False):
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if csrf:
            headers["X-CSRF-Token"] = self.csrf()
        request = urllib.request.Request(
            BASE_URL + path, data=data, headers=headers, method=method
        )
        try:
            with self.opener.open(request) as response:
                raw = response.read().decode("utf-8")
                if not raw.strip():
                    return response.status, {}
                try:
                    return response.status, json.loads(raw)
                except json.JSONDecodeError:
                    return response.status, {
                        "raw": raw,
                        "contentType": response.headers.get("Content-Type", ""),
                    }
        except urllib.error.HTTPError as error:
            raw = error.read().decode("utf-8")
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = {}
            return error.code, payload


def expect(client, method, path, expected, label, body=None, csrf=False):
    status, payload = client.request(method, path, body=body, csrf=csrf)
    if status != expected:
        fail("%s: 期望 %s，实际 %s %s" % (label, expected, status, payload))
    print("ok  %s (%s)" % (label, status))
    return payload


def stream_chat(client, conversation_id, message, timeout=60):
    """POST /api/chat/stream 并返回助手回复文本（优先取 response_delta）。"""
    body = json.dumps({"conversationId": conversation_id, "message": message}).encode("utf-8")
    headers = {
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
        "X-CSRF-Token": client.csrf(),
    }
    request = urllib.request.Request(
        BASE_URL + "/api/chat/stream", data=body, headers=headers, method="POST"
    )
    deltas = []
    final = ""
    with client.opener.open(request, timeout=timeout) as response:
        for raw in response:
            line = raw.decode("utf-8").strip()
            if not line.startswith("data:"):
                continue
            payload = json.loads(line[5:].strip())
            if payload.get("type") == "response_delta":
                deltas.append(payload.get("message", ""))
            elif payload.get("type") == "response":
                final = payload.get("message", "")
    return "".join(deltas) if deltas else final


def main():
    admin = Client()
    viewer = Client()

    print("== 管理员登录 ==")
    expect(
        admin,
        "POST",
        "/api/auth/login",
        200,
        "admin login",
        body={"username": ADMIN_USER, "password": ADMIN_PASS},
    )
    me = expect(admin, "GET", "/api/rbac/me", 200, "admin 读取自身权限")
    if "*" not in me.get("permissions", []):
        fail("admin 权限应包含 *，实际 %s" % me.get("permissions"))
    admin_user_id = next(
        item["id"]
        for item in admin.request("GET", "/api/rbac/users")[1].get("items", [])
        if item["username"] == ADMIN_USER
    )

    print("== 创建 viewer 用户 ==")
    expect(
        admin,
        "POST",
        "/api/rbac/users",
        201,
        "创建 viewer 用户",
        body={
            "username": TMP_USER,
            "displayName": "Smoke",
            "password": TMP_PASS,
            "role": "viewer",
            "enabled": True,
        },
        csrf=True,
    )
    expect(
        viewer,
        "POST",
        "/api/auth/login",
        200,
        "viewer login",
        body={"username": TMP_USER, "password": TMP_PASS},
    )
    viewer_me = expect(viewer, "GET", "/api/rbac/me", 200, "viewer 读取自身权限")
    permissions = viewer_me.get("permissions", [])
    if "project:read" not in permissions:
        fail("viewer 应具备 project:read，实际 %s" % permissions)
    for forbidden in ("project:write", "rbac:read", "agent:execute"):
        if forbidden in permissions:
            fail("viewer 不应具备 %s" % forbidden)

    print("== 权限拦截 ==")
    expect(
        viewer,
        "POST",
        "/api/projects",
        403,
        "viewer 创建项目被拒绝",
        body={"name": "should-not-exist", "description": ""},
        csrf=True,
    )
    expect(viewer, "GET", "/api/rbac/users", 403, "viewer 读取用户列表被拒绝")

    print("== CSRF 统一校验 ==")
    status, payload = admin.request(
        "POST", "/api/projects", body={"name": "smoke-csrf-check", "description": ""}
    )
    if status != 403 or payload.get("code") != "csrf_failed":
        fail("缺少 CSRF 头的写请求应被拒绝：%s %s" % (status, payload))
    print("ok  写请求缺少 CSRF 头被拒绝 (403)")
    status, payload = admin.request(
        "POST",
        "/api/conversations",
        body={"projectId": "", "title": "csrf-check"},
    )
    if status != 403 or payload.get("code") != "csrf_failed":
        fail("对话创建缺少 CSRF 头应被拒绝：%s %s" % (status, payload))
    print("ok  此前漏挂的接口同样强制 CSRF (403)")

    print("== 仪表盘 ==")
    guest = Client()
    expect(guest, "GET", "/api/dashboard/summary", 401, "未登录不能读取仪表盘")
    dashboard = expect(admin, "GET", "/api/dashboard/summary", 200, "管理员读取仪表盘")
    for field in ("conversations", "vulnerabilities", "toolCalls", "tokens"):
        if field not in dashboard:
            fail("仪表盘缺少字段 %s：%s" % (field, dashboard))
    for field in ("prompt", "completion", "total", "estimated"):
        if field not in dashboard["tokens"]:
            fail("仪表盘 token 字段缺少 %s：%s" % (field, dashboard["tokens"]))
    viewer_dashboard = expect(viewer, "GET", "/api/dashboard/summary", 200, "viewer 读取仪表盘")
    if viewer_dashboard["conversations"] != 0:
        fail("viewer 不应统计到其他用户的对话：%s" % viewer_dashboard)
    print("ok  仪表盘统计按用户隔离")

    print("== 漏洞分布 ==")
    baseline = admin.request("GET", "/api/dashboard/summary")[1]
    base_status = baseline.get("vulnerabilityStatus", {})
    base_severity = baseline.get("vulnerabilitySeverity", {})
    distribution = (
        ("critical", "open"),
        ("high", "confirmed"),
        ("medium", "fixed"),
        ("low", "ignored"),
        ("info", "false_positive"),
    )
    created_vulnerabilities = []
    for severity, status in distribution:
        item = expect(
            admin,
            "POST",
            "/api/vulnerabilities",
            201,
            "创建 %s 漏洞" % severity,
            body={
                "title": "dist-%s" % severity,
                "severity": severity,
                "description": "",
                "evidence": "",
            },
            csrf=True,
        )
        if status != "open":
            expect(
                admin,
                "PUT",
                "/api/vulnerabilities/%s" % item["id"],
                204,
                "状态改为 %s" % status,
                body={
                    "title": item["title"],
                    "severity": severity,
                    "status": status,
                    "description": "",
                    "evidence": "",
                },
                csrf=True,
            )
        created_vulnerabilities.append(item["id"])

    after = admin.request("GET", "/api/dashboard/summary")[1]
    for severity, status in distribution:
        severity_delta = after["vulnerabilitySeverity"].get(severity, 0) - base_severity.get(
            severity, 0
        )
        status_delta = after["vulnerabilityStatus"].get(status, 0) - base_status.get(status, 0)
        if severity_delta != 1:
            fail("严重度 %s 统计不正确：%s" % (severity, after["vulnerabilitySeverity"]))
        if status_delta != 1:
            fail("状态 %s 统计不正确：%s" % (status, after["vulnerabilityStatus"]))
    print("ok  状态与严重度分布统计正确")

    for vulnerability_id in created_vulnerabilities:
        expect(
            admin,
            "DELETE",
            "/api/vulnerabilities/%s" % vulnerability_id,
            204,
            "清理分布测试漏洞",
            csrf=True,
        )

    print("== 漏洞管理 ==")
    managed = []
    for index, severity in enumerate(("critical", "high", "medium"), start=1):
        item = expect(
            admin,
            "POST",
            "/api/vulnerabilities",
            201,
            "创建管理测试漏洞",
            body={
                "title": "mgmt-%d" % index,
                "severity": severity,
                "vulnerabilityType": "smoke-type",
                "target": "smoke-target-%d" % index,
                "description": "smoke description",
                "evidence": "smoke evidence",
            },
            csrf=True,
        )
        managed.append(item)

    listing = expect(
        admin,
        "GET",
        "/api/vulnerabilities?severity=critical&search=mgmt-&limit=1",
        200,
        "按严重度与关键词筛选漏洞",
    )
    if listing.get("total", 0) < 1 or len(listing.get("items", [])) > 1:
        fail("漏洞筛选分页结果不正确：%s" % listing)
    if listing["items"][0]["vulnerabilityType"] != "smoke-type":
        fail("漏洞扩展字段未返回：%s" % listing["items"][0])

    detail = expect(
        admin,
        "GET",
        "/api/vulnerabilities/%s" % managed[0]["id"],
        200,
        "读取漏洞详情",
    )
    if detail.get("target") != "smoke-target-1":
        fail("漏洞详情字段不正确：%s" % detail)

    stats = expect(admin, "GET", "/api/vulnerabilities/stats", 200, "读取漏洞统计")
    if "status" not in stats or "total" not in stats:
        fail("漏洞统计缺少 status/total：%s" % stats)

    expect(
        viewer,
        "POST",
        "/api/vulnerabilities/batch-delete",
        403,
        "viewer 批量删除被拒绝",
        body={"ids": [managed[0]["id"]]},
        csrf=True,
    )

    updated = expect(
        admin,
        "POST",
        "/api/vulnerabilities/batch-status",
        200,
        "批量修改漏洞状态",
        body={"ids": [item["id"] for item in managed], "status": "confirmed"},
        csrf=True,
    )
    if updated.get("updated") != len(managed):
        fail("批量修改状态数量不正确：%s" % updated)

    exported = expect(
        admin,
        "GET",
        "/api/vulnerabilities/export?search=mgmt-",
        200,
        "导出漏洞 CSV",
    )
    if "text/csv" not in exported.get("contentType", ""):
        fail("CSV 导出 Content-Type 不正确：%s" % exported)
    if "标题" not in exported.get("raw", ""):
        fail("CSV 导出缺少表头")

    deleted = expect(
        admin,
        "POST",
        "/api/vulnerabilities/batch-delete",
        200,
        "批量删除漏洞",
        body={"ids": [item["id"] for item in managed]},
        csrf=True,
    )
    if deleted.get("deleted") != len(managed):
        fail("批量删除数量不正确：%s" % deleted)
    expect(
        admin,
        "GET",
        "/api/vulnerabilities/%s" % managed[0]["id"],
        404,
        "删除后详情返回 404",
    )

    print("== 角色与技能 ==")
    role_list = expect(admin, "GET", "/api/agent-roles", 200, "读取角色列表")
    if not role_list.get("items"):
        fail("角色列表为空，期望已导入内置角色")
    if not any(item.get("builtin") for item in role_list["items"]):
        fail("角色列表缺少内置角色：%s" % role_list)

    custom_role = expect(
        admin,
        "POST",
        "/api/agent-roles",
        201,
        "创建自定义角色",
        body={
            "name": "smoke-role",
            "description": "smoke",
            "prompt": "你是冒烟测试角色。",
            "icon": "",
            "skills": ["active-directory-attack"],
            "enabled": True,
        },
        csrf=True,
    )
    role_project = expect(
        admin,
        "POST",
        "/api/projects",
        201,
        "创建角色测试项目",
        body={"name": "smoke-role-project", "description": "smoke"},
        csrf=True,
    )
    expect(
        admin,
        "POST",
        "/api/conversations",
        400,
        "无项目不能新建对话",
        body={"title": "no-project"},
        csrf=True,
    )
    conversation = expect(
        admin,
        "POST",
        "/api/conversations",
        201,
        "创建待删除对话",
        body={"title": "smoke-delete-conversation", "projectId": role_project["id"]},
        csrf=True,
    )
    deleted_conversation = expect(
        admin,
        "POST",
        "/api/conversations/batch-delete",
        200,
        "批量删除对话",
        body={"ids": [conversation["id"]]},
        csrf=True,
    )
    if deleted_conversation.get("deleted") != 1:
        fail("批量删除对话数量不正确：%s" % deleted_conversation)
    expect(
        admin,
        "GET",
        "/api/conversations/%s" % conversation["id"],
        404,
        "删除后对话返回 404",
    )

    database_path = os.environ.get("SOPHON_DB_PATH", "/opt/sophon/data/sophon.db")
    if os.path.exists(database_path):
        legacy_id = "legacy" + uuid.uuid4().hex
        import sqlite3

        connection = sqlite3.connect(database_path)
        now_ts = int(time.time())
        connection.execute(
            "INSERT INTO conversations (id, owner_user_id, project_id, title, created_at, updated_at)"
            " VALUES (?, (SELECT id FROM users WHERE username = 'admin'), '', 'legacy-no-project', ?, ?)",
            (legacy_id, now_ts, now_ts),
        )
        connection.commit()
        connection.close()
        expect(
            admin,
            "POST",
            "/api/chat/stream",
            400,
            "无项目会话不能发送消息",
            body={"conversationId": legacy_id, "message": "hello"},
            csrf=True,
        )
        expect(
            admin,
            "DELETE",
            "/api/conversations/%s" % legacy_id,
            204,
            "清理无项目会话",
            csrf=True,
        )

    expect(
        admin,
        "PUT",
        "/api/agent-roles/%s" % custom_role["id"],
        204,
        "更新自定义角色",
        body={
            "name": "smoke-role",
            "description": "smoke v2",
            "prompt": "你是冒烟测试角色。",
            "icon": "",
            "skills": [],
            "enabled": False,
        },
        csrf=True,
    )
    expect(
        admin,
        "POST",
        "/api/conversations",
        400,
        "停用角色不能用于对话",
        body={
            "title": "smoke-role",
            "roleId": custom_role["id"],
            "projectId": role_project["id"],
        },
        csrf=True,
    )
    expect(
        viewer,
        "DELETE",
        "/api/agent-roles/%s" % custom_role["id"],
        403,
        "viewer 不能删除角色",
        csrf=True,
    )
    expect(
        admin,
        "DELETE",
        "/api/agent-roles/%s" % custom_role["id"],
        204,
        "删除自定义角色",
        csrf=True,
    )
    expect(
        admin,
        "DELETE",
        "/api/projects/%s" % role_project["id"],
        204,
        "清理角色测试项目",
        csrf=True,
    )

    print("== 内置角色删除 ==")
    builtin_deleted = ""
    for item in role_list["items"]:
        if not item.get("builtin"):
            continue
        status, _ = admin.request(
            "DELETE",
            "/api/agent-roles/%s" % item["id"],
            csrf=True,
        )
        if status == 204:
            builtin_deleted = item["name"]
            break
    if not builtin_deleted:
        fail("未能删除任何内置角色")
    print("ok  内置角色软删除 (%s)" % builtin_deleted)
    refreshed_roles = expect(admin, "GET", "/api/agent-roles", 200, "重新读取角色列表")
    if any(item["name"] == builtin_deleted for item in refreshed_roles["items"]):
        fail("已删除的内置角色仍在列表中：%s" % builtin_deleted)
    if os.path.exists(database_path):
        import sqlite3

        connection = sqlite3.connect(database_path)
        connection.execute(
            "UPDATE agent_roles SET deleted = 0 WHERE name = ?",
            (builtin_deleted,),
        )
        connection.commit()
        connection.close()
        print("ok  恢复内置角色（保持环境可重复运行）")

    skill_list = expect(admin, "GET", "/api/skills", 200, "读取技能列表")
    if not skill_list.get("items"):
        fail("技能列表为空，期望已导入内置技能")
    first_skill = skill_list["items"][0]
    for field in ("name", "description", "tags", "fileCount"):
        if field not in first_skill:
            fail("技能缺少字段 %s：%s" % (field, first_skill))
    for item in skill_list["items"]:
        description = (item.get("description") or "").strip()
        if not description or description in (">-", ">", "|", "|-"):
            fail("技能 %s 的 description 未正确解析：%r" % (item.get("name"), description))
    print("ok  技能 description 均非空且已解析（%d 个）" % len(skill_list["items"]))
    skill_detail = expect(
        admin,
        "GET",
        "/api/skills/%s" % first_skill["name"],
        200,
        "读取技能详情",
    )
    if "content" not in skill_detail:
        fail("技能详情缺少内容")

    created_skill = expect(
        admin,
        "POST",
        "/api/skills",
        201,
        "创建技能",
        body={"name": "smoke-skill", "description": "冒烟技能"},
        csrf=True,
    )
    if created_skill.get("name") != "smoke-skill":
        fail("创建技能返回不正确：%s" % created_skill)
    expect(
        admin,
        "PUT",
        "/api/skills/smoke-skill",
        200,
        "编辑技能内容",
        body={
            "content": "---\nname: smoke-skill\ndescription: 冒烟技能 v2\nmetadata:\n  tags: [smoke]\n---\n\n## smoke-skill\n",
        },
        csrf=True,
    )
    expect(admin, "DELETE", "/api/skills/smoke-skill", 204, "删除技能", csrf=True)
    expect(admin, "GET", "/api/skills/smoke-skill", 404, "删除后读取技能返回 404")

    print("== MCP 管理 ==")
    server_list = expect(admin, "GET", "/api/mcp/servers", 200, "读取 MCP 服务列表")
    server_names = [item["name"] for item in server_list.get("items", [])]
    if "sophon-mcp-tools" not in server_names:
        fail("缺少内置 MCP 服务：%s" % server_names)
    if "pent_claude_agent" in server_names:
        fail("pent_claude_agent 已由原生子 Agent 取代，不应再注册为 MCP：%s" % server_names)
    tool_runner = next(
        (item for item in server_list.get("items", []) if item["name"] == "sophon-tool-runner"),
        None,
    )
    if tool_runner is None:
        fail("缺少工具目录 MCP 服务：%s" % server_names)
    if not tool_runner.get("enabled"):
        fail("工具目录 MCP 服务应默认启用：%s" % tool_runner)
    # 精简与停用不可用工具后，tools/ 保留 21 个 YAML（17 个启用）
    if int(tool_runner.get("toolCount", 0)) < 12:
        fail("工具目录注册数量异常：%s" % tool_runner)

    print("== MCP 工具配置 ==")
    tool_list = expect(admin, "GET", "/api/mcp/tools", 200, "读取 MCP 工具列表")
    tool_items = tool_list.get("items", [])
    if len(tool_items) < 12:
        fail("MCP 工具数量异常：%d" % len(tool_items))
    # 内置演示工具已下线，改为在工具目录服务中挑一个启用的工具验证启停链路。
    target_tool = next(
        (
            item
            for item in tool_items
            if item["serverName"] == "sophon-tool-runner" and item.get("enabled")
        ),
        None,
    )
    if target_tool is None:
        fail("工具列表缺少可用的目录工具：%s" % [item["name"] for item in tool_items[:10]])
    expect(
        admin,
        "PUT",
        "/api/mcp/tools",
        200,
        "停用工具",
        body={
            "items": [
                {
                    "serverName": target_tool["serverName"],
                    "toolName": target_tool["name"],
                    "enabled": False,
                }
            ]
        },
        csrf=True,
    )
    after_tools = expect(admin, "GET", "/api/mcp/tools", 200, "复核工具状态")
    updated_tool = next(
        (
            item
            for item in after_tools.get("items", [])
            if item["name"] == target_tool["name"]
        ),
        None,
    )
    if updated_tool is None or updated_tool.get("enabled"):
        fail("工具停用未生效：%s" % updated_tool)
    expect(
        admin,
        "PUT",
        "/api/mcp/tools",
        200,
        "恢复工具",
        body={
            "items": [
                {
                    "serverName": target_tool["serverName"],
                    "toolName": target_tool["name"],
                    "enabled": True,
                }
            ]
        },
        csrf=True,
    )
    expect(
        viewer,
        "PUT",
        "/api/mcp/tools",
        403,
        "viewer 不能保存工具配置",
        body={"items": [{"serverName": "x", "toolName": "y", "enabled": False}]},
        csrf=True,
    )
    unauth_tools = Client()
    expect(unauth_tools, "GET", "/api/mcp/tools", 401, "未登录不能读取工具列表")

    builtin_server = next(
        item for item in server_list["items"] if item["name"] == "sophon-mcp-tools"
    )
    if not builtin_server.get("builtin"):
        fail("内置 MCP 服务缺少 builtin 标记：%s" % builtin_server)
    if builtin_server.get("status") != "connected":
        fail("内置 MCP 服务应处于 connected 状态：%s" % builtin_server)
    expect(
        admin,
        "DELETE",
        "/api/mcp/servers/%s" % builtin_server["id"],
        400,
        "内置 MCP 服务不能删除",
        csrf=True,
    )

    smoke_server = expect(
        admin,
        "POST",
        "/api/mcp/servers",
        201,
        "创建 MCP 服务",
        body={
            "name": "smoke-mcp",
            "transport": "stdio",
            "command": "/opt/sophon/backend/sophon-mcp-tools",
            "args": [],
            "env": {},
            "url": "",
            "description": "smoke",
            "enabled": False,
        },
        csrf=True,
    )
    expect(
        viewer,
        "POST",
        "/api/mcp/servers/%s/test" % smoke_server["id"],
        403,
        "viewer 不能测试 MCP 服务",
        csrf=True,
    )
    tested = expect(
        admin,
        "POST",
        "/api/mcp/servers/%s/test" % smoke_server["id"],
        200,
        "测试 MCP 服务连接",
        csrf=True,
    )
    if tested.get("status") != "connected" or tested.get("toolCount", 0) < 2:
        fail("MCP 连接测试结果不正确：%s" % tested)
    expect(
        admin,
        "PUT",
        "/api/mcp/servers/%s" % smoke_server["id"],
        204,
        "更新 MCP 服务",
        body={
            "name": "smoke-mcp",
            "transport": "stdio",
            "command": "/opt/sophon/backend/sophon-mcp-tools",
            "args": [],
            "env": {},
            "url": "",
            "description": "smoke v2",
            "enabled": False,
        },
        csrf=True,
    )
    expect(
        admin,
        "DELETE",
        "/api/mcp/servers/%s" % smoke_server["id"],
        204,
        "删除 MCP 服务",
        csrf=True,
    )

    print("== 项目管理 ==")
    detail_project = expect(
        admin,
        "POST",
        "/api/projects",
        201,
        "创建项目管理测试项目",
        body={
            "name": "smoke-project-detail",
            "description": "smoke",
            "goals": "验证边界主机是否存在可利用漏洞",
            "scope": "10.0.0.0/24、example.com",
            "status": "planning",
        },
        csrf=True,
    )
    detail_project_id = detail_project["id"]
    if detail_project.get("goals") != "验证边界主机是否存在可利用漏洞":
        fail("项目目标未保存：%s" % detail_project)
    if detail_project.get("scope") != "10.0.0.0/24、example.com":
        fail("资产范围未保存：%s" % detail_project)
    if detail_project.get("status") != "planning":
        fail("项目状态未保存：%s" % detail_project)
    expect(
        admin,
        "PUT",
        "/api/projects/%s" % detail_project_id,
        204,
        "更新项目目标与资产范围",
        body={
            "name": "smoke-project-detail",
            "description": "smoke",
            "goals": "验证边界主机漏洞并获取权限",
            "scope": "10.0.0.0/24",
            "status": "active",
        },
        csrf=True,
    )
    updated_project = expect(
        admin,
        "GET",
        "/api/projects/%s" % detail_project_id,
        200,
        "复核项目目标与资产范围",
    )
    if updated_project.get("goals") != "验证边界主机漏洞并获取权限":
        fail("项目目标更新未生效：%s" % updated_project)
    if updated_project.get("scope") != "10.0.0.0/24":
        fail("资产范围更新未生效：%s" % updated_project)
    if updated_project.get("status") != "active":
        fail("项目状态更新未生效：%s" % updated_project)
    expect(
        admin,
        "PUT",
        "/api/projects/%s" % detail_project_id,
        400,
        "非法项目状态被拒绝",
        body={"name": "smoke-project-detail", "status": "unknown"},
        csrf=True,
    )
    expect(
        admin,
        "POST",
        "/api/projects",
        400,
        "超长项目目标被拒绝",
        body={"name": "smoke-too-long", "goals": "x" * 2001},
        csrf=True,
    )

    expect(
        admin,
        "POST",
        "/api/projects/%s/facts" % detail_project_id,
        200,
        "写入项目事实",
        body={"factType": "general", "key": "smoke-key", "value": "v1", "confidence": 90},
        csrf=True,
    )

    first_step = expect(
        admin,
        "POST",
        "/api/projects/%s/attack-steps" % detail_project_id,
        201,
        "创建攻击步骤",
        body={
            "name": "信息收集",
            "description": "收集目标资产",
            "status": "todo",
            "severity": "high",
            "technique": "T1595",
            "evidence": "",
        },
        csrf=True,
    )
    second_step = expect(
        admin,
        "POST",
        "/api/projects/%s/attack-steps" % detail_project_id,
        201,
        "创建第二个攻击步骤",
        body={
            "name": "漏洞利用",
            "description": "",
            "status": "doing",
            "severity": "critical",
            "technique": "T1190",
            "evidence": "poc",
        },
        csrf=True,
    )
    step_list = expect(
        admin,
        "GET",
        "/api/projects/%s/attack-steps" % detail_project_id,
        200,
        "读取攻击路径",
    )
    if [item["name"] for item in step_list["items"]] != ["信息收集", "漏洞利用"]:
        fail("攻击路径顺序不正确：%s" % step_list)

    expect(
        admin,
        "POST",
        "/api/projects/%s/attack-steps/reorder" % detail_project_id,
        204,
        "调整攻击步骤顺序",
        body={"ids": [second_step["id"], first_step["id"]]},
        csrf=True,
    )
    reordered = expect(
        admin,
        "GET",
        "/api/projects/%s/attack-steps" % detail_project_id,
        200,
        "读取调整后的攻击路径",
    )
    if reordered["items"][0]["name"] != "漏洞利用":
        fail("攻击路径顺序调整未生效：%s" % reordered)

    print("== 攻击路径图 ==")
    begin_node = expect(
        admin,
        "POST",
        "/api/projects/%s/graph/nodes" % detail_project_id,
        201,
        "创建起点节点",
        body={"kind": "begin", "title": "smoke 起点", "detail": "冒烟起点", "status": "open"},
        csrf=True,
    )
    intent_node = expect(
        admin,
        "POST",
        "/api/projects/%s/graph/nodes" % detail_project_id,
        201,
        "创建意图节点",
        body={
            "kind": "intent",
            "title": "smoke 意图",
            "detail": "端口扫描",
            "status": "running",
            "parentId": begin_node["id"],
            "relation": "spawns",
        },
        csrf=True,
    )
    fact_node = expect(
        admin,
        "POST",
        "/api/projects/%s/graph/nodes" % detail_project_id,
        201,
        "创建事实节点",
        body={
            "kind": "fact",
            "title": "smoke 事实",
            "detail": "22 端口开放",
            "status": "confirmed",
            "confidence": 90,
            "parentId": intent_node["id"],
            "relation": "yields",
        },
        csrf=True,
    )
    expect(
        admin,
        "POST",
        "/api/projects/%s/graph/nodes" % detail_project_id,
        400,
        "非法节点类型被拒绝",
        body={"kind": "unknown", "title": "bad"},
        csrf=True,
    )
    graph = expect(
        admin,
        "GET",
        "/api/projects/%s/graph" % detail_project_id,
        200,
        "读取攻击路径图",
    )
    node_ids = [item["id"] for item in graph.get("nodes", [])]
    for node in (begin_node, intent_node, fact_node):
        if node["id"] not in node_ids:
            fail("攻击路径图缺少节点：%s" % node)
    edge_pairs = [
        (item["srcId"], item["dstId"], item["rel"]) for item in graph.get("edges", [])
    ]
    if (begin_node["id"], intent_node["id"], "spawns") not in edge_pairs:
        fail("缺少 spawns 关系：%s" % edge_pairs)
    if (intent_node["id"], fact_node["id"], "yields") not in edge_pairs:
        fail("缺少 yields 关系：%s" % edge_pairs)
    graph_summary = expect(
        admin,
        "GET",
        "/api/projects/%s/summary" % detail_project_id,
        200,
        "读取图节点统计",
    )
    if graph_summary.get("counts", {}).get("attackSteps") != 3:
        fail("攻击路径统计未包含图节点：%s" % graph_summary)
    layout_result = expect(
        admin,
        "PUT",
        "/api/projects/%s/graph/layout" % detail_project_id,
        200,
        "保存画布布局",
        body={
            "items": [
                {"id": begin_node["id"], "x": 10, "y": 20},
                {"id": intent_node["id"], "x": 310, "y": 20},
            ]
        },
        csrf=True,
    )
    if layout_result.get("saved") != 2:
        fail("画布布局保存数量异常：%s" % layout_result)
    layout_graph = expect(
        admin,
        "GET",
        "/api/projects/%s/graph" % detail_project_id,
        200,
        "复核节点坐标",
    )
    positions = {
        item["id"]: (item.get("posX"), item.get("posY")) for item in layout_graph.get("nodes", [])
    }
    if positions.get(begin_node["id"]) != (10, 20):
        fail("节点坐标未保存：%s" % positions)
    expect(
        admin,
        "PUT",
        "/api/projects/%s/graph/layout" % detail_project_id,
        400,
        "非法坐标被拒绝",
        body={"items": [{"id": begin_node["id"], "x": 999999, "y": 0}]},
        csrf=True,
    )
    updated_node = expect(
        admin,
        "PUT",
        "/api/projects/%s/graph/nodes/%s" % (detail_project_id, fact_node["id"]),
        200,
        "更新节点状态",
        body={
            "kind": "fact",
            "title": "smoke 事实",
            "detail": "22 端口开放",
            "status": "dismissed",
            "confidence": 60,
        },
        csrf=True,
    )
    if updated_node.get("status") != "dismissed":
        fail("节点更新未生效：%s" % updated_node)
    expect(
        admin,
        "DELETE",
        "/api/projects/%s/graph/nodes/%s" % (detail_project_id, intent_node["id"]),
        204,
        "删除节点级联关系",
        csrf=True,
    )
    after_graph_delete = expect(
        admin,
        "GET",
        "/api/projects/%s/graph" % detail_project_id,
        200,
        "复核图数据",
    )
    remaining_edges = [
        (item["srcId"], item["dstId"]) for item in after_graph_delete.get("edges", [])
    ]
    if (begin_node["id"], intent_node["id"]) in remaining_edges:
        fail("删除节点后关系未清理：%s" % remaining_edges)
    for node in (begin_node, fact_node):
        expect(
            admin,
            "DELETE",
            "/api/projects/%s/graph/nodes/%s" % (detail_project_id, node["id"]),
            204,
            "清理攻击路径节点",
            csrf=True,
        )
    unauth_graph = Client()
    expect(
        unauth_graph,
        "GET",
        "/api/projects/%s/graph" % detail_project_id,
        401,
        "未登录不能读取攻击路径图",
    )

    print("== 项目背景注入 Agent 上下文 ==")
    briefing_conversation = expect(
        admin,
        "POST",
        "/api/conversations",
        201,
        "创建项目背景测试会话",
        body={"projectId": detail_project_id, "title": "smoke-project-briefing"},
        csrf=True,
    )
    main_reply = stream_chat(admin, briefing_conversation["id"], "请复述项目背景")
    if "验证边界主机漏洞并获取权限" not in main_reply:
        fail("主 Agent 未注入项目目标：%s" % main_reply[:400])
    if "10.0.0.0/24" not in main_reply:
        fail("主 Agent 未注入资产范围：%s" % main_reply[:400])
    print("ok  主 Agent 上下文包含项目目标与资产范围")
    sub_reply = stream_chat(admin, briefing_conversation["id"], "pent 请复述项目背景")
    if "10.0.0.0/24" not in sub_reply:
        fail("子 Agent 未注入资产范围：%s" % sub_reply[:400])
    print("ok  子 Agent 上下文包含项目资产范围")
    expect(
        admin,
        "DELETE",
        "/api/conversations/%s" % briefing_conversation["id"],
        204,
        "清理项目背景测试会话",
        csrf=True,
    )

    detail_summary = expect(
        admin,
        "GET",
        "/api/projects/%s/summary" % detail_project_id,
        200,
        "读取项目统计",
    )
    detail_counts = detail_summary.get("counts", {})
    if detail_counts.get("facts") != 1 or detail_counts.get("attackSteps") != 0:
        fail("项目统计不正确：%s" % detail_counts)

    project_list = expect(admin, "GET", "/api/projects", 200, "读取项目列表")
    target_project = next(
        (item for item in project_list["items"] if item["id"] == detail_project_id), None
    )
    if target_project is None or "counts" not in target_project:
        fail("项目列表缺少 counts 字段：%s" % target_project)

    detail_asset = expect(
        admin,
        "POST",
        "/api/assets",
        201,
        "创建项目资产",
        body={
            "projectId": detail_project_id,
            "name": "smoke-asset",
            "kind": "domain",
            "value": "smoke.example.com",
            "criticality": "high",
        },
        csrf=True,
    )
    detail_vulnerability = expect(
        admin,
        "POST",
        "/api/vulnerabilities",
        201,
        "创建项目漏洞",
        body={
            "projectId": detail_project_id,
            "title": "smoke-project-vuln",
            "severity": "high",
            "description": "",
            "evidence": "",
        },
        csrf=True,
    )
    detail_conversation = expect(
        admin,
        "POST",
        "/api/conversations",
        201,
        "创建项目对话",
        body={"title": "smoke-project-chat", "projectId": detail_project_id},
        csrf=True,
    )

    project_assets = expect(
        admin,
        "GET",
        "/api/projects/%s/assets" % detail_project_id,
        200,
        "读取关联资产",
    )
    if [item["name"] for item in project_assets["items"]] != ["smoke-asset"]:
        fail("关联资产不正确：%s" % project_assets)

    project_vulnerabilities = expect(
        admin,
        "GET",
        "/api/projects/%s/vulnerabilities" % detail_project_id,
        200,
        "读取关联漏洞",
    )
    if project_vulnerabilities.get("total", 0) < 1:
        fail("关联漏洞不正确：%s" % project_vulnerabilities)

    project_conversations = expect(
        admin,
        "GET",
        "/api/projects/%s/conversations" % detail_project_id,
        200,
        "读取关联对话",
    )
    if [item["id"] for item in project_conversations["items"]] != [detail_conversation["id"]]:
        fail("关联对话不正确：%s" % project_conversations)

    expect(
        viewer,
        "GET",
        "/api/projects/%s/summary" % detail_project_id,
        404,
        "viewer 读不到他人项目",
    )

    expect(
        admin,
        "DELETE",
        "/api/assets/%s" % detail_asset["id"],
        204,
        "清理项目资产",
        csrf=True,
    )
    expect(
        admin,
        "DELETE",
        "/api/vulnerabilities/%s" % detail_vulnerability["id"],
        204,
        "清理项目漏洞",
        csrf=True,
    )
    expect(
        admin,
        "DELETE",
        "/api/projects/%s" % detail_project_id,
        204,
        "清理项目",
        csrf=True,
    )
    batch_projects = []
    for index in (1, 2):
        batch_projects.append(
            expect(
                admin,
                "POST",
                "/api/projects",
                201,
                "创建批量删除项目",
                body={"name": "smoke-batch-%d" % index, "description": ""},
                csrf=True,
            )
        )
    batch_deleted = expect(
        admin,
        "POST",
        "/api/projects/batch-delete",
        200,
        "批量删除项目",
        body={"ids": [item["id"] for item in batch_projects]},
        csrf=True,
    )
    if batch_deleted.get("deleted") != len(batch_projects):
        fail("批量删除项目数量不正确：%s" % batch_deleted)
    expect(
        admin,
        "GET",
        "/api/projects/%s" % batch_projects[0]["id"],
        404,
        "批量删除后项目返回 404",
    )
    expect(
        admin,
        "GET",
        "/api/projects/%s/summary" % detail_project_id,
        404,
        "删除后项目统计返回 404",
    )

    print("== 项目级联删除 ==")
    cascade_project = expect(
        admin,
        "POST",
        "/api/projects",
        201,
        "创建级联删除测试项目",
        body={"name": "smoke-cascade-project", "status": "active"},
        csrf=True,
    )
    cascade_id = cascade_project["id"]
    expect(
        admin,
        "POST",
        "/api/projects/%s/facts" % cascade_id,
        200,
        "级联项目写入事实",
        body={"factType": "general", "key": "cascade-key", "value": "v", "confidence": 100},
        csrf=True,
    )
    cascade_asset = expect(
        admin,
        "POST",
        "/api/assets",
        201,
        "级联项目创建资产",
        body={
            "projectId": cascade_id,
            "name": "cascade-asset",
            "kind": "domain",
            "value": "cascade.example.com",
            "criticality": "low",
        },
        csrf=True,
    )
    cascade_vulnerability = expect(
        admin,
        "POST",
        "/api/vulnerabilities",
        201,
        "级联项目创建漏洞",
        body={
            "projectId": cascade_id,
            "title": "cascade-vuln",
            "severity": "low",
            "description": "",
        },
        csrf=True,
    )
    cascade_conversation = expect(
        admin,
        "POST",
        "/api/conversations",
        201,
        "级联项目创建对话",
        body={"projectId": cascade_id, "title": "cascade-conversation"},
        csrf=True,
    )
    expect(
        admin,
        "DELETE",
        "/api/projects/%s" % cascade_id,
        204,
        "删除项目（级联）",
        csrf=True,
    )
    expect(
        admin,
        "GET",
        "/api/projects/%s" % cascade_id,
        404,
        "级联后项目不存在",
    )
    expect(
        admin,
        "GET",
        "/api/conversations/%s" % cascade_conversation["id"],
        404,
        "级联后对话不存在",
    )
    expect(
        admin,
        "GET",
        "/api/vulnerabilities/%s" % cascade_vulnerability["id"],
        404,
        "级联后漏洞不存在",
    )
    assets_after = admin.request("GET", "/api/assets")[1]
    if any(item["id"] == cascade_asset["id"] for item in assets_after.get("items", [])):
        fail("级联删除后资产仍存在：%s" % cascade_asset["id"])
    print("ok  级联删除后资产已清理")

    print("== 基本设置 ==")
    settings = expect(admin, "GET", "/api/settings/ai", 200, "读取设置")
    for field in ("configPath", "editable", "values", "envLocked", "requiresRestart"):
        if field not in settings:
            fail("设置响应缺少字段 %s：%s" % (field, settings))
    if not settings["values"].get("agent"):
        fail("设置缺少 agent 段：%s" % settings["values"])
    hitl_values = settings["values"].get("hitl") or {}
    if not hitl_values.get("enabled"):
        fail("高风险工具审批应默认开启：%s" % hitl_values)
    hitl_tools = set(hitl_values.get("tools") or [])
    for tool in ("exec", "execute-python-script", "install-python-package"):
        if tool not in hitl_tools:
            fail("默认审批清单缺少 %s：%s" % (tool, sorted(hitl_tools)))
    print("ok  默认审批清单包含高风险工具")

    expect(
        viewer,
        "PUT",
        "/api/settings/ai",
        403,
        "viewer 不能保存设置",
        body={"agent": {"contextMaxChars": 20000}},
        csrf=True,
    )

    original_context = settings["values"]["agent"]["contextMaxChars"]
    target_context = 20000 if original_context != 20000 else 21000
    saved = expect(
        admin,
        "PUT",
        "/api/settings/ai",
        200,
        "保存在线设置",
        body={"agent": {"contextMaxChars": target_context}},
        csrf=True,
    )
    if not saved.get("saved"):
        fail("保存设置返回不正确：%s" % saved)

    refreshed = expect(admin, "GET", "/api/settings/ai", 200, "确认设置已热更新")
    if refreshed["values"]["agent"]["contextMaxChars"] != target_context:
        fail("设置未生效：%s" % refreshed["values"]["agent"])

    expect(
        admin,
        "PUT",
        "/api/settings/ai",
        400,
        "非法上下文上限被拒绝",
        body={"agent": {"contextMaxChars": 10}},
        csrf=True,
    )
    expect(
        admin,
        "PUT",
        "/api/settings/ai",
        200,
        "还原上下文上限",
        body={"agent": {"contextMaxChars": original_context}},
        csrf=True,
    )

    print("== LLM 接口格式与模型列表 ==")
    if settings["values"]["llm"].get("provider") not in ("openai_compatible", "anthropic"):
        fail("设置缺少 LLM provider：%s" % settings["values"]["llm"])
    original_provider = settings["values"]["llm"]["provider"]
    saved_provider = expect(
        admin,
        "PUT",
        "/api/settings/ai",
        200,
        "切换 Anthropic 接口格式",
        body={"llm": {"provider": "anthropic"}},
        csrf=True,
    )
    if not saved_provider.get("saved"):
        fail("切换接口格式返回不正确：%s" % saved_provider)
    provider_state = expect(admin, "GET", "/api/settings/ai", 200, "确认接口格式已保存")
    if provider_state["values"]["llm"]["provider"] != "anthropic":
        fail("接口格式未保存：%s" % provider_state["values"]["llm"])
    expect(
        admin,
        "PUT",
        "/api/settings/ai",
        400,
        "非法接口格式被拒绝",
        body={"llm": {"provider": "unknown"}},
        csrf=True,
    )
    expect(
        admin,
        "PUT",
        "/api/settings/ai",
        200,
        "还原接口格式",
        body={"llm": {"provider": original_provider}},
        csrf=True,
    )

    class ModelListHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            payload = json.dumps(
                {
                    "data": [
                        {"id": "mock-model-a", "name": "Mock A"},
                        {"id": "claude-mock", "display_name": "Claude Mock"},
                    ]
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            return

    model_server = http.server.HTTPServer(("127.0.0.1", 0), ModelListHandler)
    model_port = model_server.server_address[1]
    threading.Thread(target=model_server.serve_forever, daemon=True).start()
    try:
        openai_models = expect(
            admin,
            "POST",
            "/api/settings/llm/models",
            200,
            "拉取 OpenAI 兼容模型",
            body={
                "provider": "openai_compatible",
                "baseUrl": "http://127.0.0.1:%d" % model_port,
                "apiKey": "sk-test",
            },
            csrf=True,
        )
        openai_ids = [item["id"] for item in openai_models.get("models", [])]
        if not openai_models.get("success") or "mock-model-a" not in openai_ids:
            fail("OpenAI 模型列表不正确：%s" % openai_models)
        anthropic_models = expect(
            admin,
            "POST",
            "/api/settings/llm/models",
            200,
            "拉取 Anthropic 兼容模型",
            body={
                "provider": "anthropic",
                "baseUrl": "http://127.0.0.1:%d/v1" % model_port,
                "apiKey": "sk-ant-test",
            },
            csrf=True,
        )
        anthropic_ids = [item["id"] for item in anthropic_models.get("models", [])]
        if not anthropic_models.get("success") or "claude-mock" not in anthropic_ids:
            fail("Anthropic 模型列表不正确：%s" % anthropic_models)
        expect(
            admin,
            "POST",
            "/api/settings/llm/models",
            400,
            "拉取模型缺少地址被拒绝",
            body={"provider": "openai_compatible", "baseUrl": "", "apiKey": "sk-test"},
            csrf=True,
        )
        expect(
            viewer,
            "POST",
            "/api/settings/llm/models",
            403,
            "viewer 不能拉取模型",
            body={
                "provider": "openai_compatible",
                "baseUrl": "http://127.0.0.1:%d" % model_port,
                "apiKey": "sk-test",
            },
            csrf=True,
        )
    finally:
        model_server.shutdown()
        model_server.server_close()

    print("== 安全设置 ==")
    temp_password = "Smoke-pass-123"
    new_password = "Smoke-new-456!"
    expect(
        admin,
        "POST",
        "/api/rbac/users",
        201,
        "创建改密测试用户",
        body={
            "username": TMP_PASSWORD_USER,
            "displayName": "Smoke Password",
            "password": temp_password,
            "role": "viewer",
            "enabled": True,
        },
        csrf=True,
    )
    password_client = Client()
    expect(
        password_client,
        "POST",
        "/api/auth/login",
        200,
        "改密测试用户登录",
        body={"username": TMP_PASSWORD_USER, "password": temp_password},
    )
    expect(
        password_client,
        "POST",
        "/api/auth/password",
        400,
        "弱密码被拒绝",
        body={
            "currentPassword": temp_password,
            "newPassword": "abcdefghij",
            "confirmPassword": "abcdefghij",
        },
        csrf=True,
    )
    expect(
        password_client,
        "POST",
        "/api/auth/password",
        400,
        "两次输入不一致被拒绝",
        body={
            "currentPassword": temp_password,
            "newPassword": new_password,
            "confirmPassword": new_password + "x",
        },
        csrf=True,
    )
    expect(
        password_client,
        "POST",
        "/api/auth/password",
        400,
        "当前密码错误被拒绝",
        body={
            "currentPassword": "wrong-password-1A!",
            "newPassword": new_password,
            "confirmPassword": new_password,
        },
        csrf=True,
    )
    expect(
        password_client,
        "POST",
        "/api/auth/password",
        204,
        "修改密码成功",
        body={
            "currentPassword": temp_password,
            "newPassword": new_password,
            "confirmPassword": new_password,
        },
        csrf=True,
    )
    stale_client = Client()
    expect(
        stale_client,
        "POST",
        "/api/auth/login",
        401,
        "旧密码登录失败",
        body={"username": TMP_PASSWORD_USER, "password": temp_password},
    )
    fresh_client = Client()
    expect(
        fresh_client,
        "POST",
        "/api/auth/login",
        200,
        "新密码登录成功",
        body={"username": TMP_PASSWORD_USER, "password": new_password},
    )
    user_list = admin.request("GET", "/api/rbac/users")[1]
    password_target = next(
        item for item in user_list.get("items", []) if item["username"] == TMP_PASSWORD_USER
    )
    expect(
        admin,
        "DELETE",
        "/api/rbac/users/%s" % password_target["id"],
        204,
        "删除改密测试用户",
        csrf=True,
    )

    print("== 存储清理 ==")
    storage_config = expect(admin, "GET", "/api/settings/storage", 200, "读取存储清理配置")
    for field in ("autoClean", "intervalMinutes", "categories"):
        if field not in storage_config:
            fail("存储配置缺少字段 %s：%s" % (field, storage_config))
    if not storage_config["categories"]:
        fail("存储配置缺少清理类别")
    category_names = [item["name"] for item in storage_config["categories"]]
    for required in ("workspace", "reduction", "conversation_artifacts", "chat_uploads"):
        if required not in category_names:
            fail("存储配置缺少目录类别 %s：%s" % (required, category_names))
    dir_categories = [item for item in storage_config["categories"] if item.get("kind") == "dir"]
    if len(dir_categories) != 4:
        fail("目录类别数量不正确：%s" % storage_config["categories"])
    for item in dir_categories:
        if not item.get("path") or "files" not in item or "bytes" not in item:
            fail("目录类别缺少 path/files/bytes：%s" % item)
    if not storage_config.get("artifactRoot"):
        fail("存储配置缺少 artifactRoot")
    expect(
        admin,
        "PUT",
        "/api/settings/storage",
        400,
        "拒绝跳出根目录的路径",
        body={"categories": [{"name": "workspace", "path": "../escape"}]},
        csrf=True,
    )
    expect(viewer, "GET", "/api/settings/storage", 200, "viewer 可读取存储配置")
    expect(
        viewer,
        "POST",
        "/api/settings/storage/cleanup",
        403,
        "viewer 不能执行清理",
        body={"categories": ["audit_logs"]},
        csrf=True,
    )
    saved_storage = expect(
        admin,
        "PUT",
        "/api/settings/storage",
        200,
        "保存存储策略",
        body={
            "autoClean": storage_config["autoClean"],
            "intervalMinutes": storage_config["intervalMinutes"],
            "categories": [
                {
                    "name": item["name"],
                    "enabled": item["enabled"],
                    "retentionDays": item["retentionDays"],
                }
                for item in storage_config["categories"]
            ],
        },
        csrf=True,
    )
    if not saved_storage.get("saved"):
        fail("保存存储策略返回不正确：%s" % saved_storage)
    # 手动清理已改为忽略保留期；冒烟用不存在的类别名验证接口契约，避免清空真实审计数据。
    cleanup = expect(
        admin,
        "POST",
        "/api/settings/storage/cleanup",
        200,
        "执行存储清理",
        body={"categories": ["__smoke_noop__"]},
        csrf=True,
    )
    if "deleted" not in cleanup or "total" not in cleanup:
        fail("清理返回结构不正确：%s" % cleanup)
    if cleanup.get("total") != 0:
        fail("未知类别不应删除数据：%s" % cleanup)

    print("== 系统指标 ==")
    system_stats = expect(admin, "GET", "/api/system/stats", 200, "读取系统指标")
    if not system_stats.get("hostname"):
        fail("系统指标缺少 hostname：%s" % system_stats)
    for field in ("memoryPercent", "cpuPercent"):
        value = system_stats.get(field, 0)
        if value < 0 or value > 100:
            fail("%s 越界：%s" % (field, system_stats))
    expect(viewer, "GET", "/api/system/stats", 200, "viewer 可读取系统指标")
    unauth_client = Client()
    expect(unauth_client, "GET", "/api/system/stats", 401, "未登录不能读取系统指标")

    print("== 审计日志分页 ==")
    default_page = expect(admin, "GET", "/api/audit/logs", 200, "默认分页查询审计日志")
    if default_page.get("pageSize") != 50:
        fail("默认每页条数应为 50：%s" % default_page)
    if len(default_page.get("items", [])) > 50:
        fail("默认分页返回条数超限：%d" % len(default_page["items"]))
    total_audits = default_page.get("total", 0)
    expected_pages = max(1, (total_audits + 49) // 50)
    if default_page.get("totalPages") != expected_pages:
        fail("totalPages 计算不正确：%s" % default_page)
    for size in (100, 500, 1000):
        page = expect(
            admin,
            "GET",
            "/api/audit/logs?limit=%d" % size,
            200,
            "每页 %d 条" % size,
        )
        if page.get("pageSize") != size:
            fail("limit=%d 未生效：%s" % (size, page))
        if len(page.get("items", [])) > size:
            fail("limit=%d 返回超量" % size)
    fallback_page = expect(
        admin,
        "GET",
        "/api/audit/logs?limit=999",
        200,
        "非法每页条数回退 50",
    )
    if fallback_page.get("pageSize") != 50:
        fail("非法 limit 应回退 50：%s" % fallback_page)
    failures = expect(
        admin,
        "GET",
        "/api/audit/logs?result=failure&limit=50",
        200,
        "按结果筛选审计日志",
    )
    if failures.get("total", 0) > total_audits:
        fail("筛选后总数不应增加：%s" % failures)
    if any(item.get("result") == "success" for item in failures.get("items", [])):
        fail("失败筛选返回了成功记录")
    if total_audits > 50:
        first_page = expect(
            admin,
            "GET",
            "/api/audit/logs?limit=50&offset=0",
            200,
            "审计日志第一页",
        )
        second_page = expect(
            admin,
            "GET",
            "/api/audit/logs?limit=50&offset=50",
            200,
            "审计日志第二页",
        )
        first_ids = {item["id"] for item in first_page.get("items", [])}
        second_ids = {item["id"] for item in second_page.get("items", [])}
        if first_ids & second_ids:
            fail("分页出现重复记录")
        if second_page.get("page") != 2:
            fail("第二页页码不正确：%s" % second_page)

    print("== 自锁保护 ==")
    expect(
        admin,
        "PUT",
        "/api/rbac/users/%s" % admin_user_id,
        400,
        "管理员不能禁用自己",
        body={
            "username": ADMIN_USER,
            "displayName": "",
            "password": "",
            "role": "admin",
            "enabled": False,
        },
        csrf=True,
    )
    expect(
        admin,
        "PUT",
        "/api/rbac/users/%s" % admin_user_id,
        400,
        "管理员不能降级自己",
        body={
            "username": ADMIN_USER,
            "displayName": "",
            "password": "",
            "role": "viewer",
            "enabled": True,
        },
        csrf=True,
    )
    expect(
        admin,
        "DELETE",
        "/api/rbac/users/%s" % admin_user_id,
        400,
        "管理员不能删除自己",
        csrf=True,
    )

    print("== 最后一个管理员保护 ==")
    expect(
        admin,
        "POST",
        "/api/rbac/roles",
        201,
        "创建含 rbac:write 的自定义角色",
        body={
            "name": TMP_ROLE,
            "description": "smoke",
            "permissions": ["rbac:read", "rbac:write"],
        },
        csrf=True,
    )
    expect(
        admin,
        "POST",
        "/api/rbac/users",
        201,
        "创建自定义角色用户",
        body={
            "username": TMP_MANAGER,
            "displayName": "Smoke Manager",
            "password": TMP_PASS,
            "role": TMP_ROLE,
            "enabled": True,
        },
        csrf=True,
    )
    manager = Client()
    expect(
        manager,
        "POST",
        "/api/auth/login",
        200,
        "自定义角色用户登录",
        body={"username": TMP_MANAGER, "password": TMP_PASS},
    )
    expect(
        manager,
        "PUT",
        "/api/rbac/users/%s" % admin_user_id,
        400,
        "非管理员不能禁用最后一个管理员",
        body={
            "username": ADMIN_USER,
            "displayName": "",
            "password": "",
            "role": "admin",
            "enabled": False,
        },
        csrf=True,
    )

    print("== 路由权限映射 ==")
    for path in (
        "/api/auth/me",
        "/api/rbac/me",
        "/api/conversations",
        "/api/tasks/not-exist",
        "/api/audit/logs",
        "/api/monitor/executions",
        "/api/hitl/pending",
        "/api/projects",
        "/api/assets",
        "/api/vulnerabilities",
        "/api/vulnerabilities/stats",
        "/api/knowledge/items",
        "/api/webshell/connections",
        "/api/skills",
        "/api/settings/ai",
        "/api/admin/ping",
    ):
        status, payload = admin.request("GET", path)
        if status == 403:
            fail("管理员访问 %s 被拒绝：%s" % (path, payload))
        print("ok  admin GET %s (%s)" % (path, status))

    print("== 项目 CRUD ==")
    project = expect(
        admin,
        "POST",
        "/api/projects",
        201,
        "创建项目",
        body={"name": "smoke-project", "description": "created by smoke test"},
        csrf=True,
    )
    project_id = project["id"]
    expect(
        admin,
        "PUT",
        "/api/projects/%s" % project_id,
        204,
        "重命名项目",
        body={"name": "smoke-project-renamed", "description": "updated"},
        csrf=True,
    )
    renamed = expect(admin, "GET", "/api/projects/%s" % project_id, 200, "读取项目")
    if renamed.get("name") != "smoke-project-renamed":
        fail("项目更新未生效：%s" % renamed)

    fact = expect(
        admin,
        "POST",
        "/api/projects/%s/facts" % project_id,
        200,
        "创建项目事实",
        body={
            "factType": "general",
            "key": "smoke-key",
            "value": "v1",
            "confidence": 90,
        },
        csrf=True,
    )
    fact_again = expect(
        admin,
        "POST",
        "/api/projects/%s/facts" % project_id,
        200,
        "重复写入项目事实",
        body={
            "factType": "general",
            "key": "smoke-key",
            "value": "v2",
            "confidence": 90,
        },
        csrf=True,
    )
    if fact["id"] != fact_again["id"]:
        fail("项目事实 upsert 返回了不同的 id：%s vs %s" % (fact["id"], fact_again["id"]))
    print("ok  项目事实 upsert id 保持一致")
    expect(
        admin,
        "PUT",
        "/api/projects/%s/facts/%s" % (project_id, fact["id"]),
        204,
        "更新项目事实",
        body={"factType": "general", "value": "v3", "confidence": 80},
        csrf=True,
    )
    expect(
        admin,
        "DELETE",
        "/api/projects/%s/facts/%s" % (project_id, fact["id"]),
        204,
        "删除项目事实",
        csrf=True,
    )

    expect(
        admin,
        "DELETE",
        "/api/projects/%s" % project_id,
        204,
        "删除项目",
        csrf=True,
    )
    expect(
        admin,
        "GET",
        "/api/projects/%s" % project_id,
        404,
        "删除后读取返回 404",
    )

    print("== 漏洞与知识 CRUD ==")
    vulnerability = expect(
        admin,
        "POST",
        "/api/vulnerabilities",
        201,
        "创建漏洞",
        body={"title": "smoke-vuln", "severity": "low", "description": "", "evidence": ""},
        csrf=True,
    )
    expect(
        admin,
        "PUT",
        "/api/vulnerabilities/%s" % vulnerability["id"],
        204,
        "更新漏洞状态",
        body={
            "title": "smoke-vuln",
            "severity": "low",
            "status": "fixed",
            "description": "",
            "evidence": "",
        },
        csrf=True,
    )
    expect(
        admin,
        "DELETE",
        "/api/vulnerabilities/%s" % vulnerability["id"],
        204,
        "删除漏洞",
        csrf=True,
    )

    knowledge = expect(
        admin,
        "POST",
        "/api/knowledge/items",
        201,
        "创建知识",
        body={"category": "smoke", "title": "smoke-knowledge", "content": "smoke content"},
        csrf=True,
    )
    expect(
        admin,
        "PUT",
        "/api/knowledge/items/%s" % knowledge["id"],
        204,
        "更新知识",
        body={
            "category": "smoke",
            "title": "smoke-knowledge-2",
            "content": "smoke content updated",
        },
        csrf=True,
    )
    expect(
        admin,
        "DELETE",
        "/api/knowledge/items/%s" % knowledge["id"],
        204,
        "删除知识",
        csrf=True,
    )

    print("== 清理 ==")
    users = admin.request("GET", "/api/rbac/users")[1]
    target = next(
        (item for item in users.get("items", []) if item["username"] == TMP_USER), None
    )
    if target is None:
        fail("未找到测试用户 %s" % TMP_USER)
    expect(
        admin,
        "DELETE",
        "/api/rbac/users/%s" % target["id"],
        204,
        "删除测试用户",
        csrf=True,
    )

    users = admin.request("GET", "/api/rbac/users")[1]
    manager_target = next(
        item for item in users.get("items", []) if item["username"] == TMP_MANAGER
    )
    expect(
        admin,
        "DELETE",
        "/api/rbac/users/%s" % manager_target["id"],
        204,
        "删除自定义角色用户",
        csrf=True,
    )
    expect(
        admin,
        "DELETE",
        "/api/rbac/roles/%s" % TMP_ROLE,
        204,
        "删除自定义角色",
        csrf=True,
    )

    print("== 落盘加固 ==")
    database_path = os.environ.get("SOPHON_DB_PATH", "/opt/sophon/data/sophon.db")
    if os.path.exists(database_path):
        mode = stat.S_IMODE(os.stat(database_path).st_mode)
        if mode != 0o600:
            fail("数据库文件权限应为 0600，实际 %s" % oct(mode))
        print("ok  数据库文件权限为 0600")
        for suffix in ("-wal", "-shm"):
            candidate = database_path + suffix
            if not os.path.exists(candidate):
                continue
            mode = stat.S_IMODE(os.stat(candidate).st_mode)
            if mode != 0o600:
                fail("数据库 %s 权限应为 0600，实际 %s" % (suffix, oct(mode)))
        print("ok  数据库 WAL/SHM 权限已收紧")
    else:
        print("ok  跳过数据库权限检查（未找到 %s）" % database_path)

    print("== 审计增强 ==")
    audit_project = expect(
        admin,
        "POST",
        "/api/projects",
        201,
        "创建审计测试项目",
        body={"name": "smoke-audit-target", "status": "active"},
        csrf=True,
    )
    expect(
        admin,
        "DELETE",
        "/api/projects/%s" % audit_project["id"],
        204,
        "删除审计测试项目",
        csrf=True,
    )
    time.sleep(0.3)
    delete_audit = expect(
        admin,
        "GET",
        "/api/audit/logs?search=%s&limit=50"
        % urllib.parse.quote("DELETE /api/projects"),
        200,
        "查询删除操作审计",
    )
    matched = next(
        (
            item
            for item in delete_audit.get("items", [])
            if item.get("resourceId") == audit_project["id"]
        ),
        None,
    )
    if matched is None:
        fail(
            "审计未记录真实对象 ID：%s"
            % [item.get("resourceId") for item in delete_audit.get("items", [])[:5]]
        )
    print("ok  审计记录包含真实对象 ID")

    create_audit = expect(
        admin,
        "GET",
        "/api/audit/logs?search=%s&limit=50" % urllib.parse.quote("POST /api/projects"),
        200,
        "查询创建操作审计",
    )
    created_entry = next(
        (
            item
            for item in create_audit.get("items", [])
            if "smoke-audit-target" in (item.get("detail") or "")
        ),
        None,
    )
    if created_entry is None:
        fail("审计未记录创建请求摘要：%s" % create_audit.get("items", [])[:2])
    if "body=" not in (created_entry.get("detail") or ""):
        fail("审计摘要缺少请求体：%s" % created_entry)
    print("ok  审计记录包含请求体摘要")

    create_user_audit = expect(
        admin,
        "GET",
        "/api/audit/logs?search=%s&limit=50" % urllib.parse.quote("POST /api/rbac/users"),
        200,
        "查询用户创建审计",
    )
    user_detail = " ".join(item.get("detail", "") for item in create_user_audit.get("items", []))
    if TMP_PASS in user_detail:
        fail("审计日志泄露了明文口令")
    if "***" not in user_detail:
        fail("审计日志未对敏感字段脱敏：%s" % user_detail[:200])
    print("ok  审计摘要已脱敏敏感字段")

    all_audit = expect(
        admin,
        "GET",
        "/api/audit/logs?scope=all&limit=50",
        200,
        "管理员查看全部审计日志",
    )
    if all_audit.get("total", 0) < 1:
        fail("全局审计视图为空：%s" % all_audit)
    scope_guard_user = "smoke_audit_%d" % int(time.time())
    expect(
        admin,
        "POST",
        "/api/rbac/users",
        201,
        "创建审计权限测试用户",
        body={
            "username": scope_guard_user,
            "displayName": "",
            "password": TMP_PASS,
            "role": "viewer",
            "enabled": True,
        },
        csrf=True,
    )
    scope_guard_client = Client()
    expect(
        scope_guard_client,
        "POST",
        "/api/auth/login",
        200,
        "审计权限测试用户登录",
        body={"username": scope_guard_user, "password": TMP_PASS},
    )
    expect(
        scope_guard_client,
        "GET",
        "/api/audit/logs?scope=all",
        403,
        "非管理员不能查看全部审计日志",
    )
    guard_users = admin.request("GET", "/api/rbac/users")[1]
    guard_target = next(
        item for item in guard_users.get("items", []) if item["username"] == scope_guard_user
    )
    expect(
        admin,
        "DELETE",
        "/api/rbac/users/%s" % guard_target["id"],
        204,
        "清理审计权限测试用户",
        csrf=True,
    )

    print("== 登录限流 ==")
    lock_username = "smoke_lockout_%d" % int(time.time())
    lock_client = Client()
    for _ in range(5):
        status, _ = lock_client.request(
            "POST",
            "/api/auth/login",
            body={"username": lock_username, "password": "wrong-password"},
        )
        if status != 401:
            fail("错误密码应返回 401，实际 %s" % status)
    print("ok  连续 5 次错误密码均返回 401")
    status, blocked = lock_client.request(
        "POST",
        "/api/auth/login",
        body={"username": lock_username, "password": "wrong-password"},
    )
    if status != 429:
        fail("超过失败阈值应返回 429，实际 %s %s" % (status, blocked))
    if blocked.get("code") != "too_many_attempts":
        fail("限流返回结构不正确：%s" % blocked)
    if int(blocked.get("retryAfterSeconds", 0)) <= 0:
        fail("限流缺少 retryAfterSeconds：%s" % blocked)
    print("ok  第 6 次登录被限流 (429)")
    unlocked_client = Client()
    expect(
        unlocked_client,
        "POST",
        "/api/auth/login",
        200,
        "限流后其他账号仍可正常登录",
        body={"username": ADMIN_USER, "password": ADMIN_PASS},
    )

    print("SMOKE OK")


if __name__ == "__main__":
    main()
