#!/usr/bin/env sh
set -eu

# 在运行 Sophon 的容器内执行：
#   SOPHON_ADMIN_PASSWORD=... /opt/sophon/scripts/smoke-rbac.sh

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

# 容器内可能只有 python3，没有 curl，此时交给 Python 版本执行。
if ! command -v curl >/dev/null 2>&1; then
    exec python3 "${SCRIPT_DIR}/smoke-rbac.py" "$@"
fi

BASE_URL="${SOPHON_BASE_URL:-http://127.0.0.1:8080}"
ADMIN_USER="${SOPHON_ADMIN_USERNAME:-admin}"
ADMIN_PASS="${SOPHON_ADMIN_PASSWORD:-sophon-test-password}"
TMP_USER="smoke_$(date +%s)"
TMP_PASS="smoke-password-123"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT
ADMIN_JAR="${WORK_DIR}/admin.cookies"
USER_JAR="${WORK_DIR}/user.cookies"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

csrf() {
    awk '$6 == "sophon_csrf" {print $7}' "$1"
}

status() {
    jar="$1"
    shift
    curl -s -o /dev/null -w '%{http_code}' -b "${jar}" -c "${jar}" "$@"
}

expect_status() {
    expected="$1"
    label="$2"
    jar="$3"
    shift 3
    actual="$(status "${jar}" "$@")"
    if [ "${actual}" != "${expected}" ]; then
        fail "${label}: 期望 ${expected}，实际 ${actual}"
    fi
    echo "ok  ${label} (${actual})"
}

echo "== 管理员登录 =="
expect_status 200 "admin login" "${ADMIN_JAR}" \
    -X POST "${BASE_URL}/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}"

permissions="$(curl -s -b "${ADMIN_JAR}" -c "${ADMIN_JAR}" "${BASE_URL}/api/rbac/me")"
echo "${permissions}" | python3 -c 'import json,sys; data=json.load(sys.stdin); assert "*" in data["permissions"], data' \
    || fail "admin 权限应包含 *"
echo "ok  admin 权限为通配"

echo "== 创建 viewer 用户 =="
expect_status 201 "create viewer user" "${ADMIN_JAR}" \
    -X POST "${BASE_URL}/api/rbac/users" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $(csrf "${ADMIN_JAR}")" \
    -d "{\"username\":\"${TMP_USER}\",\"displayName\":\"Smoke\",\"password\":\"${TMP_PASS}\",\"role\":\"viewer\",\"enabled\":true}"

expect_status 200 "viewer login" "${USER_JAR}" \
    -X POST "${BASE_URL}/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"${TMP_USER}\",\"password\":\"${TMP_PASS}\"}"

viewer_permissions="$(curl -s -b "${USER_JAR}" -c "${USER_JAR}" "${BASE_URL}/api/rbac/me")"
echo "${viewer_permissions}" | python3 -c '
import json, sys
data = json.load(sys.stdin)
permissions = data["permissions"]
assert "project:read" in permissions, permissions
assert "project:write" not in permissions, permissions
assert "rbac:read" not in permissions, permissions
' || fail "viewer 权限不正确"
echo "ok  viewer 只读权限"

echo "== 权限拦截 =="
expect_status 403 "viewer 创建项目被拒绝" "${USER_JAR}" \
    -X POST "${BASE_URL}/api/projects" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $(csrf "${USER_JAR}")" \
    -d '{"name":"should-not-exist","description":""}'

expect_status 403 "viewer 读取用户列表被拒绝" "${USER_JAR}" "${BASE_URL}/api/rbac/users"

echo "== 项目 CRUD =="
project="$(curl -s -b "${ADMIN_JAR}" -c "${ADMIN_JAR}" \
    -X POST "${BASE_URL}/api/projects" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $(csrf "${ADMIN_JAR}")" \
    -d '{"name":"smoke-project","description":"created by smoke test"}')"
project_id="$(echo "${project}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
echo "ok  创建项目 ${project_id}"

expect_status 204 "更新项目" "${ADMIN_JAR}" \
    -X PUT "${BASE_URL}/api/projects/${project_id}" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $(csrf "${ADMIN_JAR}")" \
    -d '{"name":"smoke-project-renamed","description":"updated"}'

renamed="$(curl -s -b "${ADMIN_JAR}" -c "${ADMIN_JAR}" "${BASE_URL}/api/projects/${project_id}")"
echo "${renamed}" | python3 -c 'import json,sys; data=json.load(sys.stdin); assert data["name"] == "smoke-project-renamed", data' \
    || fail "项目更新未生效"
echo "ok  项目更新已生效"

expect_status 204 "删除项目" "${ADMIN_JAR}" \
    -X DELETE "${BASE_URL}/api/projects/${project_id}" \
    -H "X-CSRF-Token: $(csrf "${ADMIN_JAR}")"

expect_status 404 "删除后读取返回 404" "${ADMIN_JAR}" "${BASE_URL}/api/projects/${project_id}"

echo "== 漏洞与知识 CRUD =="
vulnerability="$(curl -s -b "${ADMIN_JAR}" -c "${ADMIN_JAR}" \
    -X POST "${BASE_URL}/api/vulnerabilities" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $(csrf "${ADMIN_JAR}")" \
    -d '{"title":"smoke-vuln","severity":"low","description":"","evidence":""}')"
vulnerability_id="$(echo "${vulnerability}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

expect_status 204 "更新漏洞状态" "${ADMIN_JAR}" \
    -X PUT "${BASE_URL}/api/vulnerabilities/${vulnerability_id}" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $(csrf "${ADMIN_JAR}")" \
    -d '{"title":"smoke-vuln","severity":"low","status":"fixed","description":"","evidence":""}'

expect_status 204 "删除漏洞" "${ADMIN_JAR}" \
    -X DELETE "${BASE_URL}/api/vulnerabilities/${vulnerability_id}" \
    -H "X-CSRF-Token: $(csrf "${ADMIN_JAR}")"

knowledge="$(curl -s -b "${ADMIN_JAR}" -c "${ADMIN_JAR}" \
    -X POST "${BASE_URL}/api/knowledge/items" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $(csrf "${ADMIN_JAR}")" \
    -d '{"category":"smoke","title":"smoke-knowledge","content":"smoke content"}')"
knowledge_id="$(echo "${knowledge}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

expect_status 204 "更新知识" "${ADMIN_JAR}" \
    -X PUT "${BASE_URL}/api/knowledge/items/${knowledge_id}" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $(csrf "${ADMIN_JAR}")" \
    -d '{"category":"smoke","title":"smoke-knowledge-2","content":"smoke content updated"}'

expect_status 204 "删除知识" "${ADMIN_JAR}" \
    -X DELETE "${BASE_URL}/api/knowledge/items/${knowledge_id}" \
    -H "X-CSRF-Token: $(csrf "${ADMIN_JAR}")"

echo "== 清理 =="
users="$(curl -s -b "${ADMIN_JAR}" -c "${ADMIN_JAR}" "${BASE_URL}/api/rbac/users")"
tmp_user_id="$(echo "${users}" | TMP_USER="${TMP_USER}" python3 -c '
import json, os, sys
target = os.environ["TMP_USER"]
items = json.load(sys.stdin)["items"]
print(next(item["id"] for item in items if item["username"] == target))
')"

expect_status 204 "删除测试用户" "${ADMIN_JAR}" \
    -X DELETE "${BASE_URL}/api/rbac/users/${tmp_user_id}" \
    -H "X-CSRF-Token: $(csrf "${ADMIN_JAR}")"

echo "SMOKE OK"
