#!/usr/bin/env sh
set -eu

# 新建文件默认仅属主可读写（日志等运行产物同样收紧）
umask 077

APP_ROOT="${SOPHON_APP_ROOT:-/opt/sophon}"
BACKEND_BIN="${APP_ROOT}/backend/sophon-server"
BACKEND_PID_FILE="/tmp/sophon-backend.pid"
NGINX_CONF="${APP_ROOT}/deploy/nginx/nginx.conf"

mkdir -p /tmp/sophon

if [ -f "${BACKEND_PID_FILE}" ]; then
    old_pid="$(cat "${BACKEND_PID_FILE}")"
    if [ -n "${old_pid}" ] && kill -0 "${old_pid}" 2>/dev/null; then
        kill "${old_pid}" 2>/dev/null || true
        i=0
        while [ "${i}" -lt 650 ]; do
            kill -0 "${old_pid}" 2>/dev/null || break
            state="$(awk '{print $3}' "/proc/${old_pid}/stat" 2>/dev/null || true)"
            [ "${state}" = "Z" ] && break
            sleep 0.1
            i=$((i + 1))
        done
        state="$(awk '{print $3}' "/proc/${old_pid}/stat" 2>/dev/null || true)"
        if kill -0 "${old_pid}" 2>/dev/null && [ "${state}" != "Z" ]; then
            kill -9 "${old_pid}" 2>/dev/null || true
        fi
    fi
fi

if [ -f /tmp/sophon-nginx.pid ]; then
    old_nginx_pid="$(cat /tmp/sophon-nginx.pid)"
    if [ -n "${old_nginx_pid}" ] && kill -0 "${old_nginx_pid}" 2>/dev/null; then
        kill "${old_nginx_pid}" 2>/dev/null || true
        sleep 1
    fi
fi

if [ -x "${APP_ROOT}/deploy/container/set-tool-caps.sh" ]; then
    "${APP_ROOT}/deploy/container/set-tool-caps.sh" || true
elif [ -f "${APP_ROOT}/deploy/container/set-tool-caps.sh" ]; then
    sh "${APP_ROOT}/deploy/container/set-tool-caps.sh" || true
fi

SOPHON_HOST=127.0.0.1 \
SOPHON_PORT=18080 \
SOPHON_DATA_DIR="${APP_ROOT}/data" \
SOPHON_CONFIG="${SOPHON_CONFIG:-${APP_ROOT}/config.yml}" \
SOPHON_VERSION="${SOPHON_VERSION:-}" \
SOPHON_MCP_COMMAND="${SOPHON_MCP_COMMAND:-${APP_ROOT}/backend/sophon-mcp-tools}" \
touch /tmp/sophon/backend.log 2>/dev/null || true
chmod 600 /tmp/sophon/backend.log 2>/dev/null || true
nohup "${BACKEND_BIN}" >/tmp/sophon/backend.log 2>&1 &
echo "$!" >"${BACKEND_PID_FILE}"

nginx -t -c "${NGINX_CONF}"
nginx -c "${NGINX_CONF}" -g 'daemon on;'

echo "Sophon started"
echo "Frontend: http://127.0.0.1:8080/"
echo "Backend:  http://127.0.0.1:18080/api/health"
