#!/usr/bin/env sh
set -eu

if [ -f /tmp/sophon-backend.pid ]; then
    pid="$(cat /tmp/sophon-backend.pid)"
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" 2>/dev/null || true
        i=0
        while [ "${i}" -lt 650 ]; do
            kill -0 "${pid}" 2>/dev/null || break
            state="$(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true)"
            [ "${state}" = "Z" ] && break
            sleep 0.1
            i=$((i + 1))
        done
        state="$(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true)"
        if kill -0 "${pid}" 2>/dev/null && [ "${state}" != "Z" ]; then
            kill -9 "${pid}" 2>/dev/null || true
        fi
    fi
    rm -f /tmp/sophon-backend.pid
fi

if [ -f /tmp/sophon-nginx.pid ]; then
    nginx -s quit -c "${SOPHON_APP_ROOT:-/opt/sophon}/deploy/nginx/nginx.conf" 2>/dev/null || true
fi

echo "Sophon stopped"
