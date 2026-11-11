#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
DEPLOY_DIR="${SCRIPT_DIR}/../deploy"

if [ ! -f "${DEPLOY_DIR}/.env" ]; then
    echo "缺少 ${DEPLOY_DIR}/.env" >&2
    echo "请先执行：cp ${DEPLOY_DIR}/.env.example ${DEPLOY_DIR}/.env，并修改其中的管理员密码" >&2
    exit 1
fi

CONFIG_FILE="${DEPLOY_DIR}/../config.yml"
CONFIG_EXAMPLE="${DEPLOY_DIR}/../config.example.yml"

if [ ! -f "${CONFIG_FILE}" ]; then
    if [ ! -f "${CONFIG_EXAMPLE}" ]; then
        echo "缺少配置文件 ${CONFIG_FILE}，且未找到模板 ${CONFIG_EXAMPLE}" >&2
        exit 1
    fi
    cp "${CONFIG_EXAMPLE}" "${CONFIG_FILE}"
    echo "已根据模板生成 ${CONFIG_FILE}，模型、Embedding 与 HITL 配置都在这里修改。"
fi

cd "${DEPLOY_DIR}"
docker compose up -d --build
docker compose ps

port="$(grep -E '^SOPHON_HTTP_PORT=' .env | tail -n 1 | cut -d '=' -f 2 || true)"
if [ -z "${port}" ]; then
    port=8080
fi

echo "Sophon 已启动：http://127.0.0.1:${port}/"
