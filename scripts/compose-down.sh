#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
DEPLOY_DIR="${SCRIPT_DIR}/../deploy"

cd "${DEPLOY_DIR}"
docker compose down

echo "Sophon 容器已停止，数据卷 sophon-data 保留。"
