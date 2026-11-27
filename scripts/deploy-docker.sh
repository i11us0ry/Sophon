#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

CONTAINER="${SOPHON_CONTAINER:-sophon-2}"
APP_ROOT="${SOPHON_APP_ROOT:-/opt/sophon}"
HOST_URL="${SOPHON_HOST_URL:-http://127.0.0.1:8081}"
GO_CACHE="${SOPHON_GO_CACHE:-/tmp/sophon-go-cache}"
NODE_IMAGE="${SOPHON_NODE_IMAGE:-node:20-bookworm-slim}"
NPM_REGISTRIES="${SOPHON_NPM_REGISTRIES:-https://registry.npmmirror.com,https://registry.npmjs.org}"
TARGET="${1:-all}"
STAMP="$(date +%Y%m%d-%H%M%S)"

BACKEND_TAR="/tmp/sophon-backend-${STAMP}.tgz"
BACKEND_BIN="/tmp/sophon-server-${STAMP}"
SUPERVISOR_BIN="/tmp/sophon-process-supervisor-${STAMP}"
TOOL_RUNNER_BIN="/tmp/sophon-tool-runner-${STAMP}"
FRONTEND_DIST="/tmp/sophon-frontend-dist-${STAMP}"
TOOLS_TAR="/tmp/sophon-tools-${STAMP}.tgz"

info() { printf '[*] %s\n' "$*"; }
ok() { printf '[+] %s\n' "$*"; }
die() { printf '[x] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法:
  ./scripts/deploy-docker.sh [all|backend|frontend]

默认:
  all      构建并部署后端和前端
  backend  只构建并部署后端
  frontend 只构建并部署前端

环境变量:
  SOPHON_CONTAINER  容器名称，默认 sophon-2
  SOPHON_APP_ROOT   容器内安装目录，默认 /opt/sophon
  SOPHON_HOST_URL   前端检查地址，默认 http://127.0.0.1:8081
  SOPHON_GO_CACHE   容器内 Go 缓存目录，默认 /tmp/sophon-go-cache
  SOPHON_NODE_IMAGE 前端构建镜像，默认 node:20-bookworm-slim
  SOPHON_NPM_REGISTRIES 前端构建 registry 列表，逗号分隔
EOF
}

case "$TARGET" in
  all|backend|frontend) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    die "未知部署目标: ${TARGET}"
    ;;
esac

command -v docker >/dev/null 2>&1 || die "缺少 docker 命令"
command -v tar >/dev/null 2>&1 || die "缺少 tar 命令"
command -v curl >/dev/null 2>&1 || die "缺少 curl 命令"
docker inspect "$CONTAINER" >/dev/null 2>&1 || die "容器不存在或不可访问: ${CONTAINER}"

build_backend() {
  info "打包后端源码"
  COPYFILE_DISABLE=1 tar \
    -C "$ROOT_DIR" \
    -czf "$BACKEND_TAR" \
    --exclude='backend/server' \
    --exclude='backend/.DS_Store' \
    --exclude='*.bak.*' \
    backend

  docker cp "$BACKEND_TAR" "${CONTAINER}:/tmp/"

  info "在容器内构建后端"
  docker exec "$CONTAINER" env \
    BUILD_DIR="/tmp/sophon-build-${STAMP}" \
    TAR_PATH="/tmp/$(basename "$BACKEND_TAR")" \
    BIN_PATH="$BACKEND_BIN" \
    SUPERVISOR_BIN="$SUPERVISOR_BIN" \
    TOOL_RUNNER_BIN="$TOOL_RUNNER_BIN" \
    GO_CACHE="$GO_CACHE" \
    sh -lc '
      set -eu
      mkdir -p "$BUILD_DIR"
      tar -xzf "$TAR_PATH" -C "$BUILD_DIR"
      cd "$BUILD_DIR/backend"
      CGO_ENABLED=1 GOCACHE="$GO_CACHE" \
        go build -trimpath -o "$BIN_PATH" ./cmd/server
      CGO_ENABLED=1 GOCACHE="$GO_CACHE" \
        go build -trimpath -o "$SUPERVISOR_BIN" ./cmd/process-supervisor
      CGO_ENABLED=1 GOCACHE="$GO_CACHE" \
        go build -trimpath -o "$TOOL_RUNNER_BIN" ./cmd/tool-runner
      test -x "$BIN_PATH"
      test -x "$SUPERVISOR_BIN"
      test -x "$TOOL_RUNNER_BIN"
    '
  ok "后端构建完成: ${BACKEND_BIN}, ${SUPERVISOR_BIN}, ${TOOL_RUNNER_BIN}"
}

build_frontend() {
  local build_script
  docker image inspect "$NODE_IMAGE" >/dev/null 2>&1 ||
    die "缺少前端构建镜像: ${NODE_IMAGE}"
  mkdir -p "$FRONTEND_DIST"
  build_script='
set -eu
mkdir -p /work /out
tar -C /src --exclude=node_modules --exclude=dist -cf /tmp/sophon-frontend.tar .
tar -C /work -xf /tmp/sophon-frontend.tar
cd /work
old_ifs=$IFS
IFS=,
for registry in $SOPHON_NPM_REGISTRIES; do
  IFS=$old_ifs
  echo "[*] npm registry: $registry"
  if npm_config_registry="$registry" npx --yes pnpm@9.15.9 install --frozen-lockfile && \
     npm_config_registry="$registry" npx --yes pnpm@9.15.9 run build; then
    cp -a dist/. /out/
    exit 0
  fi
  IFS=,
done
exit 1
'
  info "使用 Docker 构建前端: ${NODE_IMAGE}"
  docker run --rm \
    -e "SOPHON_NPM_REGISTRIES=${NPM_REGISTRIES}" \
    -v "${ROOT_DIR}/frontend:/src:ro" \
    -v "${FRONTEND_DIST}:/out" \
    --entrypoint /bin/sh \
    "$NODE_IMAGE" \
    -lc "$build_script"
  [[ -f "${FRONTEND_DIST}/index.html" ]] || die "前端构建产物缺少 index.html"
  ok "前端构建完成"
}

deploy_backend() {
  info "备份并替换后端二进制"
  docker exec "$CONTAINER" env \
    APP_ROOT="$APP_ROOT" \
    BIN_PATH="$BACKEND_BIN" \
    SUPERVISOR_BIN="$SUPERVISOR_BIN" \
    TOOL_RUNNER_BIN="$TOOL_RUNNER_BIN" \
    STAMP="$STAMP" \
    sh -lc '
      set -eu
      test -x "$BIN_PATH"
      test -x "$SUPERVISOR_BIN"
      test -x "$TOOL_RUNNER_BIN"
      cd "$APP_ROOT/backend"
      BACKUP="sophon-server.bak.${STAMP}"
      SUPERVISOR_BACKUP="sophon-process-supervisor.bak.${STAMP}"
      TOOL_RUNNER_BACKUP="sophon-tool-runner.bak.${STAMP}"
      cp -p sophon-server "$BACKUP"
      if [ -f sophon-process-supervisor ]; then
        cp -p sophon-process-supervisor "$SUPERVISOR_BACKUP"
      fi
      cp -p sophon-tool-runner "$TOOL_RUNNER_BACKUP"
      install -m 0755 "$BIN_PATH" sophon-server.new
      install -m 0755 "$SUPERVISOR_BIN" sophon-process-supervisor.new
      install -m 0755 "$TOOL_RUNNER_BIN" sophon-tool-runner.new
      mv sophon-server.new sophon-server
      mv sophon-process-supervisor.new sophon-process-supervisor
      mv sophon-tool-runner.new sophon-tool-runner
      printf "后端备份: %s, %s, %s\n" "$BACKUP" "$SUPERVISOR_BACKUP" "$TOOL_RUNNER_BACKUP"
    '
}

deploy_frontend() {
  info "备份并替换前端资源"
  docker exec "$CONTAINER" env \
    APP_ROOT="$APP_ROOT" \
    STAMP="$STAMP" \
    sh -lc '
      set -eu
      mkdir -p "$APP_ROOT/frontend/dist"
      if [ -f "$APP_ROOT/frontend/dist/index.html" ]; then
        cp -p "$APP_ROOT/frontend/dist/index.html" \
          "$APP_ROOT/frontend/dist/index.html.bak.${STAMP}"
        printf "前端备份: %s\n" "index.html.bak.${STAMP}"
      fi
    '

  docker cp \
    "${FRONTEND_DIST}/." \
    "${CONTAINER}:${APP_ROOT}/frontend/dist/"
}

sync_tools() {
  info "同步 tools/、customTools/ 和 Tool Catalog"
  COPYFILE_DISABLE=1 tar \
    -C "$ROOT_DIR" \
    -czf "$TOOLS_TAR" \
    --exclude='tools/*.bak.*' \
    --exclude='customTools/**/*.bak.*' \
    --exclude='customTools/**/__pycache__' \
    --exclude='tools/__pycache__' \
    --exclude='tools/**/__pycache__' \
    tools customTools
  docker exec "$CONTAINER" env APP_ROOT="$APP_ROOT" sh -lc '
    set -eu
    mkdir -p "$APP_ROOT/tools" "$APP_ROOT/tools/catalog" \
      "$APP_ROOT/customTools/definitions" "$APP_ROOT/customTools/scripts"
  '
  docker cp "$TOOLS_TAR" "${CONTAINER}:/tmp/"
  docker exec "$CONTAINER" env APP_ROOT="$APP_ROOT" TAR_PATH="/tmp/$(basename "$TOOLS_TAR")" sh -lc '
    set -eu
    tar -xzf "$TAR_PATH" -C "$APP_ROOT"
    rm -f "$APP_ROOT/tools/metasploit.yaml" "$APP_ROOT/tools/msfvenom.yaml"
    cp "$APP_ROOT"/customTools/definitions/*.yaml "$APP_ROOT/tools/"
  '
}

ensure_tool_runtime() {
  info "检查源码工具构建与 Python 运行时"
  docker exec "$CONTAINER" env APP_ROOT="$APP_ROOT" sh -lc '
    set -eu
    marker="$APP_ROOT/.tool-build-deps-v1"
    if [ ! -f "$marker" ]; then
      need_install=0
      for command_name in autoconf automake libtool bison flex; do
        command -v "$command_name" >/dev/null 2>&1 || need_install=1
      done
      for package_name in openssl libssh libidn pcre2 zlib bzip2; do
        pkg-config --exists "$package_name" || need_install=1
      done
      if [ "$need_install" -eq 1 ] && command -v apt-get >/dev/null 2>&1; then
        TMPDIR=/var/tmp apt-get \
          -o Dir::Etc::sourcelist=/etc/apt/sources.list \
          -o Dir::Etc::sourceparts=- update
        TMPDIR=/var/tmp DEBIAN_FRONTEND=noninteractive apt-get \
          -o Dir::Etc::sourcelist=/etc/apt/sources.list \
          -o Dir::Etc::sourceparts=- install -y --no-install-recommends \
          autoconf automake libtool bison flex libssl-dev libssh-dev libidn11-dev \
          libpcre2-dev zlib1g-dev libbz2-dev libgmp-dev ruby-addressable
      fi
      : > "$marker"
    fi
    if [ ! -x "$APP_ROOT/venv/bin/python" ]; then
      python3 -m venv --system-site-packages "$APP_ROOT/venv"
    fi
    if ! "$APP_ROOT/venv/bin/python" -c "import requests, socks, impacket, ddddocr" >/dev/null 2>&1; then
      "$APP_ROOT/venv/bin/python" -m pip install --disable-pip-version-check \
        --no-cache-dir --retries 2 --timeout 30 requests PySocks httpx h2 impacket ddddocr==1.6.1
    fi
  '
}

restart_service() {
  info "重启 Sophon 后端和 Nginx"
  docker exec "$CONTAINER" env \
    APP_ROOT="$APP_ROOT" \
    sh -lc '
      set -eu
      SOPHON_APP_ROOT="$APP_ROOT" \
        sh "$APP_ROOT/deploy/container/start.sh"
    '
}

check_health() {
  info "检查后端健康接口"
  local healthy=0
  local attempt
  for attempt in $(seq 1 30); do
    if docker exec "$CONTAINER" \
      curl -fsS http://127.0.0.1:18080/api/health >/dev/null 2>&1; then
      healthy=1
      break
    fi
    sleep 1
  done
  [[ "$healthy" -eq 1 ]] || die "后端健康检查失败"
  docker exec "$CONTAINER" curl -fsS http://127.0.0.1:18080/api/health
  printf '\n'

  info "检查前端入口"
  curl -fsS -o /dev/null -w 'chat_http=%{http_code}\n' "${HOST_URL}/chat"
}

case "$TARGET" in
  backend)
    build_backend
    deploy_backend
    ;;
  frontend)
    build_frontend
    deploy_frontend
    ;;
  all)
    build_backend
    build_frontend
    deploy_backend
    deploy_frontend
    ;;
esac

sync_tools
ensure_tool_runtime
restart_service
check_health

ok "部署完成: ${CONTAINER} (${TARGET})"
