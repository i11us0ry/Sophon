#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER=""
CONTAINER_CREATED=0
NAME="sophon"
IMAGE="kalilinux/kali-rolling:latest"
NODE_IMAGE="node:20-bookworm-slim"
HOST_PORT="8080"
STATE_DIR="${HOME}/.sophon/docker"
APP_ROOT="/opt/sophon"
ADMIN_PASSWORD="${SOPHON_ADMIN_PASSWORD:-}"
NO_START=0
SKIP_TOOLS=0
SKIP_PYTHON=0
BUILD_ONLY=0
NO_PULL=0
OFFLINE=0
DRY_RUN=0
APT_MIRROR="auto"
GO_MIRROR="auto"
NPM_REGISTRY="auto"
PIP_INDEX="auto"
PULL_RETRIES=3
APT_RETRIES=3
STAMP="$(date +%Y%m%d-%H%M%S)"
INSTALL_ID="${STAMP}-$$"
BUILD_ROOT="/tmp/sophon-docker-install-${INSTALL_ID}"
FRONTEND_BUILDER=""
GO_BIN=""

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok() { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
on_error() {
  printf '\033[31m[x]\033[0m 安装失败，脚本第 %s 行。\n' "$1" >&2
  if ((CONTAINER_CREATED == 1)); then
    printf '\033[33m[!]\033[0m 容器 %s 和 %s 中的数据均已保留，请检查后手动处理。\n' "$CONTAINER" "$STATE_DIR" >&2
  fi
}
trap 'on_error "$LINENO"' ERR

usage() {
  cat <<EOF
拉取公开镜像、创建新容器并安装 Sophon

用法:
  ./install-docker.sh [选项]

选项:
  --name NAME               新容器名称，默认 sophon
  --image IMAGE             基础镜像，默认 kalilinux/kali-rolling:latest
  --node-image IMAGE        临时前端构建镜像，默认 node:20-bookworm-slim
  --host-port PORT          宿主机端口，默认 8080
  --state-dir PATH          宿主机持久化目录，默认 ~/.sophon/docker
  --prefix PATH             容器内安装目录，默认 /opt/sophon
  --admin-password VALUE    初始管理员密码；未提供时交互输入
  --apt-mirror VALUE        auto/official/tuna/aliyun/ustc/自定义 URL
  --go-mirror VALUE         auto/official/china/自定义下载地址
  --npm-registry VALUE      auto/npm/npmmirror/自定义 registry
  --pip-index VALUE         auto/pypi/tuna/aliyun/自定义 index URL
  --pull-retries N         镜像拉取最大尝试次数，默认 3
  --apt-retries N          apt 更新重试次数，默认 3
  --no-pull                 不拉取基础镜像和前端构建镜像
  --offline                 只使用本机已有镜像，跳过镜像拉取
  --dry-run                 只显示安装计划，不创建容器
  --no-start                安装完成后不启动
  --skip-tools              跳过第三方安全工具解压和校验
  --skip-python             跳过 Python 虚拟环境依赖安装
  --build-only              仅构建并验证，不复制到安装目录
  -h, --help                显示帮助

默认安装:
  - 新建容器 ${NAME}
  - 端口 ${HOST_PORT}:8080
  - 持久化目录 ${STATE_DIR}
  - NET_RAW 能力、自动重启和 50 秒停止宽限
EOF
}

while (($#)); do
  case "$1" in
    --name) NAME="${2:?--name 缺少参数}"; shift 2 ;;
    --image) IMAGE="${2:?--image 缺少参数}"; shift 2 ;;
    --node-image) NODE_IMAGE="${2:?--node-image 缺少参数}"; shift 2 ;;
    --host-port) HOST_PORT="${2:?--host-port 缺少参数}"; shift 2 ;;
    --state-dir) STATE_DIR="${2:?--state-dir 缺少参数}"; shift 2 ;;
    --prefix) APP_ROOT="${2:?--prefix 缺少参数}"; shift 2 ;;
    --admin-password) ADMIN_PASSWORD="${2:?--admin-password 缺少参数}"; shift 2 ;;
    --apt-mirror) APT_MIRROR="${2:?--apt-mirror 缺少参数}"; shift 2 ;;
    --go-mirror) GO_MIRROR="${2:?--go-mirror 缺少参数}"; shift 2 ;;
    --npm-registry) NPM_REGISTRY="${2:?--npm-registry 缺少参数}"; shift 2 ;;
    --pip-index) PIP_INDEX="${2:?--pip-index 缺少参数}"; shift 2 ;;
    --pull-retries) PULL_RETRIES="${2:?--pull-retries 缺少参数}"; shift 2 ;;
    --apt-retries) APT_RETRIES="${2:?--apt-retries 缺少参数}"; shift 2 ;;
    --no-pull) NO_PULL=1; shift ;;
    --offline) OFFLINE=1; NO_PULL=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --no-start) NO_START=1; shift ;;
    --skip-tools) SKIP_TOOLS=1; shift ;;
    --skip-python) SKIP_PYTHON=1; shift ;;
    --build-only) BUILD_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) die "未知参数: $1" ;;
    *) die "未知参数: $1" ;;
  esac
done

[[ "$APP_ROOT" == /* ]] || die "--prefix 必须是绝对路径"
[[ "$NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || die "容器名不合法"
[[ "$HOST_PORT" =~ ^[0-9]+$ ]] && ((HOST_PORT >= 1 && HOST_PORT <= 65535)) || die "端口不合法"
[[ "$PULL_RETRIES" =~ ^[0-9]+$ ]] && ((PULL_RETRIES >= 1)) || die "pull-retries 必须是正整数"
[[ "$APT_RETRIES" =~ ^[0-9]+$ ]] && ((APT_RETRIES >= 1)) || die "apt-retries 必须是正整数"
if [[ "$STATE_DIR" == "~/"* ]]; then
  STATE_DIR="${HOME}/${STATE_DIR#\~/}"
fi
[[ "$STATE_DIR" == /* ]] || STATE_DIR="$(pwd)/${STATE_DIR}"
[[ "$APP_ROOT" != "/" ]] || die "--prefix 不能是根目录"
[[ "$APP_ROOT" =~ ^/[A-Za-z0-9_./-]+$ ]] || die "--prefix 只能包含字母、数字、下划线、点、斜杠和连字符"
[[ "$STATE_DIR" != *":"* ]] || die "--state-dir 不能包含冒号"
CONTAINER="$NAME"

validate_http_value() {
  local option="$1"
  local value="$2"
  [[ "$value" == http://* || "$value" == https://* ]] || die "${option} 必须是 http(s) URL: ${value}"
  [[ "$value" != *[[:space:]]* && "$value" != *"'"* && "$value" != *'"'* ]] || \
    die "${option} 包含不支持的字符: ${value}"
}

case "$APT_MIRROR" in
  auto|official|tuna|aliyun|ustc) ;;
  *) validate_http_value "--apt-mirror" "$APT_MIRROR"; [[ "$APT_MIRROR" != *"|"* && "$APT_MIRROR" != *"&"* && "$APT_MIRROR" != *"#"* ]] || die "--apt-mirror 不能包含 |、& 或 #" ;;
esac
case "$GO_MIRROR" in
  auto|official|china) ;;
  *) validate_http_value "--go-mirror" "$GO_MIRROR" ;;
esac
case "$NPM_REGISTRY" in
  auto|official|npm|npmmirror) ;;
  *) validate_http_value "--npm-registry" "$NPM_REGISTRY"; [[ "$NPM_REGISTRY" != *","* ]] || die "--npm-registry 不能包含逗号" ;;
esac
case "$PIP_INDEX" in
  auto|official|pypi|tuna|aliyun) ;;
  *) validate_http_value "--pip-index" "$PIP_INDEX" ;;
esac

apt_mirror_candidates() {
  case "$APT_MIRROR" in
    official) printf '%s\n' official ;;
    tuna) printf '%s\n' tuna ;;
    aliyun) printf '%s\n' aliyun ;;
    ustc) printf '%s\n' ustc ;;
    auto) printf '%s\n' aliyun tuna ustc official ;;
    *) printf '%s\n' "$APT_MIRROR" ;;
  esac
}

go_download_candidates() {
  case "$GO_MIRROR" in
    official) printf 'https://go.dev/dl/go1.25.0.linux-%s.tar.gz\n' "$ARCH" ;;
    china) printf 'https://golang.google.cn/dl/go1.25.0.linux-%s.tar.gz\n' "$ARCH" ;;
    auto)
      printf 'https://mirrors.aliyun.com/golang/go1.25.0.linux-%s.tar.gz\n' "$ARCH"
      printf 'https://mirrors.nju.edu.cn/golang/go1.25.0.linux-%s.tar.gz\n' "$ARCH"
      printf 'https://golang.google.cn/dl/go1.25.0.linux-%s.tar.gz\n' "$ARCH"
      printf 'https://go.dev/dl/go1.25.0.linux-%s.tar.gz\n' "$ARCH"
      ;;
    *) printf '%s\n' "$GO_MIRROR" ;;
  esac
}

go_proxy_candidates() {
  case "$GO_MIRROR" in
    official) printf '%s\n' 'https://proxy.golang.org,direct' ;;
    china) printf '%s\n' 'https://goproxy.cn,direct' ;;
    *)
      printf '%s\n' 'https://goproxy.cn,direct'
      printf '%s\n' 'https://mirrors.aliyun.com/goproxy/,direct'
      printf '%s\n' 'https://proxy.golang.org,direct'
      ;;
  esac
}

npm_registry_candidates() {
  case "$NPM_REGISTRY" in
    official|npm) printf '%s\n' 'https://registry.npmjs.org' ;;
    npmmirror) printf '%s\n' 'https://registry.npmmirror.com' ;;
    auto)
      printf '%s\n' 'https://registry.npmmirror.com'
      printf '%s\n' 'https://registry.npmjs.org'
      ;;
    *) printf '%s\n' "$NPM_REGISTRY" ;;
  esac
}

pip_index_candidates() {
  case "$PIP_INDEX" in
    official|pypi) printf '%s\n' 'https://pypi.org/simple' ;;
    tuna) printf '%s\n' 'https://pypi.tuna.tsinghua.edu.cn/simple' ;;
    aliyun) printf '%s\n' 'https://mirrors.aliyun.com/pypi/simple' ;;
    auto)
      printf '%s\n' 'https://pypi.tuna.tsinghua.edu.cn/simple'
      printf '%s\n' 'https://mirrors.aliyun.com/pypi/simple'
      printf '%s\n' 'https://pypi.org/simple'
      ;;
    *) printf '%s\n' "$PIP_INDEX" ;;
  esac
}

print_plan() {
  cat <<EOF
Sophon Docker 安装计划

  新容器名称:       ${NAME}
  基础镜像:         ${IMAGE}
  前端构建镜像:     ${NODE_IMAGE}
  持久化目录:       ${STATE_DIR}
  容器安装目录:     ${APP_ROOT}
  端口映射:         ${HOST_PORT}:8080
  镜像策略:         $([[ "$OFFLINE" == 1 ]] && printf '仅使用本机镜像' || { [[ "$NO_PULL" == 1 ]] && printf '不拉取镜像' || printf '拉取，最多 %s 次尝试' "$PULL_RETRIES"; })
  apt 源:           $([[ "$APT_MIRROR" == auto ]] && printf 'aliyun → tuna → ustc → official' || printf '%s' "$APT_MIRROR")
  Go 下载源:        $([[ "$GO_MIRROR" == auto ]] && printf 'aliyun → nju → china → official' || printf '%s' "$GO_MIRROR")
  npm registry:     $([[ "$NPM_REGISTRY" == auto ]] && printf 'npmmirror → npmjs' || printf '%s' "$NPM_REGISTRY")
  pip index:        $([[ "$PIP_INDEX" == auto ]] && printf 'tuna → aliyun → pypi' || printf '%s' "$PIP_INDEX")
  安装组件:         apt 依赖、Go 1.25、Python venv、可选本地 thirdTools
  安装后启动:       $([[ "$NO_START" == 1 ]] && printf '否' || printf '是')
  仅构建:           $([[ "$BUILD_ONLY" == 1 ]] && printf '是' || printf '否')

本命令为 dry-run，未访问网络、未创建目录、未创建容器。
EOF
}

if ((DRY_RUN == 1)); then
  print_plan
  exit 0
fi

command -v docker >/dev/null 2>&1 || die "宿主机未安装 Docker"
DOCKER=(docker)
if ! "${DOCKER[@]}" info >/dev/null 2>&1; then
  if command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    DOCKER=(sudo docker)
  else
    die "无法访问 Docker daemon"
  fi
fi

ensure_container_name_free() {
  if "${DOCKER[@]}" container inspect "$NAME" >/dev/null 2>&1; then
    die "容器已存在: ${NAME}；脚本不会覆盖或删除现有容器，请改用 --name"
  fi
}

ensure_host_port_free() {
  local docker_users=""
  local listeners=""
  docker_users="$("${DOCKER[@]}" ps --filter "publish=${HOST_PORT}" --format '{{.Names}}' 2>/dev/null || true)"
  [[ -z "$docker_users" ]] || die "宿主机端口 ${HOST_PORT} 已被容器占用: ${docker_users}"
  if command -v lsof >/dev/null 2>&1; then
    listeners="$(lsof -nP -iTCP:"${HOST_PORT}" -sTCP:LISTEN 2>/dev/null || true)"
  elif command -v ss >/dev/null 2>&1; then
    listeners="$(ss -ltnH "sport = :${HOST_PORT}" 2>/dev/null || true)"
  elif command -v netstat >/dev/null 2>&1; then
    listeners="$(netstat -ltn 2>/dev/null | awk -v port=":${HOST_PORT}" '$4 ~ port "$" {print}' || true)"
  fi
  [[ -z "$listeners" ]] || die "宿主机端口 ${HOST_PORT} 已被占用"
}

pull_image() {
  local image="$1"
  local option="${2:---image}"
  local attempt
  local mirror="$image"
  if "${DOCKER[@]}" image inspect "$image" >/dev/null 2>&1; then
    if ((NO_PULL == 1)); then
      info "使用本机已有镜像: ${image}"
      return
    fi
  elif ((NO_PULL == 1)); then
    die "本机没有镜像 ${image}，且已指定 --no-pull/--offline"
  fi

  for ((attempt = 1; attempt <= PULL_RETRIES; attempt++)); do
    info "拉取镜像 ${image}（第 ${attempt}/${PULL_RETRIES} 次）..."
    if "${DOCKER[@]}" pull "$image"; then
      return
    fi
    ((attempt == PULL_RETRIES)) || sleep "$((attempt * 2))"
  done

  if "${DOCKER[@]}" image inspect "$image" >/dev/null 2>&1; then
    warn "镜像拉取失败，回退到本机已有版本: ${image}"
    return
  fi
  if [[ "$image" != */* ]]; then
    mirror="docker.m.daocloud.io/library/${image}"
  else
    mirror="docker.m.daocloud.io/${image}"
  fi
  die "镜像拉取失败: ${image}。可尝试 ${option} ${mirror}、--no-pull 或 --offline"
}

create_container() {
  local container_command
  container_command='
trap '"'"'SOPHON_APP_ROOT="$SOPHON_APP_ROOT" sh "$SOPHON_APP_ROOT/deploy/container/stop.sh" 2>/dev/null || true; exit 0'"'"' TERM INT
if [ -f "$SOPHON_APP_ROOT/.install-complete" ] && [ "$(cat "$SOPHON_APP_ROOT/.install-complete" 2>/dev/null)" = "$SOPHON_INSTALL_ID" ]; then
  PATH="$SOPHON_APP_ROOT/venv/bin:$PATH" SOPHON_APP_ROOT="$SOPHON_APP_ROOT" sh "$SOPHON_APP_ROOT/deploy/container/start.sh" || true
fi
while true; do
  sleep 3600 &
  wait $!
done
'
  info "创建新容器 ${NAME}..."
  "${DOCKER[@]}" run -d \
    --name "$NAME" \
    --hostname "$NAME" \
    --init \
    --restart unless-stopped \
    --stop-timeout 50 \
    --cap-add NET_RAW \
    --label "sophon.install-id=${INSTALL_ID}" \
    -e "SOPHON_APP_ROOT=${APP_ROOT}" \
    -e "SOPHON_INSTALL_ID=${INSTALL_ID}" \
    -p "${HOST_PORT}:8080" \
    -v "${STATE_DIR}:${APP_ROOT}" \
    --entrypoint /bin/bash \
    "$IMAGE" \
    -lc "$container_command" >/dev/null
  CONTAINER_CREATED=1
}

exec_sh() { "${DOCKER[@]}" exec -u 0 "$CONTAINER" /bin/sh -lc "$*"; }

detect_arch() {
  local arch_raw
  arch_raw="$(exec_sh 'uname -m')"
  case "$arch_raw" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "容器 CPU 架构不受支持: $arch_raw" ;;
  esac
  ok "目标容器: ${CONTAINER} (${ARCH})"
}

apt_mirror_url() {
  local mirror="$1"
  local phase="${2:-secure}"
  case "$mirror" in
    official|auto) printf '%s\n' 'http://http.kali.org/kali' ;;
    tuna)
      if [[ "$phase" == "bootstrap" ]]; then
        printf '%s\n' 'http://mirrors.tuna.tsinghua.edu.cn/kali'
      else
        printf '%s\n' 'https://mirrors.tuna.tsinghua.edu.cn/kali'
      fi
      ;;
    aliyun)
      if [[ "$phase" == "bootstrap" ]]; then
        printf '%s\n' 'http://mirrors.aliyun.com/kali'
      else
        printf '%s\n' 'https://mirrors.aliyun.com/kali'
      fi
      ;;
    ustc)
      if [[ "$phase" == "bootstrap" ]]; then
        printf '%s\n' 'http://mirrors.ustc.edu.cn/kali'
      else
        printf '%s\n' 'https://mirrors.ustc.edu.cn/kali'
      fi
      ;;
    *) printf '%s\n' "$mirror" ;;
  esac
}

set_apt_mirror() {
  local mirror="$1"
  local phase="${2:-secure}"
  local base
  local files
  local file
  base="$(apt_mirror_url "$mirror" "$phase")"
  files="$(exec_sh "grep -RIlE 'https?://[^[:space:]]+/kali' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true")"
  if [[ -z "$files" ]]; then
    warn "未找到 Kali apt 源，将沿用当前镜像的 apt 配置"
    return
  fi
  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    exec_sh "test -f '${file}.sophon-original' || cp -a '${file}' '${file}.sophon-original'"
    exec_sh "sed -Ei 's#https?://[^[:space:]]+/kali#${base}#g' '${file}'"
  done <<< "$files"
}

apt_update_with_retries() {
  local mirror
  local attempt
  local phase="${1:-secure}"
  local output
  while IFS= read -r mirror; do
    [[ -n "$mirror" ]] || continue
    set_apt_mirror "$mirror" "$phase"
    for ((attempt = 1; attempt <= APT_RETRIES; attempt++)); do
      info "更新 apt 索引，源 ${mirror}/${phase}（第 ${attempt}/${APT_RETRIES} 次）..."
      if output="$(exec_sh 'DEBIAN_FRONTEND=noninteractive apt-get update 2>&1')"; then
        printf '%s\n' "$output"
        if [[ "$output" != *"Err:"* &&
          "$output" != *"Failed to fetch"* &&
          "$output" != *"Some index files failed to download"* ]]; then
          return
        fi
        warn "apt 索引存在下载错误，切换下一个镜像"
      else
        printf '%s\n' "$output" >&2
      fi
      ((attempt == APT_RETRIES)) || sleep "$((attempt * 2))"
    done
  done < <(apt_mirror_candidates)
  die "apt 索引更新失败，已尝试配置中的镜像源"
}

install_system_dependencies() {
  local package
  local required=(
    ca-certificates curl wget unzip tar xz-utils git build-essential pkg-config
    libsqlite3-dev libpcap-dev sqlite3 nginx python3 python3-venv python3-pip
    default-jre-headless libcap2-bin openssl util-linux procps iproute2
    nmap masscan sqlmap
  )
  local optional=(whatweb dirsearch hydra john nbtscan wafw00f nuclei responder)
  exec_sh 'command -v apt-get >/dev/null 2>&1' || die "基础镜像缺少 apt-get，请使用 Kali/Debian 系镜像"
  apt_update_with_retries bootstrap
  info "安装 APT HTTPS 证书依赖..."
  exec_sh 'DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates'
  apt_update_with_retries secure
  info "安装 Sophon 系统依赖..."
  exec_sh "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ${required[*]}"
  for package in "${optional[@]}"; do
    if exec_sh "apt-cache show '${package}' >/dev/null 2>&1"; then
      if ! exec_sh "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends '${package}'"; then
        warn "可选工具 ${package} 安装失败，将继续安装"
      fi
    else
      warn "当前 apt 源不提供可选工具: ${package}"
    fi
  done
}

version_ge() {
  local current="$1"
  local required="$2"
  local current_major current_minor current_patch
  local required_major required_minor required_patch
  IFS=. read -r current_major current_minor current_patch _ <<< "$current"
  IFS=. read -r required_major required_minor required_patch _ <<< "$required"
  current_major="${current_major//[^0-9]/}"
  current_minor="${current_minor//[^0-9]/}"
  current_patch="${current_patch//[^0-9]/}"
  required_major="${required_major//[^0-9]/}"
  required_minor="${required_minor//[^0-9]/}"
  required_patch="${required_patch//[^0-9]/}"
  [[ "$current_major$current_minor$current_patch" =~ ^[0-9]+$ ]] || return 1
  [[ "$required_major$required_minor$required_patch" =~ ^[0-9]+$ ]] || return 1
  ((current_major > required_major ||
    (current_major == required_major && current_minor > required_minor) ||
    (current_major == required_major && current_minor == required_minor && current_patch >= required_patch)))
}

install_go() {
  local current=""
  local version=""
  local url=""
  local index=0
  local archive=""
  local go_root="/usr/local/go-1.25.0"
  if exec_sh 'command -v go >/dev/null 2>&1'; then
    current="$(exec_sh "go version | awk '{print \$3}' | sed 's/^go//'")"
    if version_ge "$current" "1.25.0"; then
      GO_BIN="$(exec_sh 'command -v go')"
      ok "使用容器已有 Go: $current"
      return
    fi
    warn "容器 Go 版本为 ${current}，安装 Go 1.25.0"
  fi

  while IFS= read -r url; do
    [[ -n "$url" ]] || continue
    index=$((index + 1))
    archive="${BUILD_ROOT}/go-${index}.tar.gz"
    info "下载 Go 1.25.0: ${url}"
    if exec_sh "mkdir -p '${BUILD_ROOT}' && curl -fL --retry 3 --connect-timeout 20 '${url}' -o '${archive}.download' && mv '${archive}.download' '${archive}'"; then
      exec_sh "mkdir -p '${go_root}' && tar -xzf '${archive}' --strip-components=1 -C '${go_root}'"
      GO_BIN="${go_root}/bin/go"
      version="$(exec_sh "'${GO_BIN}' version | awk '{print \$3}' | sed 's/^go//'")"
      version_ge "$version" "1.25.0" || die "下载的 Go 版本不符合要求: ${version}"
      ok "Go: ${version}"
      return
    fi
  done < <(go_download_candidates)
  die "Go 1.25.0 下载失败，可使用 --go-mirror 指定完整下载地址"
}

configure_go_proxy_in_container() {
  local proxy
  proxy="$(go_proxy_candidates | head -n1)"
  [[ -n "$proxy" ]] || die "Go 模块代理为空"
  exec_sh "'${GO_BIN}' env -w GOPROXY='${proxy}'"
  ok "Go 模块代理: $proxy"
}

go_build() {
  local dir="$1"
  local output="$2"
  local package="$3"
  local proxy
  while IFS= read -r proxy; do
    info "Go 构建 ${package}，模块代理 ${proxy}"
    if exec_sh "cd '${dir}' && GOPROXY='${proxy}' CGO_ENABLED=1 '${GO_BIN}' build -trimpath -ldflags='-s -w' -o '${output}' '${package}'"; then
      return
    fi
  done < <(go_proxy_candidates)
  die "Go 构建失败: ${package}"
}

password_value() {
  [[ -n "$ADMIN_PASSWORD" ]] && return
  if [[ -t 0 ]]; then
    read -rsp "初始管理员密码（回车自动生成）: " ADMIN_PASSWORD
    printf '\n'
  fi
  if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    warn "已自动生成管理员密码: $ADMIN_PASSWORD"
  fi
  [[ "$ADMIN_PASSWORD" != *$'\n'* ]] || die "管理员密码不能包含换行"
}

build_frontend() {
  local registries=""
  local registry
  local build_script
  FRONTEND_BUILDER="${NAME}-frontend-builder-${INSTALL_ID}"
  while IFS= read -r registry; do
    registries="${registries}${registries:+,}${registry}"
  done < <(npm_registry_candidates)
  build_script='
set -eu
mkdir -p /work
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
    exit 0
  fi
  IFS=,
done
exit 1
'
  info "使用临时 Node 镜像构建前端..."
  "${DOCKER[@]}" create \
    --name "$FRONTEND_BUILDER" \
    --label "sophon.install-id=${INSTALL_ID}" \
    -e "SOPHON_NPM_REGISTRIES=${registries}" \
    -v "${ROOT_DIR}/frontend:/src:ro" \
    --entrypoint /bin/sh \
    "$NODE_IMAGE" \
    -lc "$build_script" >/dev/null
  "${DOCKER[@]}" start -a "$FRONTEND_BUILDER"
  ok "前端构建完成: ${FRONTEND_BUILDER}:/work/dist"
}

build_backend_in_container() {
  info "复制后端源码到容器临时目录..."
  exec_sh "mkdir -p '${BUILD_ROOT}/backend'"
  "${DOCKER[@]}" cp "$ROOT_DIR/backend/." "$CONTAINER:${BUILD_ROOT}/backend/"
  info "在容器内构建后端..."
  go_build "${BUILD_ROOT}/backend" "${BUILD_ROOT}/sophon-server" "./cmd/server"
  go_build "${BUILD_ROOT}/backend" "${BUILD_ROOT}/sophon-mcp-tools" "./cmd/mcp-tools"
  go_build "${BUILD_ROOT}/backend" "${BUILD_ROOT}/sophon-tool-runner" "./cmd/tool-runner"
  exec_sh "test -x '${BUILD_ROOT}/sophon-server' && test -x '${BUILD_ROOT}/sophon-mcp-tools' && test -x '${BUILD_ROOT}/sophon-tool-runner'"
}

copy_resources() {
  exec_sh "mkdir -p '${APP_ROOT}/backend' '${APP_ROOT}/frontend/dist' '${APP_ROOT}/data' \
    '${APP_ROOT}/deploy' '${APP_ROOT}/roles' '${APP_ROOT}/skills' '${APP_ROOT}/tools' \
    '${APP_ROOT}/thirdTools' '${APP_ROOT}/licenses'"
  exec_sh "install -m 0755 '${BUILD_ROOT}/sophon-server' '${APP_ROOT}/backend/sophon-server' && \
    install -m 0755 '${BUILD_ROOT}/sophon-mcp-tools' '${APP_ROOT}/backend/sophon-mcp-tools' && \
    install -m 0755 '${BUILD_ROOT}/sophon-tool-runner' '${APP_ROOT}/backend/sophon-tool-runner'"
  "${DOCKER[@]}" cp "${FRONTEND_BUILDER}:/work/dist/." "$CONTAINER:${APP_ROOT}/frontend/dist/"
  for name in deploy roles skills tools licenses; do
    "${DOCKER[@]}" cp "$ROOT_DIR/${name}/." "$CONTAINER:${APP_ROOT}/${name}/"
  done
  if [[ -d "$ROOT_DIR/thirdTools" ]] && [[ -n "$(find "$ROOT_DIR/thirdTools" -type f -print -quit)" ]]; then
    "${DOCKER[@]}" cp "$ROOT_DIR/thirdTools/." "$CONTAINER:${APP_ROOT}/thirdTools/"
  else
    warn "未提供 thirdTools；平台将使用系统命令环境，用户可稍后上传工具"
  fi
  exec_sh "find '${APP_ROOT}/deploy' '${APP_ROOT}/tools' -type f -exec sed -i 's|/opt/sophon|${APP_ROOT}|g' {} +"

  if ! exec_sh "test -f '${APP_ROOT}/config.yml'"; then
    "${DOCKER[@]}" cp "$ROOT_DIR/config.example.yml" "$CONTAINER:${APP_ROOT}/config.yml"
    exec_sh "sed -i 's|/opt/sophon|${APP_ROOT}|g; s|data_dir: ./data|data_dir: ${APP_ROOT}/data|' '${APP_ROOT}/config.yml'"
    password_value
    "${DOCKER[@]}" exec -u 0 -e CONFIG_PASSWORD="$ADMIN_PASSWORD" "$CONTAINER" python3 - "$APP_ROOT/config.yml" <<'PY'
import json
import os
import sys

path = sys.argv[1]
password = os.environ["CONFIG_PASSWORD"]
lines = open(path, encoding="utf-8").read().splitlines()
inside = False
changed = False
for index, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith("bootstrap_admin:"):
        inside = True
        continue
    if inside and line and not line.startswith(" "):
        break
    if inside and stripped.startswith("password:"):
        indent = line[:len(line) - len(line.lstrip())]
        lines[index] = f"{indent}password: {json.dumps(password, ensure_ascii=False)}"
        changed = True
        break
if not changed:
    raise SystemExit("config.yml 中未找到 auth.bootstrap_admin.password")
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY
    exec_sh "chmod 600 '${APP_ROOT}/config.yml'"
  else
    info "沿用容器内已有 config.yml"
  fi
  exec_sh "chmod 700 '${APP_ROOT}/data'"
}

install_python_container() {
  ((SKIP_PYTHON == 1)) && {
    warn "已跳过 Python 依赖安装"
    return
  }
  local index
  info "创建 Python 虚拟环境..."
  exec_sh "python3 -m venv '${APP_ROOT}/venv'"
  while IFS= read -r index; do
    [[ -n "$index" ]] || continue
    info "安装 Python 依赖，index ${index}"
    if exec_sh "'${APP_ROOT}/venv/bin/python' -m pip install --disable-pip-version-check --no-cache-dir --retries 2 --timeout 30 --index-url '${index}' requests httpx h2 impacket"; then
      exec_sh "umask 077 && printf '[global]\\nindex-url = ${index}\\n' > '${APP_ROOT}/venv/pip.conf'"
      ok "Python 包源: $index"
      return
    fi
  done < <(pip_index_candidates)
  die "Python 依赖安装失败，已尝试配置中的镜像源"
}

install_tools_container() {
  ((SKIP_TOOLS == 1)) && {
    warn "已跳过第三方工具安装"
    return
  }
  if ! exec_sh "test -d '${APP_ROOT}/thirdTools' && find '${APP_ROOT}/thirdTools' -type f -print -quit | grep -q ."; then
    warn "未提供 thirdTools，跳过工具解压；可稍后上传到 ${APP_ROOT}/thirdTools"
    return
  fi
  info "解压本地可选 thirdTools..."
  exec_sh "set -e
    T='${APP_ROOT}/thirdTools'
    if [ -f \"\$T/naabu_2.6.1_linux_${ARCH}.zip\" ]; then unzip -p \"\$T/naabu_2.6.1_linux_${ARCH}.zip\" naabu > \"\$T/naabu\"; fi
    if [ -f \"\$T/httpx_1.12.0_linux_${ARCH}.zip\" ]; then unzip -p \"\$T/httpx_1.12.0_linux_${ARCH}.zip\" httpx > \"\$T/httpx\"; fi
    if [ -f \"\$T/katana_1.8.0_linux_${ARCH}.zip\" ]; then unzip -p \"\$T/katana_1.8.0_linux_${ARCH}.zip\" katana > \"\$T/katana\"; fi
    if [ -f \"\$T/ksubdomain_linux.zip\" ]; then unzip -p \"\$T/ksubdomain_linux.zip\" ksubdomain > \"\$T/ksubdomain\"; fi
    for f in naabu httpx katana ksubdomain decompile.py host_collision.py bypass403.py; do
      [ -f \"\$T/\$f\" ] && chmod 0755 \"\$T/\$f\" || true
    done"
  if exec_sh "test -x '${APP_ROOT}/thirdTools/ksubdomain'" && \
     ! exec_sh "'${APP_ROOT}/thirdTools/ksubdomain' --help >/dev/null 2>&1"; then
    info "预编译 ksubdomain 与容器架构不兼容，尝试源码构建..."
    if exec_sh "test -f '${APP_ROOT}/thirdTools/ksubdomain-main.zip'"; then
      exec_sh "set -e
        mkdir -p '${BUILD_ROOT}/ksubdomain-src'
        unzip -oq '${APP_ROOT}/thirdTools/ksubdomain-main.zip' -d '${BUILD_ROOT}/ksubdomain-src'"
      local ksubdomain_dir
      ksubdomain_dir="$(exec_sh "find '${BUILD_ROOT}/ksubdomain-src' -maxdepth 2 -name go.mod -printf '%h\\n' | head -n1")"
      [[ -n "$ksubdomain_dir" ]] || die "ksubdomain 源码包缺少 go.mod"
      go_build "$ksubdomain_dir" "${APP_ROOT}/thirdTools/ksubdomain" "."
    else
      warn "ksubdomain 不可用且未提供源码包"
    fi
  fi
  if [[ "$ARCH" == "amd64" ]]; then
    exec_sh "for f in suo5-linux-amd64 urlfinder jadx/bin/jadx; do [ -f '${APP_ROOT}/thirdTools/'\$f ] && chmod 0755 '${APP_ROOT}/thirdTools/'\$f || true; done
      if [ -f '${APP_ROOT}/thirdTools/ILSpy_linux-x64_11.2.0.10050.zip' ]; then
        mkdir -p '${BUILD_ROOT}/ilspy'
        unzip -oq '${APP_ROOT}/thirdTools/ILSpy_linux-x64_11.2.0.10050.zip' -d '${BUILD_ROOT}/ilspy'
        mkdir -p '${APP_ROOT}/thirdTools/ilspycmd'
        cp -a '${BUILD_ROOT}/ilspy/.' '${APP_ROOT}/thirdTools/ilspycmd/'
      fi"
  else
    exec_sh "for f in suo5-linux-arm64 jadx/bin/jadx; do [ -f '${APP_ROOT}/thirdTools/'\$f ] && chmod 0755 '${APP_ROOT}/thirdTools/'\$f || true; done"
  fi
  exec_sh "for f in ksubdomain naabu httpx katana; do if [ ! -x '${APP_ROOT}/thirdTools/'\$f ]; then echo \"可选工具未提供: \$f\" >&2; fi; done"
  if exec_sh "test -f '${APP_ROOT}/deploy/container/set-tool-caps.sh'"; then
    exec_sh "SOPHON_APP_ROOT='${APP_ROOT}' sh '${APP_ROOT}/deploy/container/set-tool-caps.sh'"
  fi
}

start_service() {
  ((NO_START == 0)) || {
    warn "已跳过启动"
    return
  }
  exec_sh "PATH='${APP_ROOT}/venv/bin':\$PATH SOPHON_APP_ROOT='${APP_ROOT}' sh '${APP_ROOT}/deploy/container/start.sh'"
  if exec_sh "command -v curl >/dev/null 2>&1"; then
    exec_sh "curl -fsS --retry 10 --retry-delay 1 --retry-connrefused http://127.0.0.1:8080/api/health >/dev/null"
  fi
  exec_sh "umask 077 && printf '%s\n' '${INSTALL_ID}' > '${APP_ROOT}/.install-complete'"
}

main() {
  ensure_container_name_free
  ensure_host_port_free
  pull_image "$IMAGE" "--image"
  pull_image "$NODE_IMAGE" "--node-image"
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  create_container
  detect_arch
  install_system_dependencies
  install_go
  configure_go_proxy_in_container
  build_frontend
  build_backend_in_container
  if ((BUILD_ONLY == 1)); then
    ok "仅构建模式完成：容器 ${CONTAINER}:${BUILD_ROOT}"
    ok "前端构建产物：容器 ${FRONTEND_BUILDER}:/work/dist"
    return
  fi
  copy_resources
  install_python_container
  install_tools_container
  start_service
  ok "Sophon 已安装到容器 ${CONTAINER}:${APP_ROOT}"
  "${DOCKER[@]}" port "$CONTAINER"
}

main "$@"
