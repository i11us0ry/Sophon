#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ROOT="/opt/sophon"
HTTP_PORT="8080"
ADMIN_PASSWORD="${SOPHON_ADMIN_PASSWORD:-}"
NO_START=0
SKIP_TOOLS=0
SKIP_SYSTEM_DEPS=0
FORCE_REINSTALL=0
BUILD_ROOT=""
APT_MIRROR="${SOPHON_APT_MIRROR:-auto}"
GO_MIRROR="${SOPHON_GO_MIRROR:-auto}"
NODE_MIRROR="${SOPHON_NODE_MIRROR:-auto}"
PIP_INDEX="${SOPHON_PIP_INDEX:-auto}"
GOPROXY_VALUE="${SOPHON_GOPROXY:-https://goproxy.cn,direct}"
APT_LOCK_RETRIES="${SOPHON_APT_LOCK_RETRIES:-120}"
APT_LOCK_DELAY="${SOPHON_APT_LOCK_DELAY:-5}"
PNPM_VERSION="9.15.9"
PIP_RETRIES="${SOPHON_PIP_RETRIES:-3}"
PIP_DELAY="${SOPHON_PIP_DELAY:-3}"

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok() { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

on_error() {
  local line="$1"
  printf '\033[31m[x]\033[0m 安装失败，脚本第 %s 行。已安装文件不会自动删除。\n' "$line" >&2
}
trap 'on_error "$LINENO"' ERR

usage() {
  cat <<EOF
Sophon Linux 主机安装脚本

用法:
  sudo ./install.sh [选项]

选项:
  --prefix PATH             安装目录，默认 /opt/sophon
  --port PORT               Web 端口，默认 8080
  --admin-password VALUE    初始管理员密码；未提供时交互输入
  --no-start                安装完成后不启动
  --skip-tools              不安装和校验第三方安全工具
  --skip-system-deps        跳过系统依赖安装
  --apt-mirror VALUE        auto/aliyun/tuna/ustc/official，默认 auto
  --go-mirror VALUE         auto/official/china/ustc/aliyun/nju/完整下载 URL
  --node-mirror VALUE       auto/aliyun/npmmirror/official/完整镜像目录 URL
  --pip-index VALUE         auto/tuna/aliyun/pypi/完整 index URL，默认 auto
  --force-reinstall         已存在安装时备份并覆盖程序文件
  -h, --help                显示帮助

支持系统:
  Ubuntu、Debian、Kali Linux、CentOS/RHEL 系
EOF
}

while (($#)); do
  case "$1" in
    --prefix) APP_ROOT="${2:?--prefix 缺少参数}"; shift 2 ;;
    --port) HTTP_PORT="${2:?--port 缺少参数}"; shift 2 ;;
    --admin-password) ADMIN_PASSWORD="${2:?--admin-password 缺少参数}"; shift 2 ;;
    --no-start) NO_START=1; shift ;;
    --skip-tools) SKIP_TOOLS=1; shift ;;
    --skip-system-deps) SKIP_SYSTEM_DEPS=1; shift ;;
    --apt-mirror) APT_MIRROR="${2:?--apt-mirror 缺少参数}"; shift 2 ;;
    --go-mirror) GO_MIRROR="${2:?--go-mirror 缺少参数}"; shift 2 ;;
    --node-mirror) NODE_MIRROR="${2:?--node-mirror 缺少参数}"; shift 2 ;;
    --pip-index) PIP_INDEX="${2:?--pip-index 缺少参数}"; shift 2 ;;
    --force-reinstall) FORCE_REINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数: $1" ;;
  esac
done

[[ "$(uname -s)" == "Linux" ]] || die "主机直装仅支持 Linux"
[[ "$HTTP_PORT" =~ ^[0-9]+$ ]] && ((HTTP_PORT >= 1 && HTTP_PORT <= 65535)) || die "端口不合法"
[[ "$APP_ROOT" == /* ]] || die "--prefix 必须是绝对路径"
[[ "$APT_LOCK_RETRIES" =~ ^[0-9]+$ ]] && ((APT_LOCK_RETRIES >= 1)) || die "SOPHON_APT_LOCK_RETRIES 必须是正整数"
[[ "$APT_LOCK_DELAY" =~ ^[0-9]+$ ]] && ((APT_LOCK_DELAY >= 1)) || die "SOPHON_APT_LOCK_DELAY 必须是正整数"
[[ "$PIP_RETRIES" =~ ^[0-9]+$ ]] && ((PIP_RETRIES >= 1)) || die "SOPHON_PIP_RETRIES 必须是正整数"
[[ "$PIP_DELAY" =~ ^[0-9]+$ ]] && ((PIP_DELAY >= 1)) || die "SOPHON_PIP_DELAY 必须是正整数"
case "$APT_MIRROR" in
  auto|aliyun|tuna|ustc|official) ;;
  *) die "--apt-mirror 必须是 auto/aliyun/tuna/ustc/official" ;;
esac
case "$GO_MIRROR" in
  auto|official|china|ustc|aliyun|nju) ;;
  http://*|https://*) ;;
  *) die "--go-mirror 必须是 auto/official/china/ustc/aliyun/nju 或完整 URL" ;;
esac
case "$NODE_MIRROR" in
  auto|aliyun|npmmirror|official) ;;
  http://*|https://*) ;;
  *) die "--node-mirror 必须是 auto/aliyun/npmmirror/official 或完整镜像目录 URL" ;;
esac
case "$PIP_INDEX" in
  auto|tuna|aliyun|pypi|official) ;;
  http://*|https://*) ;;
  *) die "--pip-index 必须是 auto/tuna/aliyun/pypi/official 或完整 index URL" ;;
esac
[[ "$GOPROXY_VALUE" == *://* ]] || die "SOPHON_GOPROXY 必须是有效代理 URL"

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64"; NODE_ARCH="x64" ;;
  aarch64|arm64) ARCH="arm64"; NODE_ARCH="arm64" ;;
  *) die "不支持的 CPU 架构: $(uname -m)" ;;
esac

if ((EUID == 0)); then
  SUDO=()
elif command -v sudo >/dev/null 2>&1; then
  SUDO=(sudo)
else
  die "需要 root 或 sudo 权限"
fi

run_root() { "${SUDO[@]}" "$@"; }

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
fi
OS_ID="${ID:-unknown}"
OS_LIKE="${ID_LIKE:-}"
OS_VERSION_ID="${VERSION_ID:-}"
OS_MAJOR="${OS_VERSION_ID%%.*}"
OS_NAME="${PRETTY_NAME:-${NAME:-unknown}}"
OS_VARIANT="linux"
if [[ "$OS_NAME" == *"CentOS Stream"* ]]; then
  OS_VARIANT="centos-stream"
elif [[ "$OS_ID" == "centos" ]]; then
  OS_VARIANT="centos"
fi

detect_package_manager() {
  case "${OS_ID} ${OS_LIKE}" in
    *ubuntu*|*debian*)
      command -v apt-get >/dev/null 2>&1 || die "当前系统缺少 apt-get"
      PKG_MANAGER="apt"
      ;;
    *centos*|*rhel*|*fedora*)
      if command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
      elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
      else
        die "当前 RPM 系系统缺少 dnf/yum"
      fi
      ;;
    *)
      if command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt"
      elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
      elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
      else
        die "不支持当前系统的包管理器"
      fi
      ;;
  esac
}

backup_managed_file() {
  local file="$1"
  [[ -e "${file}.sophon-original" ]] || run_root cp -a "$file" "${file}.sophon-original"
}

restore_managed_files() {
  local directory="$1"
  local backup
  while IFS= read -r backup; do
    [[ -n "$backup" ]] || continue
    run_root cp -a "$backup" "${backup%.sophon-original}"
  done < <(find "$directory" -type f -name '*.sophon-original' -print 2>/dev/null)
}

configure_apt_mirrors() {
  local family="$1"
  local prefix
  local ubuntu_base
  local ubuntu_ports_base
  local debian_base
  local debian_security_base
  local kali_base
  local file

  if [[ "$APT_MIRROR" == "official" ]]; then
    if [[ -d /etc/apt ]]; then
      restore_managed_files /etc/apt
    fi
    return
  fi

  case "$APT_MIRROR" in
    auto|aliyun) prefix="https://mirrors.aliyun.com" ;;
    tuna) prefix="https://mirrors.tuna.tsinghua.edu.cn" ;;
    ustc) prefix="https://mirrors.ustc.edu.cn" ;;
  esac
  ubuntu_base="${prefix}/ubuntu"
  ubuntu_ports_base="${prefix}/ubuntu-ports"
  debian_base="${prefix}/debian"
  debian_security_base="${prefix}/debian-security"
  kali_base="${prefix}/kali"

  while IFS= read -r -d '' file; do
    backup_managed_file "$file"
    run_root sed -i -E \
      -e "s#https?://(archive|security)\\.ubuntu\\.com/ubuntu#${ubuntu_base}#g" \
      -e "s#https?://ports\\.ubuntu\\.com/ubuntu-ports#${ubuntu_ports_base}#g" \
      -e "s#https?://(mirrors\\.aliyun\\.com|mirrors\\.tuna\\.tsinghua\\.edu\\.cn|mirrors\\.ustc\\.edu\\.cn)/ubuntu-ports#${ubuntu_ports_base}#g" \
      -e "s#https?://(mirrors\\.aliyun\\.com|mirrors\\.tuna\\.tsinghua\\.edu\\.cn|mirrors\\.ustc\\.edu\\.cn)/ubuntu#${ubuntu_base}#g" \
      -e "s#https?://(deb\\.debian\\.org|security\\.debian\\.org|mirrors\\.aliyun\\.com|mirrors\\.tuna\\.tsinghua\\.edu\\.cn|mirrors\\.ustc\\.edu\\.cn)/debian-security#${debian_security_base}#g" \
      -e "s#https?://(deb\\.debian\\.org|ftp\\.debian\\.org|mirrors\\.aliyun\\.com|mirrors\\.tuna\\.tsinghua\\.edu\\.cn|mirrors\\.ustc\\.edu\\.cn)/debian#${debian_base}#g" \
      -e "s#https?://(http\\.kali\\.org|mirror\\.rackspace\\.com|kali\\.download|mirrors\\.aliyun\\.com|mirrors\\.tuna\\.tsinghua\\.edu\\.cn|mirrors\\.ustc\\.edu\\.cn)/kali#${kali_base}#g" \
      "$file"
  done < <(find /etc/apt -maxdepth 3 -type f \( -name '*.list' -o -name '*.sources' \) -print0 2>/dev/null)
  info "已切换 ${family} 软件源: ${APT_MIRROR/auto/aliyun}"
}

configure_centos_mirrors() {
  local file
  local vault_version=""

  if [[ "$APT_MIRROR" == "official" ]]; then
    restore_managed_files /etc/yum.repos.d
    return
  fi
  [[ "$APT_MIRROR" == "auto" || "$APT_MIRROR" == "aliyun" ]] || \
    die "CentOS 当前仅支持 --apt-mirror auto/aliyun/official"

  if [[ "$OS_VARIANT" != "centos-stream" ]]; then
    case "$OS_MAJOR" in
      7) vault_version="7.9.2009" ;;
      8) vault_version="8.5.2111" ;;
    esac
  fi

  while IFS= read -r -d '' file; do
    backup_managed_file "$file"
    run_root sed -i -E \
      -e 's/^[[:space:]]*mirrorlist=/#mirrorlist=/' \
      -e 's/^[[:space:]]*metalink=/#metalink=/' \
      -e 's/^[[:space:]]*#baseurl=/baseurl=/' \
      -e 's#https?://mirror\.stream\.centos\.org#https://mirrors.aliyun.com/centos-stream#g' \
      -e 's#https?://download\.fedoraproject\.org/pub/epel#https://mirrors.aliyun.com/epel#g' \
      -e 's#https?://dl\.fedoraproject\.org/pub/epel#https://mirrors.aliyun.com/epel#g' \
      -e 's#https?://download\.example/pub/epel#https://mirrors.aliyun.com/epel#g' \
      "$file"
    if [[ -n "$vault_version" ]]; then
      run_root sed -i -E \
        -e "s#https?://mirror\\.centos\\.org/centos/\\\$releasever#https://mirrors.aliyun.com/centos-vault/${vault_version}#g" \
        -e "s#https?://mirror\\.centos\\.org/\\\$contentdir/\\\$releasever#https://mirrors.aliyun.com/centos-vault/${vault_version}#g" \
        -e "s#https?://mirror\\.centos\\.org#https://mirrors.aliyun.com/centos-vault#g" \
        -e "s#\\\$releasever#${vault_version}#g" \
        "$file"
    else
      run_root sed -i -E \
        -e 's#https?://mirror\.centos\.org/centos#https://mirrors.aliyun.com/centos#g' \
        -e 's#https?://mirror\.centos\.org#https://mirrors.aliyun.com/centos#g' \
        "$file"
    fi
  done < <(find /etc/yum.repos.d -maxdepth 1 -type f -name '*.repo' -print0 2>/dev/null)
  info "已切换 CentOS/RHEL 软件源: 阿里云"
}

configure_os_mirrors() {
  case "$PKG_MANAGER" in
    apt) configure_apt_mirrors "${OS_ID}" ;;
    dnf|yum) configure_centos_mirrors ;;
  esac
}

detect_package_manager

apt_lock_busy() {
  local log="$1"
  grep -Eq \
    'Could not get lock|Unable to acquire the dpkg frontend lock|dpkg frontend lock|is another process using it' \
    "$log"
}

run_apt() {
  local attempt log
  log="$(mktemp "${BUILD_ROOT}/apt-XXXXXX.log")"
  for ((attempt = 1; attempt <= APT_LOCK_RETRIES; attempt++)); do
    : >"$log"
    if run_root env DEBIAN_FRONTEND=noninteractive "$@" 2>&1 | tee "$log"; then
      return
    fi
    if apt_lock_busy "$log"; then
      warn "apt/dpkg 正被后台更新占用，等待锁释放（${attempt}/${APT_LOCK_RETRIES}）..."
      sleep "$APT_LOCK_DELAY"
      continue
    fi
    return 1
  done
  die "apt/dpkg 锁等待超时；请等待 unattended-upgrades 完成后重试"
}

run_pkg() {
  local attempt
  for ((attempt = 1; attempt <= 3; attempt++)); do
    if run_root "$@"; then
      return
    fi
    ((attempt == 3)) || {
      warn "软件包操作失败，3 秒后重试（${attempt}/3）..."
      sleep 3
    }
  done
  return 1
}

version_ge() {
  local current="$1" required="$2"
  [[ "$(printf '%s\n%s\n' "$required" "$current" | sort -V | head -n1)" == "$required" ]]
}

ensure_apt() {
  local package

  ((SKIP_SYSTEM_DEPS == 0)) || {
    warn "已跳过系统依赖安装"
    return
  }
  configure_os_mirrors
  info "安装系统依赖（${OS_NAME} / ${PKG_MANAGER}）..."
  case "$PKG_MANAGER" in
    apt)
      run_apt apt-get update
      run_apt apt-get install -y \
        ca-certificates curl unzip tar xz-utils git build-essential pkg-config \
        libsqlite3-dev sqlite3 libpcap-dev nginx python3 python3-venv python3-pip \
        default-jre-headless libcap2-bin openssl
      for package in nmap masscan whatweb sqlmap dirsearch; do
        if apt-cache show "$package" >/dev/null 2>&1; then
          run_apt apt-get install -y "$package" || \
            warn "可选依赖 $package 安装失败"
        else
          warn "当前 apt 源不提供 $package，稍后由工具校验提示"
        fi
      done
      ;;
    dnf|yum)
      run_pkg "$PKG_MANAGER" install -y epel-release || \
        warn "EPEL 安装失败，部分可选安全工具可能不可用"
      configure_os_mirrors
      local -a rpm_required=(
        ca-certificates curl unzip tar xz git gcc gcc-c++ make
        sqlite-devel sqlite libpcap-devel nginx python3 python3-pip
        libcap openssl
      )
      if ((OS_MAJOR >= 8)); then
        rpm_required+=(pkgconf-pkg-config java-17-openjdk-headless)
      else
        rpm_required+=(pkgconfig java-11-openjdk-headless)
      fi
      run_pkg "$PKG_MANAGER" makecache
      run_pkg "$PKG_MANAGER" install -y "${rpm_required[@]}"
      for package in nmap masscan whatweb sqlmap dirsearch; do
        if run_root "$PKG_MANAGER" info "$package" >/dev/null 2>&1; then
          run_pkg "$PKG_MANAGER" install -y "$package" || \
            warn "可选依赖 $package 安装失败"
        else
          warn "当前 yum/dnf 源不提供 $package，稍后由工具校验提示"
        fi
      done
      ;;
  esac
}

go_download_candidates() {
  local filename="go1.25.0.linux-${ARCH}.tar.gz"
  case "$GO_MIRROR" in
    official) printf 'https://go.dev/dl/%s\n' "$filename" ;;
    china)
      printf 'https://golang.google.cn/dl/%s\n' "$filename"
      printf 'https://mirrors.aliyun.com/golang/%s\n' "$filename"
      printf 'https://mirrors.nju.edu.cn/golang/%s\n' "$filename"
      ;;
    ustc)
      printf 'https://mirrors.ustc.edu.cn/golang/%s\n' "$filename"
      printf 'https://mirrors.aliyun.com/golang/%s\n' "$filename"
      printf 'https://mirrors.nju.edu.cn/golang/%s\n' "$filename"
      ;;
    aliyun)
      printf 'https://mirrors.aliyun.com/golang/%s\n' "$filename"
      printf 'https://mirrors.nju.edu.cn/golang/%s\n' "$filename"
      ;;
    nju) printf 'https://mirrors.nju.edu.cn/golang/%s\n' "$filename" ;;
    auto)
      printf 'https://mirrors.aliyun.com/golang/%s\n' "$filename"
      printf 'https://mirrors.nju.edu.cn/golang/%s\n' "$filename"
      printf 'https://golang.google.cn/dl/%s\n' "$filename"
      printf 'https://go.dev/dl/%s\n' "$filename"
      printf 'https://mirrors.ustc.edu.cn/golang/%s\n' "$filename"
      ;;
    *) printf '%s\n' "$GO_MIRROR" ;;
  esac
}

download_go_archive() {
  local url index=0 archive=""
  while IFS= read -r url; do
    [[ -n "$url" ]] || continue
    index=$((index + 1))
    archive="${BUILD_ROOT}/go-${index}.tar.gz"
    info "下载 Go 1.25.0: ${url}" >&2
    if curl -fL \
      --retry 4 \
      --retry-delay 2 \
      --connect-timeout 20 \
      --speed-limit 1024 \
      --speed-time 30 \
      "$url" -o "$archive"; then
      if tar -tzf "$archive" >/dev/null 2>&1; then
        printf '%s\n' "$archive"
        return
      fi
      warn "Go 下载包校验失败: ${url}" >&2
    else
      warn "Go 下载失败: ${url}" >&2
    fi
  done < <(go_download_candidates)
  return 1
}

ensure_go() {
  local go_bin=""
  if command -v go >/dev/null 2>&1; then
    local current
    current="$(go version | awk '{print $3}' | sed 's/^go//')"
    if version_ge "$current" "1.25.0"; then
      go_bin="$(command -v go)"
    fi
  fi
  if [[ -z "$go_bin" ]]; then
    local runtime="${APP_ROOT}/runtime/go"
    local archive="${BUILD_ROOT}/go.tar.gz"
    if [[ -x "$runtime/bin/go" ]] && version_ge "$("$runtime/bin/go" version | awk '{print $3}' | sed 's/^go//')" "1.25.0"; then
      go_bin="$runtime/bin/go"
    else
      archive="$(download_go_archive)" || die "Go 1.25.0 下载失败，可使用 --go-mirror 指定镜像"
      run_root mkdir -p "$runtime"
      run_root tar -xzf "$archive" -C "$runtime" --strip-components=1
      go_bin="$runtime/bin/go"
    fi
  fi
  export PATH="$(dirname "$go_bin"):$PATH"
  ok "Go: $("$go_bin" version)"
}

configure_go_proxy() {
  export GOPROXY="$GOPROXY_VALUE"
  go env -w GOPROXY="$GOPROXY_VALUE"
  ok "Go 模块代理: $GOPROXY_VALUE"
}

node_download_candidates() {
  case "$NODE_MIRROR" in
    official) printf '%s\n' 'https://nodejs.org/dist/v20.20.2' ;;
    aliyun) printf '%s\n' 'https://mirrors.aliyun.com/nodejs-release/v20.20.2' ;;
    npmmirror) printf '%s\n' 'https://npmmirror.com/mirrors/node/v20.20.2' ;;
    auto)
      printf '%s\n' 'https://mirrors.aliyun.com/nodejs-release/v20.20.2'
      printf '%s\n' 'https://npmmirror.com/mirrors/node/v20.20.2'
      printf '%s\n' 'https://nodejs.org/dist/v20.20.2'
      ;;
    *) printf '%s\n' "${NODE_MIRROR%/}" ;;
  esac
}

download_node_archive() {
  local name="$1"
  local destination="$2"
  local base index=0 candidate checksum_file checksum_url expected actual
  while IFS= read -r base; do
    [[ -n "$base" ]] || continue
    index=$((index + 1))
    candidate="${BUILD_ROOT}/node-candidate-${index}.tar.xz"
    checksum_file="${BUILD_ROOT}/node-SHASUMS-${index}.txt"
    info "下载 Node.js 20.20.2: ${base}/${name}.tar.xz" >&2
    if ! curl -fL \
      --retry 3 \
      --connect-timeout 20 \
      --speed-limit 1024 \
      --speed-time 30 \
      "${base}/${name}.tar.xz" -o "$candidate"; then
      warn "Node.js 下载失败: ${base}" >&2
      continue
    fi

    expected=""
    for checksum_url in \
      "${base}/SHASUMS256.txt" \
      "https://nodejs.org/dist/v20.20.2/SHASUMS256.txt"; do
      if curl -fsSL --connect-timeout 20 "$checksum_url" -o "$checksum_file"; then
        expected="$(awk -v file="${name}.tar.xz" '$2 == file { print $1; exit }' "$checksum_file")"
        [[ -n "$expected" ]] && break
      fi
    done
    actual="$(sha256sum "$candidate" | awk '{print $1}')"
    if [[ -z "$expected" || "$actual" != "$expected" ]]; then
      warn "Node.js SHA256 校验失败: ${base}" >&2
      continue
    fi
    mv "$candidate" "$destination"
    printf '%s\n' "$destination"
    return
  done < <(node_download_candidates)
  return 1
}

ensure_node() {
  local node_bin=""
  local pnpm_current=""
  if command -v node >/dev/null 2>&1; then
    local current major
    current="$(node --version | sed 's/^v//')"
    major="${current%%.*}"
    ((major >= 20)) && node_bin="$(command -v node)"
  fi
  if [[ -z "$node_bin" ]]; then
    local runtime="${APP_ROOT}/runtime/node"
    local name="node-v20.20.2-linux-${NODE_ARCH}"
    local archive="${BUILD_ROOT}/${name}.tar.xz"
    archive="$(download_node_archive "$name" "$archive")" || \
      die "Node.js 20.20.2 下载失败，可使用 --node-mirror 指定镜像目录"
    run_root mkdir -p "$runtime"
    run_root tar -xJf "$archive" -C "$runtime" --strip-components=1
    node_bin="$runtime/bin/node"
  fi
  export PATH="$(dirname "$node_bin"):$PATH"
  if command -v pnpm >/dev/null 2>&1; then
    pnpm_current="$(pnpm --version 2>/dev/null || true)"
  fi
  if [[ "$pnpm_current" != "$PNPM_VERSION" ]]; then
    info "安装 Node 20 兼容的 pnpm ${PNPM_VERSION}..."
    run_root env PATH="$PATH" npm install --global --prefix "${APP_ROOT}/runtime/node" "pnpm@${PNPM_VERSION}"
    export PATH="${APP_ROOT}/runtime/node/bin:$PATH"
  fi
  pnpm_current="$(pnpm --version 2>/dev/null || true)"
  [[ "$pnpm_current" == "$PNPM_VERSION" ]] || \
    die "pnpm 版本验证失败，需要 ${PNPM_VERSION}，当前: ${pnpm_current:-不可用}"
  ok "Node: $(node --version)，pnpm: ${pnpm_current}"
}

build_sophon() {
  info "构建后端..."
  (
    cd "$ROOT_DIR/backend"
    CGO_ENABLED=1 "$(command -v go)" build -trimpath -ldflags="-s -w" -o "${BUILD_ROOT}/sophon-server" ./cmd/server
    CGO_ENABLED=1 "$(command -v go)" build -trimpath -ldflags="-s -w" -o "${BUILD_ROOT}/sophon-mcp-tools" ./cmd/mcp-tools
    CGO_ENABLED=1 "$(command -v go)" build -trimpath -ldflags="-s -w" -o "${BUILD_ROOT}/sophon-tool-runner" ./cmd/tool-runner
  )
  info "构建前端..."
  (
    cd "$ROOT_DIR/frontend"
    pnpm install --frozen-lockfile
    pnpm run build
  )
}

password_value() {
  if [[ -n "$ADMIN_PASSWORD" ]]; then
    return
  fi
  if [[ -t 0 ]]; then
    read -rsp "初始管理员密码（回车自动生成）: " ADMIN_PASSWORD
    printf '\n'
  fi
  if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20)"
    warn "已自动生成管理员密码: $ADMIN_PASSWORD"
  fi
  [[ "$ADMIN_PASSWORD" != *$'\n'* ]] || die "管理员密码不能包含换行"
}

set_config_password() {
  local config_file="$1"
  run_root env CONFIG_PASSWORD="$ADMIN_PASSWORD" python3 - "$config_file" <<'PY'
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
}

copy_release() {
  local backup_dir="${APP_ROOT}/.backups/$(date +%Y%m%d-%H%M%S)"
  if [[ -e "${APP_ROOT}/backend/sophon-server" ]]; then
    ((FORCE_REINSTALL == 1)) || die "${APP_ROOT} 已安装 Sophon；升级请加 --force-reinstall"
    info "备份现有程序、配置和数据库元数据..."
    run_root mkdir -p "$backup_dir"
    run_root cp -a "${APP_ROOT}/backend" "$backup_dir/backend"
    run_root cp -a "${APP_ROOT}/frontend/dist" "$backup_dir/frontend-dist"
    [[ -f "${APP_ROOT}/config.yml" ]] && run_root cp -a "${APP_ROOT}/config.yml" "$backup_dir/config.yml"
    if [[ -f "${APP_ROOT}/data/sophon.db" ]]; then
      run_root cp -a "${APP_ROOT}/data/sophon.db" "$backup_dir/sophon.db"
    fi
  fi

  run_root mkdir -p \
    "${APP_ROOT}/backend" "${APP_ROOT}/frontend/dist" "${APP_ROOT}/data" \
    "${APP_ROOT}/deploy" "${APP_ROOT}/roles" "${APP_ROOT}/skills" \
    "${APP_ROOT}/tools" "${APP_ROOT}/thirdTools" "${APP_ROOT}/licenses"
  run_root install -m 0755 "${BUILD_ROOT}/sophon-server" "${APP_ROOT}/backend/sophon-server"
  run_root install -m 0755 "${BUILD_ROOT}/sophon-mcp-tools" "${APP_ROOT}/backend/sophon-mcp-tools"
  run_root install -m 0755 "${BUILD_ROOT}/sophon-tool-runner" "${APP_ROOT}/backend/sophon-tool-runner"
  run_root cp -a "$ROOT_DIR/frontend/dist/." "${APP_ROOT}/frontend/dist/"
  for name in deploy roles skills tools licenses; do
    run_root cp -a "$ROOT_DIR/${name}/." "${APP_ROOT}/${name}/"
  done
  if [[ -d "$ROOT_DIR/thirdTools" ]] && [[ -n "$(find "$ROOT_DIR/thirdTools" -type f -print -quit)" ]]; then
    run_root cp -a "$ROOT_DIR/thirdTools/." "${APP_ROOT}/thirdTools/"
  else
    warn "未提供 thirdTools；平台将使用系统命令环境，用户可稍后上传工具"
  fi
  run_root find "${APP_ROOT}/deploy" "${APP_ROOT}/tools" -type f -exec sed -i "s|/opt/sophon|${APP_ROOT}|g" {} +
  run_root sed -i "s|listen 8080;|listen ${HTTP_PORT};|g" "${APP_ROOT}/deploy/nginx/nginx.conf"

  if [[ ! -f "${APP_ROOT}/config.yml" ]]; then
    run_root cp "$ROOT_DIR/config.example.yml" "${APP_ROOT}/config.yml"
    run_root sed -i "s|/opt/sophon|${APP_ROOT}|g; s|data_dir: ./data|data_dir: ${APP_ROOT}/data|" "${APP_ROOT}/config.yml"
    password_value
    set_config_password "${APP_ROOT}/config.yml"
  else
    info "沿用已有 config.yml"
  fi
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

install_python_deps() {
  local index
  local attempt
  local selected_index=""
  info "创建 Python 虚拟环境..."
  run_root python3 -m venv "${APP_ROOT}/venv"
  while IFS= read -r index; do
    [[ -n "$index" ]] || continue
    for ((attempt = 1; attempt <= PIP_RETRIES; attempt++)); do
      info "安装 Python 依赖，源 ${index}（${attempt}/${PIP_RETRIES}）..."
      if run_root env PIP_INDEX_URL="$index" PIP_DEFAULT_TIMEOUT=30 \
        "${APP_ROOT}/venv/bin/pip" install --disable-pip-version-check \
        --no-cache-dir --retries 1 requests httpx h2 impacket; then
        selected_index="$index"
        break
      fi
      ((attempt == PIP_RETRIES)) || sleep "$PIP_DELAY"
    done
    [[ -z "$selected_index" ]] || break
  done < <(pip_index_candidates)
  [[ -n "$selected_index" ]] || die "Python 依赖安装失败，已尝试配置中的国内源"
  printf '[global]\nindex-url = %s\n' "$selected_index" >"${BUILD_ROOT}/pip.conf"
  run_root install -m 0644 "${BUILD_ROOT}/pip.conf" "${APP_ROOT}/venv/pip.conf"
  ok "Python 包源: $selected_index"
}

extract_zip_binary() {
  local archive="$1" member="$2" destination="$3"
  [[ -f "$archive" ]] || return 1
  unzip -p "$archive" "$member" > "${BUILD_ROOT}/tool-bin"
  run_root install -m 0755 "${BUILD_ROOT}/tool-bin" "$destination"
}

install_third_tools() {
  ((SKIP_TOOLS == 1)) && {
    warn "已跳过第三方安全工具安装"
    return
  }
  if [[ ! -d "$ROOT_DIR/thirdTools" ]] || [[ -z "$(find "$ROOT_DIR/thirdTools" -type f -print -quit)" ]]; then
    warn "未提供 bundled thirdTools，跳过工具解压；可稍后上传到 ${APP_ROOT}/thirdTools"
    return
  fi
  local target="${APP_ROOT}/thirdTools"
  info "安装本地可选 thirdTools..."
  if [[ "$ARCH" == "amd64" ]]; then
    extract_zip_binary "$ROOT_DIR/thirdTools/naabu_2.6.1_linux_amd64.zip" naabu "$target/naabu" || warn "未安装 naabu"
    extract_zip_binary "$ROOT_DIR/thirdTools/httpx_1.12.0_linux_amd64.zip" httpx "$target/httpx" || warn "未安装 httpx"
    extract_zip_binary "$ROOT_DIR/thirdTools/katana_1.8.0_linux_amd64.zip" katana "$target/katana" || warn "未安装 katana"
  else
    extract_zip_binary "$ROOT_DIR/thirdTools/naabu_2.6.1_linux_arm64.zip" naabu "$target/naabu" || warn "未安装 naabu"
    extract_zip_binary "$ROOT_DIR/thirdTools/httpx_1.12.0_linux_arm64.zip" httpx "$target/httpx" || warn "未安装 httpx"
    extract_zip_binary "$ROOT_DIR/thirdTools/katana_1.8.0_linux_arm64.zip" katana "$target/katana" || warn "未安装 katana"
  fi

  if ! extract_zip_binary "$ROOT_DIR/thirdTools/ksubdomain_linux.zip" ksubdomain "$target/ksubdomain"; then
    if [[ -f "$ROOT_DIR/thirdTools/ksubdomain-main.zip" ]]; then
      info "预编译 ksubdomain 不可用，尝试从源码构建..."
      local src="${BUILD_ROOT}/ksubdomain-src"
      mkdir -p "$src"
      unzip -oq "$ROOT_DIR/thirdTools/ksubdomain-main.zip" -d "$src"
      local dir
      dir="$(find "$src" -maxdepth 2 -name go.mod -printf '%h\n' | head -n1)"
      [[ -n "$dir" ]] || die "ksubdomain 源码包缺少 go.mod"
      (cd "$dir" && CGO_ENABLED=1 "$(command -v go)" build -trimpath -o "${BUILD_ROOT}/ksubdomain" .)
      run_root install -m 0755 "${BUILD_ROOT}/ksubdomain" "$target/ksubdomain"
    else
      warn "未安装 ksubdomain"
    fi
  fi

  if [[ "$ARCH" == "amd64" ]]; then
    if [[ -f "$ROOT_DIR/thirdTools/suo5-linux-amd64" ]]; then
      run_root install -m 0755 "$ROOT_DIR/thirdTools/suo5-linux-amd64" "$target/suo5-linux-amd64"
    fi
    if [[ -f "$ROOT_DIR/thirdTools/urlfinder" ]]; then
      run_root install -m 0755 "$ROOT_DIR/thirdTools/urlfinder" "$target/urlfinder"
    fi
  else
    if [[ -f "$ROOT_DIR/thirdTools/suo5-linux-arm64" ]]; then
      run_root install -m 0755 "$ROOT_DIR/thirdTools/suo5-linux-arm64" "$target/suo5-linux-arm64"
    fi
    [[ -f "$ROOT_DIR/thirdTools/urlfinder" ]] || warn "urlfinder 未提供，当前 arm64 环境跳过"
  fi
  if [[ -d "$ROOT_DIR/thirdTools/jadx" ]]; then
    run_root mkdir -p "$target/jadx"
    run_root cp -a "$ROOT_DIR/thirdTools/jadx/." "$target/jadx/"
  fi
  for script_name in decompile.py host_collision.py bypass403.py; do
    if [[ -f "$ROOT_DIR/thirdTools/${script_name}" ]]; then
      run_root cp -a "$ROOT_DIR/thirdTools/${script_name}" "$target/"
    fi
  done

  if [[ "$ARCH" == "amd64" ]] && [[ -f "$ROOT_DIR/thirdTools/ILSpy_linux-x64_11.2.0.10050.zip" ]]; then
    local ilspy_dir="${BUILD_ROOT}/ilspy"
    mkdir -p "$ilspy_dir"
    unzip -oq "$ROOT_DIR/thirdTools/ILSpy_linux-x64_11.2.0.10050.zip" -d "$ilspy_dir"
    run_root mkdir -p "$target/ilspycmd"
    run_root cp -a "$ilspy_dir/." "$target/ilspycmd/"
  else
    warn "未安装 ILSpy cmd"
  fi

  if [[ -f "${APP_ROOT}/deploy/container/set-tool-caps.sh" ]]; then
    run_root sh "${APP_ROOT}/deploy/container/set-tool-caps.sh"
  fi
}

stop_existing() {
  ((FORCE_REINSTALL == 1)) || return 0
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet sophon.service 2>/dev/null; then
    info "停止现有 Sophon systemd 服务..."
    run_root systemctl stop sophon.service || true
  elif [[ -x "${APP_ROOT}/deploy/container/stop.sh" ]]; then
    info "停止现有 Sophon 进程..."
    run_root env SOPHON_APP_ROOT="$APP_ROOT" sh "${APP_ROOT}/deploy/container/stop.sh" || true
  fi
}

validate_runtime() {
  local missing=()
  for command_name in nginx python3 sqlite3 curl unzip; do
    command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
  done
  for command_name in nmap masscan sqlmap whatweb dirsearch; do
    command -v "$command_name" >/dev/null 2>&1 || warn "可选工具未找到: $command_name"
  done
  ((${#missing[@]} == 0)) || die "缺少核心命令: ${missing[*]}"
}

install_service() {
  command -v systemctl >/dev/null 2>&1 || {
    warn "未检测到 systemd，将直接启动"
    return 1
  }
  local unit="/etc/systemd/system/sophon.service"
  run_root tee "$unit" >/dev/null <<EOF
[Unit]
Description=Sophon Security Platform
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=PATH=${APP_ROOT}/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=SOPHON_APP_ROOT=${APP_ROOT}
ExecStart=/bin/sh ${APP_ROOT}/deploy/container/start.sh
ExecStop=/bin/sh ${APP_ROOT}/deploy/container/stop.sh
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
EOF
  run_root systemctl daemon-reload
  run_root systemctl enable sophon.service
}

start_sophon() {
  ((NO_START == 0)) || {
    warn "已跳过启动"
    return
  }
  if install_service; then
    run_root systemctl restart sophon.service
  else
    PATH="${APP_ROOT}/venv/bin:$PATH" SOPHON_APP_ROOT="$APP_ROOT" /bin/sh "${APP_ROOT}/deploy/container/start.sh"
  fi
  ok "Sophon 已启动: http://127.0.0.1:${HTTP_PORT}/"
}

main() {
  local stamp
  stamp="$(date +%Y%m%d-%H%M%S)"
  BUILD_ROOT="$(mktemp -d "/tmp/sophon-install-${stamp}.XXXXXX")"
  ensure_apt
  ensure_go
  configure_go_proxy
  ensure_node
  stop_existing
  build_sophon
  copy_release
  install_python_deps
  install_third_tools
  validate_runtime
  start_sophon
  ok "安装完成，数据目录: ${APP_ROOT}/data"
}

main "$@"
