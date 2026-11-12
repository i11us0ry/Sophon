#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/up2git"
REDACTIONS_FILE="${ROOT_DIR}/.release-redactions.tsv"
REPLACE=0
CHECK_ONLY=0
SKIP_TESTS=0
STAGE_DIR=""
GO_BIN="${GO_BIN:-go}"

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok() { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
准备 Sophon Git 发布目录

用法:
  ./scripts/prepare-release.sh [选项]

选项:
  --output PATH            发布目录，默认 ./up2git
  --replace                发布成功后将旧目录移动到时间戳备份
  --check-only             仅扫描现有发布目录
  --skip-tests             跳过发布副本后端测试
  --redactions PATH        指定本地脱敏映射，默认 ./.release-redactions.tsv
  -h, --help               显示帮助

脱敏映射文件格式:
  每行使用“原始值<TAB>替换值”，# 开头为注释。
  该文件只用于本地发布，不应提交，也不会复制到发布目录。
EOF
}

while (($#)); do
  case "$1" in
    --output) OUTPUT_DIR="${2:?--output 缺少参数}"; shift 2 ;;
    --replace) REPLACE=1; shift ;;
    --check-only) CHECK_ONLY=1; shift ;;
    --skip-tests) SKIP_TESTS=1; shift ;;
    --redactions) REDACTIONS_FILE="${2:?--redactions 缺少参数}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数: $1" ;;
  esac
done

[[ "$OUTPUT_DIR" == /* ]] || OUTPUT_DIR="${ROOT_DIR}/${OUTPUT_DIR}"
[[ "$REDACTIONS_FILE" == /* ]] || REDACTIONS_FILE="${ROOT_DIR}/${REDACTIONS_FILE}"
[[ "$OUTPUT_DIR" != "/" ]] || die "发布目录不能是根目录"

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"
}

for command_name in rsync rg perl find awk du; do
  require_command "$command_name"
done

redaction_sources() {
  [[ -f "$REDACTIONS_FILE" ]] || return 0
  awk -F '\t' '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    NF < 2 { exit 2 }
    $1 != "" { print $1 }
  ' "$REDACTIONS_FILE"
}

validate_redactions() {
  [[ -f "$REDACTIONS_FILE" ]] || {
    warn "未找到脱敏映射 ${REDACTIONS_FILE}，仅执行通用敏感检测"
    return
  }
  awk -F '\t' '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    NF < 2 { printf "脱敏映射第 %d 行缺少 TAB: %s\n", NR, $0 > "/dev/stderr"; exit 1 }
  ' "$REDACTIONS_FILE"
}

common_excludes=(
  --exclude='.DS_Store'
  --exclude='*.bak'
  --exclude='*.bak.*'
  --exclude='*.orig'
  --exclude='*.rej'
  --exclude='*.pyc'
  --exclude='__pycache__/'
)

copy_tree() {
  local source="$1"
  local target="$2"
  shift 2
  mkdir -p "$target"
  rsync -a "${common_excludes[@]}" "$@" "${source}/" "${target}/"
}

copy_release() {
  local release="$1"
  info "复制发布资源..."
  copy_tree "${ROOT_DIR}/backend" "${release}/backend" \
    --exclude='/server' \
    --exclude='/sophon-server' \
    --exclude='/sophon-mcp-tools' \
    --exclude='/sophon-tool-runner'
  copy_tree "${ROOT_DIR}/frontend" "${release}/frontend" \
    --exclude='node_modules/' \
    --exclude='dist/' \
    --exclude='*.tsbuildinfo' \
    --exclude='vite.config.js' \
    --exclude='vite.config.d.ts' \
    --exclude='src/*.js' \
    --exclude='src/**/*.js'
  copy_tree "${ROOT_DIR}/deploy" "${release}/deploy"
  copy_tree "${ROOT_DIR}/roles" "${release}/roles"
  copy_tree "${ROOT_DIR}/skills" "${release}/skills"
  copy_tree "${ROOT_DIR}/tools" "${release}/tools"
  copy_tree "${ROOT_DIR}/screenshots" "${release}/screenshots"
  copy_tree "${ROOT_DIR}/mcp-servers" "${release}/mcp-servers"
  copy_tree "${ROOT_DIR}/licenses" "${release}/licenses"
  copy_tree "${ROOT_DIR}/scripts" "${release}/scripts"

  cp "${ROOT_DIR}/README.md" "${release}/README.md"
  cp "${ROOT_DIR}/config.example.yml" "${release}/config.example.yml"
  cp "${ROOT_DIR}/install.sh" "${release}/install.sh"
  cp "${ROOT_DIR}/install-docker.sh" "${release}/install-docker.sh"
  cp "${ROOT_DIR}/.gitignore" "${release}/.gitignore"
  chmod 0755 "${release}/install.sh" "${release}/install-docker.sh"
  chmod 0755 "${release}/scripts/"*.sh
}

move_os_metadata() {
  local release="$1"
  local file target
  local index=0
  mkdir -p "${ROOT_DIR}/.release-excluded"
  while IFS= read -r -d '' file; do
    index=$((index + 1))
    target="${ROOT_DIR}/.release-excluded/$(date +%Y%m%d-%H%M%S)-${index}-${file##*/}"
    mv "$file" "$target"
  done < <(find "$release" -type f \( -name '.DS_Store' -o -name '._*' \) -print0)
}

sanitize_release() {
  local release="$1"
  [[ -f "$REDACTIONS_FILE" ]] || return
  info "应用本地脱敏映射..."
  while IFS=$'\t' read -r source replacement; do
    [[ -n "${source:-}" ]] || continue
    [[ "$source" == \#* ]] && continue
    [[ -n "${replacement:-}" ]] || replacement=""
    while IFS= read -r -d '' file; do
      RELEASE_SOURCE="$source" RELEASE_REPLACEMENT="$replacement" \
        LC_ALL=C perl -pi -e \
        's/\Q$ENV{RELEASE_SOURCE}\E/$ENV{RELEASE_REPLACEMENT}/g' "$file"
    done < <(
      find "$release" -path "${release}/.git" -prune -o -type f \( \
        -name '*.go' -o -name '*.ts' -o -name '*.js' -o -name '*.vue' \
        -o -name '*.py' -o -name '*.md' -o -name '*.yaml' -o -name '*.yml' \
        -o -name '*.json' -o -name '*.sh' -o -name '*.txt' -o -name '*.conf' \
        -o -name '*.example' -o -name 'Dockerfile' -o -name '.gitignore' \
      \) -print0
    )
  done < "$REDACTIONS_FILE"
}

scan_release() {
  local release="$1"
  local hits=""
  [[ -d "$release" ]] || die "发布目录不存在: ${release}"
  info "扫描敏感信息..."

  if [[ -f "$REDACTIONS_FILE" ]]; then
    hits="$(rg -a -l --glob '!.git/**' -F -f <(redaction_sources) "$release" 2>/dev/null || true)"
    [[ -z "$hits" ]] || {
      printf '%s\n' "$hits" >&2
      die "发布目录仍包含脱敏映射中的原始值"
    }
  fi

  hits="$(
    while IFS= read -r -d '' file; do
      [[ "$file" == "${release}/scripts/prepare-release.sh" ]] && continue
      if rg -q \
        -e '/Users/[A-Za-z0-9._-]+/(Desktop|Documents|Downloads|work|projects)(/|$)' \
        -e '/home/[A-Za-z0-9._-]+/(Desktop|Documents|Downloads|work|projects)(/|$)' \
        -e 'sk-[A-Za-z0-9]{20,}' \
        "$file"; then
        printf '%s\n' "$file"
      elif rg -U -q -P \
        'BEGIN [A-Z ]*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{40,}' \
        "$file"; then
        printf '%s\n' "$file"
      fi
    done < <(
      find "$release" -path "${release}/.git" -prune -o -type f \( \
        -name '*.go' -o -name '*.ts' -o -name '*.js' -o -name '*.vue' \
        -o -name '*.py' -o -name '*.md' -o -name '*.yaml' -o -name '*.yml' \
        -o -name '*.json' -o -name '*.sh' -o -name '*.txt' -o -name '*.conf' \
        -o -name '*.example' -o -name '*.env' -o -name 'Dockerfile' \
        -o -name '.gitignore' \
      \) -print0
    )
  )"
  [[ -z "$hits" ]] || {
    printf '%s\n' "$hits" >&2
    die "发现本机绝对路径或疑似密钥"
  }

  hits="$(find "$release" -path "${release}/.git" -prune -o -type f \( \
    -name 'config.yml' -o -name '.env' -o -name '.DS_Store' \
    -o -name '*.bak' -o -name '*.bak.*' -o -name '*.pyc' \
    -o -name '*.tsbuildinfo' -o -path '*/node_modules/*' -o -path '*/dist/*' \
    -o -path "${release}/thirdTools" -o -path "${release}/thirdTools/*" \
  \) -print)"
  [[ -z "$hits" ]] || {
    printf '%s\n' "$hits" >&2
    die "发布目录包含禁止文件"
  }
  ok "敏感信息扫描通过"
}

validate_layout() {
  local release="$1"
  local path
  for path in \
    README.md config.example.yml install.sh install-docker.sh .gitignore \
    backend/go.mod frontend/package.json deploy/docker-compose.yml \
    roles skills tools mcp-servers licenses scripts; do
    [[ -e "${release}/${path}" ]] || die "发布目录缺少: ${path}"
  done
  [[ -s "${release}/README.md" ]] || die "README.md 为空"
  ok "发布目录结构检查通过"
}

run_tests() {
  local release="$1"
  ((SKIP_TESTS == 0)) || {
    warn "已跳过发布副本测试"
    return
  }
  command -v "$GO_BIN" >/dev/null 2>&1 || die "缺少 Go 命令: ${GO_BIN}"
  info "运行发布副本后端测试..."
  (
    cd "${release}/backend"
    "$GO_BIN" test ./... -count=1
  )
  (
    cd "$release"
    bash -n install.sh install-docker.sh scripts/*.sh
  )
  ok "发布副本测试通过"
}

publish_release() {
  local release="$1"
  local backup=""
  local preserve_git=0
  if [[ -e "$OUTPUT_DIR" ]]; then
    ((REPLACE == 1)) || die "发布目录已存在；确认替换时使用 --replace"
    [[ ! -L "$OUTPUT_DIR" ]] || die "发布目录不能是符号链接"
    if [[ -d "${OUTPUT_DIR}/.git" ]]; then
      preserve_git=1
    fi
    backup="${OUTPUT_DIR}.backup.$(date +%Y%m%d-%H%M%S)-$$"
    info "移动旧发布目录到 ${backup}"
    mv "$OUTPUT_DIR" "$backup"
  fi
  mv "$release" "$OUTPUT_DIR"
  STAGE_DIR=""
  if ((preserve_git == 1)) && [[ -d "${backup}/.git" ]]; then
    cp -a "${backup}/.git" "${OUTPUT_DIR}/.git"
    ok "已保留 Git 仓库元数据"
  fi
  move_os_metadata "$OUTPUT_DIR"
  scan_release "$OUTPUT_DIR"
  ok "发布目录已生成: ${OUTPUT_DIR}"
  [[ -z "$backup" ]] || ok "旧发布目录备份: ${backup}"
  du -sh "$OUTPUT_DIR"
}

validate_redactions

if ((CHECK_ONLY == 1)); then
  scan_release "$OUTPUT_DIR"
  validate_layout "$OUTPUT_DIR"
  ok "现有发布目录检查通过"
  exit 0
fi

if [[ -e "$OUTPUT_DIR" ]] && ((REPLACE == 0)); then
  die "发布目录已存在；使用 --replace 生成新目录，或使用 --check-only 检查"
fi

STAGE_DIR="$(mktemp -d "${ROOT_DIR}/.release-stage.XXXXXX")"
info "临时发布目录: ${STAGE_DIR}"
copy_release "$STAGE_DIR"
sanitize_release "$STAGE_DIR"
scan_release "$STAGE_DIR"
validate_layout "$STAGE_DIR"
run_tests "$STAGE_DIR"
publish_release "$STAGE_DIR"
