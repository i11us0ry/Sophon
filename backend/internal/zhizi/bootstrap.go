package zhizi

const InitializationScript = `#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || { echo "需要 root 或 sudo 权限"; exit 1; }
  sudo -n true || { echo "当前用户没有免密 sudo 权限"; exit 1; }
  SUDO="sudo -n"
fi

PACKAGE_MANAGER=""
if command -v apt-get >/dev/null 2>&1; then
  PACKAGE_MANAGER="apt"
elif command -v dnf >/dev/null 2>&1; then
  PACKAGE_MANAGER="dnf"
elif command -v yum >/dev/null 2>&1; then
  PACKAGE_MANAGER="yum"
elif command -v apk >/dev/null 2>&1; then
  PACKAGE_MANAGER="apk"
else
  echo "不支持的 Linux 包管理器，仅支持 apt、dnf、yum、apk"
  exit 1
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_SOURCES=()
BACKUP_FILES=()
PACKAGES=()
MIRROR_CHANGED=0

is_domestic_host() {
  case "$1" in
    *.cn|mirrors.tuna.tsinghua.edu.cn|mirrors.aliyun.com|mirrors.cloud.tencent.com|\
    repo.huaweicloud.com|mirrors.huaweicloud.com|mirrors.ustc.edu.cn|\
    mirrors.nju.edu.cn|mirrors.sjtug.sjtu.edu.cn|mirrors.hust.edu.cn|\
    mirrors.zju.edu.cn|mirrors.163.com|mirrors.sohu.com)
      return 0
      ;;
  esac
  return 1
}

repository_is_domestic() {
  local file="$1"
  local urls url host saw_url=false
  urls="$(grep -Eo 'https?://[^[:space:]]+' "$file" 2>/dev/null || true)"
  [ -n "$urls" ] || return 1
  while IFS= read -r url; do
    [ -n "$url" ] || continue
    saw_url=true
    host="${url#*://}"
    host="${host%%/*}"
    host="${host%%\?*}"
    host="${host%%:*}"
    is_domestic_host "$host" || return 1
  done <<< "$urls"
  [ "$saw_url" = true ]
}

backup_repository_file() {
  local file="$1"
  local backup="${file}.sophon-backup.${STAMP}"
  cp -p "$file" "$backup"
  BACKUP_SOURCES+=("$file")
  BACKUP_FILES+=("$backup")
  echo "已备份软件源：$file -> $backup"
}

rewrite_repository_hosts() {
  local file="$1"
  local mirror="$2"
  sed -i -E "s#https?://[^/[:space:]\"'<>]+#https://${mirror}#g" "$file"
}

restore_repository_backups() {
  local index
  if [ "${#BACKUP_SOURCES[@]}" -eq 0 ]; then
    return
  fi
  echo "软件源刷新失败，正在恢复原配置"
  for index in "${!BACKUP_SOURCES[@]}"; do
    cp -p "${BACKUP_FILES[$index]}" "${BACKUP_SOURCES[$index]}"
    echo "已恢复：${BACKUP_SOURCES[$index]}"
  done
}

rewrite_file_set() {
  local mirror="$1"
  shift
  local file
  for file in "$@"; do
    [ -f "$file" ] || continue
    grep -Eq 'https?://' "$file" || continue
    if repository_is_domestic "$file"; then
      echo "软件源已在国内：$file"
      continue
    fi
    backup_repository_file "$file"
    rewrite_repository_hosts "$file" "$mirror"
    MIRROR_CHANGED=$((MIRROR_CHANGED + 1))
    echo "已替换软件源：$file -> https://$mirror"
  done
}

configure_repositories() {
  local files=()
  case "$PACKAGE_MANAGER" in
    apt)
      mapfile -t files < <(
        find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) \
          ! -name '*.sophon-backup.*' | sort
      )
      if [ "${#files[@]}" -gt 0 ]; then
        rewrite_file_set "mirrors.tuna.tsinghua.edu.cn" "${files[@]}"
      fi
      ;;
    dnf|yum)
      mapfile -t files < <(
        find /etc/yum.repos.d -maxdepth 1 -type f -name '*.repo' \
          ! -name '*.sophon-backup.*' | sort
      )
      if [ "${#files[@]}" -gt 0 ]; then
        rewrite_file_set "mirrors.aliyun.com" "${files[@]}"
      fi
      ;;
    apk)
      if [ -f /etc/apk/repositories ]; then
        rewrite_file_set "mirrors.tuna.tsinghua.edu.cn" /etc/apk/repositories
      fi
      ;;
  esac
}

refresh_package_metadata() {
  case "$PACKAGE_MANAGER" in
    apt)
      $SUDO apt-get update
      ;;
    dnf)
      $SUDO dnf makecache
      ;;
    yum)
      $SUDO yum makecache
      ;;
    apk)
      $SUDO apk update
      ;;
  esac
}

append_package() {
  local package="$1"
  local existing
  if [ "${#PACKAGES[@]}" -gt 0 ]; then
    for existing in "${PACKAGES[@]}"; do
      [ "$existing" = "$package" ] && return
    done
  fi
  PACKAGES+=("$package")
}

need_command() {
  local command_name="$1"
  local package="$2"
  command -v "$command_name" >/dev/null 2>&1 || append_package "$package"
}

php_has_extension() {
  command -v php >/dev/null 2>&1 && php -m 2>/dev/null | grep -Eiq "^$1$"
}

collect_needed_packages() {
  local dns_package php_cli php_curl php_mbstring php_xml php_zip java_package proc_package
  case "$PACKAGE_MANAGER" in
    apt)
      dns_package="dnsutils"
      php_cli="php-cli"
      php_curl="php-curl"
      php_mbstring="php-mbstring"
      php_xml="php-xml"
      php_zip="php-zip"
      java_package="default-jdk-headless"
      proc_package="procps"
      ;;
    dnf|yum)
      dns_package="bind-utils"
      php_cli="php-cli"
      php_curl=""
      php_mbstring="php-mbstring"
      php_xml="php-xml"
      php_zip="php-zip"
      java_package="java-17-openjdk-devel"
      proc_package="procps-ng"
      ;;
    apk)
      dns_package="bind-tools"
      php_cli="php83-cli"
      php_curl="php83-curl"
      php_mbstring="php83-mbstring"
      php_xml="php83-xml"
      php_zip="php83-zip"
      java_package="openjdk17"
      proc_package="procps"
      ;;
  esac

  if [ ! -f /etc/ssl/certs/ca-certificates.crt ] && [ ! -f /etc/pki/tls/certs/ca-bundle.crt ]; then
    append_package "ca-certificates"
  fi
  need_command curl curl
  need_command wget wget
  need_command git git
  need_command unzip unzip
  need_command zip zip
  need_command jq jq
  need_command vim vim
  need_command netstat net-tools
  need_command dig "$dns_package"
  need_command python3 python3
  case "$PACKAGE_MANAGER" in
    apt)
      need_command pip3 python3-pip
      if ! command -v python3 >/dev/null 2>&1 || ! python3 -m venv --help >/dev/null 2>&1; then
        append_package "python3-venv"
      fi
      ;;
    dnf|yum)
      need_command pip3 python3-pip
      ;;
    apk)
      need_command pip3 py3-pip
      ;;
  esac

  if ! command -v gcc >/dev/null 2>&1 || \
     ! command -v g++ >/dev/null 2>&1 || \
     ! command -v make >/dev/null 2>&1; then
    case "$PACKAGE_MANAGER" in
      apt)
        append_package "build-essential"
        ;;
      dnf|yum)
        append_package "gcc"
        append_package "gcc-c++"
        append_package "make"
        ;;
      apk)
        append_package "build-base"
        ;;
    esac
  fi

  need_command ps "$proc_package"
  need_command killall psmisc
  need_command php "$php_cli"
  php_has_extension mbstring || append_package "$php_mbstring"
  php_has_extension xml || append_package "$php_xml"
  php_has_extension zip || append_package "$php_zip"
  if [ -n "$php_curl" ]; then
    php_has_extension curl || append_package "$php_curl"
  fi
  need_command javac "$java_package"
  need_command mvn maven
}

install_missing_packages() {
  if [ "${#PACKAGES[@]}" -eq 0 ]; then
    echo "基础 Linux 工具均已存在，无需重复安装"
    return
  fi
  echo "需要安装的缺失工具：${PACKAGES[*]}"
  case "$PACKAGE_MANAGER" in
    apt)
      $SUDO apt-get install -y --no-install-recommends "${PACKAGES[@]}"
      ;;
    dnf)
      $SUDO dnf install -y "${PACKAGES[@]}"
      ;;
    yum)
      $SUDO yum install -y "${PACKAGES[@]}"
      ;;
    apk)
      $SUDO apk add --no-cache "${PACKAGES[@]}"
      ;;
  esac
}

install_composer_if_missing() {
  command -v composer >/dev/null 2>&1 && return
  echo "未检测到 Composer，尝试安装"
  case "$PACKAGE_MANAGER" in
    apt)
      $SUDO apt-get install -y --no-install-recommends composer || \
        echo "警告：当前 apt 源没有 composer 包，已跳过 Composer 安装"
      ;;
    dnf)
      $SUDO dnf install -y composer || \
        echo "警告：当前 dnf 源没有 composer 包，已跳过 Composer 安装"
      ;;
    yum)
      $SUDO yum install -y composer || \
        echo "警告：当前 yum 源没有 composer 包，已跳过 Composer 安装"
      ;;
    apk)
      $SUDO apk add --no-cache composer || \
        echo "警告：当前 apk 源没有 composer 包，已跳过 Composer 安装"
      ;;
  esac
}

configure_repositories
if ! refresh_package_metadata; then
  restore_repository_backups
  echo "软件包索引刷新失败，初始化终止"
  exit 1
fi

collect_needed_packages
install_missing_packages
install_composer_if_missing

python3 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
python3 -m pip config set global.trusted-host pypi.tuna.tsinghua.edu.cn

if command -v composer >/dev/null 2>&1; then
  composer config -g repos.packagist composer https://mirrors.aliyun.com/composer/
fi

if command -v mvn >/dev/null 2>&1; then
  mkdir -p "$HOME/.m2"
  cat > "$HOME/.m2/settings.xml" <<'MAVEN_SETTINGS'
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">
  <mirrors>
    <mirror>
      <id>aliyun</id>
      <name>Aliyun Maven</name>
      <url>https://maven.aliyun.com/repository/public</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
</settings>
MAVEN_SETTINGS
fi

echo "初始化完成；软件源替换数：$MIRROR_CHANGED"
python3 --version
php -v | head -n 1
java -version 2>&1 | head -n 1
git --version
`
