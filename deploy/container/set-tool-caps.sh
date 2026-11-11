#!/usr/bin/env sh
set -u

APP_ROOT="${SOPHON_APP_ROOT:-/opt/sophon}"
SETCAP_BIN="$(command -v setcap 2>/dev/null || true)"
GETCAP_BIN="$(command -v getcap 2>/dev/null || true)"

log() {
    printf '%s\n' "sophon raw capability: $*" >&2
}

apply_capability() {
    binary="$1"
    [ -e "${binary}" ] || return 0
    if [ -z "${SETCAP_BIN}" ]; then
        log "setcap unavailable, skipped ${binary}"
        return 0
    fi
    if "${SETCAP_BIN}" cap_net_raw+ep "${binary}" 2>/dev/null; then
        capabilities=""
        if [ -n "${GETCAP_BIN}" ]; then
            capabilities="$("${GETCAP_BIN}" "${binary}" 2>/dev/null || true)"
        fi
        log "${binary}: ${capabilities:-cap_net_raw=ep}"
        return 0
    fi
    log "failed to set cap_net_raw on ${binary}"
}

apply_capability "${APP_ROOT}/thirdTools/ksubdomain"
apply_capability "${APP_ROOT}/thirdTools/naabu"

for command_name in nmap masscan; do
    command_path="$(command -v "${command_name}" 2>/dev/null || true)"
    if [ -n "${command_path}" ]; then
        apply_capability "${command_path}"
    fi
done
