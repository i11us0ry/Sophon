#!/usr/bin/env python3
"""Manage a background suo5 tunnel without exposing it beyond loopback."""

from __future__ import annotations

import fcntl
import json
import os
import platform
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
from contextlib import contextmanager
from pathlib import Path
from typing import Any

STATE_DIR_NAME = ".suo5"
STATE_FILE_NAME = "state.json"
LOG_FILE_NAME = "suo5.log"
DEFAULT_PORT = 1111
START_READY_SECONDS = 3.0
STOP_READY_SECONDS = 3.0
ALLOWED_OPERATIONS = {"start", "status", "stop"}
ALLOWED_OPTIONS = {
    "target",
    "port",
    "method",
    "mode",
    "auth",
    "proxy",
    "header",
    "ua",
    "timeout",
    "retry",
    "debug",
    "no_gzip",
    "no_browser_headers",
}
ALLOWED_MODES = {"auto", "full", "half", "classic"}


class ManagerError(RuntimeError):
    pass


def workspace_root() -> Path:
    raw = (
        os.environ.get("SOPHON_CONVERSATION_WORKSPACE")
        or os.environ.get("SOPHON_WORKSPACE")
        or os.getcwd()
    )
    root = Path(raw).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def state_dir() -> Path:
    path = workspace_root() / STATE_DIR_NAME
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def state_path() -> Path:
    return state_dir() / STATE_FILE_NAME


@contextmanager
def manager_lock():
    directory = state_dir()
    lock_path = directory / "manager.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def read_state() -> dict[str, Any] | None:
    path = state_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise ManagerError(f"读取 suo5 状态失败: {exc}") from exc
    if not isinstance(payload, dict):
        raise ManagerError("suo5 状态文件格式不正确")
    return payload


def write_state(payload: dict[str, Any]) -> None:
    directory = state_dir()
    fd, temp_name = tempfile.mkstemp(prefix=".state-", suffix=".json", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, state_path())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def clear_state() -> None:
    try:
        state_path().unlink()
    except FileNotFoundError:
        pass


def process_start_ticks(pid: int) -> str | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        fields = stat[stat.rfind(")") + 2 :].split()
        return fields[19] if len(fields) > 19 else None
    except OSError:
        return None


def process_alive(state: dict[str, Any]) -> bool:
    try:
        pid = int(state.get("pid", 0))
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    expected_start = str(state.get("pid_start") or "")
    current_start = process_start_ticks(pid)
    if expected_start and current_start and expected_start != current_start:
        return False
    return True


def port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.25):
            return True
    except OSError:
        return False


def binary_path() -> Path:
    override = os.environ.get("SOPHON_SUO5_BINARY", "").strip()
    if override:
        candidate = Path(override).expanduser()
    else:
        machine = platform.machine().lower()
        arch = "arm64" if machine in {"aarch64", "arm64"} else "amd64"
        candidate = Path(f"/opt/sophon/thirdTools/suo5-linux-{arch}")
    if not candidate.is_file():
        raise ManagerError(f"suo5 二进制不存在: {candidate}")
    if not os.access(candidate, os.X_OK):
        raise ManagerError(f"suo5 二进制不可执行: {candidate}")
    return candidate


def parse_options(raw: str) -> dict[str, Any]:
    try:
        options = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise ManagerError(f"options_json 不是有效 JSON: {exc}") from exc
    if not isinstance(options, dict):
        raise ManagerError("options_json 必须是 JSON 对象")
    unknown = sorted(set(options) - ALLOWED_OPTIONS)
    if unknown:
        raise ManagerError(f"不支持的 suo5 参数: {', '.join(unknown)}")
    return options


def parse_target(value: Any) -> str:
    target = str(value or "").strip()
    if not target:
        raise ManagerError("start 必须提供 target")
    if len(target) > 8192 or "\r" in target or "\n" in target:
        raise ManagerError("target 格式不合法")
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ManagerError("target 仅允许有效的 http/https URL")
    if parsed.username or parsed.password:
        raise ManagerError("target 不允许包含用户名或密码")
    return target


def parse_port(value: Any) -> int:
    try:
        port = int(value or DEFAULT_PORT)
    except (TypeError, ValueError) as exc:
        raise ManagerError("port 必须是整数") from exc
    if port < 1024 or port > 65535:
        raise ManagerError("port 必须在 1024-65535 之间")
    return port


def parse_int(value: Any, name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(default if value in {None, ""} else value)
    except (TypeError, ValueError) as exc:
        raise ManagerError(f"{name} 必须是整数") from exc
    if parsed < minimum or parsed > maximum:
        raise ManagerError(f"{name} 必须在 {minimum}-{maximum} 之间")
    return parsed


def parse_headers(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    headers = [value] if isinstance(value, str) else value
    if not isinstance(headers, list) or len(headers) > 5:
        raise ManagerError("header 必须是字符串或最多 5 个字符串的数组")
    result: list[str] = []
    for raw in headers:
        header = str(raw).strip()
        if not header or len(header) > 1000 or "\r" in header or "\n" in header:
            raise ManagerError("header 格式不合法")
        if ":" not in header:
            raise ManagerError("header 必须使用 'Name: Value' 格式")
        result.append(header)
    return result


def parse_bool(value: Any, name: str) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes", "on"}:
        return True
    if normalized in {"false", "0", "no", "off"}:
        return False
    raise ManagerError(f"{name} 必须是布尔值")


def parse_auth(value: Any) -> str:
    auth = str(value or "").strip()
    if not auth:
        return f"sophon:{secrets.token_hex(16)}"
    if ":" not in auth or len(auth) > 512 or "\r" in auth or "\n" in auth:
        raise ManagerError("auth 必须使用 username:password 格式")
    username, password = auth.split(":", 1)
    if not username or not password:
        raise ManagerError("auth 的用户名和密码不能为空")
    return auth


def parse_proxy(value: Any) -> str:
    proxy = str(value or "").strip()
    if not proxy:
        return ""
    parsed = urllib.parse.urlsplit(proxy)
    if parsed.scheme not in {"http", "https", "socks5", "socks5h"} or not parsed.hostname:
        raise ManagerError("proxy 仅支持 http、https、socks5、socks5h")
    if len(proxy) > 2048 or "\r" in proxy or "\n" in proxy:
        raise ManagerError("proxy 格式不合法")
    return proxy


def build_command(binary: Path, options: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    target = parse_target(options.get("target"))
    port = parse_port(options.get("port"))
    method = str(options.get("method") or "POST").strip().upper()
    if method not in {"GET", "POST"}:
        raise ManagerError("method 仅支持 GET 或 POST")
    mode = str(options.get("mode") or "auto").strip().lower()
    if mode not in ALLOWED_MODES:
        raise ManagerError("mode 仅支持 auto、full、half、classic")
    auth = parse_auth(options.get("auth"))
    proxy = parse_proxy(options.get("proxy"))
    headers = parse_headers(options.get("header"))
    timeout = parse_int(options.get("timeout"), "timeout", 5, 1, 300)
    retry = parse_int(options.get("retry"), "retry", 1, 0, 10)

    listen = f"127.0.0.1:{port}"
    command = [
        str(binary),
        "--target",
        target,
        "--listen",
        listen,
        "--method",
        method,
        "--mode",
        mode,
        "--auth",
        auth,
        "--timeout",
        str(timeout),
        "--retry",
        str(retry),
    ]
    if proxy:
        command.extend(["--proxy", proxy])
    for header in headers:
        command.extend(["--header", header])
    if options.get("ua"):
        ua = str(options["ua"]).strip()
        if len(ua) > 512 or "\r" in ua or "\n" in ua:
            raise ManagerError("ua 格式不合法")
        command.extend(["--ua", ua])
    if parse_bool(options.get("debug"), "debug"):
        command.append("--debug")
    if parse_bool(options.get("no_gzip"), "no_gzip"):
        command.append("--no-gzip")
    if parse_bool(options.get("no_browser_headers"), "no_browser_headers"):
        command.append("--no-browser-headers")

    return command, {
        "target": target,
        "listen": listen,
        "port": port,
        "method": method,
        "mode": mode,
        "auth": auth,
        "proxy": proxy,
    }


def read_log_tail(path: Path, limit: int = 4000) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return data[-limit:].strip()


def terminate_process(state: dict[str, Any]) -> None:
    if not process_alive(state):
        return
    pid = int(state["pid"])
    try:
        os.killpg(pid, signal.SIGTERM)
    except PermissionError:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    except ProcessLookupError:
        return
    deadline = time.monotonic() + STOP_READY_SECONDS
    while time.monotonic() < deadline:
        if not process_alive(state):
            return
        time.sleep(0.1)
    try:
        os.killpg(pid, signal.SIGKILL)
    except PermissionError:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    except ProcessLookupError:
        pass


def start_tunnel(options: dict[str, Any]) -> dict[str, Any]:
    existing = read_state()
    if existing and process_alive(existing):
        return status_tunnel(existing, already_running=True)
    if existing:
        clear_state()

    binary = binary_path()
    command, values = build_command(binary, options)
    directory = state_dir()
    log_path = directory / LOG_FILE_NAME
    fd = os.open(log_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as log:
            process = subprocess.Popen(
                command,
                cwd=directory,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
    except Exception:
        raise

    state = {
        **values,
        "pid": process.pid,
        "pid_start": process_start_ticks(process.pid),
        "started_at": int(time.time()),
        "log_path": str(log_path),
    }
    write_state(state)

    deadline = time.monotonic() + START_READY_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            tail = read_log_tail(log_path)
            clear_state()
            raise ManagerError(f"suo5 启动后退出，退出码 {process.returncode}: {tail}")
        if port_open("127.0.0.1", int(values["port"])):
            origin = os.environ.get("SOPHON_API_ORIGIN", "")
            return status_tunnel(state, already_running=False, origin=origin)
        time.sleep(0.1)

    terminate_process(state)
    clear_state()
    tail = read_log_tail(log_path)
    raise ManagerError(f"suo5 未在 {START_READY_SECONDS:.0f} 秒内监听本地端口: {tail}")


def safe_status(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "running": process_alive(state) and bool(port_open(str(state.get("listen", "")).split(":", 1)[0], int(state.get("port", 0)))),
        "pid": state.get("pid"),
        "target": state.get("target"),
        "listen": state.get("listen"),
        "auth": state.get("auth"),
        "method": state.get("method"),
        "mode": state.get("mode"),
        "proxy": state.get("proxy") or "",
        "started_at": state.get("started_at"),
        "log_path": state.get("log_path"),
    }


def status_tunnel(
    state: dict[str, Any] | None = None,
    already_running: bool = False,
    origin: str = "",
) -> dict[str, Any]:
    state = state or read_state()
    if not state:
        return {"running": False, "already_running": already_running}
    result = safe_status(state)
    result["already_running"] = already_running
    if origin:
        result["api_origin"] = origin
    return result


def stop_tunnel() -> dict[str, Any]:
    state = read_state()
    if not state:
        return {"running": False, "stopped": False}
    was_running = process_alive(state)
    terminate_process(state)
    clear_state()
    return {"running": False, "stopped": was_running}


def dispatch(operation: str, raw_options: str) -> dict[str, Any]:
    operation = str(operation or "").strip().lower()
    if operation not in ALLOWED_OPERATIONS:
        raise ManagerError("operation 必须是 start、status 或 stop")
    options = parse_options(raw_options)
    if operation == "start":
        return start_tunnel(options)
    if operation == "status":
        return status_tunnel()
    return stop_tunnel()


def main() -> int:
    os.umask(0o077)
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("usage: suo5_manager.py <start|status|stop> [options_json]", file=sys.stderr)
        return 2
    raw_options = sys.argv[2] if len(sys.argv) == 3 else "{}"
    try:
        with manager_lock():
            result = dispatch(sys.argv[1], raw_options)
    except ManagerError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"错误: suo5 管理操作失败: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
