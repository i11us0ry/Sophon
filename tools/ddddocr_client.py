#!/usr/bin/env python3
"""Captcha recognition helper backed by ddddocr."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path
from typing import Any


MAX_IMAGE_BYTES = 10 * 1024 * 1024
ALLOWED_OPERATIONS = {"help", "recognize", "detect", "slide_match"}
ALLOWED_OPTIONS = {
    "image_path",
    "image_base64",
    "target_path",
    "background_path",
    "simple_target",
}

HELP_PAYLOAD = {
    "status": "help",
    "operations": {
        "recognize": "识别普通字符验证码，需要 image_path 或 image_base64",
        "detect": "检测验证码目标框，需要 image_path 或 image_base64",
        "slide_match": "匹配滑块验证码，需要 target_path 与 background_path",
    },
    "examples": [
        {"operation": "recognize", "image_path": "captcha.png"},
        {
            "operation": "slide_match",
            "target_path": "slider.png",
            "background_path": "background.png",
            "simple_target": True,
        },
    ],
}


class ClientError(RuntimeError):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


def parse_operation(value: Any) -> str:
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
    raise ClientError("invalid_options", "simple_target 必须是布尔值")


def read_file_bytes(raw_path: Any, label: str) -> bytes:
    text = str(raw_path or "").strip()
    if not text:
        raise ClientError("invalid_options", f"{label} 不能为空")
    path = Path(text).expanduser()
    if not path.is_file():
        raise ClientError("invalid_options", f"{label} 不存在: {text}")
    size = path.stat().st_size
    if size <= 0 or size > MAX_IMAGE_BYTES:
        raise ClientError("invalid_options", f"{label} 大小必须在 1 字节到 10 MiB 之间")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ClientError("invalid_options", f"读取 {label} 失败: {exc}") from exc


def image_bytes(options: dict[str, Any], path_key: str = "image_path", b64_key: str = "image_base64") -> bytes:
    path_value = str(options.get(path_key) or "").strip()
    b64_value = str(options.get(b64_key) or "").strip()
    if path_value and b64_value:
        raise ClientError("invalid_options", f"{path_key} 与 {b64_key} 不能同时提供")
    if path_value:
        return read_file_bytes(path_value, path_key)
    if not b64_value:
        raise ClientError("invalid_options", f"必须提供 {path_key} 或 {b64_key}")
    if b64_value.startswith("data:"):
        separator = b64_value.find(",")
        if separator < 0:
            raise ClientError("invalid_options", f"{b64_key} 的 data URL 格式错误")
        b64_value = b64_value[separator + 1 :]
    try:
        data = base64.b64decode("".join(b64_value.split()), validate=True)
    except (ValueError, TypeError) as exc:
        raise ClientError("invalid_options", f"{b64_key} 不是有效 Base64") from exc
    if len(data) <= 0 or len(data) > MAX_IMAGE_BYTES:
        raise ClientError("invalid_options", f"{b64_key} 大小必须在 1 字节到 10 MiB 之间")
    return data


def new_ocr(ocr: bool, det: bool) -> Any:
    try:
        import ddddocr
    except ImportError as exc:
        raise ClientError("dependency_missing", "ddddocr 未安装") from exc
    try:
        return ddddocr.DdddOcr(det=det, ocr=ocr, show_ad=False)
    except Exception as exc:
        raise ClientError("model_error", f"初始化 ddddocr 失败: {type(exc).__name__}: {exc}") from exc


def jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    if hasattr(value, "tolist"):
        return jsonable(value.tolist())
    return str(value)


def recognize(options: dict[str, Any]) -> dict[str, Any]:
    data = image_bytes(options)
    model = new_ocr(ocr=True, det=False)
    started = time.monotonic()
    try:
        text = model.classification(data)
    except Exception as exc:
        raise ClientError("recognize_error", f"验证码识别失败: {type(exc).__name__}: {exc}") from exc
    return {
        "status": "ok",
        "text": str(text or ""),
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }


def detect(options: dict[str, Any]) -> dict[str, Any]:
    data = image_bytes(options)
    model = new_ocr(ocr=False, det=True)
    started = time.monotonic()
    try:
        result = model.detection(data)
    except Exception as exc:
        raise ClientError("detect_error", f"验证码目标检测失败: {type(exc).__name__}: {exc}") from exc
    return {
        "status": "ok",
        "result": jsonable(result),
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }


def slide_match(options: dict[str, Any]) -> dict[str, Any]:
    target = read_file_bytes(options.get("target_path"), "target_path")
    background = read_file_bytes(options.get("background_path"), "background_path")
    simple_target = parse_bool(options.get("simple_target"), False)
    model = new_ocr(ocr=False, det=False)
    started = time.monotonic()
    try:
        result = model.slide_match(
            target,
            background,
            simple_target=simple_target,
        )
    except Exception as exc:
        raise ClientError("slide_match_error", f"滑块验证码匹配失败: {type(exc).__name__}: {exc}") from exc
    return {
        "status": "ok",
        "result": jsonable(result),
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }


def dispatch(operation: str, options_json: str = "{}") -> dict[str, Any]:
    operation = parse_operation(operation)
    if operation == "help":
        return HELP_PAYLOAD
    options = parse_options(options_json)
    if operation == "recognize":
        return recognize(options)
    if operation == "detect":
        return detect(options)
    if operation == "slide_match":
        return slide_match(options)
    raise ClientError("invalid_options", f"不支持的 operation: {operation}")


def parse_cli(argv: list[str]) -> tuple[str, dict[str, Any]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("operation", nargs="?")
    parser.add_argument("options_json", nargs="?")
    parser.add_argument("--image")
    parser.add_argument("--image-base64")
    parser.add_argument("--target")
    parser.add_argument("--background")
    parser.add_argument("--simple-target", action="store_true")
    args = parser.parse_args(argv[1:])

    operation = str(args.operation or "help").strip().lower()
    if operation == "help":
        return "help", {}
    if operation not in ALLOWED_OPERATIONS:
        raise ClientError("invalid_options", f"不支持的 operation: {operation}")
    if args.options_json:
        values = (
            args.image,
            args.image_base64,
            args.target,
            args.background,
            args.simple_target,
        )
        if any(value not in {None, False, ""} for value in values):
            raise ClientError("invalid_options", "options_json 与独立参数不能同时使用")
        return operation, parse_options(args.options_json)

    options: dict[str, Any] = {}
    for key, value in {
        "image_path": args.image,
        "image_base64": args.image_base64,
        "target_path": args.target,
        "background_path": args.background,
    }.items():
        if value:
            options[key] = value
    if args.simple_target:
        options["simple_target"] = True
    return operation, options


def main(argv: list[str]) -> int:
    try:
        operation, options = parse_cli(argv)
        result = HELP_PAYLOAD if operation == "help" else dispatch(operation, json.dumps(options))
    except ClientError as exc:
        print(json.dumps({"status": exc.status, "message": str(exc)}, ensure_ascii=False))
        return 2
    except Exception as exc:
        print(
            json.dumps(
                {"status": "error", "message": f"{type(exc).__name__}: {exc}"},
                ensure_ascii=False,
            )
        )
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
