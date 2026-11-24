#!/usr/bin/env python3
"""Detect virtual-host differences by varying the HTTP Host header."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import html
import http.client
import json
import random
import re
import ssl
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import quote, quote_plus, urlsplit, urlunsplit


MAX_HOSTS = 100_000
MAX_HOSTS_FILE_BYTES = 10 * 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class Response:
    host: str
    category: str
    status: int | None = None
    length: int | None = None
    content_type: str = ""
    title: str = ""
    location: str = ""
    body_sha256: str = ""
    error: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect HTTP virtual-host collisions by varying the Host header.",
    )
    parser.add_argument("--target", required=True, help="target URL used for the TCP/TLS connection")
    parser.add_argument("--hosts", required=True, help="candidate Host list, one per line")
    parser.add_argument("--threads", type=int, default=10, help="worker count (1-100, default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="request timeout in seconds (1-60)")
    parser.add_argument("--header", action="append", default=[], help="extra header: 'Name: value'")
    parser.add_argument("--user-agent", default="host-collision/1.0", help="User-Agent value")
    parser.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    parser.add_argument("--all", action="store_true", help="print non-collision results as well")
    parser.add_argument("--output", help="optional JSONL output path")
    args = parser.parse_args()

    if not 1 <= args.threads <= 100:
        parser.error("--threads must be between 1 and 100")
    if not 1 <= args.timeout <= 60:
        parser.error("--timeout must be between 1 and 60")
    return args


def parse_target(raw_url: str) -> tuple[str, int, str, str, bool]:
    parsed = urlsplit(raw_url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("--target must use http:// or https://")
    if not parsed.hostname:
        raise ValueError("--target must include a hostname or IP address")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials in --target are not supported")

    scheme = parsed.scheme.lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    return scheme, port, parsed.hostname, path, scheme == "https"


def validate_host(value: str) -> str:
    host = value.strip()
    if not host:
        raise ValueError("empty Host")
    if len(host) > 253:
        raise ValueError("Host is too long")
    if any(ord(char) < 33 or char in "/\\?#" for char in host):
        raise ValueError("Host contains an invalid character")
    return host


def load_hosts(path: str, excluded: str) -> tuple[list[str], int]:
    file_path = Path(path)
    if not file_path.is_file():
        raise ValueError(f"hosts file does not exist: {path}")
    if file_path.stat().st_size > MAX_HOSTS_FILE_BYTES:
        raise ValueError("hosts file exceeds 10 MiB")

    hosts: list[str] = []
    seen: set[str] = set()
    invalid = 0
    excluded_key = excluded.casefold()
    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            try:
                host = validate_host(raw)
            except ValueError:
                invalid += 1
                continue
            key = host.casefold()
            if key == excluded_key or key in seen:
                continue
            seen.add(key)
            hosts.append(host)
            if len(hosts) > MAX_HOSTS:
                raise ValueError(f"hosts file contains more than {MAX_HOSTS} unique entries")
    if not hosts:
        raise ValueError("hosts file contains no valid entries")
    return hosts, invalid


def parse_headers(values: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in values:
        if ":" not in raw:
            raise ValueError(f"invalid header: {raw!r}")
        name, value = raw.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name or any(ord(char) < 33 or char == ":" for char in name):
            raise ValueError(f"invalid header name: {name!r}")
        if name.casefold() == "host":
            raise ValueError("Host must be supplied through --hosts, not --header")
        if any(char in "\r\n" for char in name + value):
            raise ValueError("header values must not contain newlines")
        headers[name] = value
    return headers


def normalize_reflection(text: str, host: str) -> str:
    variants = {
        host,
        host.lower(),
        html.escape(host, quote=True),
        quote(host, safe=""),
        quote_plus(host, safe=""),
    }
    for variant in sorted(variants, key=len, reverse=True):
        if variant:
            text = text.replace(variant, "<HOST>")
    return text


def extract_title(body: str) -> str:
    match = TITLE_RE.search(body)
    if not match:
        return ""
    return SPACE_RE.sub(" ", html.unescape(match.group(1))).strip()[:200]


def request_host(
    *,
    scheme: str,
    port: int,
    target_host: str,
    path: str,
    host: str,
    timeout: int,
    insecure: bool,
    headers: dict[str, str],
    user_agent: str,
) -> Response:
    connection: http.client.HTTPConnection
    if scheme == "https":
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(
            target_host,
            port,
            timeout=timeout,
            context=context,
        )
    else:
        connection = http.client.HTTPConnection(target_host, port, timeout=timeout)

    request_headers = {
        "Host": host,
        "User-Agent": user_agent,
        "Accept": "*/*",
        "Connection": "close",
    }
    request_headers.update(headers)

    try:
        connection.request("GET", path, headers=request_headers)
        response = connection.getresponse()
        raw_body = response.read(MAX_RESPONSE_BYTES)
        body = raw_body.decode("utf-8", errors="replace")
        normalized_body = normalize_reflection(body, host)
        content_type = response.getheader("Content-Type", "")
        location = normalize_reflection(response.getheader("Location", ""), host)
        title = normalize_reflection(extract_title(body), host)
        return Response(
            host=host,
            category="observed",
            status=response.status,
            length=response.length if response.length is not None else len(raw_body),
            content_type=content_type,
            title=title,
            location=location,
            body_sha256=hashlib.sha256(normalized_body.encode("utf-8")).hexdigest(),
        )
    except Exception as exc:  # Network errors are per-candidate findings.
        return Response(host=host, category="error", error=f"{type(exc).__name__}: {exc}")
    finally:
        connection.close()


def fingerprint(response: Response) -> tuple[object, ...] | None:
    if response.category == "error":
        return None
    return (
        response.status,
        response.length,
        response.content_type,
        response.title,
        response.location,
        response.body_sha256,
    )


def classify(response: Response, baseline: Response, control: Response) -> Response:
    if response.category == "error":
        return response
    value = fingerprint(response)
    if value == fingerprint(baseline):
        category = "default"
    elif value == fingerprint(control):
        category = "catch_all"
    else:
        category = "collision"
    return Response(**{**asdict(response), "category": category})


def write_result(result: Response, output) -> None:
    output.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")
    output.flush()


def main() -> int:
    try:
        args = parse_args()
        scheme, port, target_host, path, is_https = parse_target(args.target)
        headers = parse_headers(args.header)
        hosts, invalid = load_hosts(args.hosts, target_host)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    common = {
        "scheme": scheme,
        "port": port,
        "target_host": target_host,
        "path": path,
        "timeout": args.timeout,
        "insecure": args.insecure and is_https,
        "headers": headers,
        "user_agent": args.user_agent,
    }

    baseline = request_host(host=target_host, **common)
    random_host = f"collision-{random.randrange(1 << 48):012x}.invalid"
    control = request_host(host=random_host, **common)
    if baseline.category == "error":
        print(f"error: baseline request failed: {baseline.error}", file=sys.stderr)
        return 2

    results: list[Response] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(request_host, host=host, **common): host
            for host in hosts
        }
        try:
            for future in concurrent.futures.as_completed(futures):
                results.append(classify(future.result(), baseline, control))
        except KeyboardInterrupt:
            executor.shutdown(wait=False, cancel_futures=True)
            print("interrupted", file=sys.stderr)
            return 130

    results.sort(key=lambda item: item.host.casefold())
    selected = results if args.all else [
        item for item in results if item.category == "collision"
    ]

    output = sys.stdout
    output_handle = None
    if args.output:
        output_handle = Path(args.output).open("w", encoding="utf-8")
        output = output_handle
    try:
        for result in selected:
            write_result(result, output)
    finally:
        if output_handle is not None:
            output_handle.close()

    collisions = sum(item.category == "collision" for item in results)
    catch_all = sum(item.category == "catch_all" for item in results)
    errors = sum(item.category == "error" for item in results)
    print(
        f"tested={len(results)} collisions={collisions} "
        f"catch_all={catch_all} errors={errors} invalid={invalid}",
        file=sys.stderr,
    )
    if not selected:
        print("no differential Host responses found", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
