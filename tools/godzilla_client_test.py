#!/usr/bin/env python3

import base64
import hashlib
import importlib.util
import json
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock


def load_client():
    path = Path(__file__).with_name("godzilla_client.py")
    spec = importlib.util.spec_from_file_location("godzilla_client", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class GodzillaTestServer:
    def __init__(
        self,
        client,
        password: str,
        secret_key: str,
        transport: str,
        validate_request: bool = True,
    ):
        self.client = client
        self.password = password
        self.secret_key = secret_key
        self.transport = transport
        self.validate_request = validate_request
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.handler())
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                try:
                    if outer.transport == "BASE64":
                        form = urllib.parse.parse_qs(body.decode("ascii"))
                        encrypted = base64.b64decode(form[outer.password][0])
                    else:
                        encrypted = body
                    plain = outer.client.decrypt_payload(
                        outer.secret_key,
                        "AES",
                        encrypted,
                    )
                    if plain != b"getBasicsInfo":
                        raise ValueError("unexpected request")
                    response_plain = b'{"osInfo":"Linux"}'
                    response_encrypted = outer.client.encrypt_payload(
                        outer.secret_key,
                        "AES",
                        response_plain,
                    )
                    marker = hashlib.md5(
                        f"{outer.password}{outer.secret_key}".encode("utf-8")
                    ).hexdigest().encode("ascii")
                    payload = (
                        base64.b64encode(response_encrypted)
                        if outer.transport == "BASE64"
                        else response_encrypted
                    )
                    response = marker[:16] + payload + marker[16:]
                    status = 200
                except Exception:
                    if outer.validate_request:
                        response = b"invalid"
                        status = 500
                    else:
                        response_plain = b'{"osInfo":"Linux"}'
                        response_encrypted = outer.client.encrypt_payload(
                            outer.secret_key,
                            "AES",
                            response_plain,
                        )
                        marker = hashlib.md5(
                            f"{outer.password}{outer.secret_key}".encode("utf-8")
                        ).hexdigest().encode("ascii")
                        payload = (
                            base64.b64encode(response_encrypted)
                            if outer.transport == "BASE64"
                            else response_encrypted
                        )
                        response = marker[:16] + payload + marker[16:]
                        status = 200
                self.send_response(status)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, _format, *_args):
                return

        return Handler

    @property
    def url(self):
        return f"http://127.0.0.1:{self.httpd.server_port}/shell.jsp"

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


class GodzillaClientTest(unittest.TestCase):
    def setUp(self):
        self.client = load_client()

    def test_aes_base64_connection(self):
        server = GodzillaTestServer(
            self.client,
            password="pass",
            secret_key="0123456789abcdef",
            transport="BASE64",
        ).start()
        try:
            result = self.client.dispatch(
                "test",
                json.dumps(
                    {
                        "url": server.url,
                        "password": "pass",
                        "secret_key": "0123456789abcdef",
                        "cryptor": "JavaAesBase64",
                        "protocol": "simplified",
                    }
                ),
            )
        finally:
            server.stop()
        self.assertTrue(result["connected"], result)
        self.assertEqual(result["status"], "connected")
        self.assertIn("Linux", result["sample"])

    def test_aes_raw_connection(self):
        server = GodzillaTestServer(
            self.client,
            password="pass",
            secret_key="0123456789abcdef",
            transport="RAW",
        ).start()
        try:
            result = self.client.dispatch(
                "test",
                json.dumps(
                    {
                        "url": server.url,
                        "password": "pass",
                        "secret_key": "0123456789abcdef",
                        "cryptor": "JavaAesRaw",
                        "protocol": "simplified",
                    }
                ),
            )
        finally:
            server.stop()
        self.assertTrue(result["connected"], result)

    def test_wrong_key_is_protocol_error(self):
        server = GodzillaTestServer(
            self.client,
            password="pass",
            secret_key="0123456789abcdef",
            transport="BASE64",
            validate_request=False,
        ).start()
        try:
            result = self.client.dispatch(
                "test",
                json.dumps(
                    {
                        "url": server.url,
                        "password": "pass",
                        "secret_key": "wrong-key",
                        "cryptor": "JavaAesBase64",
                        "protocol": "simplified",
                    }
                ),
            )
        finally:
            server.stop()
        self.assertFalse(result["connected"])
        self.assertEqual(result["status"], "protocol_error")

    def test_rejects_non_http_target(self):
        with self.assertRaises(self.client.ClientError):
            self.client.dispatch(
                "test",
                json.dumps(
                    {
                        "url": "file:///etc/passwd",
                        "password": "pass",
                        "secret_key": "key",
                    }
                ),
            )

    def test_help_lists_flat_parameters(self):
        result = self.client.dispatch("help", "{}")
        self.assertEqual(result["status"], "help")
        for name in ("url", "password", "secret_key", "cryptor", "headers", "protocol"):
            self.assertIn(name, result["parameters"])
        self.assertEqual(result["example"]["password"], "sophon")

    def test_official_catalog_uses_gsl5_metadata(self):
        catalog = self.client.run_official_catalog(force=True)
        self.assertEqual(catalog["status"], "ok")
        self.assertEqual(
            catalog["by_cryptor"]["csharpaesbase64"],
            {
                "cryptor": "CSHARP_AES_BASE64",
                "payload": "CSharpDynamicPayload",
            },
        )
        self.assertEqual(
            self.client.resolve_official_protocol("CSharpEvalAesBase64"),
            ("CSHARP_EVAL_AES_BASE64", "CSharpDynamicPayload"),
        )
        self.assertEqual(self.client.parse_protocol("OFFICIAL"), "official")
        self.assertEqual(self.client.parse_protocol("simplified"), "simplified")

    def test_official_failure_details_are_preserved(self):
        failure = {
            "connected": False,
            "status": "protocol_error",
            "phase": "payload_test",
            "key_fingerprint": "0123456789abcdef",
            "message": "no valid sessionId returned",
        }
        with mock.patch.object(self.client, "run_official_probe", return_value=failure):
            result = self.client.dispatch(
                "test",
                json.dumps(
                    {
                        "url": "http://authorized.example/shell.aspx",
                        "password": "pass",
                        "secret_key": "0123456789abcdef",
                        "cryptor": "CSharpAesBase64",
                        "protocol": "official",
                    }
                ),
            )
        self.assertEqual(result, failure)

    def test_auto_does_not_fallback_to_simplified(self):
        failure = {
            "connected": False,
            "status": "protocol_error",
            "phase": "payload_test",
            "message": "official failure",
        }
        with (
            mock.patch.object(self.client, "run_official_probe", return_value=failure),
            mock.patch.object(
                self.client,
                "test_simplified_connection",
                side_effect=AssertionError("simplified fallback must not run"),
            ),
        ):
            result = self.client.dispatch(
                "test",
                json.dumps(
                    {
                        "url": "http://authorized.example/shell.aspx",
                        "password": "pass",
                        "secret_key": "0123456789abcdef",
                        "cryptor": "CSharpAesBase64",
                        "protocol": "auto",
                    }
                ),
            )
        self.assertFalse(result["connected"])
        self.assertEqual(result["phase"], "payload_test")

    def test_list_returns_official_catalog(self):
        result = self.client.dispatch("list", "{}")
        self.assertEqual(result["status"], "ok")
        self.assertIn("csharpaesbase64", result["by_cryptor"])

    def test_cli_flags_build_options(self):
        operation, options = self.client.parse_cli(
            [
                "godzilla_client.py",
                "test",
                "--url",
                "http://authorized.example/shell.jsp",
                "--password",
                "sophon",
                "--secret-key",
                "0123456789abcdef",
                "--cryptor",
                "JavaAesBase64",
                "--protocol",
                "simplified",
                "--headers-json",
                '{"Cookie":"sid=test"}',
            ]
        )
        self.assertEqual(operation, "test")
        self.assertEqual(options["password"], "sophon")
        self.assertEqual(options["protocol"], "simplified")
        self.assertEqual(options["headers"]["Cookie"], "sid=test")


if __name__ == "__main__":
    unittest.main()
