#!/usr/bin/env python3

import importlib.util
import json
import os
import socket
import tempfile
import textwrap
import unittest
import warnings
from pathlib import Path
from unittest import mock


def load_manager():
    path = Path(__file__).with_name("suo5_manager.py")
    spec = importlib.util.spec_from_file_location("suo5_manager", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class Suo5ManagerTest(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        self.manager = load_manager()
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name)
        self.fake_binary = self.workspace / "fake-suo5"
        self.fake_binary.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import socket, sys, time
                args = sys.argv[1:]
                listen = args[args.index("--listen") + 1]
                host, port = listen.rsplit(":", 1)
                server = socket.socket()
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((host, int(port)))
                server.listen()
                while True:
                    time.sleep(1)
                """
            ),
            encoding="utf-8",
        )
        self.fake_binary.chmod(0o700)
        self.env = mock.patch.dict(
            os.environ,
            {
                "SOPHON_CONVERSATION_WORKSPACE": str(self.workspace),
                "SOPHON_SUO5_BINARY": str(self.fake_binary),
            },
            clear=False,
        )
        self.env.start()

    def tearDown(self):
        try:
            self.manager.stop_tunnel()
        finally:
            self.env.stop()
            self.temp.cleanup()

    def test_start_status_stop(self):
        port = free_port()
        started = self.manager.dispatch(
            "start",
            json.dumps({"target": "http://authorized.example/suo5.jsp", "port": port}),
        )
        self.assertTrue(started["running"])
        self.assertEqual(started["listen"], f"127.0.0.1:{port}")
        self.assertIn(":", started["auth"])

        status = self.manager.dispatch("status", "{}")
        self.assertTrue(status["running"])
        self.assertEqual(status["pid"], started["pid"])

        stopped = self.manager.dispatch("stop", "{}")
        self.assertTrue(stopped["stopped"])
        self.assertFalse(self.manager.dispatch("status", "{}")["running"])

    def test_rejects_unsafe_inputs(self):
        for options in [
            {"target": "file:///etc/passwd"},
            {"target": "http://user:pass@example.com/shell"},
            {"target": "http://example.com/shell", "port": 80},
            {"target": "http://example.com/shell", "header": "X-Test: ok\r\nInjected: yes"},
            {"target": "http://example.com/shell", "unknown": True},
        ]:
            with self.subTest(options=options):
                with self.assertRaises(self.manager.ManagerError):
                    self.manager.dispatch("start", json.dumps(options))

    def test_invalid_operation(self):
        with self.assertRaises(self.manager.ManagerError):
            self.manager.dispatch("restart", "{}")


if __name__ == "__main__":
    unittest.main()
