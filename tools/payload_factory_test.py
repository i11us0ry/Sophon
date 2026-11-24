#!/usr/bin/env python3

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("payload_factory.py")


def run_factory(workspace: Path, *args: str) -> dict:
    env = {
        **os.environ,
        "SOPHON_CONVERSATION_WORKSPACE": str(workspace),
    }
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"factory failed ({completed.returncode}): {completed.stderr or completed.stdout}"
        )
    return json.loads(completed.stdout)


class PayloadFactoryTest(unittest.TestCase):
    def test_godzilla_generators(self) -> None:
        cases = [
            ("java", "jsp", "JavaAesBase64", "jsp"),
            ("csharp", "aspx", "CSharpEvalAesBase64", "aspx"),
            ("php", "php", "PhpXor", "php"),
            ("asp", "asp", "AspXorBase64", "asp"),
        ]
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            for language, container, cryptor, extension in cases:
                with self.subTest(language=language, container=container):
                    result = run_factory(
                        workspace,
                        "generate",
                        "--family",
                        "godzilla",
                        "--language",
                        language,
                        "--container",
                        container,
                        "--password",
                        "sophon",
                        "--secret-key",
                        "0123456789abcdef",
                        "--cryptor",
                        cryptor,
                        "--target-url",
                        f"https://target.example/shell.{extension}",
                    )
                    self.assertTrue(result["ok"])
                    shell = Path(result["shell_file"])
                    self.assertTrue(shell.is_file())
                    self.assertEqual(shell.suffix, "." + extension)
                    self.assertGreater(shell.stat().st_size, 20)
                    self.assertIn(
                        "sophon",
                        shell.read_text(encoding="utf-8", errors="ignore"),
                    )
                    self.assertTrue(Path(result["verify_python"]).is_file())
                    self.assertTrue(Path(result["metadata"]).is_file())
                    self.assertIn(
                        "--url",
                        Path(result["report"]).read_text(encoding="utf-8"),
                    )

    def test_suo5_templates_and_scripts(self) -> None:
        cases = [
            ("java", "jsp"),
            ("csharp", "aspx"),
            ("php", "php"),
            ("javascript", "js"),
        ]
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            for language, container in cases:
                with self.subTest(language=language, container=container):
                    result = run_factory(
                        workspace,
                        "generate",
                        "--family",
                        "suo5",
                        "--language",
                        language,
                        "--container",
                        container,
                        "--target-url",
                        f"https://target.example/suo5.{container}",
                    )
                    self.assertTrue(result["ok"])
                    shell = Path(result["shell_file"])
                    self.assertTrue(shell.is_file())
                    self.assertGreater(shell.stat().st_size, 100)
                    self.assertTrue(Path(result["start_tunnel_python"]).is_file())
                    self.assertTrue(Path(result["report"]).is_file())
                    report = Path(result["report"]).read_text(encoding="utf-8")
                    self.assertIn("--target", report)
                    compile(
                        Path(result["start_tunnel_python"]).read_text(encoding="utf-8"),
                        result["start_tunnel_python"],
                        "exec",
                    )

    def test_unsupported_combination_is_structured(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = run_factory(
                Path(raw),
                "generate",
                "--family",
                "godzilla",
                "--language",
                "java",
                "--container",
                "php",
                "--password",
                "sophon",
            )
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], "unsupported_combination")
            self.assertTrue(result["supported"])


if __name__ == "__main__":
    unittest.main()
