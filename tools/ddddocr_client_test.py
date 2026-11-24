#!/usr/bin/env python3

import base64
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path


def load_client():
    path = Path(__file__).with_name("ddddocr_client.py")
    spec = importlib.util.spec_from_file_location("ddddocr_client", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeDdddOcr:
    def __init__(self, det=False, ocr=True, show_ad=False):
        self.det = det
        self.ocr = ocr
        self.show_ad = show_ad

    def classification(self, _data):
        return "ab12"

    def detection(self, _data):
        return [[1, 2, 30, 40]]

    def slide_match(self, _target, _background, simple_target=False):
        return {"target": [12, 34], "simple_target": simple_target}


class DdddocrClientTest(unittest.TestCase):
    def setUp(self):
        self.client = load_client()
        self.original_module = sys.modules.get("ddddocr")
        sys.modules["ddddocr"] = types.SimpleNamespace(DdddOcr=FakeDdddOcr)

    def tearDown(self):
        if self.original_module is None:
            sys.modules.pop("ddddocr", None)
        else:
            sys.modules["ddddocr"] = self.original_module

    def test_help(self):
        result = self.client.dispatch("help")
        self.assertEqual(result["status"], "help")
        self.assertIn("recognize", result["operations"])

    def test_recognize_from_path(self):
        with tempfile.TemporaryDirectory() as root:
            image = Path(root) / "captcha.png"
            image.write_bytes(b"fake-image")
            result = self.client.dispatch(
                "recognize",
                json.dumps({"image_path": str(image)}),
            )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["text"], "ab12")

    def test_recognize_from_base64(self):
        encoded = base64.b64encode(b"fake-image").decode("ascii")
        result = self.client.dispatch(
            "recognize",
            json.dumps({"image_base64": f"data:image/png;base64,{encoded}"}),
        )
        self.assertEqual(result["text"], "ab12")

    def test_detect(self):
        encoded = base64.b64encode(b"fake-image").decode("ascii")
        result = self.client.dispatch("detect", json.dumps({"image_base64": encoded}))
        self.assertEqual(result["result"], [[1, 2, 30, 40]])

    def test_slide_match(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "target.png"
            background = Path(root) / "background.png"
            target.write_bytes(b"target")
            background.write_bytes(b"background")
            result = self.client.dispatch(
                "slide_match",
                json.dumps(
                    {
                        "target_path": str(target),
                        "background_path": str(background),
                        "simple_target": True,
                    }
                ),
            )
        self.assertEqual(result["result"]["target"], [12, 34])
        self.assertTrue(result["result"]["simple_target"])

    def test_rejects_missing_image(self):
        with self.assertRaises(self.client.ClientError):
            self.client.dispatch("recognize", "{}")

    def test_cli_flags(self):
        operation, options = self.client.parse_cli(
            [
                "ddddocr_client.py",
                "recognize",
                "--image",
                "captcha.png",
            ]
        )
        self.assertEqual(operation, "recognize")
        self.assertEqual(options["image_path"], "captcha.png")


if __name__ == "__main__":
    unittest.main()
