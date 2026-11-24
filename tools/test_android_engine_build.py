import json
from pathlib import Path
import tempfile
import unittest

from android_engine_build import catalogue, check_inventory


class AndroidEngineBuildTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "app").mkdir()
        (self.root / "native").mkdir()
        self.gradle = self.root / "app/build.gradle.kts"
        self.gradle.write_text('    versionCode = 19\n    versionName = "1.0-fixture"\n', encoding="utf-8")
        self.lock = self.root / "native/engine-lock.json"
        self.locks = {"sources": {"sing-box": {"revision": "a" * 40}, "netbird": {"revision": "b" * 40}}}
        self.lock.write_text(json.dumps(self.locks), encoding="utf-8")
        self.pin = "c" * 40

    def test_exact_release_projection_and_stale_catalogue(self):
        expected = catalogue(self.root, self.pin)
        self.assertEqual(json.loads(expected), {
            "androidRevision": self.pin,
            "versionCode": 19,
            "versionName": "1.0-fixture",
            "engines": {"sing-box": "a" * 40, "NetBird": "b" * 40},
        })
        output = self.root / "inventory.json"
        output.write_text(expected, encoding="utf-8")
        check_inventory(output, expected)
        for old, new in (("a" * 40, "f" * 40), (self.pin, "d" * 40), ("19", "20")):
            with self.subTest(value=new):
                output.write_text(expected.replace(old, new), encoding="utf-8")
                with self.assertRaises(ValueError):
                    check_inventory(output, expected)

    def test_invalid_revision_and_conflicting_package_metadata(self):
        with self.assertRaises(ValueError):
            catalogue(self.root, "main")
        with self.gradle.open("a", encoding="utf-8") as gradle:
            gradle.write("    versionCode = 20\n")
        with self.assertRaises(ValueError):
            catalogue(self.root, self.pin)

    def test_invalid_engine_pin(self):
        self.locks["sources"]["netbird"]["revision"] = "b" * 39
        self.lock.write_text(json.dumps(self.locks), encoding="utf-8")
        with self.assertRaises(ValueError):
            catalogue(self.root, self.pin)
