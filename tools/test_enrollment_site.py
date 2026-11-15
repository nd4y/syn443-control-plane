import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from build_enrollment_site import build_site


INSTALL = "https://releases.example.invalid/syn443.apk"
SIGNER = ":".join(["A5"] * 32)


class EnrollmentSiteTest(unittest.TestCase):
    def test_static_fallback_and_exact_android_association(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "site"
            build_site(path, INSTALL, [SIGNER])
            association = json.loads((path / ".well-known/assetlinks.json").read_text(encoding="utf-8"))
            self.assertEqual(association, [{
                "relation": ["delegate_permission/common.handle_all_urls"],
                "target": {
                    "namespace": "android_app",
                    "package_name": "io.syn443.android",
                    "sha256_cert_fingerprints": [SIGNER],
                },
            }])
            page = (path / "enroll.html").read_text(encoding="utf-8")
            self.assertIn(f'href="{INSTALL}"', page)
            self.assertIn('name="referrer" content="no-referrer"', page)
            self.assertIn("снова откройте исходную ссылку", page)
            for content in ("<script", "<form", "syn443://", "code="):
                self.assertNotIn(content, page)
            with self.assertRaises(FileExistsError):
                build_site(path, INSTALL, [SIGNER])
            self.assertEqual((path / "enroll.html").read_text(encoding="utf-8"), page)

    def test_invalid_download_url_or_signer_never_writes_output(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "site"
            for url in (INSTALL.replace("https:", "http:"), INSTALL + "#secret", INSTALL + "?key=x",
                        INSTALL.replace("https://", "https://" + "name@"), INSTALL + "\n",
                        INSTALL.replace("example.invalid/", "example.invalid:443/")):
                with self.assertRaises(ValueError):
                    build_site(path, url, [SIGNER])
                self.assertFalse(path.exists())
            for values in ([], [SIGNER, SIGNER], [SIGNER.lower()], [SIGNER[:-1]], ["x"]):
                with self.assertRaises(ValueError):
                    build_site(path, INSTALL, values)
                self.assertFalse(path.exists())
