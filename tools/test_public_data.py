import unittest
from check_public_data import findings


class PublicDataTest(unittest.TestCase):
    def test_private_addresses(self):
        for octets in ((10, 2, 3, 4), (192, 168, 5, 6), (172, 16, 2, 3), (100, 106, 1, 2)):
            self.assertIn("private-address", findings(".".join(map(str, octets)).encode()))

    def test_documentation_and_loopback(self):
        self.assertFalse(findings(b"100.64.0.0/10"))
        for address in (b"127.0.0.1", b"0.0.0.0", b"192.0.2.4", b"198.51.100.8", b"203.0.113.9"):
            self.assertFalse(findings(address))

    def test_private_domains_and_paths(self):
        self.assertIn("private-domain", findings(("server." + "local").encode()))
        self.assertIn("personal-path", findings(("C:/" + "Users/person/").encode()))
        self.assertFalse(findings(b"/home/runner/work/syn443"))
        self.assertFalse(findings(b"https://example.invalid/path"))
        self.assertFalse(findings(b"kotlinx.coroutines.internal.MainDispatcherFactory"))

    def test_credential_url(self):
        self.assertIn("credential-url", findings(("https://" + "synthetic:placeholder@" + "example.invalid").encode()))
        self.assertFalse(findings(b"https://example.invalid:443/path"))
