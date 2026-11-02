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

    def test_public_denylist_allocations_do_not_allow_private_hosts(self):
        from check_public_data import PUBLIC_ALLOCATION_TOKENS
        for token in PUBLIC_ALLOCATION_TOKENS:
            self.assertFalse(findings(token.encode()))
        for octets in ((192, 0, 0, 1), (198, 18, 0, 1), (240, 0, 0, 1), (10, 0, 0, 1)):
            self.assertIn("private-address", findings(".".join(map(str, octets)).encode()))
        # Neither a longer prefix nor a token prefix is an approved allocation.
        raw = ".".join(map(str, (100, 64, 0, 0)))
        for suffix in ("/100", "/10/extra", "/10extra"):
            self.assertIn("private-address", findings((raw + suffix).encode()))

    def test_private_domains_and_paths(self):
        self.assertIn("private-domain", findings(("server." + "local").encode()))
        self.assertIn("personal-path", findings(("C:/" + "Users/person/").encode()))
        self.assertFalse(findings(b"/home/runner/work/syn443"))
        self.assertFalse(findings(b"https://example.invalid/path"))
        self.assertFalse(findings(b"kotlinx.coroutines.internal.MainDispatcherFactory"))

    def test_credential_url(self):
        self.assertIn("credential-url", findings(("https://" + "synthetic:placeholder@" + "example.invalid").encode()))
        self.assertFalse(findings(b"https://example.invalid:443/path"))

    def test_url_userinfo_cannot_cross_a_binary_control_separator(self):
        # C0/DEL are not URL userinfo. Go constants separated by these bytes do
        # not become a credential URI just because another constant has an @.
        for delimiter in (bytes([0]),bytes([1]),bytes([31]),bytes([127])):
            broken=b"https://"+b"synthetic"+delimiter+b"unrelated:constant@"+b"example.invalid"
            self.assertNotIn("credential-url",findings(bytes([127])+b"ELF"+broken))
            real=b"https://"+b"synthetic:placeholder@"+b"example.invalid"
            self.assertIn("credential-url",findings(bytes([127])+b"ELF"+delimiter+real+delimiter))
        encoded=b"https://"+b"synthetic%00:placeholder@"+b"example.invalid"
        self.assertIn("credential-url",findings(encoded))

    def test_only_exact_go_elf_symbols_are_not_mistaken_for_domains(self):
        fields = b"crypto/x509." + b"local string; crypto/x509.domain string"
        symbol = b"\x00time." + b"Local\x00"
        self.assertFalse(findings(b"\x7fELF\x00" + fields + symbol))
        self.assertIn("private-domain", findings(fields + symbol))
        for value in (b"time." + b"local", b"other." + b"local", b"x509." + b"local"):
            self.assertIn("private-domain", findings(b"\x7fELF\x00" + value + b"\x00"))
