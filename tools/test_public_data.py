from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from check_public_data import findings, scan_history


class PublicDataTest(unittest.TestCase):
    def test_history_scans_deleted_blobs_and_binary_bytes_on_other_refs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args])

            git("init", "--quiet", "--initial-branch=main")
            git("config", "user.name", "Synthetic Test")
            git("config", "user.email", "fixture@users.noreply.github.com")
            git("config", "commit.gpgsign", "false")
            sample = root / "probe.txt"
            sample.write_bytes(b"first\nserver." + b"local\nlast\n")
            git("add", "probe.txt")
            git("commit", "--quiet", "-m", "Synthetic history fixture")
            old = git("rev-parse", "HEAD:probe.txt").decode().strip()
            git("rm", "--quiet", "probe.txt")
            git("commit", "--quiet", "-m", "Remove synthetic history fixture")
            git("switch", "--quiet", "-c", "other")
            (root / "probe.bin").write_bytes(b"line\n\0bytes\n")
            git("add", "probe.bin")
            git("commit", "--quiet", "-m", "Synthetic binary fixture")
            binary = git("rev-parse", "HEAD:probe.bin").decode().strip()
            git("switch", "--quiet", "main")
            with patch("check_public_data.ROOT", root):
                self.assertEqual(set(scan_history()), {
                    (old[:12] + ":probe.txt", "private-domain"),
                    (binary[:12] + ":probe.bin", "unreviewed-binary"),
                })

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

    def test_only_exact_public_pgx_elf_regexp_is_not_a_credential_uri(self):
        symbol=b"github.com/jackc/pgx/v5/pgconn.redactURLPassword"
        regexp=b":"+b"[^@]+"+b"@"
        joined=b"formatconstant://a=,b=%s%s,c=%v"+regexp
        elf=bytes([127])+b"ELF"+bytes([0])+symbol+bytes([0])
        self.assertNotIn("credential-url",findings(elf+joined))
        self.assertIn("credential-url",findings(joined))
        self.assertIn("credential-url",findings(bytes([127])+b"ELF"+joined))
        self.assertIn("credential-url",findings(elf+joined.replace(regexp,b":"+b"[^@]*"+b"@")))
        real=b"https://"+b"synthetic:placeholder@"+b"example.invalid"
        self.assertIn("credential-url",findings(elf+joined+bytes([0])+real))

    def test_only_exact_go_elf_symbols_are_not_mistaken_for_domains(self):
        fields = b"crypto/x509." + b"local string; crypto/x509.domain string"
        symbol = b"\x00time." + b"Local\x00"
        self.assertFalse(findings(b"\x7fELF\x00" + fields + symbol))
        self.assertIn("private-domain", findings(fields + symbol))
        for value in (b"time." + b"local", b"other." + b"local", b"x509." + b"local"):
            self.assertIn("private-domain", findings(b"\x7fELF\x00" + value + b"\x00"))

    def test_only_exact_public_go_rodata_userinfo_is_exempt(self):
        metadata = (
            b"\x7fELF\x00go1.27.3\x00"
            b"dep\tgithub.com/jackc/pgx/v5\tv5.11.0\tchecksum\n"
            b"dep\tgithub.com/santhosh-tekuri/jsonschema/v6\tv6.0.3\tchecksum\n"
        )
        prefix = b"bad inst" + b"https://"
        suffix = (
            b"passworddatabasepassfilePGSSLKEYPGSSLSNItimezoneDEK-Inforoot.crt"
            + b":xxxxxx@"
        )
        real = b"https://" + b"synthetic:placeholder@" + b"example.invalid"
        for middle in (b"Location", b"audienceownerTagdeviceIdprovider"):
            public = prefix + middle + suffix
            with self.subTest(middle=middle):
                self.assertNotIn("credential-url", findings(metadata + public))
                self.assertIn("credential-url", findings(public))
                self.assertIn("credential-url", findings(metadata.replace(b"go1.27.3", b"go1.27.4") + public))
                self.assertIn("credential-url", findings(metadata + public.replace(b"root.crt", b"root.key")))
                self.assertIn("credential-url", findings(metadata + public + b"\x00" + real))
                self.assertIn("credential-url", findings(metadata + public + b"extra@"))
        self.assertIn("credential-url", findings(metadata + prefix + b"audienceownerTagdeviceIdaudience" + suffix))
