import hashlib
import io
import tarfile
import unittest

from verify_overlay_image import CERTS, check_layer


def inspect(name, payload, seen, mode=0o555, kind=tarfile.REGTYPE):
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode='w') as archive:
        entry = tarfile.TarInfo(name)
        entry.mode, entry.type, entry.size = mode, kind, len(payload)
        archive.addfile(entry, io.BytesIO(payload))
    content.seek(0)
    with tarfile.open(fileobj=content, mode='r|*') as layer:
        check_layer(layer, seen, hashlib.sha256(b'tested worker').digest())


class OverlayImageTest(unittest.TestCase):
    def test_exact_release_is_read_only_and_cannot_be_replaced_in_a_later_layer(self):
        seen = set()
        inspect('overlay-worker', b'tested worker', seen)
        self.assertEqual(seen, {'overlay-worker'})
        with self.assertRaises(ValueError):
            inspect('overlay-worker', b'tested worker', seen)
        for payload, mode in [(b'other binary', 0o555), (b'tested worker', 0o755)]:
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                inspect('overlay-worker', payload, set(), mode)

    def test_unknown_files_links_whiteouts_and_noncertificate_bytes_fail(self):
        for name, kind in [('private.json', tarfile.REGTYPE), ('.wh.private.json', tarfile.REGTYPE),
                           ('overlay-worker', tarfile.SYMTYPE), (CERTS, tarfile.REGTYPE)]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                inspect(name, b'unexpected', set(), kind=kind)
