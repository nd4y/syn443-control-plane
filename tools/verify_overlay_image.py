"""Check every shipped filesystem layer, including files hidden by later layers."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import ssl
import sys
import tarfile

CERTS = 'etc/ssl/certs/ca-certificates.crt'
DIRECTORIES = {'.', 'etc', 'etc/ssl', 'etc/ssl/certs'}


def check_layer(layer, seen, expected, service='overlay-worker'):
    for item in layer:
        name = str(PurePosixPath(item.name))
        if item.isdir() and name in DIRECTORIES:
            continue
        if not item.isreg() or name not in (service, CERTS) or name in seen:
            raise ValueError('Unexpected or repeated image layer entry')
        seen.add(name)
        with layer.extractfile(item) as data:
            if name == service:
                if item.mode & 0o7777 != 0o555 or hashlib.file_digest(data, 'sha256').digest() != expected:
                    raise ValueError('Image binary differs from the scanned release')
            else:
                if not 0 < item.size <= 1024 * 1024:
                    raise ValueError('Invalid certificate bundle size')
                pem = data.read().decode('ascii').strip()
                block = r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----'
                if not re.fullmatch(r'(?:' + block + r'\s*)+', pem):
                    raise ValueError('Unexpected data accompanying public CA roots')
                ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=pem)


def verify(archive, binary, tag, service='overlay-worker'):
    if service not in ('overlay-worker', 'telemetry-ingest'):
        raise ValueError('Unknown service image')
    with binary.open('rb') as data:
        expected = hashlib.file_digest(data, 'sha256').digest()
    with tarfile.open(archive, 'r:gz') as image:
        names = image.getnames()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate image archive entries')
        with image.extractfile('manifest.json') as stream:
            manifest, = json.load(stream)
        if manifest['RepoTags'] != [tag] or len(manifest['Layers']) != 2:
            raise ValueError('Unexpected image tag or layer count')
        seen = set()
        for name in manifest['Layers']:
            with image.extractfile(name) as raw, tarfile.open(fileobj=raw, mode='r|*') as layer:
                check_layer(layer, seen, expected, service)
        if seen != {service, CERTS}:
            raise ValueError('Incomplete release root filesystem')


if __name__ == '__main__':
    verify(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], *sys.argv[4:])
