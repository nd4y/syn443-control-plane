"""Actual issuer/API pilot boundary, with temporary synthetic keys/capabilities."""
import base64
import hashlib
import json
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import os

serve, sign = map(lambda p: str(Path(p).resolve()), sys.argv[1:])
with tempfile.TemporaryDirectory(prefix='syn443-pilot-') as temporary:
    folder = Path(temporary)
    key = folder/'issuer.pem'
    subprocess.run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',str(key)],check=True,capture_output=True)
    key.chmod(0o600)
    spki = subprocess.check_output(['openssl','pkey','-in',str(key),'-pubout','-outform','DER'])
    fixture = json.loads(Path('contracts/v1/policy-vectors.json').read_text())
    payload = json.loads(bytes.fromhex(fixture['payloadHex']))
    now = int(time.time()*1000)
    payload.update(issuedAtMs=now-5000,notBeforeMs=now-5000,refreshAfterMs=now+10000,offlineUntilMs=now+600000)
    env = dict(os.environ, SYN443_POLICY_SIGNING_KEY_FILE=str(key), SYN443_POLICY_KEY_ID='test-root',
               SYN443_POLICY_DEVICE=payload['targetDevice'], SYN443_POLICY_REVISION=str(payload['revision']))
    signed = subprocess.run([sign],input=json.dumps(payload).encode(),env=env,capture_output=True,check=True).stdout.decode().strip()
    assert len(signed.split('.'))==3
    denied = subprocess.run([sign],input=json.dumps(payload).encode(),env=dict(env,SYN443_POLICY_DEVICE='another-device'),capture_output=True)
    assert denied.returncode and not denied.stdout
    token = secrets.token_urlsafe(32)
    publication = folder/'publication.json'
    publication.write_text(json.dumps({'device':payload['targetDevice'],'tokenSHA256':hashlib.sha256(token.encode()).hexdigest(),'bundle':signed}))
    publication.chmod(0o600)
    roots = folder/'roots.json'; roots.write_text(json.dumps({'test-root':base64.b64encode(spki).decode()})); roots.chmod(0o600)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0)); port=listener.getsockname()[1]
    server_env = dict(os.environ,SYN443_POLICY_LISTEN='127.0.0.1:'+str(port),SYN443_POLICY_PUBLICATION_FILE=str(publication),SYN443_POLICY_ROOTS_FILE=str(roots))
    process = subprocess.Popen([serve],env=server_env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        url='http://127.0.0.1:'+str(port)+'/v1/device/policy'
        for _ in range(50):
            try:
                urllib.request.urlopen(url,timeout=1)
            except urllib.error.HTTPError as e:
                if e.code==401:
                    break
            except urllib.error.URLError:
                time.sleep(.1)
        else:
            raise AssertionError('Pilot API did not start')
        request=urllib.request.Request(url,headers={'Authorization':'Bearer '+token,'X-SYN443-Device':payload['targetDevice']})
        with urllib.request.urlopen(request,timeout=3) as response:
            assert response.read().decode()==signed and response.headers['Date'] and response.headers['Cache-Control']=='no-store'
        request=urllib.request.Request(url,headers={'Authorization':'Bearer '+token,'X-SYN443-Device':'another-device'})
        try:
            urllib.request.urlopen(request,timeout=3)
        except urllib.error.HTTPError as e:
            assert e.code==401 and signed.encode() not in e.read()
        else:
            raise AssertionError('Cross-device artifact disclosed')
    finally:
        process.terminate(); process.communicate(timeout=5)
print('Pilot issuer/API: scoped signing, authenticated delivery and recipient isolation passed')
