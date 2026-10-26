"""Run a fixed private build on a public runner; publish authenticated ciphertext only."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD = b'nxnative-private-build-v1'
MAX_BYTES = 2 * 1024**3

def seal(data, key):
    assert len(data) <= MAX_BYTES and len(key) == 32
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, AAD)

def unseal(data, key):
    assert 28 <= len(data) <= MAX_BYTES + 28 and len(key) == 32
    return AESGCM(key).decrypt(data[:12], data[12:], AAD)

def extract(data, target):
    target.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        assert len(entries) <= 50000 and sum(i.file_size for i in entries) <= MAX_BYTES
        seen = set()
        for item in entries:
            p = PurePosixPath(item.filename)
            assert not p.is_absolute() and '..' not in p.parts
            assert ':' not in item.filename and '\\' not in item.filename and len(p.parts) < 32
            assert item.filename.casefold() not in seen
            seen.add(item.filename.casefold())
            mode = item.external_attr >> 16
            assert stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR)
            dest = target.joinpath(*p.parts)
            assert dest.resolve().is_relative_to(target.resolve())
            if item.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(item) as src, dest.open('xb') as out:
                    shutil.copyfileobj(src, out, 1024**2)
                dest.chmod(0o755 if mode & 0o111 else 0o644)

def run():
    root = Path(os.environ['RUNNER_TEMP']) / 'sealed-build'
    root.mkdir()
    key = bytes.fromhex(os.environ.pop('BUILD_KEY'))
    payload = Path(sys.argv[1]).read_bytes()
    assert hashlib.sha256(payload).hexdigest() == sys.argv[2]
    extract(unseal(payload, key), root / 'input')
    extract((root / 'input/source.zip').read_bytes(), root / 'source')
    repo = root / 'source'
    output = root / 'output'
    output.mkdir()
    env = dict(os.environ, PYTHONUTF8='1')
    status = {'build_returncode': None, 'probe_returncode': None}
    with (output / 'build.log').open('w') as log:
        def command(args, timeout):
            return subprocess.run(args, cwd=repo, env=env, stdout=log,
                                  stderr=subprocess.STDOUT, timeout=timeout).returncode
        try:
            rc = command([sys.executable, '-m', 'pip', 'install', '-r', 'scripts/cloud-requirements.txt'], 600)
            if rc:
                raise RuntimeError('dependency setup failed')
            rc = command([sys.executable, 'scripts/cloud_ipa.py', 'build', '--input', str(root / 'input/cloud-input'),
                          '--work', str(root / 'work'), '--out', str(output / 'Cloud-intermediate.ipa'),
                          '--language', 'zh-Hant', '--validate-mac'], 7200)
            status['build_returncode'] = rc
            if rc == 0:
                status['probe_returncode'] = command([sys.executable, 'dm/tools/startup_smoke.py',
                                                       str(root / 'work'), '0100C9801FEE6000'], 40)
        except Exception as exc:
            # Keep details encrypted; do not print private logs to public Actions output.
            log.write('\nBuild exception: ' + repr(exc) + '\n')
    logs = root / 'work/logs'
    if logs.is_dir():
        shutil.copytree(logs, output / 'diagnostics')
    (output / 'status.json').write_text(json.dumps(status))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        total = 0
        for p in sorted(output.rglob('*')):
            if p.is_file():
                total += p.stat().st_size
                assert total <= MAX_BYTES
                archive.write(p, p.relative_to(output).as_posix())
    artifact = Path(os.environ['RUNNER_TEMP']) / 'build-output.enc'
    artifact.write_bytes(seal(buffer.getvalue(), key))
    print('Encrypted build result ready. SHA256=' + hashlib.sha256(artifact.read_bytes()).hexdigest())
    return 0 if status['build_returncode'] == 0 else 1

if __name__ == '__main__':
    sys.exit(run())
