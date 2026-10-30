import hashlib
import zipfile
from pathlib import Path
from build import BID, PATCH_SHA256

ROOT = Path(__file__).resolve().parent


def main():
    mod = ROOT / 'dist/DreadDeltaTime/exefs' / (BID + '.ips')
    payload = mod.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == PATCH_SHA256
    for name in ('Dread-1.0.0-DeltaTime-v2.zip', 'Dread-1.0.0-DeltaTime-experimental.zip'):
        with zipfile.ZipFile(ROOT / name, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.write(mod, 'DreadDeltaTime/exefs/' + mod.name)
        with zipfile.ZipFile(ROOT / name) as archive:
            assert archive.testzip() is None
            assert archive.namelist() == ['DreadDeltaTime/exefs/' + mod.name]
            assert archive.read('DreadDeltaTime/exefs/' + mod.name) == payload
    print('Dread-1.0.0-DeltaTime-v2.zip')


if __name__ == '__main__':
    main()
