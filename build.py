import argparse
import hashlib
import struct
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BID = '49161D9CCBC15DF944D0B6278A3C446C006B0BE8'
PATCH_SHA256 = 'f5d58727d813732ff954d20b6f43fb392854500b4e23a9668d98a8d6bdc26bdf'


def branch(source, destination, link=False):
    assert (destination - source) % 4 == 0
    displacement = (destination - source) // 4
    assert -(1 << 25) <= displacement < (1 << 25)
    return struct.pack('<I', (0x94000000 if link else 0x14000000) | (displacement & 0x3FFFFFF))


def source_image(path):
    import lz4.block

    nso = Path(path).read_bytes()
    assert nso[:4] == b'NSO0' and nso[0x40:0x54].hex().upper() == BID
    image = bytearray(0x1CED878)
    for index in range(3):
        offset, address, size = struct.unpack_from('<III', nso, 0x10 + index * 16)
        stored = struct.unpack_from('<I', nso, 0x60 + index * 4)[0]
        data = lz4.block.decompress(nso[offset:offset + stored], uncompressed_size=size)
        assert hashlib.sha256(data).digest() == nso[0xA0 + index * 32:0xC0 + index * 32]
        image[address:address + size] = data
    return image


def build_patch(image):
    records = []

    def add(address, expected, patched):
        assert image[address:address + len(expected)] == expected, hex(address)
        assert len(expected) == len(patched)
        records.append((address, patched))

    def word(value):
        return struct.pack('<I', value)

    add(0x159208, word(0x6B00011F), word(0x7100011F))
    add(0x159210, word(0xB9000260), word(0xB900027F))
    add(0x15921C, word(0x2A0003E1), word(0x2A1F03E1))
    for start, end in ((0xB287C8, 0xB28878), (0xB2DFBC, 0xB2E028)):
        calls = [address for address in range(start, end, 4)
                 if image[address:address + 4] == branch(address, 0x80BB0, True)]
        assert len(calls) == 1, calls
        address = calls[0]
        add(address, branch(address, 0x80BB0, True), branch(address, 0x80DA0, True))
    add(0x1155678, word(0x1E20CC20), word(0xD503201F))
    add(0x115569C, word(0x1E200880), word(0xD503201F))
    payload = bytearray(b'IPS32')
    for address, code in records:
        payload += (address + 0x100).to_bytes(4, 'big') + len(code).to_bytes(2, 'big') + code
    payload += b'EEOF'
    assert hashlib.sha256(payload).hexdigest() == PATCH_SHA256
    return bytes(payload), records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--nso', type=Path, default=ROOT / 'main.nso')
    args = parser.parse_args()
    payload, records = build_patch(source_image(args.nso))
    mod = ROOT / 'dist/DreadDeltaTime/exefs'
    mod.mkdir(parents=True, exist_ok=True)
    (mod / (BID + '.ips')).write_bytes(payload)
    (ROOT / 'Dread-1.0.0-DeltaTime.pchtxt').write_text(
        f'@nsobid-{BID}\n@flag offset_shift 0x100\n@enabled\n' +
        '\n'.join(f'{address:08X} {code.hex().upper()}' for address, code in records) + '\n@stop\n')
    with zipfile.ZipFile(ROOT / 'Dread-1.0.0-DeltaTime-experimental.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.write(mod / (BID + '.ips'), 'DreadDeltaTime/exefs/' + BID + '.ips')
    print('Dread-1.0.0-DeltaTime-experimental.zip')


if __name__ == '__main__':
    main()
