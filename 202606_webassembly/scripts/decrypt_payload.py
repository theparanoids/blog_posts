import base64
import hashlib
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# seed constant in $f67 as `i64.const -8984856996176175547` (line 16796)
# hex = 0x834F602A713C5E45, stored little-endian as 45 5e 3c 71 2a 60 4f 83
SEED = 0x834F602A713C5E45

# Addresses lifted from $f115 / $f67:
XOR_A, XOR_B = 1056952, 1056942            # fragment-selection XOR arrays
FRAG_PTRS, FRAG_LENS = 1058828, 1058832    # fragment table
KEY_TABLE = 1056424                        # 8 x 16-byte blocks, hashed into the AES key

class LinearMemory:
    # rebuilt from .wasm module's active data segments.

    def __init__(self, path):
        with open(path, "rb") as f:
            self.segments = list(self._active_segments(f.read()))

    @staticmethod
    def _uleb(buf, i):
        # unsigned LEB128 at buf[i] -> (value, index_after)
        value = shift = 0
        while True:
            byte = buf[i]
            i += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value, i
            shift += 7

    @classmethod
    def _sections(cls, buf):
        # (id, body) for each section after the 8-byte header
        i = 8
        while i < len(buf):
            size, start = cls._uleb(buf, i + 1)
            yield buf[i], buf[start:start + size]
            i = start + size

    @classmethod
    def _active_segments(cls, buf):
        # (load_address, bytes) for each active, memory-0 data segment
        for sid, body in cls._sections(buf):
            if sid != 11:               # 11 = Data section
                continue
            count, i = cls._uleb(body, 0)
            for _ in range(count):
                flags, i = cls._uleb(body, i)
                assert flags == 0, "expected active, memory-0 segments"
                addr, i = cls._uleb(body, i + 1)   # skip 0x41 i32.const
                size, i = cls._uleb(body, i + 1)   # skip 0x0b end
                yield addr, body[i:i + size]
                i += size

    def read(self, address, n):
        # N bytes of linear memory at address
        for base, blob in self.segments:
            if base <= address and address + n <= base + len(blob):
                return blob[address - base: address - base + n]
        raise ValueError(f"address {address:#x} is not in any data segment")

    def u32(self, address):
        return struct.unpack("<I", self.read(address, 4))[0]


def deobfuscate(mem):
    # $f115 grabs 10/30 fragments, orders,
    # base64-decodes (via $f67) 
    # outputs (indices, base64_text, ciphertext_bytes)
    a = mem.read(XOR_A, 10)
    b = mem.read(XOR_B, 10)
    idx = [a[k] ^ b[k] for k in range(10)]
    frags = [mem.read(mem.u32(FRAG_PTRS + i * 8), mem.u32(FRAG_LENS + i * 8)) for i in idx]
    b64 = b"".join(frags)
    return idx, b64, base64.b64decode(b64)

def derive_key(mem):
    # $f67 builds the key
    # perm[j] = (seed_byte[j] * 5 + 3) & 7
    # message = concat_j( block[perm[j]] XOR (j*55 - 98) )
    # key     = SHA-256(message)
    seed = SEED.to_bytes(8, "little")
    perm = [(seed[j] * 5 + 3) & 7 for j in range(8)]
    table = mem.read(KEY_TABLE, 128)
    blocks = [table[p * 16:p * 16 + 16] for p in range(8)]
    message = b"".join(
        bytes(x ^ ((j * 55 - 98) & 0xFF) for x in blocks[perm[j]])
        for j in range(8)
    )
    return perm, hashlib.sha256(message).digest()

def decrypt(ciphertext, key):
    # AES-256-GCM: blob = nonce(12) || ciphertext || tag(16)
    return AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], None)

def main():
    mem = LinearMemory("connector_bg.wasm")
    idx, b64, ciphertext = deobfuscate(mem)
    perm, key = derive_key(mem)
    plaintext = decrypt(ciphertext, key)

    print(f"fragment indices : {idx}")
    print(f"seed             : {SEED:#018x}")
    print(f"key permutation  : {perm}")
    print(f"derived AES key  : {key.hex()}")
    print(f"\nbase64 blob      :")
    print(b64)
    print(f"\nplaintext ({len(plaintext)} bytes):")
    print(plaintext.decode())

if __name__ == "__main__":
    main()
