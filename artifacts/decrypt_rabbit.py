import sys, struct, os

class RabbitLab1302:
    """
    Exact implementation of the Rabbit stream cipher variant in Lab13-02.exe:
    - Zero-state initialized context (68 bytes memset to 0; no key schedule, no IV, no warmup rounds).
    - Custom counter constants: A[0]=A[3]=A[6] = 0x4D34D35D (differs from RFC 4503 0x4D34D34D by +0x10).
    - Tail preservation: processes partial last block up to exact byte length.
    """
    def __init__(self):
        # 68 bytes context: 8 dwords X, 8 dwords C, 1 dword b (carry)
        self.X = [0] * 8
        self.C = [0] * 8
        self.b = 0
        # Notice 0x4D34D35D at indices 0, 3, 6 (RFC 4503 uses 0x4D34D34D)
        self.A = [
            0x4D34D35D, 0xD34D34D3, 0x34D34D34, 0x4D34D35D,
            0xD34D34D3, 0x34D34D34, 0x4D34D35D, 0xD34D34D3
        ]

    def _rotl(self, val, shift):
        shift &= 31
        return ((val << shift) | (val >> (32 - shift))) & 0xFFFFFFFF

    def _g_func(self, u):
        u &= 0xFFFFFFFF
        prod = u * u
        hi = (prod >> 32) & 0xFFFFFFFF
        lo = prod & 0xFFFFFFFF
        return (lo ^ hi) & 0xFFFFFFFF

    def next_block(self):
        # 1. Counter update (0x40130f - 0x401418)
        c_old = list(self.C)
        carry = self.b
        for j in range(8):
            temp = self.C[j] + self.A[j] + carry
            self.C[j] = temp & 0xFFFFFFFF
            carry = 1 if temp > 0xFFFFFFFF or temp < c_old[j] else 0
        self.b = carry

        # 2. Next-state g-functions (0x401424 - 0x401456)
        G = [self._g_func((self.X[j] + self.C[j]) & 0xFFFFFFFF) for j in range(8)]

        # 3. Next-state mixing with rotations (0x401458 - 0x401568)
        self.X[0] = (G[0] + self._rotl(G[7], 16) + self._rotl(G[6], 16)) & 0xFFFFFFFF
        self.X[1] = (G[1] + self._rotl(G[0], 8)  + G[7]) & 0xFFFFFFFF
        self.X[2] = (G[2] + self._rotl(G[1], 16) + self._rotl(G[0], 16)) & 0xFFFFFFFF
        self.X[3] = (G[3] + self._rotl(G[2], 8)  + G[1]) & 0xFFFFFFFF
        self.X[4] = (G[4] + self._rotl(G[3], 16) + self._rotl(G[2], 16)) & 0xFFFFFFFF
        self.X[5] = (G[5] + self._rotl(G[4], 8)  + G[3]) & 0xFFFFFFFF
        self.X[6] = (G[6] + self._rotl(G[5], 16) + self._rotl(G[4], 16)) & 0xFFFFFFFF
        self.X[7] = (G[7] + self._rotl(G[6], 8)  + G[5]) & 0xFFFFFFFF

        # 4. Keystream extraction (0x401767 - 0x401801)
        s0 = (self.X[0] ^ (self.X[5] >> 16) ^ ((self.X[3] & 0xFFFF) << 16)) & 0xFFFFFFFF
        s1 = (self.X[2] ^ (self.X[7] >> 16) ^ ((self.X[5] & 0xFFFF) << 16)) & 0xFFFFFFFF
        s2 = (self.X[4] ^ (self.X[1] >> 16) ^ ((self.X[7] & 0xFFFF) << 16)) & 0xFFFFFFFF
        s3 = (self.X[6] ^ (self.X[3] >> 16) ^ ((self.X[1] & 0xFFFF) << 16)) & 0xFFFFFFFF
        return struct.pack('<4I', s0, s1, s2, s3)

    def process(self, data):
        """
        Encrypts or decrypts bytes (symmetric XOR stream).
        Preserves tail: the last chunk < 16 bytes is XORed with keystream[:rem].
        """
        out = bytearray()
        offset = 0
        total = len(data)
        while offset < total:
            keystream = self.next_block()
            chunk = data[offset:offset+16]
            chunk_len = len(chunk)
            for i in range(chunk_len):
                out.append(chunk[i] ^ keystream[i])
            offset += 16
        return bytes(out[:total])

def self_check():
    """
    Self-check verifying:
    1. Known keystream vector for Lab13-02 variant
    2. Tail preservation & roundtrip
    3. Live artifact decryption validation if present
    """
    # 1. Keystream check
    c = RabbitLab1302()
    ks0 = c.next_block()
    expected_ks0 = bytes.fromhex('a0a3962c73cc4623ab0aa474f160de42')
    assert ks0 == expected_ks0, f"Keystream vector mismatch: {ks0.hex()} vs {expected_ks0.hex()}"

    # 2. Tail preservation
    c1 = RabbitLab1302()
    c2 = RabbitLab1302()
    dummy = b"BM\x00\x00\x00\x00" + b"A" * 31 # 37 bytes: 16 + 16 + 5 (tail 5)
    enc = c1.process(dummy)
    dec = c2.process(enc)
    assert dec == dummy, "Roundtrip mismatch on unaligned tail"
    assert len(enc) == 37, f"Length altered during process: {len(enc)}"
    assert enc[:2] == bytes([0x42 ^ expected_ks0[0], 0x4D ^ expected_ks0[1]]), "Magic byte XOR mismatch"

    # 3. Artifact validation if present
    artifact = os.path.join(os.path.dirname(__file__), 'temp002a9d1e.enc')
    if os.path.exists(artifact):
        with open(artifact, 'rb') as f:
            art_data = f.read()
        dec_art = RabbitLab1302().process(art_data)
        assert dec_art[:2] == b'BM', f"Artifact recovery failed magic check: {dec_art[:2]}"
        bf_size = struct.unpack('<I', dec_art[2:6])[0]
        assert bf_size == len(art_data), f"Header bfSize {bf_size} != file size {len(art_data)}"
        assert struct.unpack_from('<iiHHI', dec_art, 18) == (1505, 903, 1, 32, 0)
        recovered = os.path.join(os.path.dirname(__file__), 'recovered.bmp')
        if os.path.exists(recovered):
            with open(recovered, 'rb') as f:
                assert dec_art == f.read(), "Packaged recovery differs from decoder output"

    print("[+] All self-checks passed successfully (keystream vector, tail preservation, artifact header).")
    return True

def decrypt_file(in_path, out_path=None):
    with open(in_path, 'rb') as f:
        ciphertext = f.read()
    if len(ciphertext) < 54:
        raise ValueError(f"File {in_path} too small to be a valid BMP ({len(ciphertext)} bytes)")

    cipher = RabbitLab1302()
    plaintext = cipher.process(ciphertext)

    size = struct.unpack_from('<I', plaintext, 2)[0]
    offset, dib_size = struct.unpack_from('<II', plaintext, 10)
    width, height, planes, bits, compression = struct.unpack_from('<iiHHI', plaintext, 18)
    if (plaintext[:2] != b'BM' or size != len(plaintext) or offset != 54 or
            dib_size != 40 or width <= 0 or height == 0 or
            (planes, bits, compression) != (1, 32, 0) or
            offset + width * abs(height) * 4 != size):
        raise ValueError("Recovery is not a valid Lab13-02 32-bpp BMP; no output written")
    print(f"[+] Verified BMP: {width} x {abs(height)}, 32 bpp, {size} bytes.")

    if out_path is None:
        out_path = in_path + '.bmp'
    with open(out_path, 'xb') as f:
        f.write(plaintext)
    print(f"[+] Decrypted {in_path} ({len(ciphertext)} bytes) -> {out_path} ({len(plaintext)} bytes)")
    return out_path

if __name__ == '__main__':
    if len(sys.argv) == 1 or sys.argv[1] == '--test':
        self_check()
    else:
        inp = sys.argv[1]
        out = sys.argv[2] if len(sys.argv) > 2 else None
        decrypt_file(inp, out)
