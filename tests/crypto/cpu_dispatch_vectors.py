"""Generate full SHA/HMAC output oracles for the native dispatch regression."""

from __future__ import annotations

import hashlib
import hmac
import struct
import sys

lengths = (
    0,
    1,
    15,
    16,
    31,
    32,
    33,
    55,
    56,
    63,
    64,
    65,
    119,
    120,
    127,
    128,
    129,
    255,
    256,
    257,
    1024,
    4096,
)
key_lengths = (0, 1, 16, 31, 32, 33, 63, 64, 65, 127, 128, 129, 512)
records = []
for length in lengths:
    for key_length in key_lengths:
        seed = struct.pack("<II", key_length, length)
        for pattern in range(5):
            if pattern < 4:
                key = bytes(((0, 0x42, 0xAA, 0xFF)[pattern],)) * key_length
                message = bytes(((0, 0xBB, 0xAA, 0xFF)[pattern],)) * length
            else:
                key = hashlib.shake_256(b"key" + seed).digest(key_length)
                message = hashlib.shake_256(b"message" + seed).digest(length)
            expected = b"".join(
                hashlib.new(name, message).digest()
                for name in ("sha224", "sha256", "sha384", "sha512")
            )
            expected += b"".join(
                hmac.digest(key, message, name) for name in ("sha256", "sha384", "sha512")
            )
            records.append(seed + key + message + expected)
sys.stdout.buffer.write(b"AEGDIS01" + struct.pack("<I", len(records)) + b"".join(records))
