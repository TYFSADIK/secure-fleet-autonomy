"""Signed firmware images: a small header + Ed25519 signature that the companion/bootloader checks.

Layout:  b"FWSG" | ver(u32) | board(16s) | version(u32 semver packed) | size(u32) | sha256(32) | sig(64) | image
The signature covers the header fields and the image hash. Private key lives offline (YubiKey/HSM).
"""
import hashlib
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

HDR = "<4sI16sII32s"
HDR_LEN = struct.calcsize(HDR)


def pack_version(s):
    a, b, c = (int(x) for x in s.split("."))
    return a << 20 | b << 10 | c


def sign_image(image: bytes, board: str, version: str, key: Ed25519PrivateKey) -> bytes:
    h = struct.pack(HDR, b"FWSG", 1, board.encode()[:16].ljust(16, b"\0"), pack_version(version), len(image),
                    hashlib.sha256(image).digest())
    return h + key.sign(h) + image


def verify_image(blob: bytes, pub: Ed25519PublicKey, board: str, min_version: str) -> bytes:
    h, sig, image = blob[:HDR_LEN], blob[HDR_LEN:HDR_LEN + 64], blob[HDR_LEN + 64:]
    magic, fmt, b, ver, size, digest = struct.unpack(HDR, h)
    if magic != b"FWSG" or fmt != 1:
        raise ValueError("not a signed image")
    try:
        pub.verify(sig, h)
    except InvalidSignature:
        raise ValueError("signature invalid")
    if b.rstrip(b"\0").decode() != board:
        raise ValueError("wrong board")
    if ver < pack_version(min_version):
        raise ValueError("downgrade rejected")
    if size != len(image) or hashlib.sha256(image).digest() != digest:
        raise ValueError("image corrupted")
    return image
