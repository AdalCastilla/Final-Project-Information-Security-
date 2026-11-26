"""RSA-OAEP (SHA-256) baseline, using the same construction as the team's RSA module,
so that RSA and ECC can be benchmarked on the same machine with the same workload."""

from __future__ import annotations

import base64

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def generate_keypair(bits: int = 2048) -> RSA.RsaKey:
    return RSA.generate(bits)


def encrypt(public_key: RSA.RsaKey, plaintext: bytes) -> bytes:
    return PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(plaintext)


def decrypt(private_key: RSA.RsaKey, ciphertext: bytes) -> bytes:
    return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(ciphertext)


def encrypt_text(public_key: RSA.RsaKey, message: str) -> str:
    return base64.b64encode(encrypt(public_key, message.encode("utf-8"))).decode("ascii")


def decrypt_text(private_key: RSA.RsaKey, sms_body: str) -> str:
    return decrypt(private_key, base64.b64decode(sms_body, validate=True)).decode("utf-8")


def max_plaintext(bits: int) -> int:
    """OAEP-SHA256 capacity: k - 2*hLen - 2 bytes."""
    return bits // 8 - 2 * 32 - 2
