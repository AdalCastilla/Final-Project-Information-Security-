"""ECIES (Elliptic Curve Integrated Encryption Scheme) for short text messages.

Construction, per message:
  1. The sender generates an ephemeral key pair (k, K = kG) on the recipient's curve.
  2. Shared secret Z = x-coordinate of k * Q_B, where Q_B is the recipient's public key (ECDH).
  3. A 256-bit AES key is derived with HKDF-SHA256 over Z, bound to both public keys.
  4. The message is encrypted with AES-256-GCM (confidentiality + integrity).

Wire format (binary):  K (SEC1 point) || nonce (12 B) || tag (16 B) || ciphertext
K is compressed by default (1 + ceil(bits/8) bytes) to keep the SMS short; the uncompressed
form (1 + 2*ceil(bits/8) bytes) avoids a modular square root at the receiver.
For SMS the binary blob is Base64-encoded, matching the RSA-OAEP module of the project.

Elliptic curves cannot encrypt arbitrary data directly the way RSA does, so ECIES is the
standard way to turn ECC into a public-key encryption scheme (SEC 1 v2, ISO/IEC 18033-2).
"""

from __future__ import annotations

import base64
import math

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes

# NIST prime curves supported by the benchmark, with their field size in bits.
CURVES = {
    "P-192": 192,
    "P-224": 224,
    "P-256": 256,
    "P-384": 384,
    "P-521": 521,
}

NONCE_LEN = 12
TAG_LEN = 16
HKDF_INFO = b"LIS4062-SMS-ECIES-v1"


def point_len(curve: str, compress: bool = True) -> int:
    """Length in bytes of a SEC1 point on `curve`."""
    n = math.ceil(CURVES[curve] / 8)
    return 1 + n if compress else 1 + 2 * n


def generate_keypair(curve: str = "P-256") -> ECC.EccKey:
    """Generate a static (long-term) key pair d, Q = dG; its .public_key() is shared."""
    if curve not in CURVES:
        raise ValueError(f"unsupported curve {curve!r}")
    key = ECC.generate(curve=curve)
    key.pointQ  # PyCryptodome computes Q lazily; force it so key generation is complete.
    return key


def _derive_key(priv: ECC.EccKey, peer_pub: ECC.EccKey, eph_bytes: bytes, recip_bytes: bytes) -> bytes:
    """ECDH + HKDF-SHA256. Both public keys go into the KDF context to bind the key to them."""

    def kdf(z: bytes) -> bytes:
        return HKDF(z, 32, salt=b"", hashmod=SHA256, context=HKDF_INFO + eph_bytes + recip_bytes)

    return key_agreement(static_priv=priv, static_pub=peer_pub, kdf=kdf)


def encrypt(recipient_pub: ECC.EccKey, plaintext: bytes, compress: bool = True) -> bytes:
    curve = recipient_pub.curve
    ephemeral = ECC.generate(curve=curve)
    eph_bytes = ephemeral.public_key().export_key(format="SEC1", compress=compress)
    recip_bytes = recipient_pub.export_key(format="SEC1", compress=True)

    key = _derive_key(ephemeral, recipient_pub, eph_bytes, recip_bytes)
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return eph_bytes + nonce + tag + ciphertext


def decrypt(recipient_priv: ECC.EccKey, blob: bytes) -> bytes:
    """Receiver side. Raises ValueError if the message was tampered with or the key is wrong."""
    curve = _canonical_curve(recipient_priv.curve)
    if not blob:
        raise ValueError("empty ciphertext")
    # SEC1 prefix: 0x02/0x03 = compressed point, 0x04 = uncompressed point.
    if blob[0] in (2, 3):
        plen = point_len(curve, compress=True)
    elif blob[0] == 4:
        plen = point_len(curve, compress=False)
    else:
        raise ValueError("invalid ephemeral point encoding")
    if len(blob) < plen + NONCE_LEN + TAG_LEN:
        raise ValueError("ciphertext too short")

    eph_bytes = blob[:plen]
    nonce = blob[plen : plen + NONCE_LEN]
    tag = blob[plen + NONCE_LEN : plen + NONCE_LEN + TAG_LEN]
    ciphertext = blob[plen + NONCE_LEN + TAG_LEN :]

    ephemeral_pub = ECC.import_key(eph_bytes, curve_name=curve)
    recip_bytes = recipient_priv.public_key().export_key(format="SEC1", compress=True)

    key = _derive_key(recipient_priv, ephemeral_pub, eph_bytes, recip_bytes)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
    return cipher.decrypt_and_verify(ciphertext, tag)


def encrypt_text(recipient_pub: ECC.EccKey, message: str) -> str:
    """UTF-8 text -> Base64 string that can be sent as an SMS body."""
    return base64.b64encode(encrypt(recipient_pub, message.encode("utf-8"))).decode("ascii")


def decrypt_text(recipient_priv: ECC.EccKey, sms_body: str) -> str:
    return decrypt(recipient_priv, base64.b64decode(sms_body, validate=True)).decode("utf-8")


def ciphertext_len(curve: str, plaintext_len: int, compress: bool = True) -> int:
    return point_len(curve, compress) + NONCE_LEN + TAG_LEN + plaintext_len


def _canonical_curve(name: str) -> str:
    """PyCryptodome reports names like 'NIST P-256'; map back to our keys."""
    for c in CURVES:
        if name.endswith(c) or name.replace("p", "P-").endswith(c):
            return c
    aliases = {"secp192r1": "P-192", "secp224r1": "P-224", "secp256r1": "P-256",
               "secp384r1": "P-384", "secp521r1": "P-521", "prime256v1": "P-256"}
    if name in aliases:
        return aliases[name]
    raise ValueError(f"unsupported curve {name!r}")
