"""Sender -> SMS -> receiver walk-through for RSA-OAEP and ECIES.

Alice encrypts with Bob's public key and the Base64 text is what would travel as the SMS body.
The comparison is done at the receiver: Bob's phone (here, this script) times decryption
with his private key for both algorithms at the same security level.

Run:  .venv/bin/python sms_receiver_demo.py "your message"
"""

from __future__ import annotations

import sys
import time

import ecc_ecies as ecies
import rsa_oaep
from benchmark import sms_segments


def receive(label, decrypt_text, priv, body, runs=50):
    plain = decrypt_text(priv, body)
    t0 = time.perf_counter()
    for _ in range(runs):
        decrypt_text(priv, body)
    avg = (time.perf_counter() - t0) / runs * 1000
    print(f"  [{label}] Bob's phone decrypted: {plain!r}  ({avg:.3f} ms per message)")
    return plain


def main():
    message = sys.argv[1] if len(sys.argv) > 1 else "Meet me at the library at 6 pm. See you!!!"
    print(f"Plaintext ({len(message.encode())} bytes): {message!r}\n")

    for bits, curve in [(2048, "P-224"), (3072, "P-256")]:
        print(f"=== Security level {ecies_security(curve)} bits: RSA-{bits} vs ECC {curve} ===")
        bob_rsa = rsa_oaep.generate_keypair(bits)
        bob_ecc = ecies.generate_keypair(curve)

        rsa_sms = rsa_oaep.encrypt_text(bob_rsa.publickey(), message)
        ecc_sms = ecies.encrypt_text(bob_ecc.public_key(), message)
        print(f"  RSA SMS body ({len(rsa_sms)} chars, {sms_segments(len(rsa_sms))} SMS): {rsa_sms[:60]}...")
        print(f"  ECC SMS body ({len(ecc_sms)} chars, {sms_segments(len(ecc_sms))} SMS): {ecc_sms[:60]}...")

        assert receive("RSA", rsa_oaep.decrypt_text, bob_rsa, rsa_sms) == message
        assert receive("ECC", ecies.decrypt_text, bob_ecc, ecc_sms) == message
        print()


def ecies_security(curve):
    return {"P-224": 112, "P-256": 128}[curve]


if __name__ == "__main__":
    main()
