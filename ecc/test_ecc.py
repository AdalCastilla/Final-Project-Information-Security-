import base64
import unittest

from Crypto.PublicKey import ECC

import ecc_ecies as ecies
import rsa_oaep


class EciesTests(unittest.TestCase):
    def test_round_trip_all_curves(self):
        for curve in ecies.CURVES:
            with self.subTest(curve=curve):
                bob = ecies.generate_keypair(curve)
                msg = "Meet at the library at 6 pm. -Alice"
                body = ecies.encrypt_text(bob.public_key(), msg)
                self.assertEqual(ecies.decrypt_text(bob, body), msg)
                self.assertEqual(len(base64.b64decode(body)), ecies.ciphertext_len(curve, len(msg)))

    def test_uncompressed_point(self):
        for curve in ecies.CURVES:
            with self.subTest(curve=curve):
                bob = ecies.generate_keypair(curve)
                blob = ecies.encrypt(bob.public_key(), b"hello", compress=False)
                self.assertEqual(blob[0], 4)
                self.assertEqual(len(blob), ecies.ciphertext_len(curve, 5, compress=False))
                self.assertEqual(ecies.decrypt(bob, blob), b"hello")

    def test_unicode(self):
        bob = ecies.generate_keypair("P-256")
        msg = "Hola, ¿cómo estás? 🔐"
        self.assertEqual(ecies.decrypt_text(bob, ecies.encrypt_text(bob.public_key(), msg)), msg)

    def test_randomized(self):
        bob = ecies.generate_keypair("P-256")
        a = ecies.encrypt(bob.public_key(), b"same")
        b = ecies.encrypt(bob.public_key(), b"same")
        self.assertNotEqual(a, b)

    def test_tamper_detected(self):
        bob = ecies.generate_keypair("P-256")
        blob = bytearray(ecies.encrypt(bob.public_key(), b"transfer 10 pesos"))
        blob[-1] ^= 0x01
        with self.assertRaises(ValueError):
            ecies.decrypt(bob, bytes(blob))

    def test_wrong_key_rejected(self):
        bob = ecies.generate_keypair("P-256")
        eve = ecies.generate_keypair("P-256")
        blob = ecies.encrypt(bob.public_key(), b"secret")
        with self.assertRaises(ValueError):
            ecies.decrypt(eve, blob)

    def test_key_export_import(self):
        bob = ecies.generate_keypair("P-384")
        pem = bob.export_key(format="PEM")
        bob2 = ECC.import_key(pem)
        blob = ecies.encrypt(bob.public_key(), b"pem works")
        self.assertEqual(ecies.decrypt(bob2, blob), b"pem works")


class RsaTests(unittest.TestCase):
    def test_round_trip(self):
        k = rsa_oaep.generate_keypair(2048)
        self.assertEqual(rsa_oaep.decrypt_text(k, rsa_oaep.encrypt_text(k.publickey(), "hi")), "hi")


if __name__ == "__main__":
    unittest.main()
