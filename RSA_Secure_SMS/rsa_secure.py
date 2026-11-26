
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64
import time
import math


# RSA Key Generation
def generate_keys(bits=2048):

    private_key = RSA.generate(bits)
    public_key = private_key.publickey()

    return public_key, private_key


# RSA-OAEP Encryption
def encrypt(message, public_key):

    cipher = PKCS1_OAEP.new(
        public_key,
        hashAlgo=SHA256
    )

    encrypted = cipher.encrypt(
        message.encode("utf-8")
    )

    return base64.b64encode(encrypted).decode("ascii")


# RSA-OAEP Decryption
def decrypt(ciphertext, private_key):

    cipher = PKCS1_OAEP.new(
        private_key,
        hashAlgo=SHA256
    )

    encrypted = base64.b64decode(ciphertext)

    decrypted = cipher.decrypt(encrypted)

    return decrypted.decode("utf-8")


# SMS Segment Calculation
def sms_segments(ciphertext):

    length = len(ciphertext)

    if length <= 160:
        return 1

    return math.ceil(length / 153)


# Main Program
if __name__ == "__main__":

    bits = 2048

    # Key Generation Time
    start = time.perf_counter()
    public_key, private_key = generate_keys(bits)
    key_time = (time.perf_counter() - start) * 1000

    message = input("Enter your message: ")

    # Encryption Time
    start = time.perf_counter()
    ciphertext = encrypt(message, public_key)
    encryption_time = (time.perf_counter() - start) * 1000

    # Decryption Time
    start = time.perf_counter()
    decrypted = decrypt(ciphertext, private_key)
    decryption_time = (time.perf_counter() - start) * 1000

    print("\n--- RSA SECURE SMS ---")

    print("Key size:", bits, "bits")
    print("Original message:", message)
    print("Original size:", len(message.encode("utf-8")), "bytes")

    print("\nEncrypted message (Base64):")
    print(ciphertext)

    print("\nCiphertext length:", len(ciphertext), "characters")
    print("Estimated SMS segments:", sms_segments(ciphertext))

    print("\nDecrypted message:", decrypted)
    print("Successful decryption:", message == decrypted)

    print("\n--- PERFORMANCE ---")
    print(f"Key generation time: {key_time:.4f} ms")
    print(f"Encryption time: {encryption_time:.4f} ms")
    print(f"Decryption time: {decryption_time:.4f} ms")
