
from Crypto.Util.number import getPrime
from math import gcd


# RSA Key Generation
def generate_keys(bits=2048):

    e = 65537

    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)

        n = p * q
        phi = (p - 1) * (q - 1)

        if p != q and gcd(e, phi) == 1 and n.bit_length() == bits:
            break

    d = pow(e, -1, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


# RSA Encryption
def encrypt(message, public_key):

    e, n = public_key

    M = int.from_bytes(message.encode("utf-8"), "big")

    if M >= n:
        raise ValueError("Message is too large for this key.")

    C = pow(M, e, n)

    return C


# RSA Decryption
def decrypt(ciphertext, private_key):

    d, n = private_key

    M = pow(ciphertext, d, n)

    message = M.to_bytes(
        (M.bit_length() + 7) // 8, "big"
    ).decode("utf-8")

    return message


# RSA Demonstration
if __name__ == "__main__":

    public_key, private_key = generate_keys(2048)

    message = input("Enter your message: ")

    ciphertext = encrypt(message, public_key)

    decrypted = decrypt(ciphertext, private_key)

    print("\n--- RSA ENCRYPTION ---")
    print("Key size:", public_key[1].bit_length(), "bits")
    print("Original message:", message)
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", decrypted)
    print("Successful decryption:", message == decrypted)
