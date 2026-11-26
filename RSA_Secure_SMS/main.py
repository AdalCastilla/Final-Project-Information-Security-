
from rsa_secure import encrypt, decrypt, sms_segments
from key_manager import load_public_key, load_private_key
import time


def main():

    print("\n==============================")
    print("       RSA SECURE SMS")
    print("==============================")

    print("\n1. Alice sends a message to Bob")
    print("2. Bob sends a message to Alice")

    option = input("\nSelect an option: ")

    if option == "1":
        sender = "alice"
        receiver = "bob"

    elif option == "2":
        sender = "bob"
        receiver = "alice"

    else:
        print("Invalid option.")
        return

    # Load recipient's public key
    public_key = load_public_key(receiver)

    print("\n--- MESSAGE COMPOSITION ---")
    print("Sender:", sender.capitalize())
    print("Receiver:", receiver.capitalize())
    print("Key size:", public_key.size_in_bits(), "bits")

    message = input("Enter your message: ")

    # Check maximum RSA-OAEP message length
    max_bytes = public_key.size_in_bytes() - 66

    if len(message.encode("utf-8")) > max_bytes:
        print("Message is too large.")
        print("Maximum size:", max_bytes, "bytes")
        return

    # Encryption
    start = time.perf_counter()

    ciphertext = encrypt(message, public_key)

    encryption_time = (
        time.perf_counter() - start
    ) * 1000

    print("\n--- ENCRYPTED MESSAGE ---")
    print(ciphertext)

    print("\nCiphertext length:",
          len(ciphertext), "characters")

    print("Estimated SMS segments:",
          sms_segments(ciphertext))

    # Simulated transmission
    print("\n--- COMMUNICATION CHANNEL ---")
    print("Encrypted message transmitted (simulation).")

    # Load recipient's private key
    private_key = load_private_key(receiver)

    # Decryption
    start = time.perf_counter()

    decrypted = decrypt(ciphertext, private_key)

    decryption_time = (
        time.perf_counter() - start
    ) * 1000

    print("\n--- RECEIVED MESSAGE ---")
    print("Receiver:", receiver.capitalize())
    print("Decrypted message:", decrypted)
    print("Successful decryption:", decrypted == message)

    # Security test with incorrect private key
    print("\n--- SECURITY TEST ---")

    wrong_private_key = load_private_key(sender)

    try:
        decrypt(ciphertext, wrong_private_key)
        print("Security test: FAILED")

    except ValueError:
        print("Incorrect private key detected.")
        print("Decryption denied.")
        print("Security test: PASSED")

    # Performance results
    print("\n--- PERFORMANCE ---")
    print(f"Encryption time: {encryption_time:.4f} ms")
    print(f"Decryption time: {decryption_time:.4f} ms")


if __name__ == "__main__":
    main()
