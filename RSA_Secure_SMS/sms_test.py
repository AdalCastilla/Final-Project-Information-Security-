
import os
import time

from rsa_secure import encrypt, decrypt, sms_segments
from key_manager import load_public_key, load_private_key
from sms_service import send_sms
from twilio.base.exceptions import TwilioRestException


def main():

    print("==============================")
    print("     RSA REAL SMS TEST")
    print("==============================")

    recipient = os.getenv("RECIPIENT_PHONE_NUMBER")

    if not recipient:
        print("Recipient phone number not configured.")
        return

    # Load Bob's public key
    public_key = load_public_key("bob")

    message = input("\nEnter your message: ")

    # Validate message size
    max_bytes = public_key.size_in_bytes() - 66

    if not message or len(message.encode("utf-8")) > max_bytes:
        print(f"Invalid message. Maximum: {max_bytes} bytes.")
        return

    # RSA Encryption
    start = time.perf_counter()

    ciphertext = encrypt(message, public_key)

    encryption_time = (
        time.perf_counter() - start
    ) * 1000

    print("\n--- RSA ENCRYPTION ---")
    print("Original message:", message)
    print("Key size:", public_key.size_in_bits())
    print("Ciphertext:", ciphertext)
    print("Base64 characters:", len(ciphertext))
    print("Estimated SMS segments:", sms_segments(ciphertext))
    print(f"Encryption time: {encryption_time:.4f} ms")

    # Confirm SMS transmission
    confirmation = input("\nSend real SMS? (y/n): ")

    if confirmation.lower() != "y":
        print("Transmission cancelled.")
        return

    # Real SMS Transmission
    print("\n--- SMS TRANSMISSION ---")

    try:

        sms = send_sms(ciphertext, recipient)

        print("SMS request accepted.")
        print("Message SID:", sms.sid)
        print("Status:", sms.status)

    except TwilioRestException as error:

        print("SMS transmission failed.")
        print("Error code:", error.code)
        print("Description:", error.msg)
        return

    # Receive ciphertext from mobile phone
    print("\n--- SMS RECEPTION ---")

    received = input(
        "Paste the SMS received on Bob's phone: "
    ).strip()

    # Verify transmission
    print("Ciphertext match:", received == ciphertext)

    # RSA Decryption
    try:

        private_key = load_private_key("bob")

        start = time.perf_counter()

        decrypted = decrypt(received, private_key)

        decryption_time = (
            time.perf_counter() - start
        ) * 1000

        print("\n--- RSA DECRYPTION ---")
        print("Decrypted message:", decrypted)
        print("Successful decryption:", decrypted == message)
        print(f"Decryption time: {decryption_time:.4f} ms")

    except ValueError:

        print("Decryption failed.")


if __name__ == "__main__":
    main()
