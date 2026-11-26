
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

from statistics import mean, stdev
from pathlib import Path
from rsa_secure import sms_segments

import base64
import time
import csv


# Experimental Configuration
KEY_SIZES = [1024, 2048, 3072, 4096]

REPETITIONS = 100
KEY_REPETITIONS = 5

MESSAGE = (
    "Hello Bob! This is a confidential message."
).encode("utf-8")


RESULTS_FOLDER = Path(__file__).parent / "results"
RESULTS_FOLDER.mkdir(exist_ok=True)


def benchmark(bits):

    key_times = []
    encryption_times = []
    decryption_times = []

    print(f"\nTesting RSA {bits} bits...")

    # Key Generation Benchmark
    for i in range(KEY_REPETITIONS):

        start = time.perf_counter_ns()

        private_key = RSA.generate(bits)
        public_key = private_key.publickey()

        elapsed = (
            time.perf_counter_ns() - start
        ) / 1_000_000

        key_times.append(elapsed)

        print(
            f"Key generation {i + 1}/"
            f"{KEY_REPETITIONS}: "
            f"{elapsed:.4f} ms"
        )

    # Initialize RSA-OAEP
    encryptor = PKCS1_OAEP.new(
        public_key,
        hashAlgo=SHA256
    )

    decryptor = PKCS1_OAEP.new(
        private_key,
        hashAlgo=SHA256
    )

    # Warm-up
    for _ in range(5):

        ciphertext = encryptor.encrypt(MESSAGE)
        decryptor.decrypt(ciphertext)

    # Encryption and Decryption Benchmark
    for i in range(REPETITIONS):

        # Encryption
        start = time.perf_counter_ns()

        ciphertext = encryptor.encrypt(MESSAGE)

        elapsed = (
            time.perf_counter_ns() - start
        ) / 1_000_000

        encryption_times.append(elapsed)

        # Decryption
        start = time.perf_counter_ns()

        decrypted = decryptor.decrypt(ciphertext)

        elapsed = (
            time.perf_counter_ns() - start
        ) / 1_000_000

        decryption_times.append(elapsed)

        # Verify Correctness
        assert decrypted == MESSAGE

    # Base64 Encoding
    encoded = base64.b64encode(
        ciphertext
    ).decode("ascii")

    # Calculate Experimental Results
    result = {

        "key_size_bits": bits,

        "key_generation_mean_ms":
            mean(key_times),

        "key_generation_std_ms":
            stdev(key_times),

        "encryption_mean_ms":
            mean(encryption_times),

        "encryption_std_ms":
            stdev(encryption_times),

        "decryption_mean_ms":
            mean(decryption_times),

        "decryption_std_ms":
            stdev(decryption_times),

        "plaintext_bytes":
            len(MESSAGE),

        "ciphertext_bytes":
            len(ciphertext),

        "base64_characters":
            len(encoded),

        "sms_segments":
            sms_segments(encoded),

        "successful_tests":
            REPETITIONS
    }

    # Display Results
    print("\n--- RESULTS ---")

    print(
        f"Average key generation: "
        f"{mean(key_times):.4f} ms"
    )

    print(
        f"Average encryption: "
        f"{mean(encryption_times):.4f} ms"
    )

    print(
        f"Average decryption: "
        f"{mean(decryption_times):.4f} ms"
    )

    print(
        f"Encryption standard deviation: "
        f"{stdev(encryption_times):.4f} ms"
    )

    print(
        f"Decryption standard deviation: "
        f"{stdev(decryption_times):.4f} ms"
    )

    print("Ciphertext bytes:", len(ciphertext))
    print("Base64 characters:", len(encoded))
    print("SMS segments:", sms_segments(encoded))
    print("Successful tests:", REPETITIONS)

    return result


def main():

    results = []

    print("==============================")
    print("  RSA PERFORMANCE EVALUATION")
    print("==============================")

    print("Message:", MESSAGE.decode())
    print("Message size:", len(MESSAGE), "bytes")
    print("Repetitions:", REPETITIONS)

    for bits in KEY_SIZES:

        result = benchmark(bits)
        results.append(result)

    # Save CSV Results
    output_file = (
        RESULTS_FOLDER / "rsa_benchmark.csv"
    )

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=results[0].keys()
        )

        writer.writeheader()
        writer.writerows(results)

    print("\n==============================")
    print("BENCHMARK COMPLETED")
    print("==============================")

    print("Results saved to:")
    print(output_file)


if __name__ == "__main__":

    main()
