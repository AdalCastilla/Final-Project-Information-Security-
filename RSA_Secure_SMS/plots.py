
import csv
import matplotlib.pyplot as plt

from pathlib import Path


# Results directory
RESULTS = Path(__file__).parent / "results"

CSV_FILE = RESULTS / "rsa_benchmark.csv"


# Read experimental results
with open(CSV_FILE, "r", encoding="utf-8") as file:

    data = list(csv.DictReader(file))


key_sizes = [
    int(row["key_size_bits"])
    for row in data
]

key_times = [
    float(row["key_generation_mean_ms"])
    for row in data
]

encryption_times = [
    float(row["encryption_mean_ms"])
    for row in data
]

decryption_times = [
    float(row["decryption_mean_ms"])
    for row in data
]

encryption_std = [
    float(row["encryption_std_ms"])
    for row in data
]

decryption_std = [
    float(row["decryption_std_ms"])
    for row in data
]

base64_sizes = [
    int(row["base64_characters"])
    for row in data
]

sms_segments = [
    int(row["sms_segments"])
    for row in data
]


# General Plot Style
plt.style.use("ggplot")


def save_plot(filename):

    plt.tight_layout()

    plt.savefig(
        RESULTS / filename,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(f"Generated: {filename}")


# Plot 1: Key Generation Time
plt.figure(figsize=(8, 5))

plt.bar(
    [str(k) for k in key_sizes],
    key_times,
    color="steelblue"
)

plt.title("RSA Key Generation Performance")
plt.xlabel("RSA Key Size (bits)")
plt.ylabel("Average Time (ms)")

save_plot("rsa_key_generation.png")


# Plot 2: Encryption Time
plt.figure(figsize=(8, 5))

plt.errorbar(
    key_sizes,
    encryption_times,
    yerr=encryption_std,
    fmt="o-",
    capsize=5,
    color="royalblue"
)

plt.title("RSA Encryption Performance")
plt.xlabel("RSA Key Size (bits)")
plt.ylabel("Average Time (ms)")
plt.xticks(key_sizes)

save_plot("rsa_encryption.png")


# Plot 3: Decryption Time
plt.figure(figsize=(8, 5))

plt.errorbar(
    key_sizes,
    decryption_times,
    yerr=decryption_std,
    fmt="o-",
    capsize=5,
    color="seagreen"
)

plt.title("RSA Decryption Performance")
plt.xlabel("RSA Key Size (bits)")
plt.ylabel("Average Time (ms)")
plt.xticks(key_sizes)

save_plot("rsa_decryption.png")


# Plot 4: Encryption vs Decryption
plt.figure(figsize=(8, 5))

plt.plot(
    key_sizes,
    encryption_times,
    "o-",
    label="Encryption"
)

plt.plot(
    key_sizes,
    decryption_times,
    "s-",
    label="Decryption"
)

plt.title("RSA Encryption vs Decryption")
plt.xlabel("RSA Key Size (bits)")
plt.ylabel("Average Time (ms)")
plt.xticks(key_sizes)
plt.legend()

save_plot("rsa_comparison.png")


# Plot 5: Base64 Message Size
plt.figure(figsize=(8, 5))

plt.bar(
    [str(k) for k in key_sizes],
    base64_sizes,
    color="mediumpurple"
)

plt.axhline(
    y=160,
    color="red",
    linestyle="--",
    label="Single SMS limit"
)

plt.title("RSA Encrypted Message Size")
plt.xlabel("RSA Key Size (bits)")
plt.ylabel("Base64 Characters")
plt.legend()

save_plot("rsa_message_size.png")


# Plot 6: SMS Segments
plt.figure(figsize=(8, 5))

plt.bar(
    [str(k) for k in key_sizes],
    sms_segments,
    color="darkorange"
)

plt.title("Estimated SMS Segments")
plt.xlabel("RSA Key Size (bits)")
plt.ylabel("Number of SMS Segments")
plt.yticks(range(0, max(sms_segments) + 2))

save_plot("rsa_sms_segments.png")


print("\nAll plots generated successfully.")
