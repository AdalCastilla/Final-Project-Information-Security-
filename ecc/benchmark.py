"""RSA-OAEP vs ECC (ECIES) benchmark, same machine, same workload.

Protocol (mirrors the team's RSA benchmark, Section "Performance Evaluation Methodology"):
  * fixed 42-byte UTF-8 test message
  * 5 timed key generations per key size
  * 5 warm-up operations, then 100 timed encryptions and 100 timed decryptions
  * time.perf_counter(), Base64 excluded from timings
Experiment 2 varies the message length at equivalent security levels.
"""

from __future__ import annotations

import json
import math
import platform
import statistics
import sys
import time
from pathlib import Path

import Crypto

import ecc_ecies as ecies
import rsa_oaep

MESSAGE = "Meet me at the library at 6 pm. See you!!!"
MESSAGE_BYTES = MESSAGE.encode("utf-8")
assert len(MESSAGE_BYTES) == 42, len(MESSAGE_BYTES)

KEYGEN_RUNS = 5
WARMUP = 5
RUNS = 100

RSA_SIZES = [1024, 2048, 3072, 4096, 7680]
ECC_CURVES = ["P-192", "P-224", "P-256", "P-384", "P-521"]

# Security strength in bits: NIST SP 800-57 Part 1 Rev. 5 Table 2; RSA-4096 from SP 800-56B Rev. 2 App. D.
SECURITY = {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192,
            "P-192": 96, "P-224": 112, "P-256": 128, "P-384": 192, "P-521": 256}

MSG_LENGTHS = [8, 42, 100, 160]
PAIRS = [(2048, "P-224"), (3072, "P-256")]

OUT = Path(__file__).parent / "results"


def ms(seconds: float) -> float:
    return seconds * 1000.0


def sms_segments(chars: int) -> int:
    return 1 if chars <= 160 else math.ceil(chars / 153)


def time_ops(fn, runs=RUNS, warmup=WARMUP):
    for _ in range(warmup):
        fn()
    samples = []
    out = None
    for _ in range(runs):
        t0 = time.perf_counter()
        out = fn()
        samples.append(time.perf_counter() - t0)
    return samples, out


def summarise(samples):
    vals = [ms(s) for s in samples]
    return {"mean_ms": statistics.mean(vals), "sd_ms": statistics.stdev(vals) if len(vals) > 1 else 0.0,
            "median_ms": statistics.median(vals)}


def bench_scheme(name, size, keygen, enc, dec, pub_of, payload=MESSAGE_BYTES, keygen_runs=KEYGEN_RUNS):
    keygen()  # one untimed warm-up key generation (loads tables / caches)
    kg = []
    key = None
    for _ in range(keygen_runs):
        t0 = time.perf_counter()
        key = keygen()
        kg.append(time.perf_counter() - t0)
    pub = pub_of(key)

    enc_samples, ct = time_ops(lambda: enc(pub, payload))
    # Decrypt a fresh ciphertext each time? Decryption cost does not depend on which ciphertext,
    # so we time repeated decryptions of independently produced ciphertexts.
    cts = [enc(pub, payload) for _ in range(RUNS + WARMUP)]
    it = iter(cts)
    dec_samples, _ = time_ops(lambda: dec(key, next(it)))
    ok = sum(dec(key, c) == payload for c in cts[:RUNS])

    b64 = math.ceil(len(ct) / 3) * 4
    return {
        "scheme": name, "size": size, "security_bits": SECURITY[size], "message_bytes": len(payload),
        "keygen": summarise(kg), "encrypt": summarise(enc_samples), "decrypt": summarise(dec_samples),
        "ciphertext_bytes": len(ct), "base64_chars": b64, "sms_segments": sms_segments(b64),
        "round_trips_ok": ok, "round_trips": RUNS,
    }


def run_rsa(bits, payload=MESSAGE_BYTES, keygen_runs=KEYGEN_RUNS):
    return bench_scheme("RSA-OAEP", bits, lambda: rsa_oaep.generate_keypair(bits),
                        rsa_oaep.encrypt, rsa_oaep.decrypt, lambda k: k.publickey(), payload, keygen_runs)


def run_ecc(curve, payload=MESSAGE_BYTES, keygen_runs=KEYGEN_RUNS, compress=True):
    r = bench_scheme("ECIES" if compress else "ECIES-unc", curve, lambda: ecies.generate_keypair(curve),
                     lambda pub, m: ecies.encrypt(pub, m, compress=compress), ecies.decrypt,
                     lambda k: k.public_key(), payload, keygen_runs)
    r["compressed_point"] = compress
    return r


def log(r):
    print(f"{r['scheme']:9} {str(r['size']):6} msg={r['message_bytes']:3}B  "
          f"kg={r['keygen']['mean_ms']:10.3f}  enc={r['encrypt']['mean_ms']:8.4f}  "
          f"dec={r['decrypt']['mean_ms']:8.4f} ms  ct={r['ciphertext_bytes']}B  "
          f"b64={r['base64_chars']}  sms={r['sms_segments']}  ok={r['round_trips_ok']}/{r['round_trips']}",
          flush=True)


def main():
    OUT.mkdir(exist_ok=True)
    env = {"python": sys.version.split()[0], "pycryptodome": Crypto.__version__,
           "platform": platform.platform(), "machine": platform.machine(),
           "processor": "Apple M3", "date": time.strftime("%Y-%m-%d")}
    print(env, flush=True)

    main_results = []
    for curve in ECC_CURVES:
        r = run_ecc(curve); log(r); main_results.append(r)
    for curve in ECC_CURVES:
        r = run_ecc(curve, compress=False); log(r); main_results.append(r)
    for bits in RSA_SIZES:
        # 7680-bit key generation is very slow in Python; three runs keep the total reasonable.
        r = run_rsa(bits, keygen_runs=3 if bits > 4096 else KEYGEN_RUNS); log(r); main_results.append(r)

    length_results = []
    for bits, curve in PAIRS:
        for n in MSG_LENGTHS:
            payload = (MESSAGE_BYTES * 4)[:n]
            for r in (run_ecc(curve, payload, keygen_runs=1), run_rsa(bits, payload, keygen_runs=1)):
                log(r); length_results.append(r)

    (OUT / "results.json").write_text(json.dumps(
        {"environment": env, "protocol": {"keygen_runs": KEYGEN_RUNS, "warmup": WARMUP, "runs": RUNS,
                                          "message": MESSAGE},
         "main": main_results, "message_length": length_results}, indent=2))
    print("saved", OUT / "results.json")


if __name__ == "__main__":
    main()
