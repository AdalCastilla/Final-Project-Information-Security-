# ECC implementation and RSA vs ECC comparison

LIS4062 Information Security final project, ECC part (Rishabh Verma).

ECIES (ECDH + HKDF-SHA256 + AES-256-GCM) on the NIST curves P-192 to P-521, benchmarked against RSA-OAEP (SHA-256) on the same machine.

## Files

- `ecc_ecies.py`: ECIES encrypt/decrypt, compressed or uncompressed ephemeral point, Base64 helpers for SMS.
- `rsa_oaep.py`: RSA-OAEP baseline with the same construction as the team's RSA module.
- `test_ecc.py`: 8 unit tests (round trip on all curves, both point formats, Unicode, randomness, tamper and wrong-key rejection, PEM import).
- `benchmark.py`: 42-byte message, 5 key generations, 5 warm-ups, 100 encryptions and 100 decryptions per key size; plus a message-length experiment.
- `plots.py`: figures in `figures/` (the figures used in the report).
- `sms_receiver_demo.py`: sender to receiver walk-through for both algorithms.
- `results/`: `results.json`, `results.csv`, `receiver_demo.txt`, raw log in `results_log.txt`.

## Run

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

```bash
.venv/bin/python -m unittest -v test_ecc
```

```bash
.venv/bin/python benchmark.py && .venv/bin/python plots.py
```

The full benchmark takes several minutes because RSA-7680 key generation averages about 27 s per key.

Measured on an Apple M3, Python 3.12.7, PyCryptodome 4.6.0 (2026-11-24).
