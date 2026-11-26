"""Figures for the ECC section, from results/results.json. Output: figures/*.png (300 dpi)."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter  # noqa: E402

PLAIN = FuncFormatter(lambda v, _: f"{v:g}")


def plain_log(ax):
    ax.set_yscale("log")
    ax.yaxis.set_major_locator(LogLocator(base=10, subs=(1, 2, 5)))
    ax.yaxis.set_major_formatter(PLAIN)
    ax.yaxis.set_minor_formatter(NullFormatter())

HERE = Path(__file__).parent
DATA = json.loads((HERE / "results" / "results.json").read_text())
OUT = HERE / "figures"
OUT.mkdir(exist_ok=True)

# Fixed entity colours (validated default categorical slots 1 and 2).
RSA_C = "#2a78d6"
ECC_C = "#eb6834"
ECC_UNC_C = "#1baf7a"
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#e4e3df"

plt.rcParams.update({
    "font.family": "serif", "font.size": 10, "axes.edgecolor": INK2, "axes.labelcolor": INK,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "legend.frameon": False, "savefig.dpi": 300, "savefig.bbox": "tight",
})

main = DATA["main"]
ecc = [r for r in main if r["scheme"] == "ECIES"]
ecc_unc = [r for r in main if r["scheme"] == "ECIES-unc"]
rsa = [r for r in main if r["scheme"] == "RSA-OAEP"]


def mean(r, op):
    return r[op]["mean_ms"]


def sd(r, op):
    return r[op]["sd_ms"]


def line(ax, rows, x, op, color, label, marker="o", ls="-"):
    ax.errorbar(x, [mean(r, op) for r in rows], yerr=[sd(r, op) for r in rows], color=color, marker=marker,
                markersize=6, linewidth=2, linestyle=ls, capsize=3, elinewidth=1, label=label,
                markeredgecolor="white", markeredgewidth=1.2)


# 1. ECC encryption / decryption time per curve (compressed vs uncompressed point).
fig, axes = plt.subplots(1, 2, figsize=(9, 3.6), sharey=False)
names = [r["size"] for r in ecc]
for ax, op, title in zip(axes, ["encrypt", "decrypt"], ["Encryption (sender)", "Decryption (receiver)"]):
    line(ax, ecc, names, op, ECC_C, "Compressed point")
    line(ax, ecc_unc, names, op, ECC_UNC_C, "Uncompressed point", marker="s", ls="--")
    ax.set_title(title, color=INK, fontsize=10.5)
    ax.set_xlabel("Elliptic curve")
    ax.set_ylabel("Mean time (ms)")
    plain_log(ax)
axes[0].legend(loc="upper left")
fig.tight_layout()
fig.savefig(OUT / "ecc_enc_dec_times.png")
plt.close(fig)

# 2. RSA vs ECC by NIST security level (encryption and decryption).
LEVELS = [80, 96, 112, 128, 152, 192, 256]
sec_rsa = [LEVELS.index(r["security_bits"]) for r in rsa]
sec_ecc = [LEVELS.index(r["security_bits"]) for r in ecc_unc]
fig, axes = plt.subplots(1, 2, figsize=(9, 3.6))
for ax, op, title in zip(axes, ["encrypt", "decrypt"], ["Encryption", "Decryption at the receiver"]):
    line(ax, rsa, sec_rsa, op, RSA_C, "RSA-OAEP")
    line(ax, ecc_unc, sec_ecc, op, ECC_C, "ECIES (uncompressed point)", marker="s")
    ax.set_title(title, color=INK, fontsize=10.5)
    ax.set_xlabel("Security strength (bits) and key size")
    ax.set_ylabel("Mean time (ms)")
    plain_log(ax)
    ticks = {80: "80\nRSA-1024", 96: "96\nP-192", 112: "112\nRSA-2048\nP-224", 128: "128\nRSA-3072\nP-256",
             152: "152\nRSA-4096", 192: "192\nRSA-7680\nP-384", 256: "256\nP-521"}
    ax.set_xticks(range(len(LEVELS)), [ticks[lvl] for lvl in LEVELS], fontsize=7.5)
    ax.grid(axis="x", visible=False)
axes[0].legend(loc="upper left")
axes[1].legend(loc="upper left")
fig.tight_layout()
fig.savefig(OUT / "rsa_vs_ecc_times.png")
plt.close(fig)

# 3. Key generation time (log scale), bars grouped by security level.
fig, ax = plt.subplots(figsize=(7, 3.6))
levels = sorted({r["security_bits"] for r in rsa} | {r["security_bits"] for r in ecc})
pos = {lvl: i for i, lvl in enumerate(levels)}
w = 0.38
for rows, off, c, lab in [(rsa, -w / 2 - 0.01, RSA_C, "RSA"), (ecc, w / 2 + 0.01, ECC_C, "ECC")]:
    xs = [pos[r["security_bits"]] + off for r in rows]
    ys = [mean(r, "keygen") for r in rows]
    ax.bar(xs, ys, width=w, color=c, label=lab)
    for x, y, r in zip(xs, ys, rows):
        txt = f"{y / 1000:.2g} s" if y >= 1000 else f"{y:.3g} ms"
        ax.annotate(f"{r['size']}\n{txt}", (x, y), textcoords="offset points", xytext=(0, 3),
                    ha="center", fontsize=7, color=INK2)
ax.set_xticks(range(len(levels)), [str(lvl) for lvl in levels])
ax.set_yscale("log")
ax.set_ylim(top=ax.get_ylim()[1] * 8)
ax.set_xlabel("Security strength (bits)")
ax.set_ylabel("Mean key-generation time (ms)")
ax.legend(loc="upper left")
fig.tight_layout()
fig.savefig(OUT / "rsa_vs_ecc_keygen.png")
plt.close(fig)

# 4. SMS size: Base64 characters per security level, with the single-SMS limit.
fig, ax = plt.subplots(figsize=(7, 3.6))
for rows, off, c, lab in [(rsa, -w / 2 - 0.01, RSA_C, "RSA-OAEP"), (ecc, w / 2 + 0.01, ECC_C, "ECIES (compressed)")]:
    xs = [pos[r["security_bits"]] + off for r in rows]
    ys = [r["base64_chars"] for r in rows]
    ax.bar(xs, ys, width=w, color=c, label=lab)
    for x, y, r in zip(xs, ys, rows):
        ax.annotate(f"{y}\n({r['sms_segments']} SMS)", (x, y), textcoords="offset points", xytext=(0, 3),
                    ha="center", fontsize=7, color=INK2,)
ax.axhspan(0, 160, color="#ecebe7", zorder=0, linewidth=0, label="Fits in one SMS (160 chars)")
ax.set_xticks(range(len(levels)), [str(lvl) for lvl in levels])
ax.set_ylim(0, max(r["base64_chars"] for r in rsa) * 1.25)
ax.set_xlabel("Security strength (bits)")
ax.set_ylabel("Base64 characters (42-byte message)")
ax.legend(loc="upper left")
fig.tight_layout()
fig.savefig(OUT / "rsa_vs_ecc_sms_size.png")
plt.close(fig)

# 5. Message length vs decryption time at 112- and 128-bit security.
ml = DATA["message_length"]
fig, axes = plt.subplots(1, 2, figsize=(9, 3.4), sharey=False)
for ax, (bits, curve) in zip(axes, [(2048, "P-224"), (3072, "P-256")]):
    for scheme, size, c, lab, mk in [("RSA-OAEP", bits, RSA_C, f"RSA-{bits}", "o"),
                                     ("ECIES", curve, ECC_C, f"ECIES {curve} (compressed)", "s")]:
        rows = sorted([r for r in ml if r["scheme"] == scheme and r["size"] == size],
                      key=lambda r: r["message_bytes"])
        line(ax, rows, [r["message_bytes"] for r in rows], "decrypt", c, lab, marker=mk)
    ax.set_title(f"{rows[0]['security_bits']}-bit security", color=INK, fontsize=10.5)
    ax.set_xlabel("Message length (bytes)")
    ax.set_ylabel("Mean decryption time (ms)")
    plain_log(ax)
    ax.legend(loc="center right")
fig.tight_layout()
fig.savefig(OUT / "ecc_msg_length_decrypt.png")
plt.close(fig)

print("figures written to", OUT)
