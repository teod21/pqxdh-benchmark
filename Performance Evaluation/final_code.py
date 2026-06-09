# Performance analysis -- Classic vs Kyber vs HQC

# Imports
import time
import os
import statistics
import csv
import json
from pathlib import Path

# Cryptography libraries
import oqs # Kyber+HQC
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Data visualization
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# Configuration
OUTPUT_DIR = Path("results") # this is where the diagrams will be saved
OUTPUT_DIR.mkdir(exist_ok=True)

MSG_SIZES = [64, 512, 4096, 65536]  # different size dimensions

WARMUP_RUNS = 10 # warm up before starting the real measurements

# Format: (short name, label, NIST security level, classic bits, quantum bits)
ALGORITHMS = [
    ("NONE",       "X25519-only\n(no PQ)",    "N/A", 128, 0),
    ("Kyber512",   "PQXDH\nKyber512",         "1",   128, 128),
    ("Kyber768",   "PQXDH\nKyber768",         "3",   128, 192),
    ("Kyber1024",  "PQXDH\nKyber1024",        "5",   128, 256),
    ("HQC-128",    "PQXDH\nHQC-128",          "1",   128, 128),
    ("HQC-192",    "PQXDH\nHQC-192",          "3",   128, 192),
    ("HQC-256",    "PQXDH\nHQC-256",          "5",   128, 256),
]

# Key Derivation Function - SHA256
def derive_session_key(raw_shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32, # output (in bytes)
        salt=None, # it will be treated as zeros
        info=b"PQXDH_v1"
    )
    return hkdf.derive(raw_shared_secret)

# X25519 - does not have quantum protection
class ClassicX25519:

    def run_full_handshake(self, message: bytes) -> dict:
        t0 = time.perf_counter()

        # Bob generates his keys (identity key and signed pre-key)
        IK_B  = x25519.X25519PrivateKey.generate()
        SPK_B = x25519.X25519PrivateKey.generate()

        # Alice generates her ephemeral(temporary) keys
        IK_A = x25519.X25519PrivateKey.generate()
        EK_A = x25519.X25519PrivateKey.generate()

        # Alice computes the three Diffie-Hellman exchanges (X3DH)
        t_dh_start = time.perf_counter()
        DH1 = IK_A.exchange(SPK_B.public_key()) # Alice identity key + Bob pre-key
        DH2 = EK_A.exchange(IK_B.public_key()) # Alice ephemeral key + Bob identity key
        DH3 = EK_A.exchange(SPK_B.public_key()) # Alice ephemeral key + Bob pre-key
        t_dh = (time.perf_counter() - t_dh_start) * 1000 # ms

        # Alice - HKDF over the concatenated DH (1-3) outputs
        t_kdf_start = time.perf_counter()
        session_key = derive_session_key(DH1 + DH2 + DH3)
        t_kdf = (time.perf_counter() - t_kdf_start) * 1000

        # Alice encrypts the message with AES256 GCM
        t_enc_start = time.perf_counter()
        aesgcm = AESGCM(session_key) # Aes with the blended key (above)
        nonce = os.urandom(12) # 12 random bytes requires by AES GCM
        ciphertext = aesgcm.encrypt(nonce, message, None) # encryption
        t_enc = (time.perf_counter() - t_enc_start) * 1000

        # Bob does the same thing as Alice but in reverse, to decrypt
        t_dec_start = time.perf_counter()
        DH1b = SPK_B.exchange(IK_A.public_key())
        DH2b = IK_B.exchange(EK_A.public_key())
        DH3b = SPK_B.exchange(EK_A.public_key())

        sk_bob = derive_session_key(DH1b + DH2b + DH3b) # hkdf with his secrets
        aesgcm_bob = AESGCM(sk_bob)
        aesgcm_bob.decrypt(nonce, ciphertext, None)
        t_dec = (time.perf_counter() - t_dec_start) * 1000

        t_total = (time.perf_counter() - t0) * 1000

        # Calculate how many bytes Alice would have sent over the Internet
        IK_A_pub_bytes = IK_A.public_key().public_bytes_raw()   # 32 bytes
        EK_A_pub_bytes = EK_A.public_key().public_bytes_raw()   # 32 bytes
        network_payload = len(IK_A_pub_bytes) + len(EK_A_pub_bytes) + len(nonce) + len(ciphertext)

        # Return a list containing all recorded times and sizes
        return {
            "time_ms_total":    t_total,
            "time_ms_dh":       t_dh,
            "time_ms_pq_encap": 0.0, # no quantum
            "time_ms_pq_decap": 0.0, # no quantum
            "time_ms_kdf":      t_kdf,
            "time_ms_encrypt":  t_enc,
            "time_ms_decrypt":  t_dec,
            "pq_pk_size":       0, # no quantum
            "pq_ct_size":       0, # no quantum
            "network_payload":  network_payload,
        }

# PQXDH handshake
class PQXDHSession:

    def __init__(self, kem_name: str):
        # Load the quantum requested (Kyber/HQC)
        self.kem_name = kem_name
        self.kem = oqs.KeyEncapsulation(kem_name)

    def run_full_handshake(self, message: bytes) -> dict:
        t0 = time.perf_counter()

        # Bob generates his keys (classic + pq)
        IK_B  = x25519.X25519PrivateKey.generate()
        SPK_B = x25519.X25519PrivateKey.generate()
        PQSPK_B_pub = self.kem.generate_keypair()

        pq_pk_size = len(PQSPK_B_pub) #quantum key size

        # Alice generates her classic keys
        IK_A = x25519.X25519PrivateKey.generate()
        EK_A = x25519.X25519PrivateKey.generate()

        # Alice classic operations (as before)
        t_dh_start = time.perf_counter()
        DH1 = IK_A.exchange(SPK_B.public_key())
        DH2 = EK_A.exchange(IK_B.public_key())
        DH3 = EK_A.exchange(SPK_B.public_key())
        t_dh_alice = (time.perf_counter() - t_dh_start) * 1000

        # Alice quantum operations (encapsulation)
        t_pq_encap_start = time.perf_counter()
        # Alice uses Bob's quantum public key to generate a locked box (PQCT) 
        # and a shared quantum secret (PQ_SS) that is inside the box.
        PQCT, PQ_SS = self.kem.encap_secret(PQSPK_B_pub)
        t_pq_encap = (time.perf_counter() - t_pq_encap_start) * 1000

        pq_ct_size = len(PQCT) 

        # HKDF with DH(1-3) and quantum secret (PQ_SS)
        t_kdf_start = time.perf_counter()
        session_key_alice = derive_session_key(DH1 + DH2 + DH3 + PQ_SS)
        t_kdf_alice = (time.perf_counter() - t_kdf_start) * 1000

        # Encrypt the message with AES256 GCM
        t_enc_start = time.perf_counter()
        aesgcm = AESGCM(session_key_alice)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message, None)
        t_enc = (time.perf_counter() - t_enc_start) * 1000

        # Calculate network payload 
        IK_A_pub_bytes = IK_A.public_key().public_bytes_raw()
        EK_A_pub_bytes = EK_A.public_key().public_bytes_raw()
        network_payload = (len(IK_A_pub_bytes) + len(EK_A_pub_bytes) +
                           pq_ct_size + len(nonce) + len(ciphertext))

        # Bob does the same operations in reverse
        t_dh_bob_start = time.perf_counter()
        DH1b = SPK_B.exchange(IK_A.public_key())
        DH2b = IK_B.exchange(EK_A.public_key())
        DH3b = SPK_B.exchange(EK_A.public_key())
        t_dh_bob = (time.perf_counter() - t_dh_bob_start) * 1000

        # Bob uses his quantum key to open the box (PQCT) to find the PQ_SS
        t_pq_decap_start = time.perf_counter()
        PQ_SS_bob = self.kem.decap_secret(PQCT)
        t_pq_decap = (time.perf_counter() - t_pq_decap_start) * 1000

        # Bob's mixed secrets
        session_key_bob = derive_session_key(DH1b + DH2b + DH3b + PQ_SS_bob)

        # Bob decrypts the message
        t_dec_start = time.perf_counter()
        aesgcm_bob = AESGCM(session_key_bob)
        plaintext = aesgcm_bob.decrypt(nonce, ciphertext, None)
        t_dec = (time.perf_counter() - t_dec_start) * 1000

        # Verification — both parties must obtain the same session key
        assert plaintext == message, "ERROR: decrypted plaintext does not match original!"

        t_total = (time.perf_counter() - t0) * 1000

        return {
            "time_ms_total":    t_total,
            "time_ms_dh":       t_dh_alice,
            "time_ms_pq_encap": t_pq_encap,
            "time_ms_pq_decap": t_pq_decap,
            "time_ms_kdf":      t_kdf_alice,
            "time_ms_encrypt":  t_enc,
            "time_ms_decrypt":  t_dec,
            "pq_pk_size":       pq_pk_size,
            "pq_ct_size":       pq_ct_size,
            "network_payload":  network_payload,
        }

# Benchmarking
def run_benchmark(runs: int = 100, msg_sizes: list = None) -> dict:
    # Default list of sizes
    if msg_sizes is None:
        msg_sizes = MSG_SIZES

    # Result and timing
    all_results = {}

    # Takes an algorithm from the list
    for algo_tuple in ALGORITHMS:
        algo_name  = algo_tuple[0]
        algo_label = algo_tuple[1]
       
        print(f"\n{'='*65}")
        print(f"  BENCHMARK: {algo_label.replace(chr(10), ' ')}  ({runs} runs, {WARMUP_RUNS} warmup)")
        print(f"{'='*65}")

        all_results[algo_name] = {}

        # Takes a file size
        for msg_size in msg_sizes:
            print(f"  Message size: {msg_size} bytes ...", end=" ", flush=True)

            # Warm up phase
            for _ in range(WARMUP_RUNS):
                warmup_msg = os.urandom(msg_size)
                # Check if it's classic or pq
                if algo_name == "NONE":
                    ClassicX25519().run_full_handshake(warmup_msg)
                else:
                    PQXDHSession(algo_name).run_full_handshake(warmup_msg)

            # Measurement phase
            # Create 10 lists for the timings we keep
            samples = {k: [] for k in [
                "time_ms_total", "time_ms_dh", "time_ms_pq_encap",
                "time_ms_pq_decap", "time_ms_kdf", "time_ms_encrypt",
                "time_ms_decrypt", "pq_pk_size", "pq_ct_size", "network_payload"
            ]}

            for _ in range(runs):
                message = os.urandom(msg_size) # generate message

                if algo_name == "NONE":
                    session = ClassicX25519()
                else:
                    session = PQXDHSession(algo_name)

                # Returns the timings
                result = session.run_full_handshake(message)

                # Splits the timings
                for key in samples:
                    samples[key].append(result[key])

            # Compute summary statistics
            # We need averages
            stats = {} 
            for key, values in samples.items():
                stats[key] = {
                    "avg":    statistics.mean(values), # the average
                    "std":    statistics.stdev(values) if len(values) > 1 else 0.0, # standard deviation
                    "median": statistics.median(values), # the middle number, when sort
                    "min":    min(values), # fastest run
                    "max":    max(values), # slowest run
                    "raw":    values # keep all 100 raw numbers (Boxplot)
                }

            # Save them in the result table
            all_results[algo_name][msg_size] = stats

            # Print a summary on the screen
            print(f"avg={stats['time_ms_total']['avg']:.3f} ms  "
                  f"std={stats['time_ms_total']['std']:.3f} ms ✓")

    return all_results

# Data export -- store for diagrams
def export_csv(all_results: dict, runs: int):

    csv_path = OUTPUT_DIR / "benchmark.csv"

    # Define de headers
    fieldnames = [
        "algorithm", "msg_size_bytes",
        "total_avg_ms", "total_std_ms", "total_median_ms", "total_min_ms", "total_max_ms",
        "dh_avg_ms", "pq_encap_avg_ms", "pq_decap_avg_ms",
        "kdf_avg_ms", "encrypt_avg_ms", "decrypt_avg_ms",
        "pq_pk_size_bytes", "pq_ct_size_bytes", "network_payload_bytes",
        "warmup_runs", "measurement_runs"
    ]

    # Open and write row by row
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader() # column names

        # Go through the dictionary and write each algorithm on a new line
        for algo_name, sizes in all_results.items():
            for msg_size, stats in sizes.items():
                writer.writerow({
                    "algorithm":             algo_name,
                    "msg_size_bytes":        msg_size,
                    "total_avg_ms":          round(stats["time_ms_total"]["avg"],    4),
                    "total_std_ms":          round(stats["time_ms_total"]["std"],    4),
                    "total_median_ms":       round(stats["time_ms_total"]["median"], 4),
                    "total_min_ms":          round(stats["time_ms_total"]["min"],    4),
                    "total_max_ms":          round(stats["time_ms_total"]["max"],    4),
                    "dh_avg_ms":             round(stats["time_ms_dh"]["avg"],           4),
                    "pq_encap_avg_ms":       round(stats["time_ms_pq_encap"]["avg"],     4),
                    "pq_decap_avg_ms":       round(stats["time_ms_pq_decap"]["avg"],     4),
                    "kdf_avg_ms":            round(stats["time_ms_kdf"]["avg"],          4),
                    "encrypt_avg_ms":        round(stats["time_ms_encrypt"]["avg"],      4),
                    "decrypt_avg_ms":        round(stats["time_ms_decrypt"]["avg"],      4),
                    "pq_pk_size_bytes":      round(stats["pq_pk_size"]["avg"],      1),
                    "pq_ct_size_bytes":      round(stats["pq_ct_size"]["avg"],      1),
                    "network_payload_bytes": round(stats["network_payload"]["avg"], 1),
                    "warmup_runs":           WARMUP_RUNS,
                    "measurement_runs":      runs,
                })

    print(f"\n[EXPORT] CSV saved: {csv_path}")

    # Raw data backup
    json_full_path = OUTPUT_DIR / "benchmark_full.json"
    with open(json_full_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"[EXPORT] JSON with raw samples saved: {json_full_path}")

# Data visualization
COLORS = {
    "NONE":      "#607D8B",
    "Kyber512":  "#1565C0",
    "Kyber768":  "#1976D2",
    "Kyber1024": "#42A5F5",
    "HQC-128":   "#B71C1C",
    "HQC-192":   "#E53935",
    "HQC-256":   "#EF9A9A",
}

def label(algo_name: str) -> str:
    # Search the algorithm name and replace it with its label (define above)
    # Kyber512 --> PQXDH\nKyber512
    for t in ALGORITHMS:
        if t[0] == algo_name:
            return t[1].replace("\n", " ")
    return algo_name

# Figure 1 -- Bar chart: total handshake time per algorithm
# Kyber vs HQC vs Classic.
def fig1_total_time_per_algorithm(all_results: dict, msg_size: int = 64):
    # Create the figure 12x6
    fig, ax = plt.subplots(figsize=(12, 6))

    # Extract the data
    algos  = list(all_results.keys()) # algorithm name
    avgs   = [all_results[a][msg_size]["time_ms_total"]["avg"] for a in algos] # average time
    stds   = [all_results[a][msg_size]["time_ms_total"]["std"] for a in algos] # standard deviation
    colors = [COLORS.get(a, "#90A4AE") for a in algos] # matching color
    labels = [label(a) for a in algos] # labels

    # Draw the bars
    bars = ax.bar(labels, avgs, yerr=stds, capsize=5,
                  color=colors, edgecolor="black", linewidth=0.7, alpha=0.88)

    # Add text on top of bars
    for bar, avg, std in zip(bars, avgs, stds):
        ax.text(bar.get_x() + bar.get_width() / 2, # center the text
                bar.get_height() + std + 0.01, # place it above the std deviation
                f"{avg:.2f} ms", ha="center", va="bottom", fontsize=9, fontweight="bold")

    # Add the title, axis names, grid lines
    ax.set_title(f"Total PQXDH handshake time per algorithm\n"
                 f"(message={msg_size} B, mean ± std dev, n={list(all_results.values())[0][msg_size]['time_ms_total']['avg'].__class__.__name__})",
                 fontsize=13, fontweight="bold", pad=15)
    ax.set_ylabel("Time (ms)", fontsize=11)
    ax.set_xlabel("KEM Algorithm", fontsize=11)
    ax.set_ylim(0, max(avgs) * 1.3) # y-axis 30% taller that the highest bar to fit the text
    ax.grid(axis="y", linestyle="--", alpha=0.5) # dotted lines
    ax.axvline(x=0.5, color="gray", linestyle=":", linewidth=1.2) # separate classic from quantum

    # Save it as PNG file
    plt.tight_layout()
    path = OUTPUT_DIR / f"fig1_total_time_msg{msg_size}B.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[FIGURE] Saved: {path}")

# Figure 2 -- Boxplot: distribution of handshake times across measurement runs
def fig2_boxplot_time(all_results: dict, msg_size: int = 64):
    # Create the figure 13x6
    fig, ax = plt.subplots(figsize=(13, 6))

    # Extract the data -- requires the entire dataset to calculate the quartiles and outliners
    algos  = list(all_results.keys())
    data   = [all_results[a][msg_size]["time_ms_total"]["raw"] for a in algos]
    labels_list = [label(a) for a in algos]
    colors = [COLORS.get(a, "#90A4AE") for a in algos]

    # Draw the Boxplot
    # Enable the patch_artist to allow filling the boxes with color
    bp = ax.boxplot(data, patch_artist=True, notch=False,
                    medianprops=dict(color="black", linewidth=2))

    # Apply colors
    # alpha=0.75 for transparency to see the median line
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.75)

    # Titles, labels and grid lines
    ax.set_xticklabels(labels_list, fontsize=9)
    ax.set_title(f"Handshake time distribution — Boxplot\n(message={msg_size} B)",
                 fontsize=13, fontweight="bold", pad=15)
    ax.set_ylabel("Time (ms)", fontsize=11)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    # Save the image
    plt.tight_layout()
    path = OUTPUT_DIR / f"fig2_boxplot_msg{msg_size}B.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[FIGURE] Saved: {path}")

# Figure 3 -- Line chart: total handshake time vs message size
def fig3_scalability(all_results: dict):
    # Create the figure 11x6
    fig, ax = plt.subplots(figsize=(11, 6))

    # Sort x-axis data -- ascending order
    msg_sizes_sorted = sorted(next(iter(all_results.values())).keys())

    # Draw the lines
    for algo_name, sizes_data in all_results.items():
        avgs = [sizes_data[s]["time_ms_total"]["avg"] for s in msg_sizes_sorted]
        stds = [sizes_data[s]["time_ms_total"]["std"] for s in msg_sizes_sorted]
        color = COLORS.get(algo_name, "#90A4AE")
        
        # Plot the circular markes and std deviation barrs
        ax.errorbar(msg_sizes_sorted, avgs, yerr=stds,
                    label=label(algo_name), color=color,
                    marker="o", linewidth=2, capsize=4, markersize=6)
        
    # Apply logarithmic scale
    ax.set_xscale("log")

    # Titles, labels and legend
    ax.set_xticks(msg_sizes_sorted)
    ax.set_xticklabels([f"{s} B" for s in msg_sizes_sorted])
    ax.set_title("Scalability: Handshake time vs Message size",
                 fontsize=13, fontweight="bold", pad=15)
    ax.set_ylabel("Total time (ms)", fontsize=11)
    ax.set_xlabel("Message size (bytes, logarithmic scale)", fontsize=11)
    ax.legend(fontsize=9, loc="upper left")
    ax.grid(linestyle="--", alpha=0.5)

    # Save the image
    plt.tight_layout()
    path = OUTPUT_DIR / "fig3_scalability.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[FIGURE] Saved: {path}")

# Figure 4 -- Stacked bar: handshake time by component
def fig4_component_breakdown(all_results: dict, msg_size: int = 64):
    # Filter the data -- classic/pq
    pq_algos = [a for a in all_results.keys() if a != "NONE"]
    if not pq_algos:
        return

    # Cryptographic components, labels, colors
    components  = ["time_ms_dh", "time_ms_pq_encap", "time_ms_pq_decap",
                   "time_ms_kdf", "time_ms_encrypt", "time_ms_decrypt"]
    comp_labels = ["DH (X3DH)", "PQ Encap", "PQ Decap", "HKDF", "AES Encrypt", "AES Decrypt"]
    comp_colors = ["#1976D2", "#E53935", "#FF7043", "#43A047", "#8E24AA", "#00ACC1"]

    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(pq_algos))
    width = 0.55

    # Track the height of bars
    bottoms = np.zeros(len(pq_algos))

    # Build the stacks
    for comp, clabel, ccolor in zip(components, comp_labels, comp_colors):
        vals = [all_results[a][msg_size][comp]["avg"] for a in pq_algos]
        
        # Draw the current component on top of the bottom height
        ax.bar(x, vals, width, bottom=bottoms, label=clabel,
               color=ccolor, edgecolor="white", linewidth=0.5, alpha=0.88)

        # Add the drawn component's height for the next loop       
        bottoms += np.array(vals)

    # Titles, legend
    ax.set_xticks(x)
    ax.set_xticklabels([label(a) for a in pq_algos], fontsize=9)
    ax.set_title(f"Handshake time decomposition by component\n(message={msg_size} B)",
                 fontsize=13, fontweight="bold", pad=15)
    ax.set_ylabel("Time (ms)", fontsize=11)
    ax.legend(loc="upper left", fontsize=9)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    # Save the image
    plt.tight_layout()
    path = OUTPUT_DIR / f"fig4_component_breakdown_msg{msg_size}B.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[FIGURE] Saved: {path}")

# Figure 5 -- Grouped bar: PQ pk size, PQ ct size, total network payload
def fig5_network_overhead(all_results: dict, msg_size: int = 64):
    # Extract the data -- public key, ciphertext, payload
    algos         = list(all_results.keys())
    pk_sizes      = [all_results[a][msg_size]["pq_pk_size"]["avg"]      for a in algos]
    ct_sizes      = [all_results[a][msg_size]["pq_ct_size"]["avg"]      for a in algos]
    payload_total = [all_results[a][msg_size]["network_payload"]["avg"] for a in algos]

    # Calculate the base x-axis positions and define a fixed bar width
    x = np.arange(len(algos))
    width = 0.25

    # Draw bars
    # x-width -- pushes PK bar to the left
    # x -- keeps the CT bar perfectly centered
    # x + width -- pushes the payload bar to the right
    fig, ax = plt.subplots(figsize=(13, 6))
    ax.bar(x - width,   pk_sizes,      width, label="PQ Public Key (bytes)",      color="#1565C0", alpha=0.85)
    ax.bar(x,           ct_sizes,      width, label="PQ Ciphertext (bytes)",       color="#E53935", alpha=0.85)
    ax.bar(x + width,   payload_total, width, label="Total network payload (bytes)", color="#2E7D32", alpha=0.85)

    # Titles, legend
    ax.set_xticks(x)
    ax.set_xticklabels([label(a) for a in algos], fontsize=9)
    ax.set_title(f"Network overhead per algorithm\n(message={msg_size} B)",
                 fontsize=13, fontweight="bold", pad=15)
    ax.set_ylabel("Size (bytes)", fontsize=11)
    ax.legend(fontsize=10)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    # Save the image
    plt.tight_layout()
    path = OUTPUT_DIR / f"fig5_network_overhead_msg{msg_size}B.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[FIGURE] Saved: {path}")

# Figure 6 -- Scatter plot: quantum security level, by bits, vs total handshake time
def fig6_security_vs_performance(all_results: dict, msg_size: int = 64):
    # Create the image
    fig, ax = plt.subplots(figsize=(10, 7))

    # Loop through the list of algs
    for algo_tuple in ALGORITHMS:
        algo_name, algo_label, nist_level, _, quantum_bits = algo_tuple
        if algo_name not in all_results:
            continue

        avg_time = all_results[algo_name][msg_size]["time_ms_total"]["avg"]
        std_time = all_results[algo_name][msg_size]["time_ms_total"]["std"]
        color    = COLORS.get(algo_name, "#90A4AE")
        
        # Choose a marker for the alg family
        # diamond -- classic; square -- Kyber; circle -- HQC
        marker   = "D" if algo_name == "NONE" else ("s" if "Kyber" in algo_name else "o")

        # Plot the scatter with its std deviation
        ax.errorbar(quantum_bits, avg_time, yerr=std_time,
                    fmt=marker, color=color, markersize=12,
                    capsize=5, linewidth=2,
                    markeredgecolor="black", markeredgewidth=0.7)

        # Add labels
        ax.annotate(algo_label,
                    xy=(quantum_bits, avg_time),
                    xytext=(8, 6), textcoords="offset points",
                    fontsize=8.5, color=color)

    # Title, labels
    ax.set_title("Trade-off: Quantum security level vs Performance\n"
                 "(squares = Kyber, circles = HQC, diamond = Baseline)",
                 fontsize=12, fontweight="bold", pad=15)
    ax.set_xlabel("Quantum security level (bits)", fontsize=11)
    ax.set_ylabel("Total handshake time (ms)", fontsize=11)
    ax.set_xticks([0, 128, 192, 256])
    ax.grid(linestyle="--", alpha=0.5)

    # Legend -- shapes and colors
    kyber_patch = mpatches.Patch(color="#1976D2", label="Kyber family (CRYSTALS-Kyber / ML-KEM)")
    hqc_patch   = mpatches.Patch(color="#E53935", label="HQC family")
    base_patch  = mpatches.Patch(color="#607D8B", label="Baseline X25519 (no PQ)")
    ax.legend(handles=[kyber_patch, hqc_patch, base_patch], fontsize=9, loc="upper left")

    # Save the image
    plt.tight_layout()
    path = OUTPUT_DIR / f"fig6_security_vs_performance_msg{msg_size}B.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[FIGURE] Saved: {path}")

# Generates figures
def generate_all_figures(all_results: dict):
    print(f"\n{'='*65}")
    print("GENERATING FIGURES")
    print(f"{'='*65}")
    fig1_total_time_per_algorithm(all_results, msg_size=64)
    fig2_boxplot_time(all_results, msg_size=64)
    fig3_scalability(all_results)
    fig4_component_breakdown(all_results, msg_size=64)
    fig5_network_overhead(all_results, msg_size=64)
    fig6_security_vs_performance(all_results, msg_size=64)

# Summary table in terminal
def print_summary_table(all_results: dict, msg_size: int = 64):
    # Title
    print(f"\n{'='*100}")
    print(f"SUMMARY TABLE -- msg={msg_size} B  (warmup={WARMUP_RUNS} discarded runs)")
    
    # Table header -- align columns
    print(f"{'='*100}")
    hdr = (f"{'Algorithm':<18} {'NIST Lvl':>8} {'Total avg':>10} {'Total std':>10} "
           f"{'PQ Encap':>10} {'PQ Decap':>10} {'PQ PK (B)':>10} "
           f"{'PQ CT (B)':>10} {'Payload (B)':>12}")
    print(hdr)
    print("-" * 100) # separator line
    
    # Iterate over the defined algs
    for algo_tuple in ALGORITHMS:
        algo_name, _, nist_level, _, _ = algo_tuple
        # Skip if were not successfully benchmarked
        if algo_name not in all_results:
            continue
        
        # Extract the branch for the alg and message size
        s = all_results[algo_name][msg_size]

        # Print data
        print(f"{algo_name:<18} {nist_level:>8} "
              f"{s['time_ms_total']['avg']:>10.3f} "
              f"{s['time_ms_total']['std']:>10.3f} "
              f"{s['time_ms_pq_encap']['avg']:>10.3f} "
              f"{s['time_ms_pq_decap']['avg']:>10.3f} "
              f"{s['pq_pk_size']['avg']:>10.1f} "
              f"{s['pq_ct_size']['avg']:>10.1f} "
              f"{s['network_payload']['avg']:>12.1f}")

# Main
if __name__ == "__main__":
    print("PQXDH BENCHMARK -- Analysis")
    print("Algorithms: X25519 + Kyber (512/768/1024) + HQC (128/192/256)")
    print(f"Warmup runs (discarded): {WARMUP_RUNS}")
    print(f"Results saved to: {OUTPUT_DIR.resolve()}\n")

    RUNS = 100

    try:
        # Run the main benchmark
        all_results = run_benchmark(runs=RUNS, msg_sizes=MSG_SIZES)

        # Print summary tables for every message size
        for msg_size in MSG_SIZES:
            print_summary_table(all_results, msg_size=msg_size)

        # Export data
        export_csv(all_results, runs=RUNS)

        # Generate figures
        generate_all_figures(all_results)

        print(f"\n✅ Benchmark complete! All files are in: {OUTPUT_DIR.resolve()}")

    except oqs.MechanismNotEnabledError as e:
        print(f"\n❌ Algorithm not available in your liboqs build: {e}")
        print("   Check: python -c \"import oqs; print(oqs.get_enabled_kem_mechanisms())\"")
    except Exception as e:
        import traceback
        print(f"\n❌ Error: {e}")
        traceback.print_exc()