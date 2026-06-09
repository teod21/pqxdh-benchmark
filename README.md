# PQXDH-benchmark
Implementation and experimental evaluation of the hybrid key agreement protocol PQXDH, comparing classical X25519 with post-quantum KEM algorithms (Kyber and HQC) and demonstrating a downgrade Man-in-the-Middle attack with transcript binding as a mitigation mechanism.

Developed as part of a Master's thesis.

## Description
This repository contains two experimental components:
  **Part 1 - Performance Evaluation** (final_code.py) 
  Measures the perfomance of seven cryptographic configurations in a controlled environment
  - Classic: X25519 (no PQ)
  - Kyber (512, 768, 1024)
  - HQC (128, 192, 256)
  **Part 2 - Vulnerability Analysis** (client.py, server.py, mallory.py, client_secure.py, server_secure.py)
  A functional PQXDH client-server implementation over TCP, demonstrating:
  - Normal hybrid handshake (X25519 + Kyber 512)
  - Active Man-in-the Middle downgrade attack
  - Transcript binding as a detection and mitigation mechanism

## Requirements
### Dependecies
```bash
# System packages
sudo apt update
sudo apt install -y cmake gcc libssl-dev git ninja-build
# liboqs
git clone --branch 0.10.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
ninja && sudo ninja install && sudo ldconfig
cd ../..
# Python packages
pip install git+https://github.com/open-quantum-safe/liboqs-python.git@0.10.0
pip install cryptography matplotlib numpy
```
### Runtime environment
  - Python 3.14.4
  - Ubuntu 24.04.4
  - Memory 4G RAM 

## Part 1 - Performance Evaluation
Run 100 iterations per algorithm per message size (64B, 512B, 4KB, 64KB) with 10 warmup runs removed.
```bash
python3 final_code.py
```
The results are saved in `results/` like this:
  - `benchmark.csv` - statistics
  -  `benchmark_full.json` - raw data
  - `fig1_total_time_msg64B.png` - handshake latency per algorithm
  - `fig2_boxplot_msg64B.png` — time distribution (boxplot)
  - `fig3_scalability.png` — latency vs message size
  - `fig4_component_breakdown_msg64B.png` — time per cryptographic component
  - `fig5_network_overhead_msg64B.png` — key and ciphertext sizes
  - `fig6_security_vs_performance_msg64B.png` — security/performance trade-off

## Part 2 - Vulnerability Analysis
### Demo 1 - Handshake without attacker
```bash
# Fist terminal - Bob (server)
python3 server.py
# Second terminal - Alice (client)
python3 client.py --runs 100
```
The results are saved in `results/network/` like this:
  - `network_benchmark_Kyber512.csv` - statistics
  - `fig_network_breakdown_Kyber512.png` - total handshake time on components
  - `fig_rtt_distribution_Kyber512.png` - statistical distribution of times

### Demo 2 - Man-in-the-Middle attack
Mallory intercepts Alice's connection and replaces Bob's post-quantum public key with her own.
> Open Wireshark on interface lo with filter `tcp_post == 5000` and `tcp_post == 5001` before running.
```bash
# First terminal - Bob (server, port 5000)
python3 server.py
# Second terminal - Mallory (MITM proxy, pot 5001 -> 5000)
python3 mallory.py
# Third terminal - Alice (client, port 5001)
python3 client.py --port 5001
```
**Expected results:**
  - Malory decapsulates Alice's KEM ciphertext and learns PQ_SS
  - Mallory cannot derive the full session key (doesn't know the DH outputs)
  - Session remains confidential despite partial KEM compromise.

### Demo 3 - Transcript Binding
The secure version binds the session key to a hash of all exchanged bytes:
```
transcript_hash = SHA256(bundle_bytes || alice_msg_bytes)
SK = HKDF(DH1 || DH2 || DH3 || SS_pq || transcript_hash)
```
When Mallory modifies the bundle, the transcript diverges between Alice and Bob, causing AES authentication to fail.
```bash
# First terminal - Bob
python3 server_secure.py
# Second terminal - Mallory
python3 mallory.py
# Third terminal - Alice
python3 client_secure.py --port 5001
```
**Expected result on server console:**
```
[Session 1] 🛡️  MAC AUTHENTICATION FAILED
[Session 1]    Transcript mismatch detected!
[Session 1]    Possible MITM downgrade attack!
```

### Demo 4 - Secure Benchmark
```bash
# First terminal
python3 server_secure.py
# Second terminal -- values from demo 1
python3 client_secure.py --runs 100 --vulnerable-avg 3.02 --vulnerable-std 2.01
```
Results saved to `results_secure/`:
  - `secure_benchmark_Kyber512.csv`
  - `fig_secure_breakdown_Kyber512.png` — component times including transcript hash cost
  - `fig_price_of_security_Kyber512.png` — vulnerable vs secure comparison

## Key Results

| Algorithm | Total time (ms) | PQ Public Key | PQ Ciphertext |
|-----------|----------------|---------------|---------------|
| X25519 (classic) | 0.392 | — | — |
| Kyber512 | 0.453 | 800 B | 768 B |
| Kyber1024 | 0.565 | 1,568 B | 1,568 B |
| HQC-128 | 11.027 | 2,249 B | 4,433 B |
| HQC-256 | 168.040 | 7,245 B | 14,421 B |

## Acknowledgements
This implementation was developed with the assistance of Claude (Anthropic), 
an AI coding tool, as part of the research conducted for a Master's thesis. 
The experimental design, data analysis, and conclusions are entirely the author's own work.

## References
- [FIPS 203] NIST, "Module-Lattice-Based Key-Encapsulation Mechanism Standard", 2024
- [PQXDH] T. Perrin, "The PQXDH Key Agreement Protocol", Signal Foundation, 2023
- [X3DH] M. Marlinspike and T. Perrin, "The X3DH Key Agreement Protocol", Signal Foundation, 2016
- [liboqs] Open Quantum Safe Project — https://openquantumsafe.org






