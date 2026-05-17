# SecureVault
### Integrated Cryptographic Security System

A Python-based cryptographic toolkit implementing classical and modern security algorithms from scratch — no external cryptography libraries used.

---

## Project Structure

```
securevault/
├── main.py                   # CLI entry point
├── gui.py                    # Tkinter GUI entry point
├── utils.py                  # Shared helper functions
├── module1_classical.py      # Classical Cipher Engine
├── module2_stream.py         # Stream & Block Cipher
├── module3_hash.py           # Hash & Authentication
├── module4_keyx.py           # Key Exchange & Number Theory
├── module5_blockchain.py     # Blockchain Audit Logger
├── bonus_rsa.py              # RSA Implementation (+3)
├── bonus_network.py          # Network Simulation (+2)
├── bonus_merkle.py           # Merkle Tree (+2)
├── tests/
│   ├── test_module1.py
│   ├── test_module2.py
│   ├── test_module3.py
│   ├── test_module4.py
│   └── test_module5.py
├── data/
│   └── blockchain.json
└── README.md
```

---

## How to Run

### CLI
```bash
python main.py
```

### GUI
```bash
python gui.py
```

### Tests
```bash
python -m unittest discover tests
```

---

## Requirements

- Python 3.9+
- No external libraries required
- Standard library only: `hashlib`, `hmac`, `os`, `json`, `math`, `time`, `threading`, `tkinter`

---

## Modules

### Module 1 — Classical Cipher Engine
Implements six classical ciphers from scratch:
- **Caesar Cipher** — alphabetic shift by arbitrary amount
- **ROT-13** — Caesar with fixed shift of 13 (self-inverse)
- **Vigenere Cipher** — repeating keyword cipher with Index of Coincidence key-length analysis
- **One-Time Pad (OTP)** — XOR with truly random key; mathematically unbreakable
- **Substitution Cipher** — full 26-character alphabet substitution
- **Columnar Transposition** — rearranges characters by column order

### Module 2 — Stream & Block Cipher
- **LCG PRNG** — Linear Congruential Generator with configurable seed, multiplier, increment
- **Stream Cipher** — LCG keystream XORed with plaintext
- **Block Cipher** — 2-round S-box and P-box substitution-permutation network on 8-byte blocks
- **Avalanche Effect Demo** — shows bit diffusion on 1-bit input change
- **Frequency Test** — statistical randomness test on LCG output

### Module 3 — Hash & Authentication
- **Hash Functions** — MD5, SHA-1, SHA-256, SHA-512 via hashlib
- **HMAC-SHA256** — built manually using inner/outer pad construction
- **PBKDF2 Password Hashing** — 100,000 iterations with random salt; JSON storage
- **File Integrity Checker** — SHA-256 file hashing with tamper detection
- **Birthday Attack Simulator** — finds hash collisions on truncated SHA-256

### Module 4 — Key Exchange & Number Theory
All algorithms implemented from scratch:
- **Extended Euclidean Algorithm** — finds GCD and Bezout coefficients
- **Modular Inverse** — using Extended GCD
- **Euler's Totient Function** — φ(n)
- **Chinese Remainder Theorem** — solves systems of congruences
- **Miller-Rabin Primality Test** — probabilistic test for large primes
- **Diffie-Hellman Key Exchange** — 512-bit safe prime, full Alice-Bob simulation
- **Brute-Force Discrete Log Attack** — demonstrates need for large primes
- **Timing Side-Channel Demo** — measures modular exponentiation timing

### Module 5 — Blockchain Audit Logger
- **Block Structure** — index, timestamp, event_type, event_data, previous_hash, nonce, block_hash
- **Proof-of-Work Mining** — configurable difficulty (leading zeros)
- **Chain Validation** — detects any tampered block
- **Tamper Demo** — deliberately corrupts a block then validates
- **Persistent Storage** — saves and loads chain from `data/blockchain.json`
- **Audit Logging** — all cryptographic operations across modules are logged as blocks

---

## Bonus Features

| Feature | Marks | Description |
|---|---|---|
| RSA Implementation | +3 | Keygen, encrypt, decrypt, sign, verify using Module 4 number theory |
| Network Simulation | +2 | Alice, Bob, Eve on separate threads with shared Queue channel |
| Merkle Tree | +2 | Full tree from blockchain hashes, proof generation and verification |
| GUI Interface | +3 | Tkinter GUI with tabbed interface for all modules |

**Total bonus: +10 marks**

---

## Design Decisions

**No cryptography libraries** — all algorithms are hand-coded to demonstrate understanding of the underlying mathematics and operations.

**Modular architecture** — each module is independent and importable. `main.py` and `gui.py` are thin wrappers that call module functions.

**Blockchain as audit log** — every cryptographic operation across all modules logs an event to the blockchain, creating a tamper-evident record of all activity.

**Security notes** — the LCG stream cipher, classical ciphers, and small DH parameters are intentionally weak/educational. The app demonstrates their vulnerabilities (key reuse, frequency analysis, brute-force) alongside secure alternatives (PBKDF2, SHA-256, 512-bit DH).

---

## Example Usage

```python
# Classical cipher
from module1_classical import caesar_encrypt
cipher = caesar_encrypt("Hello World", 13)

# Hash a message
from module3_hash import hash_message
digest = hash_message("Hello", "sha256")

# Diffie-Hellman
from module4_keyx import dh_generate_private_key, dh_compute_public_key
priv = dh_generate_private_key(p)
pub  = dh_compute_public_key(priv, g, p)

# Log to blockchain
from module5_blockchain import log_event
log_event("ENCRYPT", {"algorithm": "caesar", "shift": 13})
```

---

