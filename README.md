# APL Project — Smart Encryption Advisor & Engine

A complete, end-to-end Python CLI tool that **analyses** a data file or text string, **recommends** the most suitable encryption algorithm based on measured data characteristics, and then **interactively encrypts and decrypts** using that algorithm.

---

## Project Structure

```
APL Project/
├── main.py             ← CLI entry point & menu orchestrator
├── profiler.py         ← Dataset profiling & analysis module
├── selector.py         ← Algorithm selection engine
├── crypto_engine.py    ← Encryption & decryption implementations
├── container.py        ← Binary .enc file serialisation / deserialisation
├── param_collector.py  ← Dynamic parameter collection (interactive prompts)
├── display.py          ← Rich ANSI CLI display helpers
├── test_roundtrip.py   ← Automated round-trip verification suite
├── requirements.txt    ← Python dependencies
└── sample_data/
    ├── employees.csv   ← Structured tabular sample (→ AES-256-GCM)
    └── pangrams.txt    ← Plain printable-text sample (→ ROT Cipher)
```

---

## Quick Start

### 1. Install the dependency

```bash
# Option A — system-wide (macOS)
pip3 install cryptography --break-system-packages

# Option B — inside a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
```

### 2. Run the interactive menu

```bash
python3 main.py
```

### 3. Or use direct CLI flags

```bash
# Encrypt a file (prompts for algorithm confirmation & passphrase)
python3 main.py --encrypt sample_data/employees.csv

# Decrypt an encrypted file
python3 main.py --decrypt employees.enc

# Profile a file without encrypting
python3 main.py --analyse sample_data/employees.csv
```

---

## Module Overview

### `profiler.py` — Dataset Profiling

Computes three metrics from the raw bytes:

| Metric | Description |
|---|---|
| **Shannon Entropy** | Bits per byte (0.0 = all identical, 8.0 = perfectly random) |
| **Byte Size** | Total number of bytes in the input |
| **Printable Ratio** | Fraction of bytes that are printable ASCII |

Then classifies the data into one of four **profiles**:

| Profile | Entropy | Printable | Typical data |
|---|---|---|---|
| `structured_text` | 3.5 – 7.0 | ≥ 85% | CSV, JSON, XML, prose |
| `classical_cipher_text` | < 3.5 | ≥ 90% | Simple text, demo data |
| `high_entropy_binary` | > 7.0 | any | Compressed, encrypted, media |
| `binary_stream` | anything else | < 85% | Mixed binary |

---

### `selector.py` — Algorithm Selection Engine

Maps each profile to the optimal algorithm:

| Profile | Recommended Algorithm | Tier |
|---|---|---|
| `structured_text` | **AES-256-GCM** | Production |
| `high_entropy_binary` | **ChaCha20-Poly1305** | Production |
| `binary_stream` | **ChaCha20-Poly1305** | Production |
| `classical_cipher_text` | **ROT Cipher** | Educational |

The user can always **override** the recommendation via the interactive menu.

---

### `crypto_engine.py` — Encryption & Decryption

| Algorithm | Key Derivation | Parameters | Auth Tag |
|---|---|---|---|
| AES-256-GCM | PBKDF2-HMAC-SHA256 (600k iter) | Passphrase → 32-byte key, 12-byte nonce, 16-byte salt | ✔ 16 bytes |
| ChaCha20-Poly1305 | PBKDF2-HMAC-SHA256 (600k iter) | Passphrase → 32-byte key, 12-byte nonce, 16-byte salt | ✔ 16 bytes |
| Multi-byte XOR | None | Key byte (0–255), repeating | ✖ |
| ROT Cipher | None | Shift integer (1–25) | ✖ |

---

### `container.py` — Binary `.enc` File Format

Each encrypted output file has the following layout:

```
┌──────────────────────────────────────────────┐
│  4 bytes  – Magic: "APLC"                    │
│  1 byte   – Format version (0x01)            │
│  1 byte   – Algorithm ID byte                │
│  2 bytes  – JSON metadata length (uint16 BE) │
│  N bytes  – JSON metadata (salt, nonce, …)   │
│  4 bytes  – Ciphertext length (uint32 BE)    │
│  M bytes  – Raw ciphertext                   │
└──────────────────────────────────────────────┘
```

---

## Running the Tests

```bash
python3 test_roundtrip.py
```

The test suite verifies:
- Profiler entropy, printable-ratio, and classification logic
- Selector profile → algorithm routing
- AES-256-GCM in-memory and disk round-trips (7 payload types)
- ChaCha20-Poly1305 in-memory and disk round-trips (7 payload types)
- Wrong-passphrase rejection for both AEAD ciphers
- XOR identity property (key=0) and round-trips (4 key values)
- ROT round-trips (3 shifts) and ROT-13 self-inverse property

---

## Security Notes

- **Production ciphers** (AES-256-GCM, ChaCha20-Poly1305) provide authenticated encryption — any tampering with the ciphertext is detected.
- **Educational ciphers** (XOR, ROT) are intentionally weak and included for learning / demonstration only. Do **not** use them to protect sensitive data.
- Passphrases are never echoed to the terminal (`getpass` is used).
- The PBKDF2 iteration count (600,000) follows the NIST SP 800-132 guidance for 2024.
