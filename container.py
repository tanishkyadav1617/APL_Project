# =============================================================================
# container.py  —  Encrypted Output Packaging Module
# =============================================================================
# Serialises an encrypted container dict to a binary .enc file and deserialises
# it back.  The file format is:
#
#   ┌──────────────────────────────────────────────────────────────────────┐
#   │  4 bytes   – magic number  "APLC"  (APL Crypto)                     │
#   │  1 byte    – format version  (currently 0x01)                       │
#   │  1 byte    – algorithm ID byte  (see ALGO_TO_BYTE mapping below)    │
#   │  2 bytes   – length of the JSON metadata block  (big-endian uint16) │
#   │  N bytes   – JSON metadata  (UTF-8, no ciphertext)                  │
#   │  4 bytes   – ciphertext length  (big-endian uint32)                 │
#   │  M bytes   – raw ciphertext bytes                                   │
#   └──────────────────────────────────────────────────────────────────────┘
#
# All binary fields (salt, nonce) are stored as hex strings inside the JSON
# metadata block for human readability and cross-platform compatibility.
# =============================================================================

import json
import struct
from pathlib import Path

from selector import ALGO_AES_GCM, ALGO_CHACHA20, ALGO_XOR, ALGO_ROT


# ── File format constants ─────────────────────────────────────────────────────
MAGIC          = b"APLC"
FORMAT_VERSION = 0x01

# Map algorithm strings to a compact 1-byte ID stored in the file header
ALGO_TO_BYTE: dict[str, int] = {
    ALGO_AES_GCM : 0x01,
    ALGO_CHACHA20: 0x02,
    ALGO_XOR     : 0x10,
    ALGO_ROT     : 0x11,
}
BYTE_TO_ALGO: dict[int, str] = {v: k for k, v in ALGO_TO_BYTE.items()}


# ── Serialisation helpers ─────────────────────────────────────────────────────

def _container_to_meta(container: dict) -> dict:
    """
    Convert a crypto_engine container dict to a JSON-serialisable metadata dict.

    Raw bytes values (salt, nonce) are hex-encoded.  The ciphertext is stored
    separately as raw bytes in the file body.

    Parameters
    ----------
    container : dict – Output of crypto_engine.encrypt().

    Returns
    -------
    dict – JSON-serialisable metadata (no ciphertext).
    """
    algo = container["algorithm"]
    meta: dict = {"algorithm": algo}

    if algo in (ALGO_AES_GCM, ALGO_CHACHA20):
        meta["salt"]  = container["salt"].hex()
        meta["nonce"] = container["nonce"].hex()

    elif algo == ALGO_XOR:
        meta["key_byte"] = container["key_byte"]

    elif algo == ALGO_ROT:
        meta["shift"] = container["shift"]

    return meta


def _meta_to_container(meta: dict, ciphertext: bytes) -> dict:
    """
    Reconstruct a crypto_engine container dict from JSON metadata + raw ciphertext.

    Parameters
    ----------
    meta       : dict  – Deserialised JSON metadata from the file header.
    ciphertext : bytes – Raw ciphertext bytes from the file body.

    Returns
    -------
    dict – Container compatible with crypto_engine.decrypt().
    """
    algo = meta["algorithm"]
    container: dict = {"algorithm": algo, "ciphertext": ciphertext}

    if algo in (ALGO_AES_GCM, ALGO_CHACHA20):
        container["salt"]  = bytes.fromhex(meta["salt"])
        container["nonce"] = bytes.fromhex(meta["nonce"])

    elif algo == ALGO_XOR:
        container["key_byte"] = meta["key_byte"]

    elif algo == ALGO_ROT:
        container["shift"] = meta["shift"]

    return container


# ── Public API ────────────────────────────────────────────────────────────────

def save_container(container: dict, output_path: str) -> Path:
    """
    Serialise *container* to a binary .enc file at *output_path*.

    Parameters
    ----------
    container   : dict – Output of crypto_engine.encrypt().
    output_path : str  – Destination file path (created/overwritten).

    Returns
    -------
    pathlib.Path – Resolved path of the written file.
    """
    algo      = container["algorithm"]
    algo_byte = ALGO_TO_BYTE.get(algo, 0xFF)

    # Build JSON metadata (excludes ciphertext)
    meta_dict  = _container_to_meta(container)
    meta_bytes = json.dumps(meta_dict, separators=(",", ":")).encode("utf-8")

    if len(meta_bytes) > 0xFFFF:
        raise ValueError("Metadata block exceeds 65 535 bytes — this should never happen.")

    ciphertext = container["ciphertext"]

    out = Path(output_path)
    with out.open("wb") as fh:
        fh.write(MAGIC)                                          # 4 bytes
        fh.write(struct.pack(">BB", FORMAT_VERSION, algo_byte)) # 2 bytes
        fh.write(struct.pack(">H", len(meta_bytes)))            # 2 bytes
        fh.write(meta_bytes)                                     # N bytes
        fh.write(struct.pack(">I", len(ciphertext)))            # 4 bytes
        fh.write(ciphertext)                                     # M bytes

    return out.resolve()


def load_container(input_path: str) -> dict:
    """
    Deserialise a binary .enc file into a crypto_engine-compatible container dict.

    Parameters
    ----------
    input_path : str – Path to the .enc file.

    Returns
    -------
    dict – Container with "algorithm", "ciphertext", and algorithm-specific fields.

    Raises
    ------
    ValueError  – If the file magic or version is unrecognised.
    FileNotFoundError – If *input_path* does not exist.
    """
    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError(f"Encrypted file not found: {input_path}")

    with path.open("rb") as fh:
        # Magic
        magic = fh.read(4)
        if magic != MAGIC:
            raise ValueError(
                f"Not a valid .enc file (bad magic bytes: {magic!r})."
            )

        # Version + algorithm byte
        version, algo_byte = struct.unpack(">BB", fh.read(2))
        if version != FORMAT_VERSION:
            raise ValueError(
                f"Unsupported file format version: 0x{version:02X}."
            )

        algo = BYTE_TO_ALGO.get(algo_byte)
        if algo is None:
            raise ValueError(
                f"Unrecognised algorithm byte in file: 0x{algo_byte:02X}."
            )

        # JSON metadata
        meta_len   = struct.unpack(">H", fh.read(2))[0]
        meta_bytes = fh.read(meta_len)
        meta_dict  = json.loads(meta_bytes.decode("utf-8"))

        # Ciphertext
        cipher_len = struct.unpack(">I", fh.read(4))[0]
        ciphertext = fh.read(cipher_len)

        if len(ciphertext) != cipher_len:
            raise ValueError("File appears truncated — ciphertext length mismatch.")

    return _meta_to_container(meta_dict, ciphertext)
