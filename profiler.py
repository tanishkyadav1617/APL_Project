# =============================================================================
# profiler.py  —  Dataset Profiling & Analysis Module
# =============================================================================
# Ingests a file or raw bytes, computes Shannon entropy, byte size, and
# printable-character ratio, then classifies the data into one of four
# recognised data-type profiles used by the Algorithm Selection Engine.
# =============================================================================

import math
import string
from pathlib import Path


# ── Profile constants (returned as human-readable tags) ─────────────────────
PROFILE_STRUCTURED_TEXT    = "structured_text"       # CSV, JSON, XML, prose …
PROFILE_HIGH_ENTROPY       = "high_entropy_binary"   # compressed, encrypted, media
PROFILE_CLASSICAL          = "classical_cipher_text" # printable, low-entropy text
PROFILE_BINARY_STREAM      = "binary_stream"         # binary with moderate entropy

# Entropy thresholds (bits per byte, maximum is 8.0)
ENTROPY_LOW_THRESHOLD      = 3.5   # typical plain prose sits below this
ENTROPY_HIGH_THRESHOLD     = 7.0   # encrypted / compressed data sits above this


# ── Core helpers ─────────────────────────────────────────────────────────────

def load_data(source: str) -> bytes:
    """
    Load data from a file path or from a raw string.

    Parameters
    ----------
    source : str
        Either a filesystem path to an existing file, or a raw text string.

    Returns
    -------
    bytes
        Raw byte content ready for analysis.
    """
    path = Path(source)
    if path.exists() and path.is_file():
        with open(path, "rb") as fh:
            return fh.read()
    # Treat as a raw text string if the path does not resolve
    return source.encode("utf-8", errors="replace")


def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy (bits per byte) for *data*.

    The formula is:  H = -Σ p(x) · log₂(p(x))
    A completely uniform byte distribution yields 8.0 bits/byte.
    Plain ASCII text typically sits in the 3–5 bit/byte range.

    Parameters
    ----------
    data : bytes
        Raw byte sequence to analyse.

    Returns
    -------
    float
        Entropy value in the range [0.0, 8.0].
    """
    if not data:
        return 0.0

    # Count occurrences of each byte value (0-255)
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    total   = len(data)
    entropy = 0.0
    for count in freq.values():
        probability = count / total
        entropy    -= probability * math.log2(probability)

    return round(entropy, 4)


def printable_ratio(data: bytes) -> float:
    """
    Return the fraction of bytes that are printable ASCII characters,
    including common whitespace (space, tab, newline, carriage-return).

    Parameters
    ----------
    data : bytes
        Raw byte sequence to analyse.

    Returns
    -------
    float
        A value in [0.0, 1.0]; 1.0 means every byte is printable ASCII.
    """
    if not data:
        return 0.0

    printable_set = set(string.printable.encode("ascii"))
    count = sum(1 for b in data if b in printable_set)
    return round(count / len(data), 4)


def classify_profile(entropy: float, ratio: float, size_bytes: int) -> str:
    """
    Map metric values onto one of the four recognised data-type profiles.

    Decision logic
    ──────────────
    ① ratio ≥ 0.90  AND  entropy < LOW_THRESHOLD   →  classical_cipher_text
       Almost entirely printable + very low entropy  (simple substitution,
       ROT-style ciphers, or plain human-readable text that needs a light
       educational cipher).

    ② ratio ≥ 0.85  AND  LOW_THRESHOLD ≤ entropy ≤ HIGH_THRESHOLD
                                                    →  structured_text
       Mostly printable + moderate entropy (CSV, JSON, XML, prose).
       Best protected by AES-256-GCM.

    ③ entropy > HIGH_THRESHOLD                     →  high_entropy_binary
       Very high entropy regardless of printability (already-compressed,
       already-encrypted, or multimedia).  ChaCha20-Poly1305 is preferred
       because it performs well on arbitrary-length binary streams.

    ④ Everything else                               →  binary_stream
       Mixed binary that doesn't fit the above categories.

    Parameters
    ----------
    entropy     : float  – Shannon entropy of the data (bits/byte).
    ratio       : float  – Printable-character ratio in [0, 1].
    size_bytes  : int    – Number of bytes in the dataset.

    Returns
    -------
    str
        One of the PROFILE_* constants defined at the top of this module.
    """
    if ratio >= 0.90 and entropy < ENTROPY_LOW_THRESHOLD:
        return PROFILE_CLASSICAL

    if ratio >= 0.85 and ENTROPY_LOW_THRESHOLD <= entropy <= ENTROPY_HIGH_THRESHOLD:
        return PROFILE_STRUCTURED_TEXT

    if entropy > ENTROPY_HIGH_THRESHOLD:
        return PROFILE_HIGH_ENTROPY

    return PROFILE_BINARY_STREAM


def profile_data(source: str) -> dict:
    """
    Full analysis pipeline: load → measure → classify.

    Parameters
    ----------
    source : str
        File path or raw text string.

    Returns
    -------
    dict with keys:
        source          – the original *source* argument
        size_bytes      – byte length of the data
        entropy         – Shannon entropy (float, bits/byte)
        printable_ratio – fraction of printable bytes (float)
        profile         – data-type profile string (one of PROFILE_* constants)
        data            – the raw bytes (for downstream use)
    """
    data    = load_data(source)
    entropy = shannon_entropy(data)
    ratio   = printable_ratio(data)
    size    = len(data)
    profile = classify_profile(entropy, ratio, size)

    return {
        "source"         : source,
        "size_bytes"     : size,
        "entropy"        : entropy,
        "printable_ratio": ratio,
        "profile"        : profile,
        "data"           : data,
    }
