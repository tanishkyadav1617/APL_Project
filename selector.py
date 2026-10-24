# =============================================================================
# selector.py  —  Algorithm Selection Engine
# =============================================================================
# Maps a data-type profile (produced by profiler.py) onto the most suitable
# encryption algorithm and tier, and returns structured metadata used by the
# rest of the pipeline.
# =============================================================================

from profiler import (
    PROFILE_STRUCTURED_TEXT,
    PROFILE_HIGH_ENTROPY,
    PROFILE_CLASSICAL,
    PROFILE_BINARY_STREAM,
)


# ── Algorithm identifiers ─────────────────────────────────────────────────────
ALGO_AES_GCM       = "AES-256-GCM"
ALGO_CHACHA20      = "ChaCha20-Poly1305"
ALGO_XOR           = "Multi-byte XOR"
ALGO_ROT           = "ROT Cipher"

# ── Tier labels ──────────────────────────────────────────────────────────────
TIER_PRODUCTION    = "Production"
TIER_EDUCATIONAL   = "Educational / Playground"

# ── Algorithm catalogue ──────────────────────────────────────────────────────
# Each entry carries everything the rest of the pipeline needs to know about
# an algorithm without hard-coding logic outside this module.

ALGORITHM_CATALOGUE: dict[str, dict] = {

    ALGO_AES_GCM: {
        "id"         : ALGO_AES_GCM,
        "tier"       : TIER_PRODUCTION,
        "description": (
            "AES-256 in Galois/Counter Mode — an authenticated, symmetric cipher "
            "standardised by NIST.  It provides both confidentiality (via AES-CTR) "
            "and integrity / authenticity (via the GHASH-based Poly1305 tag). "
            "Ideal for structured text and tabular data."
        ),
        "key_params" : ["passphrase"],   # parameters the user must supply
        "profiles"   : [PROFILE_STRUCTURED_TEXT],
    },

    ALGO_CHACHA20: {
        "id"         : ALGO_CHACHA20,
        "tier"       : TIER_PRODUCTION,
        "description": (
            "ChaCha20-Poly1305 — an authenticated stream cipher designed by Daniel "
            "Bernstein.  It outperforms AES on platforms without hardware AES "
            "acceleration and is particularly well-suited to binary / high-entropy "
            "data streams because it has no block-padding overhead."
        ),
        "key_params" : ["passphrase"],
        "profiles"   : [PROFILE_HIGH_ENTROPY, PROFILE_BINARY_STREAM],
    },

    ALGO_XOR: {
        "id"         : ALGO_XOR,
        "tier"       : TIER_EDUCATIONAL,
        "description": (
            "Multi-byte XOR — each plaintext byte is XORed with the corresponding "
            "byte of a repeating key.  Easy to implement and visualise; useful for "
            "teaching stream-cipher concepts.  NOT secure for real data."
        ),
        "key_params" : ["xor_key_byte"],  # single byte (0-255) used as repeating key
        "profiles"   : [],               # used only when user overrides
    },

    ALGO_ROT: {
        "id"         : ALGO_ROT,
        "tier"       : TIER_EDUCATIONAL,
        "description": (
            "ROT Cipher — a generalised Caesar cipher that shifts each alphabetic "
            "character by a configurable integer.  ROT-13 is the most famous variant. "
            "Non-alphabetic characters are left unchanged.  NOT secure for real data."
        ),
        "key_params" : ["shift"],         # integer shift in [1, 25]
        "profiles"   : [PROFILE_CLASSICAL],
    },
}


# ── Selection logic ───────────────────────────────────────────────────────────

def recommend_algorithm(profile: str) -> dict:
    """
    Return the recommended algorithm metadata dict for a given data profile.

    The selection follows this priority order:
      1. PROFILE_STRUCTURED_TEXT   →  AES-256-GCM
      2. PROFILE_HIGH_ENTROPY      →  ChaCha20-Poly1305
      3. PROFILE_BINARY_STREAM     →  ChaCha20-Poly1305  (handles arbitrary binary)
      4. PROFILE_CLASSICAL         →  ROT Cipher          (educational, plain text)

    Parameters
    ----------
    profile : str
        One of the PROFILE_* constants from profiler.py.

    Returns
    -------
    dict
        The matching entry from ALGORITHM_CATALOGUE.
    """
    mapping: dict[str, str] = {
        PROFILE_STRUCTURED_TEXT: ALGO_AES_GCM,
        PROFILE_HIGH_ENTROPY   : ALGO_CHACHA20,
        PROFILE_BINARY_STREAM  : ALGO_CHACHA20,
        PROFILE_CLASSICAL      : ALGO_ROT,
    }

    algo_id = mapping.get(profile, ALGO_AES_GCM)   # safe default
    return ALGORITHM_CATALOGUE[algo_id]


def list_algorithms() -> list[dict]:
    """Return all algorithm metadata dicts (used for manual override menus)."""
    return list(ALGORITHM_CATALOGUE.values())


def get_algorithm(algo_id: str) -> dict:
    """
    Retrieve a specific algorithm by its identifier string.

    Parameters
    ----------
    algo_id : str
        One of the ALGO_* constants (e.g. 'AES-256-GCM').

    Returns
    -------
    dict
        The matching entry from ALGORITHM_CATALOGUE.

    Raises
    ------
    KeyError
        If *algo_id* is not found in the catalogue.
    """
    if algo_id not in ALGORITHM_CATALOGUE:
        raise KeyError(f"Unknown algorithm '{algo_id}'.")
    return ALGORITHM_CATALOGUE[algo_id]
