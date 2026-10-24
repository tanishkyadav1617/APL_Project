# =============================================================================
# crypto_engine.py  —  Encryption & Decryption Engine
# =============================================================================
# Provides one encrypt() and one decrypt() entry-point that dispatch to the
# correct algorithm implementation.  Each implementation returns / expects a
# structured "container" dictionary that carries all metadata needed for a
# successful round-trip (algorithm, IV/nonce, salt, ciphertext, etc.).
# =============================================================================

import os
import hashlib
import struct

from selector import ALGO_AES_GCM, ALGO_CHACHA20, ALGO_XOR, ALGO_ROT

# ── Key-derivation parameters (PBKDF2-HMAC-SHA256) ──────────────────────────
KDF_ITERATIONS  = 600_000   # NIST-recommended minimum for 2024
KDF_SALT_BYTES  = 16        # 128-bit salt
AES_KEY_BYTES   = 32        # AES-256  →  32-byte key
AES_NONCE_BYTES = 12        # GCM nonce (96 bits recommended by NIST SP 800-38D)
CHACHA_KEY_BYTES  = 32      # ChaCha20 key length
CHACHA_NONCE_BYTES = 12     # ChaCha20-Poly1305 nonce (96 bits — required by cryptography library)


# =============================================================================
# Internal helpers
# =============================================================================

def _derive_key(passphrase: str, salt: bytes, key_len: int) -> bytes:
    """
    Derive a cryptographic key from a user passphrase using PBKDF2-HMAC-SHA256.

    Parameters
    ----------
    passphrase : str   – The user's secret passphrase (UTF-8 encoded internally).
    salt       : bytes – Random salt (should be 16 bytes minimum).
    key_len    : int   – Desired key length in bytes.

    Returns
    -------
    bytes – Derived key of exactly *key_len* bytes.
    """
    return hashlib.pbkdf2_hmac(
        hash_name   = "sha256",
        password    = passphrase.encode("utf-8"),
        salt        = salt,
        iterations  = KDF_ITERATIONS,
        dklen       = key_len,
    )


# =============================================================================
# AES-256-GCM
# =============================================================================

def _aes_gcm_encrypt(data: bytes, passphrase: str) -> dict:
    """
    Encrypt *data* with AES-256-GCM.

    Steps
    -----
    1. Generate a random 16-byte salt and 12-byte nonce.
    2. Derive a 32-byte key via PBKDF2-HMAC-SHA256.
    3. Encrypt using AES-256-GCM which appends a 16-byte authentication tag.

    Returns
    -------
    dict with keys: algorithm, salt, nonce, ciphertext  (all bytes where raw)
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ImportError(
            "The 'cryptography' package is required for AES-256-GCM.\n"
            "Install it with:  pip install cryptography"
        )

    salt   = os.urandom(KDF_SALT_BYTES)
    nonce  = os.urandom(AES_NONCE_BYTES)
    key    = _derive_key(passphrase, salt, AES_KEY_BYTES)

    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)   # no additional data

    return {
        "algorithm" : ALGO_AES_GCM,
        "salt"      : salt,
        "nonce"     : nonce,
        "ciphertext": ciphertext,   # already includes the 16-byte GCM tag
    }


def _aes_gcm_decrypt(container: dict, passphrase: str) -> bytes:
    """
    Decrypt an AES-256-GCM container.  Raises ValueError if the tag is wrong.

    Parameters
    ----------
    container  : dict  – The output of _aes_gcm_encrypt().
    passphrase : str   – The user's secret passphrase.

    Returns
    -------
    bytes – Original plaintext.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
    except ImportError:
        raise ImportError("The 'cryptography' package is required.")

    key    = _derive_key(passphrase, container["salt"], AES_KEY_BYTES)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(container["nonce"], container["ciphertext"], None)
    except InvalidTag:
        raise ValueError(
            "Decryption failed — wrong passphrase or corrupted ciphertext "
            "(GCM authentication tag mismatch)."
        )
    return plaintext


# =============================================================================
# ChaCha20-Poly1305
# =============================================================================

def _chacha20_encrypt(data: bytes, passphrase: str) -> dict:
    """
    Encrypt *data* with ChaCha20-Poly1305.

    Steps
    -----
    1. Generate a random 16-byte salt and 16-byte nonce.
    2. Derive a 32-byte key via PBKDF2-HMAC-SHA256.
    3. Encrypt using ChaCha20-Poly1305 (appends 16-byte Poly1305 tag).

    Returns
    -------
    dict with keys: algorithm, salt, nonce, ciphertext
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except ImportError:
        raise ImportError(
            "The 'cryptography' package is required for ChaCha20-Poly1305.\n"
            "Install it with:  pip install cryptography"
        )

    salt   = os.urandom(KDF_SALT_BYTES)
    nonce  = os.urandom(CHACHA_NONCE_BYTES)
    key    = _derive_key(passphrase, salt, CHACHA_KEY_BYTES)

    chacha     = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, data, None)

    return {
        "algorithm" : ALGO_CHACHA20,
        "salt"      : salt,
        "nonce"     : nonce,
        "ciphertext": ciphertext,
    }


def _chacha20_decrypt(container: dict, passphrase: str) -> bytes:
    """
    Decrypt a ChaCha20-Poly1305 container.

    Parameters
    ----------
    container  : dict  – The output of _chacha20_encrypt().
    passphrase : str   – The user's secret passphrase.

    Returns
    -------
    bytes – Original plaintext.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.exceptions import InvalidTag
    except ImportError:
        raise ImportError("The 'cryptography' package is required.")

    key    = _derive_key(passphrase, container["salt"], CHACHA_KEY_BYTES)
    chacha = ChaCha20Poly1305(key)

    try:
        plaintext = chacha.decrypt(container["nonce"], container["ciphertext"], None)
    except InvalidTag:
        raise ValueError(
            "Decryption failed — wrong passphrase or corrupted ciphertext "
            "(Poly1305 authentication tag mismatch)."
        )
    return plaintext


# =============================================================================
# Multi-byte XOR
# =============================================================================

def _xor_encrypt(data: bytes, key_byte: int) -> dict:
    """
    Encrypt (or decrypt — XOR is its own inverse) *data* with a repeating
    single-byte key.

    The same function is used for both directions since XOR(XOR(x)) = x.

    Parameters
    ----------
    data     : bytes – Input data.
    key_byte : int   – Key byte in [0, 255].

    Returns
    -------
    dict with keys: algorithm, key_byte, ciphertext
    """
    if not 0 <= key_byte <= 255:
        raise ValueError("XOR key_byte must be an integer in [0, 255].")

    ciphertext = bytes(b ^ key_byte for b in data)

    return {
        "algorithm" : ALGO_XOR,
        "key_byte"  : key_byte,
        "ciphertext": ciphertext,
    }


def _xor_decrypt(container: dict, key_byte: int) -> bytes:
    """
    Decrypt a multi-byte XOR container by XORing again with the same key byte.

    Parameters
    ----------
    container : dict  – The output of _xor_encrypt().
    key_byte  : int   – The same key byte used for encryption.

    Returns
    -------
    bytes – Original plaintext.
    """
    # XOR is symmetric: decrypt == encrypt
    result = _xor_encrypt(container["ciphertext"], key_byte)
    return result["ciphertext"]


# =============================================================================
# ROT Cipher
# =============================================================================

def _rot_encrypt(data: bytes, shift: int) -> dict:
    """
    Apply a ROT (Caesar) cipher with *shift* positions to every alphabetic
    byte in *data*.  Non-alphabetic bytes are passed through unchanged.

    Parameters
    ----------
    data  : bytes – Input data (typically ASCII/UTF-8 text).
    shift : int   – Shift distance in [1, 25].

    Returns
    -------
    dict with keys: algorithm, shift, ciphertext
    """
    if not 1 <= shift <= 25:
        raise ValueError("ROT shift must be an integer in [1, 25].")

    def _shift_byte(b: int, s: int) -> int:
        if ord('A') <= b <= ord('Z'):
            return (b - ord('A') + s) % 26 + ord('A')
        if ord('a') <= b <= ord('z'):
            return (b - ord('a') + s) % 26 + ord('a')
        return b

    ciphertext = bytes(_shift_byte(b, shift) for b in data)

    return {
        "algorithm" : ALGO_ROT,
        "shift"     : shift,
        "ciphertext": ciphertext,
    }


def _rot_decrypt(container: dict, shift: int) -> bytes:
    """
    Reverse the ROT cipher by shifting in the opposite direction.

    Parameters
    ----------
    container : dict – The output of _rot_encrypt().
    shift     : int  – The same shift used for encryption.

    Returns
    -------
    bytes – Original plaintext.
    """
    reverse_shift = (26 - shift) % 26
    result = _rot_encrypt(container["ciphertext"], reverse_shift if reverse_shift else 26)
    return result["ciphertext"]


# =============================================================================
# Public API
# =============================================================================

def encrypt(data: bytes, algo_id: str, params: dict) -> dict:
    """
    Dispatch to the correct encryption implementation.

    Parameters
    ----------
    data    : bytes – Plaintext / raw data to encrypt.
    algo_id : str   – One of the ALGO_* constants from selector.py.
    params  : dict  – Algorithm-specific parameters collected from the user:
                        AES-256-GCM / ChaCha20-Poly1305 → {"passphrase": str}
                        Multi-byte XOR                   → {"xor_key_byte": int}
                        ROT Cipher                       → {"shift": int}

    Returns
    -------
    dict – Encrypted container (algorithm-dependent keys + "ciphertext").
    """
    if algo_id == ALGO_AES_GCM:
        return _aes_gcm_encrypt(data, params["passphrase"])

    if algo_id == ALGO_CHACHA20:
        return _chacha20_encrypt(data, params["passphrase"])

    if algo_id == ALGO_XOR:
        return _xor_encrypt(data, int(params["xor_key_byte"]))

    if algo_id == ALGO_ROT:
        return _rot_encrypt(data, int(params["shift"]))

    raise ValueError(f"Unknown algorithm '{algo_id}'.")


def decrypt(container: dict, params: dict) -> bytes:
    """
    Dispatch to the correct decryption implementation.

    Parameters
    ----------
    container : dict – The encrypted container (e.g. loaded from a .enc file).
    params    : dict – Decryption parameters collected from the user:
                        AES-256-GCM / ChaCha20-Poly1305 → {"passphrase": str}
                        Multi-byte XOR                   → {"xor_key_byte": int}
                        ROT Cipher                       → {"shift": int}

    Returns
    -------
    bytes – Decrypted plaintext.
    """
    algo_id = container.get("algorithm")

    if algo_id == ALGO_AES_GCM:
        return _aes_gcm_decrypt(container, params["passphrase"])

    if algo_id == ALGO_CHACHA20:
        return _chacha20_decrypt(container, params["passphrase"])

    if algo_id == ALGO_XOR:
        return _xor_decrypt(container, int(params["xor_key_byte"]))

    if algo_id == ALGO_ROT:
        return _rot_decrypt(container, int(params["shift"]))

    raise ValueError(f"Unknown algorithm in container: '{algo_id}'.")
