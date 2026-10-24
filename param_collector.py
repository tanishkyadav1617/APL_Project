# =============================================================================
# param_collector.py  —  Dynamic Parameter Collection Module
# =============================================================================
# Prompts the user for algorithm-specific parameters via the CLI and returns
# them as a structured dict ready for crypto_engine.encrypt() / decrypt().
#
# All password / passphrase input uses getpass so the secret never echoes to
# the terminal.
# =============================================================================

import getpass
from selector import ALGO_AES_GCM, ALGO_CHACHA20, ALGO_XOR, ALGO_ROT


# ── Colour helpers (ANSI — gracefully disabled on Windows) ───────────────────

def _cyan(text: str) -> str:
    return f"\033[96m{text}\033[0m"

def _yellow(text: str) -> str:
    return f"\033[93m{text}\033[0m"

def _bold(text: str) -> str:
    return f"\033[1m{text}\033[0m"


# ── Generic prompts ───────────────────────────────────────────────────────────

def _prompt_passphrase(confirm: bool = True) -> str:
    """
    Interactively prompt for a passphrase, with optional confirmation.

    Parameters
    ----------
    confirm : bool – If True, ask the user to re-enter the passphrase to
                     catch typos (used during encryption; skip during decryption).

    Returns
    -------
    str – The collected passphrase.
    """
    while True:
        passphrase = getpass.getpass(_cyan("  Enter passphrase: "))
        if not passphrase:
            print(_yellow("  ⚠  Passphrase cannot be empty.  Please try again."))
            continue

        if confirm:
            confirm_pp = getpass.getpass(_cyan("  Confirm passphrase: "))
            if passphrase != confirm_pp:
                print(_yellow("  ⚠  Passphrases do not match.  Please try again."))
                continue

        return passphrase


def _prompt_xor_key_byte() -> int:
    """
    Prompt for an integer XOR key byte in [0, 255].

    Returns
    -------
    int – The chosen key byte.
    """
    while True:
        raw = input(_cyan("  Enter XOR key byte [0–255]: ")).strip()
        try:
            value = int(raw)
            if 0 <= value <= 255:
                return value
            print(_yellow("  ⚠  Value must be between 0 and 255."))
        except ValueError:
            print(_yellow("  ⚠  Please enter a whole number."))


def _prompt_rot_shift() -> int:
    """
    Prompt for an integer ROT shift in [1, 25].

    Returns
    -------
    int – The chosen shift distance.
    """
    while True:
        raw = input(_cyan("  Enter ROT shift [1–25]  (13 for ROT-13): ")).strip()
        try:
            value = int(raw)
            if 1 <= value <= 25:
                return value
            print(_yellow("  ⚠  Shift must be between 1 and 25."))
        except ValueError:
            print(_yellow("  ⚠  Please enter a whole number."))


# ── Public API ────────────────────────────────────────────────────────────────

def collect_encrypt_params(algo_id: str) -> dict:
    """
    Collect all parameters required to *encrypt* with the given algorithm.

    Parameters
    ----------
    algo_id : str – One of the ALGO_* constants from selector.py.

    Returns
    -------
    dict – Ready-to-pass params dict for crypto_engine.encrypt().
    """
    print()
    print(_bold(f"  ── Parameter collection for {algo_id} (encryption) ──"))

    if algo_id in (ALGO_AES_GCM, ALGO_CHACHA20):
        print("  A passphrase is used to derive a cryptographic key via PBKDF2-HMAC-SHA256.")
        passphrase = _prompt_passphrase(confirm=True)
        return {"passphrase": passphrase}

    if algo_id == ALGO_XOR:
        print("  A single byte (0–255) is used as the repeating XOR key.")
        key_byte = _prompt_xor_key_byte()
        return {"xor_key_byte": key_byte}

    if algo_id == ALGO_ROT:
        print("  An integer shift (1–25) rotates each alphabetic character.")
        shift = _prompt_rot_shift()
        return {"shift": shift}

    raise ValueError(f"Unknown algorithm: '{algo_id}'.")


def collect_decrypt_params(algo_id: str) -> dict:
    """
    Collect all parameters required to *decrypt* with the given algorithm.

    Parameters
    ----------
    algo_id : str – Algorithm identifier read from the encrypted container.

    Returns
    -------
    dict – Ready-to-pass params dict for crypto_engine.decrypt().
    """
    print()
    print(_bold(f"  ── Parameter collection for {algo_id} (decryption) ──"))

    if algo_id in (ALGO_AES_GCM, ALGO_CHACHA20):
        print("  Enter the passphrase used during encryption.")
        passphrase = _prompt_passphrase(confirm=False)   # no confirmation needed
        return {"passphrase": passphrase}

    if algo_id == ALGO_XOR:
        print("  Enter the XOR key byte used during encryption.")
        key_byte = _prompt_xor_key_byte()
        return {"xor_key_byte": key_byte}

    if algo_id == ALGO_ROT:
        print("  Enter the ROT shift used during encryption.")
        shift = _prompt_rot_shift()
        return {"shift": shift}

    raise ValueError(f"Unknown algorithm: '{algo_id}'.")
