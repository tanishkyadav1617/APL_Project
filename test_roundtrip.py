#!/usr/bin/env python3
# =============================================================================
# test_roundtrip.py  —  Automated Round-Trip Verification Suite
# =============================================================================
# Exercises every encryption algorithm with multiple test payloads to confirm
# that:
#   1. encrypt() produces a non-empty ciphertext that differs from plaintext.
#   2. The container can be saved to disk and loaded back correctly.
#   3. decrypt() exactly restores the original plaintext.
#
# Run with:  python test_roundtrip.py
# =============================================================================

import os
import sys
import tempfile

# Project modules
import profiler
import selector
import crypto_engine
import container as enc_container
from selector import ALGO_AES_GCM, ALGO_CHACHA20, ALGO_XOR, ALGO_ROT


# ── ANSI helpers ──────────────────────────────────────────────────────────────
def _ok(msg):   print(f"  \033[92m✔\033[0m  {msg}")
def _fail(msg): print(f"  \033[91m✖\033[0m  {msg}"); sys.exit(1)
def _info(msg): print(f"  \033[94m→\033[0m  {msg}")
def _head(msg): print(f"\n\033[1m\033[96m{'─'*60}\n  {msg}\n{'─'*60}\033[0m")


# ── Test payloads ─────────────────────────────────────────────────────────────

TEST_PAYLOADS = {
    "Short ASCII text" : b"Hello, World! This is a test.",
    "CSV tabular data" : (
        b"name,age,city\nAlice,30,New York\nBob,25,London\n"
    ),
    "Binary blob"      : os.urandom(256),    # random bytes
    "Empty data"       : b"",               # edge case
    "Single byte"      : b"X",
    "Unicode (UTF-8)"  : "Héllo Wörld — 日本語テスト 🔐".encode("utf-8"),
    "Long text (8KB)"  : b"A" * 8192,
}


# ── Per-algorithm test helpers ────────────────────────────────────────────────

def _test_modern_cipher(algo_id: str, passphrase: str) -> None:
    """Test AES-256-GCM or ChaCha20-Poly1305 round-trip."""
    _head(f"{algo_id}  (passphrase='{passphrase}')")

    params = {"passphrase": passphrase}

    for label, plaintext in TEST_PAYLOADS.items():
        _info(f"Payload: {label}  ({len(plaintext)} bytes)")

        # Edge case: empty data is valid for AEAD ciphers (produces auth tag only)
        result     = crypto_engine.encrypt(plaintext, algo_id, params)
        ciphertext = result["ciphertext"]

        # Ciphertext should differ from plaintext (unless empty+empty)
        if plaintext and ciphertext == plaintext:
            _fail(f"Ciphertext equals plaintext for '{label}'!")

        # Round-trip via in-memory container
        decrypted = crypto_engine.decrypt(result, params)
        if decrypted != plaintext:
            _fail(f"Decrypted output does not match original for '{label}'!")
        _ok("In-memory round-trip passed.")

        # Round-trip via disk container (skip empty payload — empty file is trivial)
        if plaintext:
            with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as tmp:
                tmp_path = tmp.name

            try:
                enc_container.save_container(result, tmp_path)
                loaded    = enc_container.load_container(tmp_path)
                decrypted2 = crypto_engine.decrypt(loaded, params)
                if decrypted2 != plaintext:
                    _fail(f"Disk round-trip mismatch for '{label}'!")
                _ok("Disk round-trip passed.")
            finally:
                os.unlink(tmp_path)

    # Wrong passphrase must raise ValueError
    _info("Testing wrong-passphrase detection …")
    try:
        sample   = crypto_engine.encrypt(b"secret data", algo_id, params)
        bad_params = {"passphrase": passphrase + "_WRONG"}
        crypto_engine.decrypt(sample, bad_params)
        _fail("Wrong passphrase was NOT detected — authentication failure!")
    except ValueError:
        _ok("Wrong passphrase correctly rejected (authentication tag mismatch).")


def _test_xor() -> None:
    """Test Multi-byte XOR round-trip across several key bytes."""
    _head("Multi-byte XOR")

    for key_byte in (0, 1, 127, 255):
        params = {"xor_key_byte": key_byte}
        _info(f"Key byte = {key_byte}")

        for label, plaintext in TEST_PAYLOADS.items():
            result    = crypto_engine.encrypt(plaintext, ALGO_XOR, params)
            decrypted = crypto_engine.decrypt(result, params)
            if decrypted != plaintext:
                _fail(f"XOR round-trip failed for '{label}' (key={key_byte})!")
        _ok(f"All payloads passed for key byte {key_byte}.")

    # key_byte=0 is a special case: ciphertext == plaintext (XOR with 0 is identity)
    _info("Verifying XOR key=0 identity property …")
    sample = b"test"
    r = crypto_engine.encrypt(sample, ALGO_XOR, {"xor_key_byte": 0})
    assert r["ciphertext"] == sample, "XOR key=0 should be identity!"
    _ok("XOR key=0 identity property confirmed.")


def _test_rot() -> None:
    """Test ROT Cipher round-trip across several shifts."""
    _head("ROT Cipher")

    for shift in (1, 13, 25):
        params = {"shift": shift}
        _info(f"Shift = {shift}")

        for label, plaintext in TEST_PAYLOADS.items():
            result    = crypto_engine.encrypt(plaintext, ALGO_ROT, params)
            decrypted = crypto_engine.decrypt(result, params)
            if decrypted != plaintext:
                _fail(f"ROT round-trip failed for '{label}' (shift={shift})!")
        _ok(f"All payloads passed for shift {shift}.")

    # ROT-13 is self-inverse: encrypt(encrypt(x)) == x
    _info("Verifying ROT-13 self-inverse property …")
    sample = b"Hello World"
    r1 = crypto_engine.encrypt(sample, ALGO_ROT, {"shift": 13})
    r2 = crypto_engine.encrypt(r1["ciphertext"], ALGO_ROT, {"shift": 13})
    assert r2["ciphertext"] == sample, "ROT-13 should be self-inverse!"
    _ok("ROT-13 self-inverse property confirmed.")


def _test_profiler() -> None:
    """Test the profiler module on known inputs."""
    _head("Profiler Module")

    # Pure ASCII prose should yield structured_text or classical
    prose  = b"The quick brown fox jumps over the lazy dog. " * 20
    report = profiler.profile_data.__wrapped__(prose) if hasattr(profiler.profile_data, "__wrapped__") else None

    entropy  = profiler.shannon_entropy(prose)
    ratio    = profiler.printable_ratio(prose)
    _info(f"Prose entropy={entropy:.3f}, printable_ratio={ratio:.3f}")
    assert ratio > 0.95, "Prose should be >95% printable."
    _ok("Prose printable ratio check passed.")

    # Random bytes should yield high entropy
    rand_bytes = os.urandom(4096)
    rand_ent   = profiler.shannon_entropy(rand_bytes)
    _info(f"Random bytes entropy={rand_ent:.3f}")
    assert rand_ent > 7.0, f"Random bytes entropy should be >7.0, got {rand_ent}"
    _ok("Random bytes entropy check passed.")

    # Constant bytes (all zeros) should yield entropy=0
    zeros_ent = profiler.shannon_entropy(b"\x00" * 1000)
    _info(f"All-zeros entropy={zeros_ent}")
    assert zeros_ent == 0.0, f"All-zeros entropy should be 0.0, got {zeros_ent}"
    _ok("All-zeros entropy check passed.")

    # classify_profile routing
    assert profiler.classify_profile(3.0, 0.95, 100) == profiler.PROFILE_CLASSICAL
    assert profiler.classify_profile(4.5, 0.90, 100) == profiler.PROFILE_STRUCTURED_TEXT
    assert profiler.classify_profile(7.5, 0.10, 100) == profiler.PROFILE_HIGH_ENTROPY
    assert profiler.classify_profile(5.0, 0.50, 100) == profiler.PROFILE_BINARY_STREAM
    _ok("All profile classification rules passed.")


def _test_selector() -> None:
    """Test the selector module routing."""
    _head("Selector Module")

    mapping = {
        profiler.PROFILE_STRUCTURED_TEXT    : ALGO_AES_GCM,
        profiler.PROFILE_HIGH_ENTROPY       : ALGO_CHACHA20,
        profiler.PROFILE_BINARY_STREAM      : ALGO_CHACHA20,
        profiler.PROFILE_CLASSICAL          : ALGO_ROT,
    }
    for profile, expected_algo in mapping.items():
        rec = selector.recommend_algorithm(profile)
        if rec["id"] != expected_algo:
            _fail(
                f"Profile '{profile}' should map to '{expected_algo}', "
                f"got '{rec['id']}'."
            )
        _ok(f"Profile '{profile}' → '{rec['id']}'.")


# ── Main test runner ──────────────────────────────────────────────────────────

def main() -> None:
    print("\n\033[1m\033[96m" + "═" * 60)
    print("  APL Project — Round-Trip Verification Suite")
    print("═" * 60 + "\033[0m")

    _test_profiler()
    _test_selector()
    _test_modern_cipher(ALGO_AES_GCM, "SuperSecret!Pass123")
    _test_modern_cipher(ALGO_CHACHA20, "anotherP@55phr4se")
    _test_xor()
    _test_rot()

    print("\n" + "═" * 60)
    print(f"  \033[92m\033[1m✔  All tests passed!\033[0m")
    print("═" * 60 + "\n")


if __name__ == "__main__":
    main()
