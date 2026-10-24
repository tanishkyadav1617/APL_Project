#!/usr/bin/env python3
# =============================================================================
# main.py  —  CLI Entry Point & Menu Orchestrator
# =============================================================================
# Wires together all modules:
#
#   profiler       →  Analyse the input data
#   selector       →  Recommend an encryption algorithm
#   param_collector→  Collect algorithm-specific parameters from the user
#   crypto_engine  →  Perform encryption / decryption
#   container      →  Serialise / deserialise the encrypted output file
#   display        →  Render the CLI UI
#
# Usage:
#   python main.py
#   python main.py --encrypt <file>
#   python main.py --decrypt <file.enc>
#   python main.py --analyse <file>
# =============================================================================

import sys
import os
import argparse
from pathlib import Path

# Project modules
import profiler
import selector
import crypto_engine
import container as enc_container
import param_collector
import display


# ── Utility ───────────────────────────────────────────────────────────────────

def _ask(prompt: str, default: str = "") -> str:
    """
    Read a line of input from the user, stripping surrounding whitespace.

    Parameters
    ----------
    prompt  : str – Text displayed before the cursor.
    default : str – Returned if the user presses Enter with no input.

    Returns
    -------
    str – User's response (or *default* if empty).
    """
    try:
        response = input(display.cyan(prompt)).strip()
        return response if response else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def _confirm(prompt: str) -> bool:
    """Ask a yes/no question; return True for 'y' / 'Y'."""
    answer = _ask(f"{prompt} [y/N]: ", "n")
    return answer.lower() == "y"


def _safe_output_path(base: str, suffix: str) -> str:
    """
    Build an output file path that does not overwrite an existing file by
    appending a numeric counter if needed.

    Parameters
    ----------
    base   : str – Base name without extension (e.g. "output").
    suffix : str – Extension including the dot (e.g. ".enc" or ".dec.txt").

    Returns
    -------
    str – A file path that does not currently exist.
    """
    candidate = base + suffix
    counter   = 1
    while Path(candidate).exists():
        candidate = f"{base}_{counter}{suffix}"
        counter  += 1
    return candidate


# ── Workflow: Analyse Only ────────────────────────────────────────────────────

def workflow_analyse(source: str) -> None:
    """
    Profile *source* and print the analysis report.  No encryption.

    Parameters
    ----------
    source : str – File path or raw text string.
    """
    print()
    display.print_info("Analysing", source)

    try:
        report = profiler.profile_data(source)
    except Exception as exc:
        display.print_error(f"Could not read source: {exc}")
        return

    display.print_profile_report(report)
    recommendation = selector.recommend_algorithm(report["profile"])
    display.print_recommendation(recommendation)


# ── Workflow: Encrypt ─────────────────────────────────────────────────────────

def workflow_encrypt(source: str | None = None) -> None:
    """
    Full encryption workflow:
      1. Load & profile source data.
      2. Display analysis + recommended algorithm.
      3. Allow user to accept or override the recommendation.
      4. Collect algorithm parameters.
      5. Encrypt and save the .enc file.

    Parameters
    ----------
    source : str | None – File path or raw text string, or None to prompt.
    """
    # ── Step 1: get source ────────────────────────────────────────────────────
    if source is None:
        display.print_section("Input Source")
        print(f"  {display.dim('Enter a file path or paste a raw text string.')}")
        source = _ask("  Source: ")
        if not source:
            display.print_warning("No source provided.  Returning to menu.")
            return

    # ── Step 2: profile ───────────────────────────────────────────────────────
    print()
    display.print_info("Reading", source)
    try:
        report = profiler.profile_data(source)
    except Exception as exc:
        display.print_error(f"Failed to load source: {exc}")
        return

    display.print_profile_report(report)

    # ── Step 3: recommendation & optional override ────────────────────────────
    recommended = selector.recommend_algorithm(report["profile"])
    display.print_recommendation(recommended)

    chosen_algo = recommended  # default
    print()
    if _confirm("  Override the recommendation and choose a different algorithm?"):
        all_algos = selector.list_algorithms()
        display.print_algo_menu(all_algos)
        while True:
            raw = _ask(f"  Select algorithm [1–{len(all_algos)}]: ")
            try:
                idx = int(raw) - 1
                if 0 <= idx < len(all_algos):
                    chosen_algo = all_algos[idx]
                    break
            except ValueError:
                pass
            display.print_warning(f"Please enter a number between 1 and {len(all_algos)}.")

    # ── Step 4: collect parameters ────────────────────────────────────────────
    try:
        params = param_collector.collect_encrypt_params(chosen_algo["id"])
    except KeyboardInterrupt:
        print()
        display.print_warning("Parameter collection cancelled.")
        return

    # ── Step 5: encrypt ───────────────────────────────────────────────────────
    print()
    display.print_info("Encrypting with", display.bold(chosen_algo["id"]))

    try:
        enc_result = crypto_engine.encrypt(report["data"], chosen_algo["id"], params)
    except Exception as exc:
        display.print_error(f"Encryption failed: {exc}")
        return

    # ── Step 6: determine output path ─────────────────────────────────────────
    source_path = Path(source)
    if source_path.exists():
        # Strip all extensions for cleaner names (e.g. data.csv → data)
        base_name = source_path.stem
        out_dir   = source_path.parent
        out_base  = str(out_dir / base_name)
    else:
        out_base  = "encrypted_output"

    default_out = _safe_output_path(out_base, ".enc")
    print()
    custom_out  = _ask(
        f"  Output file path [{default_out}]: ",
        default_out,
    )
    out_path    = custom_out if custom_out else default_out

    # ── Step 7: save container ────────────────────────────────────────────────
    try:
        saved_path = enc_container.save_container(enc_result, out_path)
        out_size   = saved_path.stat().st_size
    except Exception as exc:
        display.print_error(f"Failed to save output: {exc}")
        return

    display.print_encryption_summary(
        str(saved_path),
        chosen_algo["id"],
        report["size_bytes"],
        out_size,
    )


# ── Workflow: Decrypt ─────────────────────────────────────────────────────────

def workflow_decrypt(enc_path: str | None = None) -> None:
    """
    Full decryption workflow:
      1. Load and parse the .enc container file.
      2. Display the container metadata.
      3. Collect decryption parameters.
      4. Decrypt and save the restored plaintext.

    Parameters
    ----------
    enc_path : str | None – Path to the .enc file, or None to prompt.
    """
    # ── Step 1: get file path ─────────────────────────────────────────────────
    if enc_path is None:
        display.print_section("Decrypt Encrypted File")
        enc_path = _ask("  Path to .enc file: ")
        if not enc_path:
            display.print_warning("No path provided.  Returning to menu.")
            return

    # ── Step 2: load container ────────────────────────────────────────────────
    try:
        c = enc_container.load_container(enc_path)
    except FileNotFoundError as exc:
        display.print_error(str(exc))
        return
    except ValueError as exc:
        display.print_error(f"Invalid container: {exc}")
        return

    algo_id = c["algorithm"]
    display.print_section("Container Metadata")
    display.print_info("File"     , enc_path)
    display.print_info("Algorithm", display.bold(algo_id))

    # Show extra metadata where available (salts / nonces in hex, truncated)
    if "salt" in c:
        display.print_info("Salt (hex)", c["salt"].hex()[:32] + "…")
    if "nonce" in c:
        display.print_info("Nonce (hex)", c["nonce"].hex())
    if "key_byte" in c:
        display.print_info("XOR key byte", str(c["key_byte"]))
    if "shift" in c:
        display.print_info("ROT shift", str(c["shift"]))

    # ── Step 3: collect decryption parameters ─────────────────────────────────
    try:
        params = param_collector.collect_decrypt_params(algo_id)
    except KeyboardInterrupt:
        print()
        display.print_warning("Decryption cancelled.")
        return

    # ── Step 4: decrypt ───────────────────────────────────────────────────────
    print()
    display.print_info("Decrypting with", display.bold(algo_id))

    try:
        plaintext = crypto_engine.decrypt(c, params)
    except ValueError as exc:
        display.print_error(str(exc))
        return
    except Exception as exc:
        display.print_error(f"Unexpected decryption error: {exc}")
        return

    # ── Step 5: save restored file ────────────────────────────────────────────
    enc_p       = Path(enc_path)
    base_name   = enc_p.stem            # e.g.  "data"  from  "data.enc"
    out_dir     = enc_p.parent
    out_base    = str(out_dir / f"{base_name}_decrypted")
    default_out = _safe_output_path(out_base, ".txt")

    print()
    custom_out  = _ask(
        f"  Output file path [{default_out}]: ",
        default_out,
    )
    out_path    = custom_out if custom_out else default_out

    try:
        with open(out_path, "wb") as fh:
            fh.write(plaintext)
    except Exception as exc:
        display.print_error(f"Could not write output: {exc}")
        return

    display.print_decryption_summary(out_path, algo_id, len(plaintext))

    # ── Step 6: optional preview ──────────────────────────────────────────────
    print()
    if _confirm("  Preview the first 500 characters of the restored content?"):
        print()
        try:
            preview = plaintext[:500].decode("utf-8", errors="replace")
        except Exception:
            preview = repr(plaintext[:500])
        display.print_section("Content Preview")
        print(display.dim("  " + preview.replace("\n", "\n  ")))


# ── Interactive main menu ─────────────────────────────────────────────────────

def interactive_menu() -> None:
    """
    Present the top-level interactive menu in a loop until the user quits.
    """
    display.print_banner()

    while True:
        display.print_main_menu()
        choice = _ask("  Select an option: ").upper()

        if choice == "1":
            workflow_encrypt()
        elif choice == "2":
            workflow_decrypt()
        elif choice == "3":
            display.print_section("Analyse Only")
            source = _ask("  File path or text string: ")
            if source:
                workflow_analyse(source)
            else:
                display.print_warning("No source provided.")
        elif choice in ("Q", "QUIT", "EXIT"):
            print()
            display.print_success("Goodbye!")
            print()
            sys.exit(0)
        else:
            display.print_warning(f"Unrecognised option '{choice}'.  Please try again.")


# ── CLI argument parsing ──────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """
    Build and return the argument parser for non-interactive invocation.

    Examples
    --------
    python main.py                          # interactive menu
    python main.py --encrypt data.csv       # encrypt a file directly
    python main.py --decrypt data.enc       # decrypt a .enc file
    python main.py --analyse data.csv       # profile only
    """
    p = argparse.ArgumentParser(
        prog        = "main.py",
        description = "APL Project — Smart Encryption Advisor & Engine",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog      = (
            "Run without arguments for the interactive menu.\n\n"
            "Examples:\n"
            "  python main.py --encrypt mydata.csv\n"
            "  python main.py --decrypt mydata.enc\n"
            "  python main.py --analyse mydata.csv\n"
        ),
    )
    group = p.add_mutually_exclusive_group()
    group.add_argument(
        "--encrypt", "-e",
        metavar = "SOURCE",
        help    = "File path or text string to encrypt.",
    )
    group.add_argument(
        "--decrypt", "-d",
        metavar = "ENC_FILE",
        help    = "Path to a .enc file to decrypt.",
    )
    group.add_argument(
        "--analyse", "-a",
        metavar = "SOURCE",
        help    = "File path or text string to analyse (no encryption).",
    )
    return p


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    """Parse CLI arguments and dispatch to the appropriate workflow."""
    parser = build_parser()
    args   = parser.parse_args()

    display.print_banner()

    if args.encrypt:
        workflow_encrypt(args.encrypt)
    elif args.decrypt:
        workflow_decrypt(args.decrypt)
    elif args.analyse:
        workflow_analyse(args.analyse)
    else:
        # No flags supplied — drop into the interactive menu
        # (re-use the banner already printed above)
        while True:
            display.print_main_menu()
            choice = _ask("  Select an option: ").upper()

            if choice == "1":
                workflow_encrypt()
            elif choice == "2":
                workflow_decrypt()
            elif choice == "3":
                display.print_section("Analyse Only")
                source = _ask("  File path or text string: ")
                if source:
                    workflow_analyse(source)
                else:
                    display.print_warning("No source provided.")
            elif choice in ("Q", "QUIT", "EXIT"):
                print()
                display.print_success("Goodbye!")
                print()
                sys.exit(0)
            else:
                display.print_warning(f"Unrecognised option '{choice}'.  Please try again.")


if __name__ == "__main__":
    main()
