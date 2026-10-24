# =============================================================================
# display.py  —  Rich CLI Display Helpers
# =============================================================================
# Provides all terminal formatting, banner printing, table rendering, and
# progress messaging used by main.py.  Keeping display logic separate from
# business logic keeps the codebase clean and testable.
# =============================================================================

import os
import textwrap

# ── ANSI colour / style codes ────────────────────────────────────────────────
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_BLUE   = "\033[94m"
_CYAN   = "\033[96m"
_WHITE  = "\033[97m"
_BG_DARK= "\033[40m"


def _c(code: str, text: str) -> str:
    """Wrap *text* in the given ANSI code + reset."""
    return f"{code}{text}{_RESET}"


# Convenience wrappers
def bold(t: str)   -> str: return _c(_BOLD, t)
def red(t: str)    -> str: return _c(_RED, t)
def green(t: str)  -> str: return _c(_GREEN, t)
def yellow(t: str) -> str: return _c(_YELLOW, t)
def blue(t: str)   -> str: return _c(_BLUE, t)
def cyan(t: str)   -> str: return _c(_CYAN, t)
def dim(t: str)    -> str: return _c(_DIM, t)


# ── Terminal width ────────────────────────────────────────────────────────────

def _width() -> int:
    """Return terminal width (or 80 as a safe default)."""
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def _hr(char: str = "─", colour: str = _BLUE) -> str:
    """Horizontal rule spanning the terminal width."""
    return _c(colour, char * _width())


# ── Banners ───────────────────────────────────────────────────────────────────

BANNER = r"""
  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗
 ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗
 ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║
 ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║
 ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝
  ╚══-══╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝

  By: Tanishk Yadav, Arush Tyagi, Daksh
"""

def print_banner() -> None:
    """Print the application banner."""
    print(_c(_CYAN + _BOLD, BANNER))
    title = "  APL Project — Smart Encryption Advisor & Engine"
    print(bold(title))
    print(dim("  Analyse · Profile · Recommend · Encrypt · Decrypt"))
    print()
    print(_hr())


def print_section(title: str) -> None:
    """Print a labelled section divider."""
    print()
    print(_hr("─", _BLUE))
    print(bold(cyan(f"  ◆  {title}")))
    print(_hr("─", _BLUE))


def print_success(msg: str) -> None:
    print(f"\n  {green('✔')}  {msg}")


def print_warning(msg: str) -> None:
    print(f"\n  {yellow('⚠')}  {yellow(msg)}")


def print_error(msg: str) -> None:
    print(f"\n  {red('✖')}  {red(msg)}")


def print_info(label: str, value: str) -> None:
    """Print a single key-value info line."""
    print(f"  {cyan(label + ':')}  {value}")


# ── Profile report ────────────────────────────────────────────────────────────

def _profile_label(profile: str) -> str:
    """Colour-code the profile name for display."""
    colours = {
        "structured_text"    : _GREEN,
        "high_entropy_binary": _RED,
        "classical_cipher_text": _YELLOW,
        "binary_stream"      : _BLUE,
    }
    colour = colours.get(profile, _WHITE)
    return _c(colour + _BOLD, profile.replace("_", " ").title())


def print_profile_report(report: dict) -> None:
    """
    Render the data-profiling results in a clean, readable table.

    Parameters
    ----------
    report : dict – Output of profiler.profile_data().
    """
    print_section("Dataset Analysis Report")

    source = report["source"]
    # Truncate long paths/strings for display
    if len(source) > 60:
        source = "…" + source[-57:]

    print_info("Source"          , source)
    print_info("Size"            , f"{report['size_bytes']:,} bytes")
    print_info("Shannon Entropy" , f"{report['entropy']:.4f} bits/byte  (max 8.0)")
    print_info("Printable Ratio" , f"{report['printable_ratio']:.1%}")
    print_info("Data Profile"   , _profile_label(report["profile"]))

    # Entropy bar (visual aid)
    bar_len    = 40
    filled     = round((report["entropy"] / 8.0) * bar_len)
    bar_colour = _GREEN if report["entropy"] < 5 else (_YELLOW if report["entropy"] < 7 else _RED)
    bar        = _c(bar_colour, "█" * filled) + dim("░" * (bar_len - filled))
    print(f"\n  {cyan('Entropy:')}  [{bar}]  {report['entropy']:.2f}/8.00")


# ── Algorithm recommendation display ─────────────────────────────────────────

def print_recommendation(algo_meta: dict) -> None:
    """
    Display the recommended algorithm with its tier and description.

    Parameters
    ----------
    algo_meta : dict – Entry from selector.ALGORITHM_CATALOGUE.
    """
    print_section("Algorithm Recommendation")

    tier_colour = _GREEN if algo_meta["tier"] == "Production" else _YELLOW
    tier_str    = _c(tier_colour + _BOLD, f"[{algo_meta['tier']}]")

    print(f"\n  {bold(algo_meta['id'])}  {tier_str}")
    print()

    # Word-wrap the description
    desc_lines = textwrap.wrap(algo_meta["description"], width=_width() - 4)
    for line in desc_lines:
        print(f"  {dim(line)}")


# ── Algorithm selector menu ───────────────────────────────────────────────────

def print_algo_menu(algorithms: list[dict]) -> None:
    """
    Print a numbered menu of all available algorithms for manual override.

    Parameters
    ----------
    algorithms : list[dict] – List of algorithm metadata dicts.
    """
    print_section("Manual Algorithm Override")
    print()
    for i, algo in enumerate(algorithms, start=1):
        tier_colour = _GREEN if algo["tier"] == "Production" else _YELLOW
        tier_str    = _c(tier_colour, f"[{algo['tier']}]")
        print(f"  {cyan(str(i) + '.')}  {bold(algo['id'])}  {tier_str}")
    print()


# ── Main menu ─────────────────────────────────────────────────────────────────

def print_main_menu() -> None:
    """Print the top-level CLI menu."""
    print_section("Main Menu")
    print()
    print(f"  {cyan('1.')}  {bold('Encrypt')} a file or text string")
    print(f"  {cyan('2.')}  {bold('Decrypt')} an encrypted .enc file")
    print(f"  {cyan('3.')}  {bold('Analyse only')} — profile a file without encrypting")
    print(f"  {cyan('Q.')}  {bold('Quit')}")
    print()


# ── Encryption summary ────────────────────────────────────────────────────────

def print_encryption_summary(output_path: str, algo_id: str, size_in: int, size_out: int) -> None:
    """
    Display a post-encryption summary box.

    Parameters
    ----------
    output_path : str – Path of the written .enc file.
    algo_id     : str – Algorithm that was used.
    size_in     : int – Original data size in bytes.
    size_out    : int – Encrypted file size in bytes.
    """
    print_section("Encryption Complete")
    print_success(f"File saved to:  {bold(output_path)}")
    print_info("Algorithm"     , bold(algo_id))
    print_info("Original size" , f"{size_in:,} bytes")
    print_info("Encrypted size", f"{size_out:,} bytes  "
                                  f"(+{size_out - size_in:,} bytes overhead for metadata & tag)")


def print_decryption_summary(output_path: str, algo_id: str, size_bytes: int) -> None:
    """
    Display a post-decryption summary box.

    Parameters
    ----------
    output_path : str – Path of the restored plaintext file.
    algo_id     : str – Algorithm that was used.
    size_bytes  : int – Restored plaintext size in bytes.
    """
    print_section("Decryption Complete")
    print_success(f"Plaintext saved to:  {bold(output_path)}")
    print_info("Algorithm used" , bold(algo_id))
    print_info("Restored size"  , f"{size_bytes:,} bytes")
