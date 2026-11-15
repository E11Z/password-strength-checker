"""Check a password against the bundled list of common passwords."""

from functools import lru_cache
from importlib import resources

# Attackers try these substitutions automatically, so "p@$$w0rd" should
# be caught the same as "password".
LEET_MAP = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
                          "0": "o", "$": "s", "5": "s", "7": "t"})


@lru_cache(maxsize=1)
def load_wordlist() -> frozenset[str]:
    # Read-only access to package data; the password itself is never written anywhere.
    text = resources.files("pwcheck").joinpath("data/common_passwords.txt").read_text("utf-8")
    words = (line.strip().lower() for line in text.splitlines())
    return frozenset(w for w in words if w and not w.startswith("#"))


def _candidates(password: str) -> set[str]:
    """Variants an attacker's wordlist rules would also cover."""
    lowered = password.lower()
    # Strip trailing digits/symbols too, since "dragon2024!" is just "dragon" plus a suffix.
    stripped = lowered.rstrip("0123456789!@#$%^&*?.")
    variants = {lowered, stripped, lowered.translate(LEET_MAP), stripped.translate(LEET_MAP)}
    return {v for v in variants if v}


def is_common(password: str, wordlist: frozenset[str] | None = None) -> bool:
    words = load_wordlist() if wordlist is None else wordlist
    return any(c in words for c in _candidates(password))
