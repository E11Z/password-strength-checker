"""Detect predictable patterns that make a password weaker than its length suggests.

Each finding carries `bits`: a rough guess of what that span is really worth
to an attacker who knows the pattern, so the scorer can replace the naive
per-character estimate for that span.
"""

import math
import re
from dataclasses import dataclass

from pwcheck.entropy import bits_per_char

MIN_RUN = 4

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "!@#$%^&*()")
SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "1234567890")

YEAR_AT_END = re.compile(r"(19\d\d|20\d\d)$")
SAME_CHAR = re.compile(r"(.)\1{2,}")
REPEATED_CHUNK = re.compile(r"(.{2,}?)\1+")


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int
    bits: float
    message: str

    @property
    def length(self) -> int:
        return self.end - self.start


def _with_reversed(strings: tuple[str, ...]) -> tuple[str, ...]:
    return strings + tuple(s[::-1] for s in strings)


def _find_runs(password: str, alphabets: tuple[str, ...]) -> list[tuple[int, int]]:
    """Maximal spans of at least MIN_RUN chars that appear contiguously in an alphabet."""
    lowered = password.lower()
    runs: list[tuple[int, int]] = []
    i = 0
    while i < len(lowered):
        j = i + 1
        while j < len(lowered) and any(lowered[i:j + 1] in a for a in alphabets):
            j += 1
        if j - i >= MIN_RUN:
            runs.append((i, j))
            i = j
        else:
            i += 1
    return runs


def _run_bits(alphabets: tuple[str, ...], length: int) -> float:
    # An attacker only has to guess where the run starts and how long it is.
    starts = sum(len(a) for a in alphabets)
    return math.log2(starts) + math.log2(length)


def find_keyboard_walks(password: str) -> list[Finding]:
    rows = _with_reversed(KEYBOARD_ROWS)
    return [
        Finding("keyboard", s, e, _run_bits(rows, e - s),
                f"keyboard walk of {e - s} keys in a row")
        for s, e in _find_runs(password, rows)
    ]


def find_sequences(password: str) -> list[Finding]:
    seqs = _with_reversed(SEQUENCES)
    return [
        Finding("sequence", s, e, _run_bits(seqs, e - s),
                f"alphabet or number sequence of {e - s} characters")
        for s, e in _find_runs(password, seqs)
    ]


def find_repeats(password: str) -> list[Finding]:
    per_char = bits_per_char(password)
    findings = [
        Finding("repeat", m.start(), m.end(), per_char + math.log2(m.end() - m.start()),
                f"the same character repeated {m.end() - m.start()} times")
        for m in SAME_CHAR.finditer(password)
    ]
    for m in REPEATED_CHUNK.finditer(password):
        chunk = m.group(1)
        # Single-character repeats are already reported above.
        if len(set(chunk)) == 1:
            continue
        copies = (m.end() - m.start()) // len(chunk)
        findings.append(Finding("repeat", m.start(), m.end(),
                                len(chunk) * per_char + math.log2(copies),
                                f"a {len(chunk)}-character chunk repeated {copies} times"))
    return findings


def find_year_suffix(password: str) -> list[Finding]:
    m = YEAR_AT_END.search(password)
    if not m:
        return []
    # 1900-2099 is only 200 options, and recent years are guessed first.
    return [Finding("year", m.start(), m.end(), math.log2(200), "ends with a year")]


def find_all(password: str) -> list[Finding]:
    return (find_keyboard_walks(password) + find_sequences(password)
            + find_repeats(password) + find_year_suffix(password))
