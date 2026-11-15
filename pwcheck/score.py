"""Combine entropy, wordlist and pattern checks into a rating and advice."""

import math
from dataclasses import dataclass, field

from pwcheck.common import is_common, load_wordlist
from pwcheck.entropy import bits_per_char, entropy_bits, pool_size
from pwcheck.patterns import Finding, find_all

# Upper bounds (exclusive) in effective bits. Roughly: under 28 falls to an
# online guessing attack, under 60 to an offline attack on a fast hash.
RATINGS = (
    (28, "very weak"),
    (36, "weak"),
    (60, "fair"),
    (80, "good"),
    (math.inf, "strong"),
)

MIN_GOOD_LENGTH = 12

ADVICE = {
    "common": "This is on a list of common passwords; attackers try these first. Pick something unique.",
    "keyboard": "Avoid keyboard walks like 'qwerty' or 'asdf'; they are among the first guesses.",
    "sequence": "Avoid runs like 'abcd' or '1234'.",
    "repeat": "Avoid repeating characters or chunks; repeats add almost no strength.",
    "year": "Drop the year on the end; years are one of the first things attackers append.",
}


@dataclass
class Report:
    rating: str
    raw_bits: float
    effective_bits: float
    common: bool
    findings: list[Finding] = field(default_factory=list)
    advice: list[str] = field(default_factory=list)


def rate(bits: float) -> str:
    for limit, label in RATINGS:
        if bits < limit:
            return label
    return RATINGS[-1][1]


def _non_overlapping(findings: list[Finding]) -> list[Finding]:
    """Keep the longest findings first so one span is never discounted twice."""
    chosen: list[Finding] = []
    taken: set[int] = set()
    for f in sorted(findings, key=lambda f: (-f.length, f.start)):
        span = set(range(f.start, f.end))
        if not span & taken:
            chosen.append(f)
            taken |= span
    return sorted(chosen, key=lambda f: f.start)


def effective_bits(password: str, findings: list[Finding], common: bool) -> float:
    raw = entropy_bits(password)
    if common:
        # A wordlist hit is only as strong as the attacker's position in the list.
        return min(raw, math.log2(len(load_wordlist())))
    covered = sum(f.length for f in findings)
    bits = (len(password) - covered) * bits_per_char(password) + sum(f.bits for f in findings)
    return min(raw, bits)


def build_advice(password: str, findings: list[Finding], common: bool, rating: str) -> list[str]:
    tips: list[str] = []
    kinds = ["common"] if common else []
    kinds += [f.kind for f in findings]
    for kind in dict.fromkeys(kinds):
        tips.append(ADVICE[kind])
    if len(password) < MIN_GOOD_LENGTH:
        tips.append(f"Use at least {MIN_GOOD_LENGTH} characters; length adds more strength than symbols do.")
    if pool_size(password) < 62 and rating not in ("good", "strong"):
        tips.append("Mix in upper case, digits or symbols, or use a longer passphrase of random words.")
    if not tips:
        tips.append("Looks good. Keep it unique to one site and store it in a password manager.")
    return tips


def analyse(password: str) -> Report:
    common = is_common(password)
    findings = _non_overlapping(find_all(password))
    bits = effective_bits(password, findings, common)
    rating = rate(bits)
    return Report(
        rating=rating,
        raw_bits=entropy_bits(password),
        effective_bits=bits,
        common=common,
        findings=findings,
        advice=build_advice(password, findings, common, rating),
    )
