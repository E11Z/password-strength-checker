"""Brute-force entropy estimate from character pool size and length."""

import math
import string

LOWER = 26
UPPER = 26
DIGITS = 10
# string.punctuation plus the space character.
SYMBOLS = len(string.punctuation) + 1
# Non-ASCII characters have no natural pool size; 100 is a deliberately
# modest guess so emoji or accents help a little without dominating the score.
OTHER = 100


def pool_size(password: str) -> int:
    """Sum the sizes of every character class the password draws from."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += LOWER
    if any(c in string.ascii_uppercase for c in password):
        pool += UPPER
    if any(c in string.digits for c in password):
        pool += DIGITS
    if any(c in string.punctuation or c == " " for c in password):
        pool += SYMBOLS
    if any(not c.isascii() for c in password):
        pool += OTHER
    return pool


def bits_per_char(password: str) -> float:
    pool = pool_size(password)
    return math.log2(pool) if pool else 0.0


def entropy_bits(password: str) -> float:
    """Bits an attacker would need if every character were chosen at random.

    This is an upper bound: humans do not choose at random, which is why
    the pattern checks exist to pull this number down.
    """
    return len(password) * bits_per_char(password)
