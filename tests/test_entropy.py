import math

import pytest

from pwcheck.entropy import entropy_bits, pool_size


@pytest.mark.parametrize(
    "password, expected",
    [
        ("", 0),
        ("abc", 26),
        ("ABC", 26),
        ("123", 10),
        ("!!", 33),
        ("a b", 26 + 33),
        ("aB3!", 26 + 26 + 10 + 33),
        ("café", 26 + 100),
    ],
)
def test_pool_size(password: str, expected: int) -> None:
    assert pool_size(password) == expected


def test_entropy_empty_is_zero() -> None:
    assert entropy_bits("") == 0


def test_entropy_lowercase() -> None:
    assert entropy_bits("abcdefgh") == pytest.approx(8 * math.log2(26))


def test_longer_is_stronger() -> None:
    assert entropy_bits("aaaaaaaaaaaa") > entropy_bits("aaaaaaaa")


def test_more_classes_is_stronger() -> None:
    assert entropy_bits("aB3!aB3!") > entropy_bits("abcdabcd")
