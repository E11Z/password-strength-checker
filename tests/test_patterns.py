import pytest

from pwcheck.patterns import (
    find_all,
    find_keyboard_walks,
    find_repeats,
    find_sequences,
    find_year_suffix,
)


def kinds(password: str) -> set[str]:
    return {f.kind for f in find_all(password)}


@pytest.mark.parametrize("password", ["qwerty", "xxASDFxx", "poiuy", "mnbvc", "!@#$%"])
def test_keyboard_walks_found(password: str) -> None:
    assert find_keyboard_walks(password)


def test_keyboard_walk_span() -> None:
    [walk] = find_keyboard_walks("zzQWERTYzz")
    assert (walk.start, walk.end) == (2, 8)


def test_short_walk_ignored() -> None:
    assert not find_keyboard_walks("qwe")


@pytest.mark.parametrize("password", ["abcd", "1234", "9876", "zyxw", "x7890x"])
def test_sequences_found(password: str) -> None:
    assert find_sequences(password)


def test_same_char_repeat() -> None:
    [rep] = find_repeats("hiaaaaa")
    assert (rep.start, rep.end) == (2, 7)


def test_chunk_repeat() -> None:
    reps = find_repeats("abcabcabc")
    assert any(r.length == 9 for r in reps)


def test_two_of_same_is_not_flagged() -> None:
    assert not find_repeats("book")


@pytest.mark.parametrize("password", ["summer1999", "Pa55-2024", "x2099"])
def test_year_suffix_found(password: str) -> None:
    assert find_year_suffix(password)


@pytest.mark.parametrize("password", ["2024start", "summer1899", "abc21000"])
def test_year_suffix_not_found(password: str) -> None:
    assert not find_year_suffix(password)


def test_random_looking_password_is_clean() -> None:
    assert kinds("Zq8#vLm2pT") == set()


def test_pattern_bits_are_cheaper_than_random() -> None:
    # A 10-key walk should be worth far less than 10 random lowercase letters (~47 bits).
    [walk] = find_keyboard_walks("qwertyuiop")
    assert walk.bits < 15


def test_messages_do_not_echo_password() -> None:
    secret = "qwertyaaaa2024"
    for finding in find_all(secret):
        assert "qwerty" not in finding.message
        assert "2024" not in finding.message
