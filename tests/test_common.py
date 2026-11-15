import pytest

from pwcheck.common import is_common, load_wordlist


def test_wordlist_loads_and_skips_comments() -> None:
    words = load_wordlist()
    assert "password" in words
    assert len(words) >= 50
    assert not any(w.startswith("#") for w in words)


def test_wordlist_is_lowercase() -> None:
    assert all(w == w.lower() for w in load_wordlist())


@pytest.mark.parametrize(
    "password",
    ["password", "PASSWORD", "Password", "p@$$w0rd", "dragon2024", "monkey!", "Qwerty123"],
)
def test_common_variants_are_flagged(password: str) -> None:
    assert is_common(password)


@pytest.mark.parametrize("password", ["correct-horse-battery", "Zq8#vLm2pT", "!!!!", ""])
def test_uncommon_passwords_pass(password: str) -> None:
    assert not is_common(password)


def test_custom_wordlist() -> None:
    assert is_common("Kestrel", frozenset({"kestrel"}))
