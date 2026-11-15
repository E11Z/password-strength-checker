import pytest

from pwcheck.score import analyse, rate


@pytest.mark.parametrize(
    "bits, label",
    [(0, "very weak"), (27.9, "very weak"), (28, "weak"), (40, "fair"),
     (60, "good"), (79.9, "good"), (80, "strong"), (200, "strong")],
)
def test_rate_thresholds(bits: float, label: str) -> None:
    assert rate(bits) == label


@pytest.mark.parametrize("password", ["", "password", "P@ssw0rd", "123456", "qwerty", "aaaaaaaa"])
def test_very_weak(password: str) -> None:
    assert analyse(password).rating == "very weak"


def test_common_password_flagged_and_advised() -> None:
    report = analyse("letmein")
    assert report.common
    assert any("common passwords" in tip for tip in report.advice)


def test_patterns_reduce_effective_bits() -> None:
    report = analyse("Qwertyuiop2024")
    assert report.effective_bits < report.raw_bits
    assert {f.kind for f in report.findings} >= {"keyboard", "year"}


def test_year_lowers_rating() -> None:
    assert analyse("Tg7#kPq2xW1999").effective_bits < analyse("Tg7#kPq2xWzRb!").effective_bits


def test_findings_do_not_overlap() -> None:
    findings = analyse("1234567890").findings
    covered = [i for f in findings for i in range(f.start, f.end)]
    assert len(covered) == len(set(covered))


@pytest.mark.parametrize("password", ["Zq8#vLm2pT!rW6&yB", "kettle-orbit-plume-saddle-junk"])
def test_strong(password: str) -> None:
    report = analyse(password)
    assert report.rating == "strong"
    assert report.findings == []


def test_short_password_gets_length_advice() -> None:
    assert any("12 characters" in tip for tip in analyse("Zq8#vL").advice)


def test_strong_password_gets_positive_advice() -> None:
    assert analyse("Zq8#vLm2pT!rW6&yB").advice == [
        "Looks good. Keep it unique to one site and store it in a password manager."
    ]
