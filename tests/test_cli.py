import io
import subprocess
import sys
from pathlib import Path

import pytest

from pwcheck import cli

ROOT = Path(__file__).resolve().parent.parent


class FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_reads_first_line_from_stdin() -> None:
    assert cli.read_password(True, io.StringIO("hunter2 \nignored\n")) == "hunter2 "


def test_piped_input_used_without_flag() -> None:
    assert cli.read_password(False, io.StringIO("abc\r\n")) == "abc"


def test_tty_uses_hidden_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "from-getpass")
    assert cli.read_password(False, FakeTTY()) == "from-getpass"


def test_main_prints_rating_without_echoing(monkeypatch: pytest.MonkeyPatch,
                                            capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("Dragon2024\n"))
    assert cli.main(["--stdin"]) == 0
    out = capsys.readouterr().out
    assert "Rating: VERY WEAK" in out
    assert "common passwords" in out
    assert "Dragon" not in out


def test_eof_on_prompt_exits_cleanly(monkeypatch: pytest.MonkeyPatch,
                                     capsys: pytest.CaptureFixture[str]) -> None:
    def raise_eof(prompt: str) -> str:
        raise EOFError
    monkeypatch.setattr(cli.getpass, "getpass", raise_eof)
    monkeypatch.setattr(sys, "stdin", FakeTTY())
    assert cli.main([]) == 1
    assert "No password entered" in capsys.readouterr().err


def test_password_argument_is_rejected() -> None:
    with pytest.raises(SystemExit):
        cli.parse_args(["hunter2"])


def test_end_to_end_subprocess() -> None:
    before = set(ROOT.rglob("*"))
    result = subprocess.run(
        [sys.executable, str(ROOT / "main.py")],
        input="Zq8#vLm2pT!rW6&yB\n", capture_output=True, text=True, cwd=ROOT, check=True,
    )
    assert "Rating: STRONG" in result.stdout
    assert "Zq8#" not in result.stdout + result.stderr
    # Ignore bytecode caches; nothing else should appear on disk.
    new_files = {p for p in set(ROOT.rglob("*")) - before if "__pycache__" not in p.parts}
    assert new_files == set()
