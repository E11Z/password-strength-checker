"""Command line entry point.

The password is deliberately never accepted as an argument: argv is visible
to other users via `ps` and is saved in shell history.
"""

import argparse
import getpass
import sys
from typing import TextIO

from pwcheck.score import Report, analyse


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pwcheck",
        description="Score password strength offline. Reads from a hidden prompt, "
                    "or from stdin when input is piped.",
    )
    parser.add_argument("--stdin", action="store_true",
                        help="read the password from the first line of stdin instead of prompting")
    return parser.parse_args(argv)


def read_password(use_stdin: bool, stream: TextIO | None = None) -> str:
    # Looked up at call time so a replaced sys.stdin is honoured.
    stream = stream or sys.stdin
    if use_stdin or not stream.isatty():
        # Only the first line counts; strip the newline but keep meaningful spaces.
        return stream.readline().rstrip("\r\n")
    return getpass.getpass("Password (input hidden): ")


def format_report(report: Report) -> str:
    # The password itself is never part of the output.
    lines = [
        f"Rating: {report.rating.upper()}",
        f"Estimated strength: {report.effective_bits:.1f} bits "
        f"(naive estimate {report.raw_bits:.1f} bits before pattern checks)",
    ]
    issues = (["found in the list of common passwords"] if report.common else [])
    issues += [f.message for f in report.findings]
    if issues:
        lines.append("Issues:")
        lines += [f"  - {issue}" for issue in issues]
    lines.append("Advice:")
    lines += [f"  - {tip}" for tip in report.advice]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        password = read_password(args.stdin)
    except (EOFError, KeyboardInterrupt):
        print("\nNo password entered.", file=sys.stderr)
        return 1
    print(format_report(analyse(password)))
    return 0
