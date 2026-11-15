# Password Strength Checker

An offline command line tool that scores how hard a password would be to guess, explains why, and suggests fixes. Weak passwords are still one of the most common ways accounts get broken into.

## How it works
1. **Read the password safely.** On a terminal it uses a hidden prompt (`getpass`), so nothing shows on screen. If you pipe input in, it reads the first line of stdin. It never takes the password as a command line argument, because arguments show up in `ps` and get saved in shell history.
2. **Estimate raw entropy.** It works out the pool of characters you used (lower case 26, upper case 26, digits 10, symbols 33, anything non-ASCII 100) and calculates `length × log2(pool)` bits. That is how many guesses a brute-force attack would need if every character were random.
3. **Check the common password list.** It compares the password against a small hand-written list in `pwcheck/data/common_passwords.txt`. It also checks the obvious variants an attacker would try: any capitalisation, leetspeak (`p@$$w0rd` → `password`), and trailing digits or symbols removed (`dragon2024!` → `dragon`). A match caps the score at about 7 bits, because a wordlist attack finds it almost straight away.
4. **Look for weak patterns.**
   - Keyboard walks of 4 or more keys along a row (`qwerty`, `asdf`, `poiuy`, `!@#$`)
   - Alphabet or number sequences (`abcd`, `1234`, `9876`)
   - Repeated characters (`aaa`) or repeated chunks (`abcabc`)
   - A year from 1900 to 2099 on the end (`summer1999`)
5. **Work out effective entropy.** Each pattern replaces the bits for its part of the password with a much smaller figure: what an attacker needs to guess once they know the pattern. For a keyboard walk, that is just where it starts and how long it is. For a year, it is one of about 200 values. If patterns overlap, the longest one wins, so no character is discounted twice.
6. **Give a rating and advice.** The effective bits are mapped to a rating, then short tips are added for each problem found.

| Effective bits | Rating    |
|----------------|-----------|
| under 28       | very weak |
| 28 to 35       | weak      |
| 36 to 59       | fair      |
| 60 to 79       | good      |
| 80 and up      | strong    |

### Design choices
- **Standard library only.** No dependencies at runtime, so it is easy to audit and there is no supply chain risk in a tool that handles secrets. pytest is only used for the tests.
- **The password never touches disk or logs.** There is no logging module, no history file and no network access. The output never repeats the password or any part of it; findings say "keyboard walk of 6 keys" instead of quoting the keys. A test runs the tool end to end and checks that it creates no new files.
- **The wordlist is hand-written.** It contains only well-known generic choices like `password` and `qwerty`, typed from general knowledge. No breach data is bundled.
- **Pattern discounts instead of fixed penalties.** Taking "10 points off for a year" is arbitrary. Swapping the span's bits for an estimate of how many guesses the pattern really needs keeps the whole score in one unit (bits), and that is easier to reason about.
- **Thresholds.** Below about 28 bits a password can fall to online guessing. Below about 60 bits it is at risk from an offline attack on a fast hash. 80 bits and up is out of reach for brute force.

## Install
    git clone <repo-url>
    cd password-strength-checker
    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt

## Usage
Hidden prompt (recommended):

    .venv/bin/python main.py

From stdin, for scripting or testing with example passwords:

    printf '%s\n' 'Summer2024!' | .venv/bin/python main.py
    printf '%s\n' 'aaaaaa111' | .venv/bin/python main.py --stdin

It also runs as a module:

    .venv/bin/python -m pwcheck --help

Don't pipe in a real password with `echo` in an interactive shell, because the command (password included) is saved in your shell history. Use the hidden prompt for real passwords.

## Example output
    $ printf '%s\n' 'aaaaaa111' | .venv/bin/python main.py
    Rating: VERY WEAK
    Estimated strength: 14.5 bits (naive estimate 46.5 bits before pattern checks)
    Issues:
      - the same character repeated 6 times
      - the same character repeated 3 times
    Advice:
      - Avoid repeating characters or chunks; repeats add almost no strength.
      - Use at least 12 characters; length adds more strength than symbols do.
      - Mix in upper case, digits or symbols, or use a longer passphrase of random words.

    $ printf '%s\n' 'Zq8#vLm2pT!rW6&yB' | .venv/bin/python main.py
    Rating: STRONG
    Estimated strength: 111.7 bits (naive estimate 111.7 bits before pattern checks)
    Advice:
      - Looks good. Keep it unique to one site and store it in a password manager.

## Tests
    .venv/bin/python -m pytest

The tests cover pool size and entropy maths, wordlist matching including leetspeak and suffix variants, each pattern detector, rating thresholds, advice, and the CLI. The CLI tests check the hidden prompt path, piped input, that the password is never echoed, and that no files are written.

## What I learned
- Raw entropy (`length × log2(pool)`) is only an upper bound. People don't choose randomly, so `Qwertyuiop2024` looks like 80+ bits but is really much less.
- Attackers don't just try a wordlist. They also try mangling rules (capitals, leetspeak, appended years), so a checker has to normalise input the same way.
- Handling secrets well is mostly about what you leave out: no argv input, no logging, no echoing parts of the password in error messages.
- A default argument like `stream=sys.stdin` is bound when the function is defined, so it ignores a later swap of `sys.stdin`. Resolving it at call time fixed the tests.

## Limitations
- There is no English dictionary, so words with leetspeak such as `Tr0ub4dor&3` score higher than they should unless they are in the small wordlist.
- Passphrases are scored by character counts, not by number of words, so `kettle-orbit-plume-saddle` is overestimated compared with a proper diceware estimate.
- Keyboard walks are only detected along rows of a US QWERTY layout, not down columns (`1qaz`) or on other layouts.
- The wordlist is deliberately tiny. Real tools such as zxcvbn use much larger frequency-ranked lists.
- The score is an estimate for teaching, not a guarantee.

## Disclaimer
For educational use on systems you own or have permission to test.
