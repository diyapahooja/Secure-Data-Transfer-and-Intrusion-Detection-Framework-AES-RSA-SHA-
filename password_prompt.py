"""
password_prompt.py
------------------
Console helper that masks password input with asterisks.

Python's built-in getpass hides input completely. This helper shows one
"*" per typed character in Windows terminals, which matches the project
requirement. If masked typing is not supported, it falls back safely.
"""

import getpass
import os
import sys


def masked_password(prompt: str = "Password: ") -> str:
    """Read a password from the console and echo one asterisk per key."""
    if not sys.stdin.isatty():
        return input(prompt)

    if os.name == "nt":
        import msvcrt

        password_chars = []
        print(prompt, end="", flush=True)

        while True:
            ch = msvcrt.getwch()

            if ch in ("\r", "\n"):
                print()
                return "".join(password_chars)

            if ch == "\x03":
                raise KeyboardInterrupt

            if ch == "\b":
                if password_chars:
                    password_chars.pop()
                    print("\b \b", end="", flush=True)
                continue

            if ch in ("\x00", "\xe0"):
                msvcrt.getwch()
                continue

            password_chars.append(ch)
            print("*", end="", flush=True)

    return getpass.getpass(prompt)
