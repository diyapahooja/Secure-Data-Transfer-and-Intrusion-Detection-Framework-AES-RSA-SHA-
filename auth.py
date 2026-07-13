"""
auth.py
-------
User Authentication module.

Passwords are never stored in plaintext. We use bcrypt, which
automatically generates a random salt per password and is designed
to be slow (resistant to brute-force/rainbow-table attacks) — this is
a stronger choice than a single round of SHA-256 for password storage,
and is the same family of algorithm used for this purpose in
production systems.

This module is intentionally decoupled from the encryption modules:
authentication answers "is this really the claimed user?", which is a
different problem from confidentiality (AES) or integrity (SHA-256).
"""

import json
import os
import hashlib
import hmac
import secrets

try:
    import bcrypt
except ModuleNotFoundError:
    bcrypt = None

from config import USER_DB_PATH
from security_logger import log_event
import intrusion_detection as ids

_PBKDF2_ITERATIONS = 200_000


def _hash_password(password: str) -> dict:
    """
    Prefer bcrypt when it is installed. If a demo machine is missing
    bcrypt, use Python's built-in PBKDF2-HMAC-SHA256 so the project
    still runs instead of crashing at startup.
    """
    if bcrypt is not None:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        return {"algorithm": "bcrypt", "password_hash": hashed.decode("utf-8")}

    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), _PBKDF2_ITERATIONS
    ).hex()
    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": _PBKDF2_ITERATIONS,
        "salt": salt,
        "password_hash": digest,
    }


def _verify_password(password: str, record: dict) -> bool:
    algorithm = record.get("algorithm", "bcrypt")

    if algorithm == "bcrypt":
        if bcrypt is None:
            print("[!] bcrypt is not installed. Run: python -m pip install bcrypt")
            return False
        stored_hash = record["password_hash"].encode("utf-8")
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash)

    if algorithm == "pbkdf2_sha256":
        iterations = int(record.get("iterations", _PBKDF2_ITERATIONS))
        salt = record["salt"].encode("utf-8")
        expected = record["password_hash"]
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        ).hex()
        return hmac.compare_digest(digest, expected)

    return False


def _load_users() -> dict:
    if not os.path.isfile(USER_DB_PATH):
        return {}
    with open(USER_DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_users(users: dict):
    with open(USER_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def register_user(username: str, password: str) -> bool:
    """
    Register a new user. Returns True on success, False if the
    username already exists.
    """
    users = _load_users()
    if username in users:
        log_event("REGISTER", username, "Username already exists", status="FAILED")
        return False

    users[username] = _hash_password(password)
    _save_users(users)
    log_event("REGISTER", username, "New account created", status="OK")
    return True


def authenticate_user(username: str, password: str) -> bool:
    """
    Verify a username/password pair.

    Before checking the password at all, we check whether the IDS
    module has locked this account out due to a suspected brute-force
    pattern — a locked account is rejected immediately without even
    touching bcrypt, exactly like a real login system would behave.
    """
    if ids.is_locked_out(username):
        remaining = ids.seconds_until_unlock(username)
        log_event(
            "LOGIN",
            username,
            f"Rejected: account locked ({remaining}s remaining)",
            status="FAILED",
        )
        print(f"[!] Account '{username}' is locked. Try again in {remaining}s.")
        return False

    users = _load_users()
    record = users.get(username)

    if record is None:
        ids.record_failed_login(username)
        log_event("LOGIN", username, "No such user", status="FAILED")
        return False

    if _verify_password(password, record):
        ids.record_successful_login(username)
        log_event("LOGIN", username, "Successful login", status="OK")
        return True
    else:
        ids.record_failed_login(username)
        log_event("LOGIN", username, "Incorrect password", status="FAILED")
        return False


def user_exists(username: str) -> bool:
    return username in _load_users()
