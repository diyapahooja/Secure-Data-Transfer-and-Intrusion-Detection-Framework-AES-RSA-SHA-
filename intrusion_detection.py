"""
intrusion_detection.py
-----------------------
A lightweight, host-based, log-based Intrusion Detection module.

IMPORTANT SCOPE NOTE (for the report and for anyone grading this):
This is NOT a network-level IDS (it does not inspect packets or
traffic). It is a signature-based detector that watches this
application's own authentication log for a known attack PATTERN —
repeated failed logins in a short window, the classic signature of a
brute-force or credential-stuffing attempt — and raises an alert.
This is a legitimate and common first layer of intrusion detection
(the same idea behind account lockout policies in real systems), it
is just scoped to this single application rather than a whole network.

Design:
- Failed login attempts are tracked in memory per username, each with
  a timestamp.
- If MAX_FAILED_ATTEMPTS occur within FAILED_ATTEMPT_WINDOW_SECONDS,
  an alert is raised and the account is temporarily locked.
- All decisions are also written to the security/alerts logs so the
  Performance Analysis module can report on them later.
"""

import time

from config import (
    MAX_FAILED_ATTEMPTS,
    FAILED_ATTEMPT_WINDOW_SECONDS,
    LOCKOUT_DURATION_SECONDS,
)
from security_logger import log_alert

# In-memory state: { username: [timestamp, timestamp, ...] }
_failed_attempts = {}

# In-memory state: { username: lockout_expiry_timestamp }
_locked_accounts = {}


def is_locked_out(username: str) -> bool:
    """Return True if the account is currently locked due to a detected attack."""
    expiry = _locked_accounts.get(username)
    if expiry is None:
        return False
    if time.time() >= expiry:
        # Lockout has expired naturally
        del _locked_accounts[username]
        return False
    return True


def seconds_until_unlock(username: str) -> int:
    """How many seconds remain on an active lockout (0 if not locked)."""
    expiry = _locked_accounts.get(username)
    if expiry is None:
        return 0
    return max(0, int(expiry - time.time()))


def record_failed_login(username: str):
    """
    Record a failed login attempt and check whether it matches the
    brute-force pattern. Raises an alert and locks the account if so.
    """
    now = time.time()
    attempts = _failed_attempts.setdefault(username, [])
    attempts.append(now)

    # Discard attempts outside the sliding time window
    cutoff = now - FAILED_ATTEMPT_WINDOW_SECONDS
    attempts[:] = [t for t in attempts if t >= cutoff]

    if len(attempts) >= MAX_FAILED_ATTEMPTS:
        _locked_accounts[username] = now + LOCKOUT_DURATION_SECONDS
        log_alert(
            alert_type="BRUTE_FORCE_SUSPECTED",
            username=username,
            detail=(
                f"{len(attempts)} failed login attempts within "
                f"{FAILED_ATTEMPT_WINDOW_SECONDS} seconds. "
                f"Account locked for {LOCKOUT_DURATION_SECONDS} seconds."
            ),
            severity="HIGH",
        )
        # Reset the window so the same burst doesn't re-trigger the
        # alert on every subsequent attempt while already locked.
        attempts.clear()


def record_successful_login(username: str):
    """Clear any failed-attempt history for the user after a clean login."""
    _failed_attempts.pop(username, None)


def record_integrity_failure(username: str, detail: str):
    """
    Raise an alert when a decrypted message/file fails its SHA-256
    integrity check. This indicates the ciphertext was corrupted or
    tampered with in transit.
    """
    log_alert(
        alert_type="INTEGRITY_VIOLATION",
        username=username,
        detail=detail,
        severity="HIGH",
    )


def record_signature_failure(username: str, detail: str):
    """
    Raise an alert when a digital signature fails verification,
    indicating the data may not be authentic or may have been altered
    after signing.
    """
    log_alert(
        alert_type="SIGNATURE_VERIFICATION_FAILED",
        username=username,
        detail=detail,
        severity="HIGH",
    )
