"""
security_logger.py
-------------------
Centralised security event logging.

Every authentication attempt, encryption/decryption action, signature
operation, and intrusion alert is written as a structured row to a CSV
file. This is what the Performance Analysis and Intrusion Detection
modules later read back in with pandas.

Logging to CSV (rather than plain text) is a deliberate design choice:
it keeps the log machine-readable so it can be analysed, filtered, and
charted without writing a custom parser.
"""

import csv
import os
from datetime import datetime

from config import SECURITY_LOG_PATH, ALERTS_LOG_PATH

_SECURITY_FIELDS = ["timestamp", "event_type", "username", "detail", "status"]
_ALERT_FIELDS = ["timestamp", "alert_type", "username", "detail", "severity"]


def _ensure_header(path: str, fields: list):
    """Create the CSV file with a header row if it does not exist yet."""
    if not os.path.isfile(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(fields)


def log_event(event_type: str, username: str, detail: str, status: str = "OK"):
    """
    Append a security event to the security log.

    event_type examples: LOGIN, LOGOUT, ENCRYPT, DECRYPT, SIGN, VERIFY,
                          KEY_GEN, INTEGRITY_CHECK
    status examples: OK, FAILED, ERROR
    """
    _ensure_header(SECURITY_LOG_PATH, _SECURITY_FIELDS)
    with open(SECURITY_LOG_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(timespec="seconds"),
            event_type,
            username,
            detail,
            status,
        ])


def log_alert(alert_type: str, username: str, detail: str, severity: str = "HIGH"):
    """
    Append an intrusion-detection alert to the dedicated alerts log.

    Kept separate from the general security log so the IDS module
    (and the report/demo) can show "real" alerts without having to
    filter them out of routine activity.
    """
    _ensure_header(ALERTS_LOG_PATH, _ALERT_FIELDS)
    with open(ALERTS_LOG_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(timespec="seconds"),
            alert_type,
            username,
            detail,
            severity,
        ])
    # Also surface the alert immediately on the console — a real IDS
    # would page/email a security analyst; here we print to simulate
    # a live alert.
    print(f"\n[!!ALERT!!] {severity} | {alert_type} | user={username} | {detail}\n")


def read_security_log():
    """Return the security log as a list of dict rows (empty list if none)."""
    if not os.path.isfile(SECURITY_LOG_PATH):
        return []
    with open(SECURITY_LOG_PATH, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def read_alerts_log():
    """Return the alerts log as a list of dict rows (empty list if none)."""
    if not os.path.isfile(ALERTS_LOG_PATH):
        return []
    with open(ALERTS_LOG_PATH, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))
