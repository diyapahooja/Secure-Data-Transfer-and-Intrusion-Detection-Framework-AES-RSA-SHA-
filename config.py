"""
config.py
---------
Central configuration for the Secure Data Transfer and Intrusion
Detection Framework (SDTIDF).

Keeping every path and tunable constant in one file makes the system
easier to grade, demo, and modify (e.g. changing the lockout threshold
for the intrusion detection module does not require touching auth.py).
"""

import os

# ---------------------------------------------------------------
# Base directory layout
# ---------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

KEYS_DIR = os.path.join(BASE_DIR, "keys")
DATA_DIR = os.path.join(BASE_DIR, "data")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

for _dir in (KEYS_DIR, DATA_DIR, LOGS_DIR, REPORTS_DIR):
    os.makedirs(_dir, exist_ok=True)

# ---------------------------------------------------------------
# File paths
# ---------------------------------------------------------------
USER_DB_PATH = os.path.join(DATA_DIR, "users.json")
SECURITY_LOG_PATH = os.path.join(LOGS_DIR, "security_log.csv")
ALERTS_LOG_PATH = os.path.join(LOGS_DIR, "alerts_log.csv")
PERFORMANCE_LOG_PATH = os.path.join(LOGS_DIR, "performance_log.csv")

DEFAULT_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "rsa_private.pem")
DEFAULT_PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "rsa_public.pem")
DEFAULT_SIGN_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "sign_private.pem")
DEFAULT_SIGN_PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "sign_public.pem")

# ---------------------------------------------------------------
# Cryptography defaults
# ---------------------------------------------------------------
DEFAULT_RSA_KEY_SIZE = 2048
DEFAULT_AES_KEY_BITS = 256

# ---------------------------------------------------------------
# Intrusion Detection thresholds
# ---------------------------------------------------------------
# A "brute-force" pattern is declared when this many failed logins
# occur for the same username within the time window below.
MAX_FAILED_ATTEMPTS = 3
FAILED_ATTEMPT_WINDOW_SECONDS = 60 * 5  # 5 minutes

# After the threshold is hit, the account is locked for this long.
LOCKOUT_DURATION_SECONDS = 60 * 10  # 10 minutes
