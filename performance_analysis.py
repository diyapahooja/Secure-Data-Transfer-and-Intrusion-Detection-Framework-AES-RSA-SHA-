"""
performance_analysis.py
-------------------------
Performance Analysis module.

Every cryptographic operation timed by the CLI is written to
performance_log.csv. This module reads that log back in with pandas
and produces summary statistics and matplotlib charts — e.g. average
AES encryption time vs RSA key size, or encryption time vs input size.

Keeping this as its own module (rather than scattering print()
timing statements through the CLI) means the performance data can be
re-analysed at any time without re-running the cryptographic
operations themselves.
"""

import csv
import os
from pathlib import Path

import pandas as pd
import matplotlib
matplotlib.use("Agg")  # safe for headless/non-GUI environments
import matplotlib.pyplot as plt

from config import PERFORMANCE_LOG_PATH, REPORTS_DIR

_FIELDS = ["timestamp", "operation", "key_size_or_bits", "data_size_bytes", "duration_seconds"]


def _fallback_dir() -> str:
    """Return a user-writable fallback folder for locked/restricted folders."""
    path = Path.home() / "Documents" / "SDTIDF_Runtime_Output"
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def _fallback_performance_log_path() -> str:
    return os.path.join(_fallback_dir(), "performance_log.csv")


def _write_performance_row(path: str, row: list):
    file_exists = os.path.isfile(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(_FIELDS)
        writer.writerow(row)


def _readable_performance_log_path() -> str:
    if os.path.isfile(PERFORMANCE_LOG_PATH):
        return PERFORMANCE_LOG_PATH
    fallback = _fallback_performance_log_path()
    if os.path.isfile(fallback):
        return fallback
    return PERFORMANCE_LOG_PATH


def _safe_chart_path(filename: str) -> str:
    original = os.path.join(REPORTS_DIR, filename)
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(original, "ab"):
            pass
        return original
    except PermissionError:
        fallback = os.path.join(_fallback_dir(), filename)
        print(f"[!] Reports folder is locked. Saving chart to: {fallback}")
        return fallback


def log_performance(operation: str, key_size_or_bits, data_size_bytes: int, duration_seconds: float):
    """Append one timing record. Called by the CLI after each crypto operation."""
    from datetime import datetime

    row = [
        datetime.now().isoformat(timespec="seconds"),
        operation,
        key_size_or_bits,
        data_size_bytes,
        f"{duration_seconds:.6f}",
    ]

    try:
        _write_performance_row(PERFORMANCE_LOG_PATH, row)
    except PermissionError:
        fallback = _fallback_performance_log_path()
        _write_performance_row(fallback, row)
        print(f"[!] Performance log folder is locked. Saved timing data to: {fallback}")


def load_performance_df():
    """Load the performance log as a pandas DataFrame (empty DF if no data yet)."""
    log_path = _readable_performance_log_path()
    if not os.path.isfile(log_path):
        return pd.DataFrame(columns=_FIELDS)
    df = pd.read_csv(log_path)
    df["duration_seconds"] = pd.to_numeric(df["duration_seconds"], errors="coerce")
    df["data_size_bytes"] = pd.to_numeric(df["data_size_bytes"], errors="coerce")
    return df


def summary_table() -> pd.DataFrame:
    """
    Returns a summary DataFrame: mean/min/max duration and average
    data size, grouped by operation type.
    """
    df = load_performance_df()
    if df.empty:
        return df
    summary = df.groupby("operation").agg(
        count=("duration_seconds", "count"),
        avg_duration_s=("duration_seconds", "mean"),
        min_duration_s=("duration_seconds", "min"),
        max_duration_s=("duration_seconds", "max"),
        avg_data_size_bytes=("data_size_bytes", "mean"),
    ).reset_index()
    return summary


def plot_duration_by_operation(save_path: str = None) -> str:
    """
    Bar chart: average duration per operation type (ENCRYPT, DECRYPT,
    SIGN, VERIFY, KEY_GEN, etc.). Saves to a PNG and returns the path.
    """
    df = summary_table()
    save_path = save_path or _safe_chart_path("avg_duration_by_operation.png")

    fig, ax = plt.subplots(figsize=(8, 5))
    if df.empty:
        ax.text(0.5, 0.5, "No performance data yet.\nRun some operations first.",
                ha="center", va="center")
    else:
        ax.bar(df["operation"], df["avg_duration_s"], color="#2c6e91")
        ax.set_xlabel("Operation")
        ax.set_ylabel("Average duration (seconds)")
        ax.set_title("Average Operation Duration by Type")
        plt.xticks(rotation=30, ha="right")
        fig.tight_layout()

    fig.savefig(save_path, dpi=150)
    plt.close(fig)
    return save_path


def plot_duration_vs_size(operation: str, save_path: str = None) -> str:
    """
    Scatter/line chart: how duration scales with input data size for a
    specific operation (e.g. 'AES_ENCRYPT'). Useful for demonstrating
    that AES scales roughly linearly with data size while RSA does not
    depend on plaintext size at all (since it only ever encrypts the
    fixed-size AES key).
    """
    df = load_performance_df()
    df = df[df["operation"] == operation].sort_values("data_size_bytes")
    save_path = save_path or _safe_chart_path(f"{operation.lower()}_duration_vs_size.png")

    fig, ax = plt.subplots(figsize=(8, 5))
    if df.empty:
        ax.text(0.5, 0.5, f"No data for '{operation}' yet.", ha="center", va="center")
    else:
        ax.plot(df["data_size_bytes"], df["duration_seconds"], marker="o", color="#a83232")
        ax.set_xlabel("Input data size (bytes)")
        ax.set_ylabel("Duration (seconds)")
        ax.set_title(f"{operation}: Duration vs Input Size")
        fig.tight_layout()

    fig.savefig(save_path, dpi=150)
    plt.close(fig)
    return save_path
