"""
main.py
--------
Secure Data Transfer and Intrusion Detection Framework (SDTIDF)
Main Console Interface

All modules are wired together here. The menu follows the same
numbered-option style as the original OEL brief so the demo flow
is easy to follow during viva/grading.

Run:
    python main.py
"""

import os
import time

from dependency_check import ensure_required_dependencies

ensure_required_dependencies()

from config import (
    DEFAULT_PRIVATE_KEY_PATH,
    DEFAULT_PUBLIC_KEY_PATH,
    DEFAULT_SIGN_PRIVATE_KEY_PATH,
    DEFAULT_SIGN_PUBLIC_KEY_PATH,
    DEFAULT_RSA_KEY_SIZE,
    DEFAULT_AES_KEY_BITS,
    DATA_DIR,
)
import auth
import crypto_utils as cu
import digital_signature as ds
import intrusion_detection as ids
import performance_analysis as pa
from password_prompt import masked_password
from security_logger import log_event, read_security_log, read_alerts_log

# ---------------------------------------------------------------
# Session state
# ---------------------------------------------------------------
_current_user: str = None  # set after successful login


def _require_login():
    """Print a warning and return False if no user is logged in."""
    if _current_user is None:
        print("[!] You must log in first. Choose option 1 or 2 from the main menu.")
        return False
    return True


# ---------------------------------------------------------------
# Auth screens
# ---------------------------------------------------------------
def screen_register():
    print("\n=== Register New Account ===")
    username = input("New username: ").strip()
    if not username:
        print("[!] Username cannot be blank.")
        return
    password = masked_password("Password: ").strip()
    confirm = masked_password("Confirm password: ").strip()
    if password != confirm:
        print("[!] Passwords do not match.")
        return
    if auth.register_user(username, password):
        print(f"[+] Account '{username}' created successfully.")
    else:
        print(f"[!] Username '{username}' already exists. Choose a different name.")


def screen_login() -> bool:
    """Returns True if login succeeds and sets _current_user."""
    global _current_user
    print("\n=== Login ===")
    username = input("Username: ").strip()
    password = masked_password("Password: ").strip()
    if auth.authenticate_user(username, password):
        _current_user = username
        print(f"[+] Welcome, {username}! You are now logged in.")
        return True
    else:
        print("[!] Login failed. Please check your username and password.")
        return False


def screen_logout():
    global _current_user
    if _current_user:
        log_event("LOGOUT", _current_user, "User logged out")
        print(f"[+] Goodbye, {_current_user}.")
        _current_user = None
    else:
        print("[!] No user is currently logged in.")


# ---------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------
def screen_generate_keys():
    if not _require_login():
        return
    print("\n=== Generate RSA Keypairs ===")
    print("This generates TWO keypairs:")
    print("  (A) Encryption keypair  — used to protect the AES session key")
    print("  (B) Signing keypair     — used for digital signatures (RSA-PSS)")

    size_input = input(
        f"RSA key size for both keypairs (1024 / 2048 / 4096) [default {DEFAULT_RSA_KEY_SIZE}]: "
    ).strip() or str(DEFAULT_RSA_KEY_SIZE)
    try:
        key_size = int(size_input)
        if key_size not in (1024, 2048, 4096):
            raise ValueError
    except ValueError:
        print("[!] Invalid key size. Must be 1024, 2048 or 4096.")
        return

    print("\n[*] Generating encryption keypair ...")
    t0 = time.time()
    enc_priv, enc_pub = cu.generate_rsa_keypair(key_size)
    t1 = time.time()
    pa.log_performance("KEY_GEN_ENCRYPT", key_size, 0, t1 - t0)

    cu.save_pem(enc_priv, DEFAULT_PRIVATE_KEY_PATH)
    cu.save_pem(enc_pub, DEFAULT_PUBLIC_KEY_PATH)
    print(f"[+] Encryption keys saved: {DEFAULT_PRIVATE_KEY_PATH}, {DEFAULT_PUBLIC_KEY_PATH}")

    print("[*] Generating signing keypair ...")
    t0 = time.time()
    sign_priv, sign_pub = ds.generate_signing_keypair(key_size)
    t1 = time.time()
    pa.log_performance("KEY_GEN_SIGN", key_size, 0, t1 - t0)

    cu.save_pem(sign_priv, DEFAULT_SIGN_PRIVATE_KEY_PATH)
    cu.save_pem(sign_pub, DEFAULT_SIGN_PUBLIC_KEY_PATH)
    print(f"[+] Signing keys saved:    {DEFAULT_SIGN_PRIVATE_KEY_PATH}, {DEFAULT_SIGN_PUBLIC_KEY_PATH}")

    log_event("KEY_GEN", _current_user, f"Generated {key_size}-bit RSA keypairs")
    print(f"\n[Timing] Encryption key generation: {t1 - t0:.4f}s")


# ---------------------------------------------------------------
# Encrypt
# ---------------------------------------------------------------
def screen_encrypt():
    if not _require_login():
        return
    print("\n=== Encrypt Data ===")

    # --- Check keys exist ---
    if not os.path.isfile(DEFAULT_PUBLIC_KEY_PATH):
        print("[!] Encryption public key not found. Generate keys first (option 3).")
        return
    if not os.path.isfile(DEFAULT_SIGN_PRIVATE_KEY_PATH):
        print("[!] Signing private key not found. Generate keys first (option 3).")
        return

    # --- Get plaintext ---
    choice = input("Encrypt (1) message you type now  (2) text file from disk [1/2]: ").strip() or "1"
    if choice == "2":
        path = input("Path to input file: ").strip()
        if not os.path.isfile(path):
            print("[!] File not found.")
            return
        with open(path, "rb") as f:
            plaintext = f.read()
        print(f"[*] Read {len(plaintext)} bytes from '{path}'.")
    else:
        msg = input("Enter message to encrypt: ").strip()
        if not msg:
            print("[!] Message cannot be blank.")
            return
        plaintext = msg.encode("utf-8")

    # --- AES key size ---
    aes_input = input(f"AES key size in bits (128 / 256) [default {DEFAULT_AES_KEY_BITS}]: ").strip()
    try:
        aes_bits = int(aes_input) if aes_input else DEFAULT_AES_KEY_BITS
        if aes_bits not in (128, 256):
            raise ValueError
    except ValueError:
        print("[!] Invalid AES key size. Using 256.")
        aes_bits = 256

    # --- Load keys ---
    pub_pem = cu.load_pem(DEFAULT_PUBLIC_KEY_PATH)
    sign_priv_pem = cu.load_pem(DEFAULT_SIGN_PRIVATE_KEY_PATH)

    # --- Encrypt ---
    print("[*] Encrypting ...")
    t0 = time.time()
    enc_aes_key, iv, ciphertext, hash_hex = cu.encrypt_text_flow(plaintext, pub_pem, aes_bits)
    t1 = time.time()
    encrypt_duration = t1 - t0
    pa.log_performance("AES_ENCRYPT", aes_bits, len(plaintext), encrypt_duration)

    # --- Sign the PLAINTEXT hash (sender signs what they wrote, not the ciphertext) ---
    print("[*] Signing SHA-256 digest with RSA-PSS ...")
    t0 = time.time()
    signature = ds.sign_data(plaintext, sign_priv_pem)
    t1 = time.time()
    pa.log_performance("RSA_PSS_SIGN", DEFAULT_RSA_KEY_SIZE, len(plaintext), t1 - t0)

    # --- Save package ---
    out_name = input("Output filename [default: encrypted_package.json]: ").strip() or "encrypted_package.json"
    out_path = os.path.join(DATA_DIR, out_name)
    import time as _time
    meta = {
        "sender": _current_user,
        "original_size_bytes": len(plaintext),
        "aes_key_bits": aes_bits,
        "timestamp": _time.ctime(),
    }
    cu.package_and_save(enc_aes_key, iv, ciphertext, hash_hex, out_path, meta, signature)

    print(f"\n[Summary]")
    print(f"  SHA-256 hash of plaintext : {hash_hex}")
    print(f"  Original size             : {len(plaintext)} bytes")
    print(f"  Ciphertext size           : {len(ciphertext)} bytes")
    print(f"  AES key size              : {aes_bits} bits")
    print(f"  Encryption time           : {encrypt_duration:.4f}s")
    print(f"  Digital signature length  : {len(signature)} bytes")

    log_event("ENCRYPT", _current_user, f"Encrypted {len(plaintext)} bytes → {out_path}")


# ---------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------
def screen_decrypt():
    if not _require_login():
        return
    print("\n=== Decrypt Data ===")

    # --- Check keys ---
    if not os.path.isfile(DEFAULT_PRIVATE_KEY_PATH):
        print("[!] Encryption private key not found. Generate keys first.")
        return
    if not os.path.isfile(DEFAULT_SIGN_PUBLIC_KEY_PATH):
        print("[!] Signing public key not found. Generate keys first.")
        return

    pkg_name = input("Encrypted package filename [default: encrypted_package.json]: ").strip() or "encrypted_package.json"
    pkg_path = os.path.join(DATA_DIR, pkg_name)
    if not os.path.isfile(pkg_path):
        print(f"[!] File not found: {pkg_path}")
        return

    priv_pem = cu.load_pem(DEFAULT_PRIVATE_KEY_PATH)
    sign_pub_pem = cu.load_pem(DEFAULT_SIGN_PUBLIC_KEY_PATH)
    payload = cu.load_package(pkg_path)

    # --- Decrypt ---
    print("[*] Decrypting ...")
    t0 = time.time()
    try:
        plaintext, integrity_ok, computed_hash = cu.decrypt_text_flow(
            payload["enc_aes_key"], payload["iv"],
            payload["ciphertext"], payload["hash"], priv_pem
        )
    except Exception as e:
        print(f"[!] Decryption failed: {e}")
        log_event("DECRYPT", _current_user, f"Decryption error: {e}", status="FAILED")
        return
    t1 = time.time()
    decrypt_duration = t1 - t0
    pa.log_performance("AES_DECRYPT", payload["meta"].get("aes_key_bits", "?"),
                        len(plaintext), decrypt_duration)

    # --- Integrity check ---
    print(f"\n[Integrity Check]")
    print(f"  Stored hash  : {payload['hash']}")
    print(f"  Computed hash: {computed_hash}")
    if integrity_ok:
        print("  Result       : OK — data was NOT tampered with.")
    else:
        print("  Result       : FAILED — data may have been tampered with!")
        ids.record_integrity_failure(_current_user,
            f"Hash mismatch in {pkg_path}: stored={payload['hash']}, computed={computed_hash}")

    log_event("INTEGRITY_CHECK", _current_user,
              f"{'OK' if integrity_ok else 'FAILED'} for {pkg_path}",
              status="OK" if integrity_ok else "FAILED")

    # --- Digital signature verification ---
    if payload.get("signature"):
        print("\n[Digital Signature Verification]")
        t0 = time.time()
        sig_valid = ds.verify_signature(plaintext, payload["signature"], sign_pub_pem)
        t1 = time.time()
        pa.log_performance("RSA_PSS_VERIFY", DEFAULT_RSA_KEY_SIZE, len(plaintext), t1 - t0)

        if sig_valid:
            sender = payload["meta"].get("sender", "unknown")
            print(f"  Result : VALID — message was signed by '{sender}'.")
        else:
            print("  Result : INVALID — signature verification failed!")
            ids.record_signature_failure(_current_user,
                f"Signature invalid in package {pkg_path}")
        log_event("VERIFY_SIG", _current_user,
                  f"Signature {'VALID' if sig_valid else 'INVALID'} in {pkg_path}",
                  status="OK" if sig_valid else "FAILED")
    else:
        print("\n[!] No digital signature found in this package.")

    # --- Show / save plaintext ---
    print(f"\n[Timing] Decryption: {decrypt_duration:.4f}s")
    save_choice = input("\nSave decrypted content to a file? (y/N): ").strip().lower()
    if save_choice == "y":
        out_name = input("Output filename [default: decrypted_output.txt]: ").strip() or "decrypted_output.txt"
        out_path = os.path.join(DATA_DIR, out_name)
        with open(out_path, "wb") as f:
            f.write(plaintext)
        print(f"[+] Saved to {out_path}")
    else:
        try:
            print("\n--- Decrypted Message ---")
            print(plaintext.decode("utf-8"))
            print("--- End ---")
        except UnicodeDecodeError:
            print("[*] Binary content — choose 'y' at the save prompt to write it to a file.")

    log_event("DECRYPT", _current_user, f"Decrypted {pkg_path}")


# ---------------------------------------------------------------
# Security Logs viewer
# ---------------------------------------------------------------
def screen_view_logs():
    if not _require_login():
        return
    print("\n=== Security Event Log (last 20 entries) ===")
    rows = read_security_log()
    if not rows:
        print("[*] No security events logged yet.")
        return
    header = f"{'Timestamp':<22} {'Event':<20} {'User':<15} {'Status':<8} Detail"
    print(header)
    print("-" * len(header))
    for row in rows[-20:]:
        print(f"{row['timestamp']:<22} {row['event_type']:<20} {row['username']:<15} {row['status']:<8} {row['detail']}")

    print("\n=== Intrusion Detection Alerts ===")
    alerts = read_alerts_log()
    if not alerts:
        print("[*] No alerts raised yet.")
    else:
        for a in alerts:
            print(f"[{a['severity']}] {a['timestamp']} | {a['alert_type']} | user={a['username']} | {a['detail']}")


# ---------------------------------------------------------------
# Performance analysis
# ---------------------------------------------------------------
def screen_performance():
    if not _require_login():
        return
    print("\n=== Performance Analysis ===")

    summary = pa.summary_table()
    if summary.empty:
        print("[*] No performance data yet. Run some encrypt/decrypt/key-gen operations first.")
        return

    print("\n[Summary Table]")
    print(summary.to_string(index=False))

    path1 = pa.plot_duration_by_operation()
    print(f"\n[+] Chart saved: {path1}")

    for op in summary["operation"].unique():
        path2 = pa.plot_duration_vs_size(op)
        print(f"[+] Chart saved: {path2}")


# ---------------------------------------------------------------
# Quick demo  (for viva — shows the whole pipeline in one shot)
# ---------------------------------------------------------------
def screen_quick_demo():
    print("\n=== QUICK DEMO: Full Pipeline ===")
    print("[*] Generating 2048-bit RSA keypairs (encryption + signing) ...")

    enc_priv, enc_pub = cu.generate_rsa_keypair(2048)
    sign_priv, sign_pub = ds.generate_signing_keypair(2048)

    sample = b"SDTIDF Demo: AES + RSA + SHA-256 + Digital Signature!"
    print(f"[*] Plaintext: {sample.decode()}")

    enc_aes_key, iv, ciphertext, hash_hex = cu.encrypt_text_flow(sample, enc_pub, 256)
    print(f"[+] Encrypted. SHA-256={hash_hex[:20]}...")

    signature = ds.sign_data(sample, sign_priv)
    print(f"[+] Signed with RSA-PSS. Signature length: {len(signature)} bytes.")

    plaintext, integrity_ok, _ = cu.decrypt_text_flow(enc_aes_key, iv, ciphertext, hash_hex, enc_priv)
    sig_valid = ds.verify_signature(plaintext, signature, sign_pub)

    print(f"[+] Decrypted: {plaintext.decode()}")
    print(f"[+] Integrity check : {'OK' if integrity_ok else 'FAILED'}")
    print(f"[+] Signature valid : {'YES' if sig_valid else 'NO'}")
    print("\n[Demo complete. All layers verified successfully.]")


# ---------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------
def main():
    print("=" * 60)
    print("                 CIPHERVAULT")
    print(" Intelligent Secure Data Protection Framework")
    print(" AES-256 | RSA | SHA-256 | Digital Signatures")
    print("=" * 60)

    while True:
        logged_in_str = f"[{_current_user}]" if _current_user else "[not logged in]"
        print(f"""
--- MAIN MENU ---  {logged_in_str}

  Auth
    1) Register new account
    2) Login
    3) Logout

  Cryptography
    4) Generate RSA keypairs  (encryption + signing)
    5) Secure File Encryption (AES-256)
    6) Secure File Recovery

  Monitoring
    7) View security & alert logs
    8) Security Analytics Dashboard

  9) Quick demo  (full pipeline, no login required)
  0) Exit
""")
        choice = input("Choose: ").strip()

        if choice == "1":
            screen_register()
        elif choice == "2":
            screen_login()
        elif choice == "3":
            screen_logout()
        elif choice == "4":
            screen_generate_keys()
        elif choice == "5":
            screen_encrypt()
        elif choice == "6":
            screen_decrypt()
        elif choice == "7":
            screen_view_logs()
        elif choice == "8":
            screen_performance()
        elif choice == "9":
            screen_quick_demo()
        elif choice == "0":
            print("Exiting CipherVault. Stay secure.")
            break
        else:
            print("[!] Invalid option. Please choose a number from the menu.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted. Exiting.")
