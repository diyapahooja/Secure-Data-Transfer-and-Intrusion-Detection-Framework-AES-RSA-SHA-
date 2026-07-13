"""
crypto_utils.py
----------------
Core cryptographic engine: AES (confidentiality), RSA (key exchange),
and SHA-256 (integrity). This module is a cleaned-up, modularised
evolution of the original hybrid-encryption logic, split out so it
can be reused by both the CLI and the digital-signature module.

Design recap (hybrid encryption):
  1. A random AES session key is generated for every message/file.
  2. The plaintext is encrypted with AES-CBC (fast, symmetric).
  3. The AES key itself is encrypted with the recipient's RSA public
     key (solves the key-distribution problem of symmetric crypto).
  4. A SHA-256 hash of the plaintext is computed so the recipient can
     detect tampering after decryption.
"""

import base64
import json
import os
from typing import Tuple

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


# ---------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------
def b64enc(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64dec(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def sha256_hex(data: bytes) -> str:
    h = SHA256.new()
    h.update(data)
    return h.hexdigest()


# ---------------------------------------------------------------
# PKCS7 padding for AES-CBC
# ---------------------------------------------------------------
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(padded: bytes) -> bytes:
    if not padded:
        raise ValueError("Invalid padded data (empty).")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length.")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes.")
    return padded[:-pad_len]


# ---------------------------------------------------------------
# RSA key management
# ---------------------------------------------------------------
def generate_rsa_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """Returns (private_pem, public_pem) as bytes."""
    key = RSA.generate(key_size)
    private_pem = key.export_key(format="PEM")
    public_pem = key.publickey().export_key(format="PEM")
    return private_pem, public_pem


def save_pem(data: bytes, path: str):
    with open(path, "wb") as f:
        f.write(data)


def load_pem(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# ---------------------------------------------------------------
# AES functions
# ---------------------------------------------------------------
def generate_aes_key(key_size_bits: int = 256) -> bytes:
    if key_size_bits not in (128, 192, 256):
        raise ValueError("AES key size must be 128, 192 or 256.")
    return get_random_bytes(key_size_bits // 8)


def aes_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """AES-CBC with PKCS7 padding. Returns (iv, ciphertext)."""
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pkcs7_pad(plaintext, 16)
    ciphertext = cipher.encrypt(padded)
    return iv, ciphertext


def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded)


# ---------------------------------------------------------------
# RSA encrypt/decrypt (used only to wrap/unwrap the AES key)
# ---------------------------------------------------------------
def rsa_encrypt(data: bytes, public_pem: bytes) -> bytes:
    pubkey = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(data)


def rsa_decrypt(ciphertext: bytes, private_pem: bytes) -> bytes:
    privkey = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(ciphertext)


# ---------------------------------------------------------------
# File packaging (now also carries an optional digital signature)
# ---------------------------------------------------------------
def package_and_save(enc_aes_key: bytes, iv: bytes, ciphertext: bytes,
                      hash_hex: str, out_path: str, meta: dict = None,
                      signature: bytes = None):
    meta = meta or {}
    payload = {
        "enc_aes_key": b64enc(enc_aes_key),
        "iv": b64enc(iv),
        "ciphertext": b64enc(ciphertext),
        "hash": hash_hex,
        "signature": b64enc(signature) if signature else None,
        "meta": meta,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"[+] Encrypted package saved to: {out_path}")


def load_package(path: str):
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    return {
        "enc_aes_key": b64dec(payload["enc_aes_key"]),
        "iv": b64dec(payload["iv"]),
        "ciphertext": b64dec(payload["ciphertext"]),
        "hash": payload["hash"],
        "signature": b64dec(payload["signature"]) if payload.get("signature") else None,
        "meta": payload.get("meta", {}),
    }


# ---------------------------------------------------------------
# Top-level operations
# ---------------------------------------------------------------
def encrypt_text_flow(plaintext: bytes, rsa_public_pem: bytes,
                       aes_key_size: int = 256) -> Tuple[bytes, bytes, bytes, str]:
    """Returns (enc_aes_key, iv, ciphertext, hash_hex)."""
    aes_key = generate_aes_key(aes_key_size)
    hash_hex = sha256_hex(plaintext)
    iv, ciphertext = aes_encrypt(plaintext, aes_key)
    enc_aes_key = rsa_encrypt(aes_key, rsa_public_pem)
    return enc_aes_key, iv, ciphertext, hash_hex


def decrypt_text_flow(enc_aes_key: bytes, iv: bytes, ciphertext: bytes,
                       expected_hash_hex: str, rsa_private_pem: bytes
                       ) -> Tuple[bytes, bool, str]:
    """Decrypts and verifies integrity. Returns (plaintext, integrity_ok, computed_hash_hex)."""
    aes_key = rsa_decrypt(enc_aes_key, rsa_private_pem)
    plaintext = aes_decrypt(iv, ciphertext, aes_key)
    computed_hash = sha256_hex(plaintext)
    integrity_ok = (computed_hash == expected_hash_hex)
    return plaintext, integrity_ok, computed_hash
