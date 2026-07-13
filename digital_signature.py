"""
digital_signature.py
----------------------
Digital Signature module using RSA-PSS (Probabilistic Signature
Scheme) over a SHA-256 digest.

This is a SEPARATE concern from the RSA key-exchange used in
crypto_utils.py. Key exchange (encrypting the AES key with RSA-OAEP)
gives you CONFIDENTIALITY of the session key. A digital signature
gives you AUTHENTICITY and NON-REPUDIATION: proof that the message was
really created by the holder of a specific private key, and that the
sender cannot later deny having sent it.

Because of these different goals, this module uses its own RSA
keypair (a "signing key"), separate from the keypair used for AES key
wrapping. Reusing one RSA keypair for both encryption and signing is
generally discouraged in real systems, so this project keeps them
distinct on purpose, and the report explains why.

RSA-PSS is used instead of the older PKCS#1 v1.5 signature scheme
because PSS is randomised (a different signature is produced each
time, even for the same message) and is the scheme recommended by
modern cryptographic guidance.
"""

from typing import Tuple

from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256


def generate_signing_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """Returns (private_pem, public_pem) for a dedicated signing keypair."""
    key = RSA.generate(key_size)
    private_pem = key.export_key(format="PEM")
    public_pem = key.publickey().export_key(format="PEM")
    return private_pem, public_pem


def sign_data(data: bytes, private_pem: bytes) -> bytes:
    """
    Produce an RSA-PSS signature over SHA-256(data).
    Returns the raw signature bytes.
    """
    key = RSA.import_key(private_pem)
    h = SHA256.new(data)
    signature = pss.new(key).sign(h)
    return signature


def verify_signature(data: bytes, signature: bytes, public_pem: bytes) -> bool:
    """
    Verify an RSA-PSS signature against the given data and public key.
    Returns True if valid, False if verification fails for any reason
    (wrong key, tampered data, corrupted signature, etc.).
    """
    key = RSA.import_key(public_pem)
    h = SHA256.new(data)
    verifier = pss.new(key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
