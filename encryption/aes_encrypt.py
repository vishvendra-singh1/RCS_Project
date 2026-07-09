"""
AES-256-GCM Encryption/Decryption
===================================
For the simulation pipeline (main.py, app.py Tab 1/2), aes_encrypt()
generates a fresh random key each call — latency measurement only,
decryption is not needed there.

For the database pipeline (app.py Tab 4), aes_encrypt_for_storage()
and aes_decrypt() use a fixed app-level key so records can be
encrypted once and decrypted later.

In a real production system the app key would come from a secrets
manager (AWS KMS, HashiCorp Vault, etc.) rather than being hardcoded.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---- App-level AES-256 key for DB storage ----
# REPLACE THIS with a secrets manager in production.
_APP_KEY = bytes.fromhex("4b7a9f2c1d8e3b5a6f0c4d2e7a1b9f3c"
                         "8d5e2a4b1c7f0d3e6a9b2c5f8d1e4a7b")


def aes_encrypt(data: str) -> bytes:
    """
    Encrypt with a fresh random AES-256-GCM key.
    Used in the simulation pipeline for latency measurement only —
    the key is discarded after encryption so this output cannot be
    decrypted. Use aes_encrypt_for_storage() for persistent records.
    """
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return ciphertext


def aes_encrypt_for_storage(data: str) -> bytes:
    """
    Encrypt using the fixed app-level AES-256-GCM key.
    Output format: nonce (16 bytes) + tag (16 bytes) + ciphertext.
    Decryptable with aes_decrypt().
    """
    cipher = AES.new(_APP_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return cipher.nonce + tag + ciphertext


def aes_decrypt(blob: bytes) -> str:
    """
    Decrypt a blob produced by aes_encrypt_for_storage().
    Returns the original plaintext string.
    """
    nonce      = blob[:16]
    tag        = blob[16:32]
    ciphertext = blob[32:]
    cipher     = AES.new(_APP_KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()