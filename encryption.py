"""
encryption.py — AES-256-CBC encryption using the `cryptography` library.

A static key is derived from an environment variable (or a default for demo
purposes).  In production, use a proper key-management service.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# 32-byte (256-bit) key — set AES_SECRET_KEY env-var in production
_RAW_KEY = os.environ.get('AES_SECRET_KEY', 'MyDemoSecretKey1MyDemoSecretKey1')
AES_KEY  = _RAW_KEY[:32].encode('utf-8')   # ensure exactly 32 bytes


def encrypt_data(plaintext: str) -> str:
    """
    Encrypt *plaintext* with AES-256-CBC.
    Returns a base64-encoded string:  <IV (16 bytes)><ciphertext>
    """
    iv        = os.urandom(16)                    # random IV per encryption
    padder    = padding.PKCS7(128).padder()
    padded    = padder.update(plaintext.encode()) + padder.finalize()

    cipher    = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv),
                       backend=default_backend())
    encryptor = cipher.encryptor()
    ct        = encryptor.update(padded) + encryptor.finalize()

    # Store IV + ciphertext together, base64-encoded
    return base64.b64encode(iv + ct).decode('utf-8')


def decrypt_data(token: str) -> str:
    """
    Decrypt a token produced by :func:`encrypt_data`.
    Returns the original plaintext string.
    """
    try:
        raw        = base64.b64decode(token.encode('utf-8'))
        iv, ct     = raw[:16], raw[16:]

        cipher     = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv),
                            backend=default_backend())
        decryptor  = cipher.decryptor()
        padded     = decryptor.update(ct) + decryptor.finalize()

        unpadder   = padding.PKCS7(128).unpadder()
        plaintext  = unpadder.update(padded) + unpadder.finalize()
        return plaintext.decode('utf-8')
    except Exception:
        return '[decryption error]'
