from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode())


def generate_key_32() -> bytes:
    return os.urandom(32)


def wrap_key(master_key: bytes, dek: bytes, *, aad: bytes) -> tuple[str, str]:
    if len(master_key) != 32:
        raise ValueError("master_key must be 32 bytes")
    if len(dek) != 32:
        raise ValueError("dek must be 32 bytes")

    nonce = os.urandom(12)
    ct = AESGCM(master_key).encrypt(nonce, dek, aad)
    return b64e(nonce), b64e(ct)


def unwrap_key(master_key: bytes, wrap_nonce_b64: str, wrapped_dek_b64: str, *, aad: bytes) -> bytes:
    if len(master_key) != 32:
        raise ValueError("master_key must be 32 bytes")
    nonce = b64d(wrap_nonce_b64)
    ct = b64d(wrapped_dek_b64)
    dek = AESGCM(master_key).decrypt(nonce, ct, aad)
    if len(dek) != 32:
        raise ValueError("Unwrapped DEK has invalid length")
    return dek


def encrypt_file_to_path(dek: bytes, src, dst_path: Path) -> tuple[str, str, int]:
    """Encrypts bytes from src (file-like) to dst_path using AES-256-GCM.

    Returns (nonce_b64, tag_b64, plaintext_size).
    """
    if len(dek) != 32:
        raise ValueError("dek must be 32 bytes")

    nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(dek), modes.GCM(nonce)).encryptor()

    total_plain = 0
    with dst_path.open("wb") as out:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            total_plain += len(chunk)
            out.write(encryptor.update(chunk))
        out.write(encryptor.finalize())

    tag = encryptor.tag
    return b64e(nonce), b64e(tag), total_plain


def decrypt_file_iter(dek: bytes, path: Path, nonce_b64: str, tag_b64: str, *, chunk_size: int = 1024 * 1024):
    """Yields plaintext chunks for an AES-256-GCM encrypted file."""
    if len(dek) != 32:
        raise ValueError("dek must be 32 bytes")

    nonce = b64d(nonce_b64)
    tag = b64d(tag_b64)
    decryptor = Cipher(algorithms.AES(dek), modes.GCM(nonce, tag)).decryptor()

    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            out = decryptor.update(chunk)
            if out:
                yield out
        try:
            tail = decryptor.finalize()
        except InvalidTag as exc:
            raise ValueError("Decryption failed (invalid tag)") from exc
        if tail:
            yield tail
