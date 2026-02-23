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


def reencrypt_file_to_path(
    *,
    old_dek: bytes,
    new_dek: bytes,
    src_path: Path,
    src_nonce_b64: str,
    src_tag_b64: str,
    dst_path: Path,
    chunk_size: int = 1024 * 1024,
) -> tuple[str, str, int]:
    """Re-encrypts an AES-256-GCM file from old_dek to new_dek without writing plaintext to disk.

    Returns (new_nonce_b64, new_tag_b64, plaintext_size).
    """
    if len(old_dek) != 32:
        raise ValueError("old_dek must be 32 bytes")
    if len(new_dek) != 32:
        raise ValueError("new_dek must be 32 bytes")

    src_nonce = b64d(src_nonce_b64)
    src_tag = b64d(src_tag_b64)
    decryptor = Cipher(algorithms.AES(old_dek), modes.GCM(src_nonce, src_tag)).decryptor()

    dst_nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(new_dek), modes.GCM(dst_nonce)).encryptor()

    total_plain = 0
    with src_path.open("rb") as src, dst_path.open("wb") as dst:
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            plain = decryptor.update(chunk)
            if plain:
                total_plain += len(plain)
                dst.write(encryptor.update(plain))

        try:
            tail_plain = decryptor.finalize()
        except InvalidTag as exc:
            raise ValueError("Decryption failed (invalid tag)") from exc

        if tail_plain:
            total_plain += len(tail_plain)
            dst.write(encryptor.update(tail_plain))

        dst.write(encryptor.finalize())

    return b64e(dst_nonce), b64e(encryptor.tag), total_plain
