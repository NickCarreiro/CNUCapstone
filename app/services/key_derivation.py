from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import settings


def _read_file(path: str) -> bytes:
    p = Path(path)
    return p.read_bytes()


@lru_cache(maxsize=1)
def _root_key_from_passphrase() -> bytes:
    if not settings.passphrase_file:
        raise ValueError("PFV_PASSPHRASE_FILE is not set")
    if not settings.salt_file:
        raise ValueError("PFV_SALT_FILE is not set")

    passphrase = _read_file(settings.passphrase_file).strip()
    if not passphrase:
        raise ValueError("Passphrase file is empty")

    salt = _read_file(settings.salt_file)
    if len(salt) < 16:
        raise ValueError("Salt file must be at least 16 bytes")

    # Derive a 32-byte root key. Parameters are a tradeoff: strong enough for a server,
    # not too slow for dev.
    return hash_secret_raw(
        secret=passphrase,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )


def _hkdf(root_key: bytes, *, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(root_key)


def using_passphrase() -> bool:
    return bool(settings.passphrase_file)


@lru_cache(maxsize=1)
def master_key_bytes() -> bytes:
    if settings.passphrase_file:
        root = _root_key_from_passphrase()
        return _hkdf(root, info=b"pfv:master-key:v1", length=32)

    # Fallback: PFV_MASTER_KEY is base64url-encoded 32 bytes
    raw = base64.urlsafe_b64decode(settings.master_key.encode())
    if len(raw) != 32:
        raise ValueError("PFV_MASTER_KEY must decode to 32 bytes")
    return raw


@lru_cache(maxsize=1)
def totp_fernet_key_str() -> str:
    if settings.passphrase_file:
        root = _root_key_from_passphrase()
        raw = _hkdf(root, info=b"pfv:totp-fernet:v1", length=32)
        return base64.urlsafe_b64encode(raw).decode()

    return settings.totp_encryption_key
