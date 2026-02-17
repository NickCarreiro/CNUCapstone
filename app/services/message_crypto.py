from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.services.key_derivation import message_fernet_key_str

_PREFIX = "enc:v1:"


def _fernet() -> Fernet:
    return Fernet(message_fernet_key_str().encode())


def encrypt_message(plaintext: str) -> str:
    token = _fernet().encrypt(plaintext.encode()).decode()
    return f"{_PREFIX}{token}"


def decrypt_message(ciphertext_or_plaintext: str) -> str:
    value = ciphertext_or_plaintext or ""
    if not value.startswith(_PREFIX):
        # Backward compatibility for existing plaintext rows.
        return value
    token = value[len(_PREFIX) :]
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        # Do not leak cipher internals in UI; return redacted marker.
        return "[message unavailable]"
