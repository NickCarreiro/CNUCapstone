from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from app.services.crypto import decrypt_file_iter, encrypt_file_to_path
from app.services.key_derivation import message_attachment_key_bytes, message_fernet_key_str

_PREFIX = "enc:v1:"
DM_ATTACHMENT_SCHEME_RECIPIENT = "recipient_v1"
DM_ATTACHMENT_SCHEME_SYSTEM = "dm_system_v1"


def _fernet() -> Fernet:
    return Fernet(message_fernet_key_str().encode())


def is_message_encrypted(value: str | None) -> bool:
    return bool(value and value.startswith(_PREFIX))


def encrypt_message(plaintext: str) -> str:
    token = _fernet().encrypt(plaintext.encode()).decode()
    return f"{_PREFIX}{token}"


def decrypt_message(ciphertext_or_plaintext: str) -> str:
    value = ciphertext_or_plaintext or ""
    if not is_message_encrypted(value):
        # Backward compatibility for existing plaintext rows.
        return value
    token = value[len(_PREFIX) :]
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        # Do not leak cipher internals in UI; return redacted marker.
        return "[message unavailable]"


def encrypt_message_attachment_to_path(src, dst_path: Path) -> tuple[str, str, int]:
    """Encrypt direct-message attachment bytes to disk with AES-256-GCM."""
    return encrypt_file_to_path(message_attachment_key_bytes(), src, dst_path)


def decrypt_message_attachment_iter(path: Path, nonce_b64: str, tag_b64: str, *, chunk_size: int = 1024 * 1024):
    """Yield decrypted direct-message attachment bytes from disk."""
    return decrypt_file_iter(message_attachment_key_bytes(), path, nonce_b64, tag_b64, chunk_size=chunk_size)
