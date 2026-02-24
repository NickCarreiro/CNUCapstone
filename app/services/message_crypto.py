from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.services.crypto import decrypt_file_iter, encrypt_file_to_path
from app.services.key_derivation import message_attachment_key_bytes, message_fernet_key_str
from app.services.crypto import b64d, b64e

_PREFIX = "enc:v1:"
_DM_BODY_PREFIX_CONVERSATION = "dmenc:v2:"
_DM_BODY_PREFIX_CONVERSATION_LEGACY = "dmencv2:"
DM_BODY_SCHEME_FERNET = "dm_body_fernet_v1"
DM_BODY_SCHEME_CONVERSATION = "dm_body_conversation_v1"
DM_ATTACHMENT_SCHEME_RECIPIENT = "recipient_v1"
DM_ATTACHMENT_SCHEME_SYSTEM = "dm_system_v1"
DM_ATTACHMENT_SCHEME_CONVERSATION = "dm_conversation_v1"


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


def _conversation_body_payload(value: str) -> tuple[str, str] | None:
    for prefix in (_DM_BODY_PREFIX_CONVERSATION, _DM_BODY_PREFIX_CONVERSATION_LEGACY):
        if value.startswith(prefix):
            return prefix, value[len(prefix) :]
    return None


def is_dm_conversation_encrypted(value: str | None) -> bool:
    return bool(value and _conversation_body_payload(value) is not None)


def encrypt_dm_body(plaintext: str, conversation_dek: bytes) -> str:
    if len(conversation_dek) != 32:
        raise ValueError("conversation_dek must be 32 bytes")
    nonce = os.urandom(12)
    ct = AESGCM(conversation_dek).encrypt(nonce, plaintext.encode(), b"dm-body:v2")
    return f"{_DM_BODY_PREFIX_CONVERSATION}{b64e(nonce)}:{b64e(ct)}"


def _decrypt_dm_payload(encoded: str, conversation_dek: bytes) -> str:
    nonce_b64, sep, payload_b64 = encoded.partition(":")
    if not sep:
        raise ValueError("Invalid dm conversation payload")
    nonce = b64d(nonce_b64)
    payload = b64d(payload_b64)
    plain = AESGCM(conversation_dek).decrypt(nonce, payload, b"dm-body:v2")
    return plain.decode()


def _unwrap_message_layers(value: str, conversation_dek: bytes, *, max_layers: int = 256) -> str:
    current = value
    for _ in range(max_layers):
        payload = _conversation_body_payload(current)
        if payload is not None:
            _, encoded = payload
            current = _decrypt_dm_payload(encoded, conversation_dek)
            continue
        if is_message_encrypted(current):
            current = decrypt_message(current)
            if current == "[message unavailable]":
                return current
            continue
        break
    return current


def decrypt_dm_body(ciphertext_or_plaintext: str, conversation_dek: bytes) -> str:
    value = ciphertext_or_plaintext or ""
    payload = _conversation_body_payload(value)
    if payload is None:
        return decrypt_message(value)
    if len(conversation_dek) != 32:
        return "[message unavailable]"
    try:
        return _unwrap_message_layers(value, conversation_dek)
    except Exception:
        return "[message unavailable]"


def encrypt_message_attachment_to_path(src, dst_path: Path) -> tuple[str, str, int]:
    """Encrypt direct-message attachment bytes to disk with AES-256-GCM."""
    return encrypt_file_to_path(message_attachment_key_bytes(), src, dst_path)


def decrypt_message_attachment_iter(path: Path, nonce_b64: str, tag_b64: str, *, chunk_size: int = 1024 * 1024):
    """Yield decrypted direct-message attachment bytes from disk."""
    return decrypt_file_iter(message_attachment_key_bytes(), path, nonce_b64, tag_b64, chunk_size=chunk_size)
