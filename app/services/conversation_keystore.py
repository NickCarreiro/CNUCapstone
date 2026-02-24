from __future__ import annotations

import logging
import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.core import AuditLog, ConversationKey
from app.services.crypto import generate_key_32, unwrap_key, wrap_key
from app.services.key_derivation import master_key_bytes

logger = logging.getLogger(__name__)


def _ordered_user_ids(user_a_id: uuid.UUID, user_b_id: uuid.UUID) -> tuple[uuid.UUID, uuid.UUID]:
    return (user_a_id, user_b_id) if str(user_a_id) <= str(user_b_id) else (user_b_id, user_a_id)


def conversation_aad(thread_id: uuid.UUID, user_low_id: uuid.UUID, user_high_id: uuid.UUID) -> bytes:
    return f"dm-thread:{thread_id}:{user_low_id}:{user_high_id}".encode()


def ensure_conversation_key(
    db: Session,
    *,
    thread_id: uuid.UUID,
    user_a_id: uuid.UUID,
    user_b_id: uuid.UUID,
) -> tuple[ConversationKey, bool]:
    user_low_id, user_high_id = _ordered_user_ids(user_a_id, user_b_id)
    existing = db.query(ConversationKey).filter(ConversationKey.thread_id == thread_id).first()
    if existing:
        if existing.user_low_id != user_low_id or existing.user_high_id != user_high_id:
            raise ValueError("Conversation key user pair does not match thread participants")
        return existing, False

    master = master_key_bytes()
    dek = generate_key_32()
    aad = conversation_aad(thread_id, user_low_id, user_high_id)
    wrap_nonce, wrapped_dek = wrap_key(master, dek, aad=aad)
    row = ConversationKey(
        thread_id=thread_id,
        user_low_id=user_low_id,
        user_high_id=user_high_id,
        wrap_nonce=wrap_nonce,
        wrapped_dek=wrapped_dek,
        key_version=1,
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
            db.add(
                AuditLog(
                    user_id=None,
                    event_type="encryption.conversation_key_provisioned",
                    details=(
                        f"Provisioned conversation key id={row.id} thread={thread_id} "
                        f"users=({user_low_id},{user_high_id}) version={row.key_version}."
                    ),
                )
            )
    except IntegrityError:
        existing = db.query(ConversationKey).filter(ConversationKey.thread_id == thread_id).first()
        if existing:
            if existing.user_low_id != user_low_id or existing.user_high_id != user_high_id:
                raise ValueError("Conversation key user pair does not match thread participants")
            return existing, False
        raise
    logger.info(
        "Provisioned conversation key id=%s for thread=%s users=(%s,%s) version=%s",
        row.id,
        thread_id,
        user_low_id,
        user_high_id,
        row.key_version,
    )
    return row, True


def get_conversation_dek(key_row: ConversationKey) -> bytes:
    master = master_key_bytes()
    aad = conversation_aad(key_row.thread_id, key_row.user_low_id, key_row.user_high_id)
    return unwrap_key(master, key_row.wrap_nonce, key_row.wrapped_dek, aad=aad)
