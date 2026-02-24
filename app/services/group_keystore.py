from __future__ import annotations

import logging

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.core import AuditLog, Group, GroupKey
from app.services.crypto import generate_key_32, unwrap_key, wrap_key
from app.services.key_derivation import master_key_bytes

logger = logging.getLogger(__name__)


def ensure_group_key(db: Session, group: Group) -> GroupKey:
    existing = db.query(GroupKey).filter(GroupKey.group_id == group.id).first()
    if existing:
        return existing

    master = master_key_bytes()
    dek = generate_key_32()
    wrap_nonce, wrapped = wrap_key(master, dek, aad=f"group:{group.id}".encode())
    record = GroupKey(group_id=group.id, wrap_nonce=wrap_nonce, wrapped_dek=wrapped, key_version=1)
    try:
        db.add(record)
        db.flush()
        db.add(
            AuditLog(
                user_id=None,
                event_type="encryption.group_key_provisioned",
                details=(
                    f"Provisioned group key id={record.id} for group={group.id} "
                    f"version={record.key_version}."
                ),
            )
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.query(GroupKey).filter(GroupKey.group_id == group.id).first()
        if existing:
            return existing
        raise
    db.refresh(record)
    logger.info(
        "Provisioned group key id=%s for group=%s version=%s",
        record.id,
        group.id,
        record.key_version,
    )
    return record


def get_group_dek(db: Session, group: Group) -> bytes:
    key_row = ensure_group_key(db, group)
    master = master_key_bytes()
    return unwrap_key(master, key_row.wrap_nonce, key_row.wrapped_dek, aad=f"group:{group.id}".encode())
