from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.core import Group, GroupKey
from app.services.crypto import generate_key_32, unwrap_key, wrap_key
from app.services.key_derivation import master_key_bytes


def ensure_group_key(db: Session, group: Group) -> GroupKey:
    existing = db.query(GroupKey).filter(GroupKey.group_id == group.id).first()
    if existing:
        return existing

    master = master_key_bytes()
    dek = generate_key_32()
    wrap_nonce, wrapped = wrap_key(master, dek, aad=f"group:{group.id}".encode())
    record = GroupKey(group_id=group.id, wrap_nonce=wrap_nonce, wrapped_dek=wrapped, key_version=1)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_group_dek(db: Session, group: Group) -> bytes:
    key_row = ensure_group_key(db, group)
    master = master_key_bytes()
    return unwrap_key(master, key_row.wrap_nonce, key_row.wrapped_dek, aad=f"group:{group.id}".encode())
