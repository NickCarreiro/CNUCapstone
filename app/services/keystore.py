from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.core import User, UserKey
from app.services.crypto import generate_key_32, unwrap_key, wrap_key
from app.services.key_derivation import master_key_bytes


def ensure_user_key(db: Session, user: User) -> UserKey:
    existing = db.query(UserKey).filter(UserKey.user_id == user.id).first()
    if existing:
        return existing

    master = master_key_bytes()
    dek = generate_key_32()
    wrap_nonce, wrapped = wrap_key(master, dek, aad=str(user.id).encode())

    record = UserKey(user_id=user.id, wrap_nonce=wrap_nonce, wrapped_dek=wrapped, key_version=1)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_user_dek(db: Session, user: User) -> bytes:
    key_row = ensure_user_key(db, user)
    master = master_key_bytes()
    return unwrap_key(master, key_row.wrap_nonce, key_row.wrapped_dek, aad=str(user.id).encode())
