from __future__ import annotations

from datetime import datetime

from app.models.core import AuditLog, User


def add_audit_log(
    db,
    *,
    user: User | None,
    event_type: str,
    details: str | None = None,
) -> AuditLog:
    row = AuditLog(
        user_id=user.id if user else None,
        event_type=event_type,
        event_timestamp=datetime.utcnow(),
        details=details,
    )
    db.add(row)
    return row
