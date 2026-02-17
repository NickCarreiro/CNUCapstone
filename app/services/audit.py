from __future__ import annotations

from datetime import datetime

from fastapi import Request

from app.models.core import AuditLog, User


def _request_ip(request: Request | None) -> str | None:
    if not request:
        return None
    # If behind nginx/ALB, these may be present. We treat them as best-effort.
    xff = (request.headers.get("x-forwarded-for") or "").strip()
    if xff:
        # XFF may contain a chain. Use the first entry.
        first = xff.split(",")[0].strip()
        return first[:64] if first else None
    xreal = (request.headers.get("x-real-ip") or "").strip()
    if xreal:
        return xreal[:64]
    host = getattr(getattr(request, "client", None), "host", None)
    return str(host)[:64] if host else None


def add_audit_log(
    db,
    *,
    user: User | None,
    event_type: str,
    details: str | None = None,
    request: Request | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    row = AuditLog(
        user_id=user.id if user else None,
        event_type=event_type,
        event_timestamp=datetime.utcnow(),
        ip_address=(ip_address or _request_ip(request)),
        details=details,
    )
    db.add(row)
    return row
