from __future__ import annotations

from app.models.core import ActivityEvent, User


def add_event(db, user: User, *, action: str, message: str, level: str = "INFO") -> ActivityEvent:
    event = ActivityEvent(user_id=user.id, action=action, message=message, level=level)
    db.add(event)
    return event
