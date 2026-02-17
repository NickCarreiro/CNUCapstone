import uuid
from datetime import datetime

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.core import Session as SessionModel
from app.models.core import User


def _get_session_id(request: Request) -> str | None:
    cookie = request.cookies.get("pfv_session")
    if cookie:
        cleaned = cookie.strip().strip('"')
        if cleaned:
            return cleaned

    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip().strip('"')
        if token:
            return token

    return None


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:

    session_id = _get_session_id(request)
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

    session = (
        db.query(SessionModel)
        .filter(
            SessionModel.id == sid,
            SessionModel.is_active.is_(True),
            SessionModel.expires_at > datetime.utcnow(),
        )
        .first()
    )
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")

    user = db.query(User).filter(User.id == session.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return user
