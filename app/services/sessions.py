from datetime import datetime
from sqlalchemy.orm import Session

from app.models.core import Session as SessionModel, User
from app.services.security import session_expiry


def create_session(db: Session, user: User) -> SessionModel:
    session = SessionModel(
        user_id=user.id,
        created_at=datetime.utcnow(),
        expires_at=session_expiry(),
        is_active=True,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session
