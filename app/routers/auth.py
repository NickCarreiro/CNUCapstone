from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.core import Session as SessionModel
from app.models.core import User
from app.schemas.auth import LoginRequest, SessionOut, UserCreate, UserOut
from app.services.security import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    hash_password,
    verify_password,
)
from app.services.sessions import create_session
import pyotp

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")

    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=SessionOut)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if user.totp_enabled:
        if not payload.totp_code:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="TOTP required")
        secret = decrypt_totp_secret(user.totp_secret_enc or "")
        if not pyotp.TOTP(secret).verify(payload.totp_code):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP")

    session = create_session(db, user)
    user.last_login = datetime.utcnow()
    db.commit()
    db.refresh(session)
    return session


@router.post("/logout")
def logout(session_id: str, db: Session = Depends(get_db)):
    session = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    session.is_active = False
    db.commit()
    return {"status": "ok"}


@router.post("/totp/enroll")
def enroll_totp(user_id: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    totp = pyotp.TOTP(pyotp.random_base32())
    user.totp_secret_enc = encrypt_totp_secret(totp.secret)
    user.totp_enabled = True
    db.commit()
    return {"provisioning_uri": totp.provisioning_uri(name=user.username)}
