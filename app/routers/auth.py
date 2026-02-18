from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.core import Session as SessionModel
from app.models.core import User
from app.schemas.auth import LoginRequest, SessionOut, UserCreate, UserOut
from app.services.audit import add_audit_log
from app.services.security import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    hash_password,
    verify_password,
)
from app.services.sessions import create_session
from app.services.keystore import ensure_user_key
import pyotp

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut)
def register(payload: UserCreate, request: Request, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")

    is_first_user = db.query(User.id).first() is None
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        is_admin=is_first_user,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    ensure_user_key(db, user)
    add_audit_log(
        db,
        user=user,
        event_type="account.registered",
        details="Account created via API registration.",
        request=request,
    )
    if user.is_admin:
        add_audit_log(
            db,
            user=user,
            event_type="account.role_admin_granted",
            details="System administrator role granted.",
            request=request,
        )
    db.commit()
    return user


@router.post("/login", response_model=SessionOut)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not verify_password(payload.password, user.password_hash):
        add_audit_log(
            db,
            user=user,
            event_type="signin.failed_password",
            details="API login password verification failed.",
            request=request,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if user.totp_enabled:
        if not payload.totp_code:
            add_audit_log(
                db,
                user=user,
                event_type="signin.failed_totp_required",
                details="API MFA code required.",
                request=request,
            )
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="TOTP required")
        secret = decrypt_totp_secret(user.totp_secret_enc or "")
        if not pyotp.TOTP(secret).verify(payload.totp_code):
            add_audit_log(
                db,
                user=user,
                event_type="signin.failed_totp_invalid",
                details="API MFA verification failed.",
                request=request,
            )
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP")

    if getattr(user, "is_disabled", False):
        add_audit_log(
            db,
            user=user,
            event_type="signin.blocked_disabled",
            details="API sign-in blocked (account disabled).",
            request=request,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    ensure_user_key(db, user)
    session = create_session(db, user)
    user.last_login = datetime.utcnow()
    add_audit_log(
        db,
        user=user,
        event_type="signin.success",
        details="API sign-in completed.",
        request=request,
    )
    db.commit()
    db.refresh(session)
    return session


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    # Prefer logging out the caller's current session (cookie or Authorization bearer token)
    session_id = request.cookies.get("pfv_session")
    auth = request.headers.get("authorization")
    if not session_id and auth and auth.lower().startswith("bearer "):
        session_id = auth.split(" ", 1)[1].strip()
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        import uuid

        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

    session = db.query(SessionModel).filter(SessionModel.id == sid).first()
    if session:
        user = db.query(User).filter(User.id == session.user_id).first()
        session.is_active = False
        if user:
            add_audit_log(db, user=user, event_type="signout", details="API sign-out completed.", request=request)
        db.commit()
    return {"status": "ok"}


@router.post("/totp/enroll")
def enroll_totp(user_id: str, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    totp = pyotp.TOTP(pyotp.random_base32())
    user.totp_secret_enc = encrypt_totp_secret(totp.secret)
    user.totp_enabled = True
    add_audit_log(db, user=user, event_type="mfa.enabled", details="MFA enabled via API enrollment.", request=request)
    db.commit()
    return {"provisioning_uri": totp.provisioning_uri(name=user.username)}
