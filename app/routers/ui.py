import os
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models.core import FileRecord, Session as SessionModel, User
from app.services.security import decrypt_totp_secret, encrypt_totp_secret, verify_password
from app.services.sessions import create_session
import pyotp

router = APIRouter(prefix="/ui", tags=["ui"])
templates = Jinja2Templates(directory="templates")


def _get_session(db: Session, session_id: str | None) -> SessionModel | None:
    if not session_id:
        return None
    try:
        parsed = uuid.UUID(session_id)
    except ValueError:
        return None
    return (
        db.query(SessionModel)
        .filter(
            SessionModel.id == parsed,
            SessionModel.is_active.is_(True),
            SessionModel.expires_at > datetime.utcnow(),
        )
        .first()
    )


def _get_current_user(db: Session, request: Request) -> User | None:
    session_id = request.cookies.get("pfv_session")
    session = _get_session(db, session_id)
    if not session:
        return None
    return db.query(User).filter(User.id == session.user_id).first()


def _user_root(user: User) -> Path:
    root = Path(settings.staging_path) / str(user.id)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _safe_join(root: Path, rel_path: str) -> Path:
    rel = (rel_path or "").strip()
    rel = rel.lstrip("/").replace("\\", "/")
    candidate = (root / rel).resolve()
    root_resolved = root.resolve()
    if not candidate.is_relative_to(root_resolved):
        raise HTTPException(status_code=400, detail="Invalid path")
    return candidate


@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login")
def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    totp_code: str | None = Form(None),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password"},
            status_code=401,
        )

    if user.totp_enabled:
        if not totp_code:
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "TOTP code required"},
                status_code=401,
            )
        secret = decrypt_totp_secret(user.totp_secret_enc or "")
        if not pyotp.TOTP(secret).verify(totp_code):
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Invalid TOTP code"},
                status_code=401,
            )

    session = create_session(db, user)
    user.last_login = datetime.utcnow()
    db.commit()

    response = RedirectResponse(url="/ui", status_code=303)
    response.set_cookie("pfv_session", str(session.id), httponly=True)
    return response


@router.get("")
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    files = db.query(FileRecord).filter(FileRecord.user_id == user.id).all()
    root = _user_root(user).resolve()
    file_rows = []
    for record in files:
        try:
            rel = Path(record.file_path).resolve().relative_to(root)
            rel_path = str(rel)
        except ValueError:
            rel_path = record.file_path
        file_rows.append({"record": record, "rel_path": rel_path})

    folder_rows = []
    for dirpath, dirnames, _ in os.walk(root):
        rel = Path(dirpath).resolve().relative_to(root)
        rel_path = "" if str(rel) == "." else str(rel)
        depth = 0 if rel_path == "" else len(Path(rel_path).parts)
        folder_rows.append({"path": rel_path, "depth": depth})
        dirnames.sort()
    folder_rows.sort(key=lambda item: (item["depth"], item["path"]))

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "files": file_rows,
            "folders": folder_rows,
            "error": None,
        },
    )


@router.get("/totp")
def totp_setup(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    secret = None
    provisioning_uri = None
    if user.totp_enabled:
        return templates.TemplateResponse(
            "totp_setup.html",
            {
                "request": request,
                "user": user,
                "enabled": True,
                "secret": None,
                "provisioning_uri": None,
                "error": None,
            },
        )

    if user.totp_secret_enc:
        secret = decrypt_totp_secret(user.totp_secret_enc)
    else:
        totp = pyotp.TOTP(pyotp.random_base32())
        secret = totp.secret
        user.totp_secret_enc = encrypt_totp_secret(secret)
        db.commit()

    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.username, issuer_name=settings.totp_issuer
    )

    return templates.TemplateResponse(
        "totp_setup.html",
        {
            "request": request,
            "user": user,
            "enabled": False,
            "secret": secret,
            "provisioning_uri": provisioning_uri,
            "error": None,
        },
    )


@router.post("/totp/verify")
def totp_verify(
    request: Request,
    code: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    if not user.totp_secret_enc:
        return RedirectResponse(url="/ui/totp", status_code=303)

    secret = decrypt_totp_secret(user.totp_secret_enc)
    if not pyotp.TOTP(secret).verify(code):
        return templates.TemplateResponse(
            "totp_setup.html",
            {
                "request": request,
                "user": user,
                "enabled": False,
                "secret": secret,
                "provisioning_uri": pyotp.TOTP(secret).provisioning_uri(
                    name=user.username, issuer_name=settings.totp_issuer
                ),
                "error": "Invalid code. Try the current code from your authenticator app.",
            },
            status_code=400,
        )

    user.totp_enabled = True
    db.commit()
    return RedirectResponse(url="/ui/totp", status_code=303)


@router.post("/totp/disable")
def totp_disable(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    user.totp_enabled = False
    user.totp_secret_enc = None
    db.commit()
    return RedirectResponse(url="/ui/totp", status_code=303)


@router.post("/upload")
def upload_from_ui(
    request: Request,
    folder: str = Form(""),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    user_dir = _user_root(user)
    safe_name = Path(file.filename).name
    dest_dir = _safe_join(user_dir, folder)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / safe_name

    with dest.open("wb") as f:
        for chunk in iter(lambda: file.file.read(1024 * 1024), b""):
            f.write(chunk)

    record = FileRecord(
        user_id=user.id,
        file_name=safe_name,
        file_path=str(dest),
        file_size=dest.stat().st_size,
    )
    db.add(record)
    db.commit()

    return RedirectResponse(url="/ui", status_code=303)


@router.post("/folder")
def create_folder(
    request: Request,
    folder: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    user_dir = _user_root(user)
    dest_dir = _safe_join(user_dir, folder)
    dest_dir.mkdir(parents=True, exist_ok=True)
    return RedirectResponse(url="/ui", status_code=303)


@router.post("/move")
def move_file(
    request: Request,
    file_id: str = Form(...),
    new_folder: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    record = (
        db.query(FileRecord)
        .filter(FileRecord.id == file_id, FileRecord.user_id == user.id)
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="File not found")

    user_dir = _user_root(user)
    dest_dir = _safe_join(user_dir, new_folder)
    dest_dir.mkdir(parents=True, exist_ok=True)

    current_path = Path(record.file_path)
    dest = dest_dir / current_path.name
    current_path.replace(dest)

    record.file_path = str(dest)
    db.commit()
    return RedirectResponse(url="/ui", status_code=303)


@router.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    session_id = request.cookies.get("pfv_session")
    session = _get_session(db, session_id)
    if session:
        session.is_active = False
        db.commit()
    response = RedirectResponse(url="/ui/login", status_code=303)
    response.delete_cookie("pfv_session")
    return response
