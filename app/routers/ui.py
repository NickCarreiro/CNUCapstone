import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
import mimetypes
import logging

from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models.core import ActivityEvent, FileRecord, Session as SessionModel, User
from app.services.crypto import decrypt_file_iter, encrypt_file_to_path
from app.services.keystore import ensure_user_key, get_user_dek
from app.services.activity import add_event
from app.services.security import decrypt_totp_secret, encrypt_totp_secret, hash_password, verify_password
from app.services.sessions import create_session
import pyotp

router = APIRouter(prefix="/ui", tags=["ui"])
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger("uvicorn.error")
_FILE_TOKEN_CACHE: dict[str, dict[str, str]] = {}


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


def _get_session_id(request: Request) -> str:
    return request.cookies.get("pfv_session") or ""


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


def _get_user_file(db: Session, user: User, file_id: str) -> FileRecord:
    try:
        fid = uuid.UUID(file_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="File not found")
    record = (
        db.query(FileRecord)
        .filter(FileRecord.id == fid, FileRecord.user_id == user.id)
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="File not found")
    return record


def _issue_file_token(session_id: str, file_id: uuid.UUID) -> str:
    if not session_id:
        return str(file_id)
    token = uuid.uuid4().hex
    _FILE_TOKEN_CACHE.setdefault(session_id, {})[token] = str(file_id)
    return token


def _resolve_file_token(session_id: str, token: str) -> str:
    if session_id:
        cached = _FILE_TOKEN_CACHE.get(session_id, {}).get(token)
        if cached:
            return cached
    try:
        parsed = uuid.UUID(token)
        return str(parsed)
    except ValueError:
        raise HTTPException(status_code=404, detail="File not found")


def _get_user_file_by_token(db: Session, user: User, request: Request, token: str) -> FileRecord:
    session_id = _get_session_id(request)
    file_id = _resolve_file_token(session_id, token)
    return _get_user_file(db, user, file_id)


def _resolve_user_file_path(user: User, path_str: str) -> Path:
    user_dir = _user_root(user).resolve()
    resolved = Path(path_str).resolve()
    if not resolved.is_relative_to(user_dir):
        raise HTTPException(status_code=400, detail="Invalid file path")
    return resolved


def _ensure_tree_node(node: dict) -> dict:
    if "__files__" not in node:
        node["__files__"] = []
    return node


def _build_vault_tree(root: Path, files: list[FileRecord]) -> dict:
    tree: dict[str, dict] = {}
    _ensure_tree_node(tree)

    for dirpath, dirnames, _ in os.walk(root):
        if ".trash" in Path(dirpath).parts:
            continue
        rel = Path(dirpath).resolve().relative_to(root)
        if str(rel) == ".":
            node = tree
        else:
            node = tree
            for part in rel.parts:
                node = node.setdefault(part, {})
                _ensure_tree_node(node)
        dirnames.sort()

    for record in files:
        try:
            rel = Path(record.file_path).resolve().relative_to(root)
        except ValueError:
            continue
        parts = rel.parts
        if not parts:
            continue
        *folders, filename = parts
        node = tree
        for part in folders:
            node = node.setdefault(part, {})
            _ensure_tree_node(node)
        _ensure_tree_node(node)
        node["__files__"].append(filename)

    def _sort_tree(node: dict) -> None:
        if "__files__" in node:
            node["__files__"].sort()
        for key in sorted(k for k in node.keys() if k != "__files__"):
            _sort_tree(node[key])

    _sort_tree(tree)
    return tree


def _normalize_rel_path(value: str) -> str:
    return (value or "").strip().lstrip("/").replace("\\", "/")


def _parse_terminal_command(raw: str) -> tuple[str, list[str]]:
    tokens = [t for t in (raw or "").strip().split() if t]
    if not tokens:
        return "", []
    cmd = tokens[0].lower()
    aliases = {
        "ls": "list",
        "mv": "move",
        "cp": "copy",
        "mkdir": "directory",
    }
    cmd = aliases.get(cmd, cmd)
    return cmd, tokens[1:]


def _format_list_entries(entries: list[str]) -> str:
    if not entries:
        return "(empty)"
    return "\n".join(entries)


def _ensure_no_symlink(path: Path, root: Path) -> None:
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid path")
    current = root.resolve()
    for part in rel.parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise HTTPException(status_code=400, detail="Symlinks are not allowed")


@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {"request": request, "error": None, "username": None},
    )


@router.post("/register")
def register_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
):
    username = username.strip()
    if not username:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Username is required.", "username": username},
            status_code=400,
        )
    if password != confirm_password:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Passwords do not match.", "username": username},
            status_code=400,
        )
    if len(password) < 10:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Password must be at least 10 characters.", "username": username},
            status_code=400,
        )

    existing = db.query(User).filter(User.username == username).first()
    if existing:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Username already exists.", "username": username},
            status_code=409,
        )

    user = User(username=username, password_hash=hash_password(password))
    db.add(user)
    db.commit()
    db.refresh(user)

    ensure_user_key(db, user)
    add_event(db, user, action="auth", message=f"Account created for '{user.username}'.")
    session = create_session(db, user)
    user.last_login = datetime.utcnow()
    db.commit()

    response = RedirectResponse(url="/ui", status_code=303)
    response.set_cookie("pfv_session", str(session.id), httponly=True)
    return response


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

    ensure_user_key(db, user)
    add_event(db, user, action="auth", message=f"Signed in as '{user.username}'.")
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

    files = (
        db.query(FileRecord)
        .filter(FileRecord.user_id == user.id, FileRecord.is_trashed.is_(False))
        .all()
    )
    session_id = _get_session_id(request)
    if session_id:
        _FILE_TOKEN_CACHE[session_id] = {}
    root = _user_root(user).resolve()
    file_rows = []
    for idx, record in enumerate(files, start=1):
        try:
            rel = Path(record.file_path).resolve().relative_to(root)
            rel_path = str(rel)
        except ValueError:
            rel_path = record.file_path
        token = _issue_file_token(session_id, record.id)
        file_rows.append(
            {
                "record": record,
                "rel_path": rel_path,
                "token": token,
                "display_name": f"File {idx}",
            }
        )

    folder_rows = []
    for dirpath, dirnames, _ in os.walk(root):
        # Hide trash folder from the picker/tree.
        if ".trash" in Path(dirpath).parts:
            continue
        rel = Path(dirpath).resolve().relative_to(root)
        rel_path = "" if str(rel) == "." else str(rel)
        depth = 0 if rel_path == "" else len(Path(rel_path).parts)
        folder_rows.append({"path": rel_path, "depth": depth})
        dirnames.sort()
    folder_rows.sort(key=lambda item: (item["depth"], item["path"]))

    folder_tree: dict[str, dict] = {}
    for folder in folder_rows:
        if not folder["path"]:
            continue
        node = folder_tree
        for part in Path(folder["path"]).parts:
            node = node.setdefault(part, {})

    vault_tree = _build_vault_tree(root, files)

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "files": file_rows,
            "folders": folder_rows,
            "folder_tree": folder_tree,
            "vault_tree": vault_tree,
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

    ensure_user_key(db, user)
    dek = get_user_dek(db, user)
    user_dir = _user_root(user)
    safe_name = Path(file.filename).name
    dest_dir = _safe_join(user_dir, folder)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / safe_name

    add_event(
        db,
        user,
        action="encrypt",
        message=f"Encrypting upload '{safe_name}' -> '{folder or '/'}' (AES-256-GCM)...",
    )
    db.commit()

    nonce_b64, tag_b64, plain_size = encrypt_file_to_path(dek, file.file, dest)
    mime_type, _ = mimetypes.guess_type(safe_name)

    record = FileRecord(
        user_id=user.id,
        file_name=safe_name,
        file_path=str(dest),
        file_size=plain_size,
        original_path=None,
        is_trashed=False,
        trashed_at=None,
        is_encrypted=True,
        enc_nonce=nonce_b64,
        enc_tag=tag_b64,
        mime_type=mime_type,
    )
    db.add(record)
    add_event(
        db,
        user,
        action="upload",
        message=f"Upload complete: '{safe_name}' ({plain_size} bytes).",
        level="SUCCESS",
    )
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
    add_event(db, user, action="fs", message=f"Created folder '{folder}'.", level="SUCCESS")
    db.commit()
    return RedirectResponse(url="/ui", status_code=303)


@router.post("/move")
def move_file(
    request: Request,
    file_token: str = Form(...),
    new_folder: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    record = _get_user_file_by_token(db, user, request, file_token)
    if record.is_trashed:
        raise HTTPException(status_code=400, detail="File is in trash")

    user_dir = _user_root(user)
    dest_dir = _safe_join(user_dir, new_folder)
    dest_dir.mkdir(parents=True, exist_ok=True)

    current_path = _resolve_user_file_path(user, record.file_path)
    dest = dest_dir / current_path.name
    current_path.replace(dest)

    record.file_path = str(dest)
    add_event(db, user, action="fs", message=f"Moved '{record.file_name}' -> '{new_folder or '/'}'.", level="SUCCESS")
    db.commit()
    return RedirectResponse(url="/ui", status_code=303)


@router.post("/rename")
def rename_file(
    request: Request,
    file_token: str = Form(...),
    new_name: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    record = _get_user_file_by_token(db, user, request, file_token)
    safe_name = Path(new_name).name.strip()
    if not safe_name:
        raise HTTPException(status_code=400, detail="Invalid name")

    old_name = record.file_name
    current_path = _resolve_user_file_path(user, record.file_path)
    dest = current_path.with_name(safe_name)
    current_path.replace(dest)

    record.file_name = safe_name
    record.file_path = str(dest)
    if record.is_trashed and record.original_path:
        record.original_path = str(Path(record.original_path).with_name(safe_name))
    add_event(db, user, action="fs", message=f"Renamed '{old_name}' -> '{safe_name}'.", level="SUCCESS")
    db.commit()
    return RedirectResponse(url=request.headers.get("referer", "/ui"), status_code=303)


@router.post("/trash")
def trash_file(
    request: Request,
    file_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    record = _get_user_file_by_token(db, user, request, file_token)
    if record.is_trashed:
        return RedirectResponse(url="/ui", status_code=303)

    current_path = _resolve_user_file_path(user, record.file_path)
    user_dir = _user_root(user)
    trash_dir = (user_dir / ".trash" / str(record.id)).resolve()
    trash_dir.mkdir(parents=True, exist_ok=True)
    dest = trash_dir / current_path.name
    current_path.replace(dest)

    record.original_path = str(current_path)
    record.file_path = str(dest)
    record.is_trashed = True
    record.trashed_at = datetime.utcnow()
    add_event(db, user, action="fs", message=f"Trashed '{record.file_name}'.", level="WARN")
    db.commit()
    return RedirectResponse(url="/ui", status_code=303)


@router.get("/trash")
def trash_view(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    files = (
        db.query(FileRecord)
        .filter(FileRecord.user_id == user.id, FileRecord.is_trashed.is_(True))
        .all()
    )
    session_id = _get_session_id(request)
    if session_id:
        _FILE_TOKEN_CACHE[session_id] = {}
    root = _user_root(user).resolve()
    rows = []
    for idx, record in enumerate(files, start=1):
        try:
            rel = Path(record.file_path).resolve().relative_to(root)
            rel_path = str(rel)
        except ValueError:
            rel_path = record.file_path
        token = _issue_file_token(session_id, record.id)
        rows.append(
            {
                "record": record,
                "rel_path": rel_path,
                "token": token,
                "display_name": f"File {idx}",
            }
        )

    return templates.TemplateResponse(
        "trash.html",
        {"request": request, "user": user, "files": rows},
    )


@router.post("/restore")
def restore_file(
    request: Request,
    file_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    record = _get_user_file_by_token(db, user, request, file_token)
    if not record.is_trashed or not record.original_path:
        return RedirectResponse(url="/ui/trash", status_code=303)

    current_path = _resolve_user_file_path(user, record.file_path)
    dest = _resolve_user_file_path(user, record.original_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    current_path.replace(dest)

    record.file_path = str(dest)
    record.is_trashed = False
    record.trashed_at = None
    record.original_path = None
    add_event(db, user, action="fs", message=f"Restored '{record.file_name}'.", level="SUCCESS")
    db.commit()
    return RedirectResponse(url="/ui", status_code=303)


@router.post("/delete")
def delete_forever(
    request: Request,
    file_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    record = _get_user_file_by_token(db, user, request, file_token)
    path = _resolve_user_file_path(user, record.file_path)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    add_event(db, user, action="fs", message=f"Deleted forever '{record.file_name}'.", level="ERROR")
    db.delete(record)
    db.commit()
    return RedirectResponse(url="/ui/trash", status_code=303)


@router.get("/files/{file_token}")
def open_file(file_token: str, request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    record = _get_user_file_by_token(db, user, request, file_token)
    resolved = _resolve_user_file_path(user, record.file_path)
    if not resolved.exists():
        raise HTTPException(status_code=404, detail="File missing on disk")

    headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
    if not record.is_encrypted or not record.enc_nonce or not record.enc_tag:
        return FileResponse(
            path=resolved,
            filename=record.file_name,
            media_type=record.mime_type or "application/octet-stream",
            headers=headers,
        )

    add_event(db, user, action="decrypt", message=f"Decrypting '{record.file_name}' for download...")
    db.commit()
    dek = get_user_dek(db, user)
    headers["Content-Disposition"] = f'attachment; filename="{record.file_name}"'
    return StreamingResponse(
        decrypt_file_iter(dek, resolved, record.enc_nonce or "", record.enc_tag or ""),
        media_type=record.mime_type or "application/octet-stream",
        headers=headers,
    )


@router.get("/preview/{file_token}")
def preview_file(file_token: str, request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    record = _get_user_file_by_token(db, user, request, file_token)
    resolved = _resolve_user_file_path(user, record.file_path)
    if not resolved.exists():
        raise HTTPException(status_code=404, detail="File missing on disk")

    headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
    if not record.is_encrypted or not record.enc_nonce or not record.enc_tag:
        media_type, _ = mimetypes.guess_type(record.file_name)
        headers["Content-Disposition"] = f'inline; filename="{record.file_name}"'
        logger.info("preview: serving plaintext file '%s' (user=%s)", record.file_name, user.username)
        return FileResponse(path=resolved, filename=record.file_name, media_type=media_type, headers=headers)

    add_event(db, user, action="decrypt", message=f"Decrypting '{record.file_name}' for preview...")
    db.commit()
    dek = get_user_dek(db, user)
    headers["Content-Disposition"] = f'inline; filename="{record.file_name}"'
    logger.info("preview: decrypting file '%s' (user=%s)", record.file_name, user.username)
    return StreamingResponse(
        decrypt_file_iter(dek, resolved, record.enc_nonce or "", record.enc_tag or ""),
        media_type=record.mime_type or "application/octet-stream",
        headers=headers,
    )


@router.get("/activity")
def activity_feed(
    request: Request,
    response: Response,
    after_id: int = 0,
    limit: int = 200,
    tail: bool = False,
    redact: bool = False,
    no_history: bool = False,
    db: Session = Depends(get_db),
):
    response.headers["Cache-Control"] = "no-store"
    user = _get_current_user(db, request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    limit = max(1, min(limit, 200))
    q = db.query(ActivityEvent).filter(ActivityEvent.user_id == user.id)
    last_id = (
        db.query(ActivityEvent.id)
        .filter(ActivityEvent.user_id == user.id)
        .order_by(ActivityEvent.id.desc())
        .limit(1)
        .scalar()
    )

    if no_history and after_id <= 0:
        return {"events": [], "last_id": last_id or 0}

    if tail and after_id <= 0:
        rows = q.order_by(ActivityEvent.id.desc()).limit(limit).all()
        rows.reverse()
    else:
        rows = q.filter(ActivityEvent.id > after_id).order_by(ActivityEvent.id).limit(limit).all()

    def _redact_message(action: str) -> str:
        return {
            "auth": "Authentication event.",
            "decrypt": "File decrypted.",
            "upload": "Upload completed.",
            "fs": "Filesystem operation.",
            "terminal": "Terminal command executed.",
            "cmd": "Terminal command executed.",
        }.get(action, "Activity event.")

    return {
        "events": [
            {
                "id": row.id,
                "ts": row.event_timestamp.isoformat(),
                "level": row.level,
                "action": row.action,
                "message": _redact_message(row.action) if redact else row.message,
            }
            for row in rows
        ],
        "last_id": last_id or 0,
    }


@router.post("/terminal")
def terminal_command(
    request: Request,
    command: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    cmd, args = _parse_terminal_command(command)
    if cmd == "help":
        message = (
            "Commands:\n"
            "  list [folder]\n"
            "  move <src> <dst>\n"
            "  copy <src> <dst>\n"
            "  rename <src> <dst>\n"
            "  directory <path>\n"
            "Paths are relative to your vault."
        )
        add_event(db, user, action="terminal", message=message)
        return {"ok": True, "message": message}

    if cmd not in {"list", "move", "copy", "rename", "directory"}:
        raise HTTPException(status_code=400, detail="Unsupported command")

    root = _user_root(user)
    safe_args = [_normalize_rel_path(a) for a in args]

    if cmd == "list":
        target = safe_args[0] if safe_args else ""
        path = _safe_join(root, target)
        _ensure_no_symlink(path, root)
        if not path.exists() or not path.is_dir():
            raise HTTPException(status_code=400, detail="Folder not found")
        entries = []
        for item in sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
            if item.is_symlink():
                continue
            name = f"{item.name}/" if item.is_dir() else item.name
            entries.append(name)
        message = _format_list_entries(entries)
        add_event(db, user, action="terminal", message=f"list {target or '/'}\n{message}")
        return {"ok": True, "message": message}

    if cmd == "directory":
        if len(safe_args) < 1:
            raise HTTPException(status_code=400, detail="Missing directory path")
        target = _safe_join(root, safe_args[0])
        _ensure_no_symlink(target, root)
        target.mkdir(parents=True, exist_ok=True)
        add_event(db, user, action="terminal", message=f"directory {safe_args[0]}")
        return {"ok": True, "message": "Directory created."}

    if len(safe_args) < 2:
        raise HTTPException(status_code=400, detail="Missing path arguments")

    src = _safe_join(root, safe_args[0])
    dst = _safe_join(root, safe_args[1])

    _ensure_no_symlink(src, root)
    _ensure_no_symlink(dst.parent, root)

    if not src.exists():
        raise HTTPException(status_code=400, detail="Source not found")

    if cmd == "rename":
        _ensure_no_symlink(dst.parent, root)
        if src.is_dir():
            dst = dst if dst.suffix == "" else dst
        if dst.exists():
            raise HTTPException(status_code=400, detail="Destination already exists")
        src.rename(dst)
        add_event(db, user, action="terminal", message=f"rename {safe_args[0]} -> {safe_args[1]}")
        return {"ok": True, "message": "Renamed."}

    if cmd == "move":
        _ensure_no_symlink(dst.parent, root)
        if dst.exists():
            raise HTTPException(status_code=400, detail="Destination already exists")
        shutil.move(str(src), str(dst))
        add_event(db, user, action="terminal", message=f"move {safe_args[0]} -> {safe_args[1]}")
        return {"ok": True, "message": "Moved."}

    if cmd == "copy":
        _ensure_no_symlink(dst.parent, root)
        if dst.exists():
            raise HTTPException(status_code=400, detail="Destination already exists")
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        add_event(db, user, action="terminal", message=f"copy {safe_args[0]} -> {safe_args[1]}")
        return {"ok": True, "message": "Copied."}

    raise HTTPException(status_code=400, detail="Unsupported command")


@router.get("/terminal/suggest")
def terminal_suggest(
    request: Request,
    prefix: str = "",
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    root = _user_root(user)
    raw = _normalize_rel_path(prefix)
    base_dir = raw
    partial = ""
    if raw and not raw.endswith("/"):
        base_dir = str(Path(raw).parent) if str(Path(raw).parent) != "." else ""
        partial = Path(raw).name

    target_dir = _safe_join(root, base_dir)
    if not target_dir.exists() or not target_dir.is_dir():
        return {"suggestions": []}

    suggestions: list[str] = []
    for item in sorted(target_dir.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
        name = item.name
        if partial and not name.lower().startswith(partial.lower()):
            continue
        rel = str(Path(base_dir) / name) if base_dir else name
        if item.is_dir():
            rel = f"{rel}/"
        suggestions.append(rel)

    return {"suggestions": suggestions[:50]}


@router.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    session_id = request.cookies.get("pfv_session")
    session = _get_session(db, session_id)
    if session:
        user = db.query(User).filter(User.id == session.user_id).first()
        session.is_active = False
        if user:
            add_event(db, user, action="auth", message="Signed out.")
        db.commit()
    response = RedirectResponse(url="/ui/login", status_code=303)
    response.delete_cookie("pfv_session")
    return response
