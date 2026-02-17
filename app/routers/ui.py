import os
import shlex
import shutil
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from urllib.parse import quote_plus

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
import mimetypes
import logging

from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models.core import (
    ActivityEvent,
    AuditLog,
    DirectMessage,
    FileRecord,
    Group,
    GroupFileRecord,
    GroupInvite,
    GroupKey,
    GroupMembership,
    Session as SessionModel,
    User,
    UserKey,
)
from app.services.crypto import b64d, decrypt_file_iter, encrypt_file_to_path, unwrap_key
from app.services.key_derivation import master_key_bytes, using_passphrase
from app.services.group_keystore import ensure_group_key, get_group_dek
from app.services.keystore import ensure_user_key, get_user_dek
from app.services.activity import add_event
from app.services.audit import add_audit_log
from app.services.security import decrypt_totp_secret, encrypt_totp_secret, hash_password, verify_password
from app.services.sessions import create_session
import pyotp

router = APIRouter(prefix="/ui", tags=["ui"])
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger("uvicorn.error")
_FILE_TOKEN_CACHE: dict[str, dict[str, str]] = {}
_TERMINAL_SCOPE_CACHE: dict[str, dict[str, str]] = {}

_TERMINAL_COMMANDS = [
    "help",
    "pwd",
    "scope",
    "groups",
    "usegroup",
    "useuser",
    "list",
    "tree",
    "find",
    "stat",
    "view",
    "hash",
    "quota",
    "encstatus",
    "encproof",
    "gfiles",
    "gdownload",
    "directory",
    "move",
    "copy",
    "rename",
]
_TERMINAL_SCAN_LIMIT = 20000
_TERMINAL_RESULT_LIMIT = 200
_TERMINAL_PREVIEW_MAX_BYTES = 256 * 1024
_TERMINAL_PREVIEW_MAX_LINES = 200
_TERMINAL_ENCPROOF_MAX_DECRYPT_BYTES = 32 * 1024
_TERMINAL_ENCPROOF_PREVIEW_LINES = 40
_TERMINAL_TEXT_EXTS = {
    ".txt",
    ".md",
    ".csv",
    ".log",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".py",
    ".js",
    ".ts",
    ".html",
    ".css",
    ".xml",
    ".rst",
}


def _hex_bytes(data: bytes, *, limit: int = 64) -> str:
    view = data[: max(0, int(limit))]
    return " ".join(f"{b:02x}" for b in view) if view else "(empty)"


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


def _group_root(group_id: uuid.UUID) -> Path:
    root = Path(settings.staging_path) / "groups" / str(group_id)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _terminal_scope_key(request: Request) -> str:
    # Scope is stored per browser session cookie; empty means "no scope".
    return _get_session_id(request)


def _terminal_set_scope_user(request: Request) -> None:
    key = _terminal_scope_key(request)
    if not key:
        return
    _TERMINAL_SCOPE_CACHE[key] = {"type": "user"}


def _terminal_set_scope_group(request: Request, *, group_id: uuid.UUID, group_name: str) -> None:
    key = _terminal_scope_key(request)
    if not key:
        return
    _TERMINAL_SCOPE_CACHE[key] = {"type": "group", "group_id": str(group_id), "group_name": group_name}


def _terminal_get_scope(request: Request) -> dict[str, str]:
    key = _terminal_scope_key(request)
    if not key:
        return {"type": "user"}
    scope = _TERMINAL_SCOPE_CACHE.get(key)
    if not scope:
        scope = {"type": "user"}
        _TERMINAL_SCOPE_CACHE[key] = scope
    return scope


def _terminal_root_for_scope(user: User, scope: dict[str, str]) -> tuple[Path, str]:
    if scope.get("type") == "group" and scope.get("group_id"):
        try:
            gid = uuid.UUID(scope["group_id"])
        except ValueError:
            return _user_root(user), "user"
        return _group_root(gid), f"group:{scope.get('group_name') or gid}"
    return _user_root(user), "user"


def _admin_redirect(message: str, *, error: bool = False) -> RedirectResponse:
    key = "error" if error else "notice"
    return RedirectResponse(url=f"/ui/admin/users?{key}={quote_plus(message)}", status_code=303)


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
    raw = (raw or "").strip()
    if not raw:
        return "", []
    try:
        tokens = shlex.split(raw)
    except ValueError:
        tokens = raw.split()
    if not tokens:
        return "", []
    cmd = tokens[0].lower()
    aliases = {
        "ls": "list",
        "mv": "move",
        "cp": "copy",
        "mkdir": "directory",
        "cat": "view",
        "sha256": "hash",
        "du": "quota",
        "encryption": "encstatus",
        "cryptostatus": "encstatus",
        "keys": "encstatus",
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


def _terminal_rel_path(root: Path, path: Path) -> str:
    rel = path.resolve().relative_to(root.resolve())
    rel_str = str(rel).replace("\\", "/")
    return "/" if rel_str == "." else rel_str


def _format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    unit = units[0]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            break
        value /= 1024
    if unit == "B":
        return f"{int(value)} {unit}"
    return f"{value:.2f} {unit}"


def _parse_int_arg(value: str, *, default: int, minimum: int, maximum: int, name: str) -> int:
    if value == "":
        return default
    try:
        parsed = int(value)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{name} must be an integer")
    if parsed < minimum or parsed > maximum:
        raise HTTPException(status_code=400, detail=f"{name} must be between {minimum} and {maximum}")
    return parsed


def _build_tree_lines(root: Path, start: Path, *, depth: int) -> list[str]:
    base = _terminal_rel_path(root, start)
    lines = ["/" if base == "/" else f"{base}/"]
    scanned = 0

    def walk(path: Path, prefix: str, level: int) -> bool:
        nonlocal scanned
        if level >= depth:
            return False

        try:
            entries = [p for p in sorted(path.iterdir(), key=lambda x: (x.is_file(), x.name.lower())) if not p.is_symlink()]
        except OSError:
            lines.append(f"{prefix}`-- [unreadable]")
            return False
        for idx, entry in enumerate(entries):
            scanned += 1
            if scanned > _TERMINAL_SCAN_LIMIT:
                lines.append(f"{prefix}`-- ... (scan limit reached)")
                return True
            connector = "`-- " if idx == len(entries) - 1 else "|-- "
            label = f"{entry.name}/" if entry.is_dir() else entry.name
            lines.append(f"{prefix}{connector}{label}")
            if entry.is_dir():
                child_prefix = f"{prefix}{'    ' if idx == len(entries) - 1 else '|   '}"
                if walk(entry, child_prefix, level + 1):
                    return True
        return False

    walk(start, "", 0)
    return lines


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

    is_first_user = db.query(User.id).first() is None
    user = User(
        username=username,
        password_hash=hash_password(password),
        is_admin=is_first_user,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    ensure_user_key(db, user)
    add_event(db, user, action="auth", message=f"Account created for '{user.username}'.")
    add_audit_log(db, user=user, event_type="account.registered", details="Account created via web registration.", request=request)
    if user.is_admin:
        add_event(db, user, action="auth", message="System administrator role granted to first account.", level="SUCCESS")
        add_audit_log(db, user=user, event_type="account.role_admin_granted", details="System administrator role granted.", request=request)
    session = create_session(db, user)
    user.last_login = datetime.utcnow()
    add_audit_log(db, user=user, event_type="signin.success", details="Signed in after registration.", request=request)
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
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password"},
            status_code=401,
        )
    if not verify_password(password, user.password_hash):
        add_audit_log(db, user=user, event_type="signin.failed_password", details="Password verification failed.", request=request)
        db.commit()
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password"},
            status_code=401,
        )

    if user.totp_enabled:
        if not totp_code:
            add_audit_log(db, user=user, event_type="signin.failed_totp_required", details="MFA code required.", request=request)
            db.commit()
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "TOTP code required"},
                status_code=401,
            )
        secret = decrypt_totp_secret(user.totp_secret_enc or "")
        if not pyotp.TOTP(secret).verify(totp_code):
            add_audit_log(db, user=user, event_type="signin.failed_totp_invalid", details="Invalid MFA code.", request=request)
            db.commit()
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Invalid TOTP code"},
                status_code=401,
            )

    ensure_user_key(db, user)
    add_event(db, user, action="auth", message=f"Signed in as '{user.username}'.")
    add_audit_log(db, user=user, event_type="signin.success", details="Interactive sign-in completed.", request=request)
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
                "display_name": record.file_name,
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


@router.get("/notifications")
def notifications_state(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return Response(status_code=401)

    unread_messages = (
        db.query(func.count(DirectMessage.id))
        .filter(
            DirectMessage.recipient_id == user.id,
            DirectMessage.read_at.is_(None),
        )
        .scalar()
        or 0
    )
    pending_group_invites = (
        db.query(func.count(GroupInvite.id))
        .filter(
            GroupInvite.invitee_id == user.id,
            GroupInvite.status == "pending",
        )
        .scalar()
        or 0
    )
    total_unread = int(unread_messages) + int(pending_group_invites)
    return {
        "unread_messages": int(unread_messages),
        "pending_group_invites": int(pending_group_invites),
        "groups_badge_total": total_unread,
        "server_time_utc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@router.get("/admin/users")
def admin_users_page(request: Request, db: Session = Depends(get_db)):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    now = datetime.utcnow()
    users = db.query(User).order_by(User.created_at.asc(), User.username.asc()).all()
    active_sessions_by_user = {
        user_id: int(count)
        for user_id, count in (
            db.query(SessionModel.user_id, func.count(SessionModel.id))
            .filter(
                SessionModel.is_active.is_(True),
                SessionModel.expires_at > now,
            )
            .group_by(SessionModel.user_id)
            .all()
        )
    }
    files_by_user = {
        user_id: int(count)
        for user_id, count in (
            db.query(FileRecord.user_id, func.count(FileRecord.id))
            .group_by(FileRecord.user_id)
            .all()
        )
    }
    groups_by_user = {
        user_id: int(count)
        for user_id, count in (
            db.query(GroupMembership.user_id, func.count(GroupMembership.id))
            .group_by(GroupMembership.user_id)
            .all()
        )
    }
    admin_count = sum(1 for u in users if u.is_admin)

    rows = [
        {
            "user": target,
            "active_sessions": active_sessions_by_user.get(target.id, 0),
            "file_count": files_by_user.get(target.id, 0),
            "group_count": groups_by_user.get(target.id, 0),
        }
        for target in users
    ]

    return templates.TemplateResponse(
        "admin_users.html",
        {
            "request": request,
            "user": admin_user,
            "rows": rows,
            "admin_count": admin_count,
            "totp_enabled_count": sum(1 for u in users if u.totp_enabled),
            "active_session_total": sum(item["active_sessions"] for item in rows),
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


@router.get("/audit")
def audit_log_page(
    request: Request,
    event: str = "",
    q: str = "",
    limit: int = 200,
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    event_filter = (event or "").strip()
    text_filter = (q or "").strip()
    limit = max(1, min(limit, 1000))

    query = db.query(AuditLog).filter(AuditLog.user_id == user.id)
    if event_filter:
        query = query.filter(AuditLog.event_type.ilike(f"%{event_filter}%"))
    if text_filter:
        like = f"%{text_filter}%"
        query = query.filter(or_(AuditLog.event_type.ilike(like), AuditLog.details.ilike(like)))

    total_matching = query.count()
    logs = query.order_by(AuditLog.event_timestamp.desc(), AuditLog.id.desc()).limit(limit).all()

    signin_events = sum(1 for row in logs if row.event_type.startswith("signin."))
    failed_signins = sum(1 for row in logs if row.event_type.startswith("signin.failed"))
    account_events = sum(
        1
        for row in logs
        if row.event_type.startswith("account.")
        or row.event_type.startswith("mfa.")
        or row.event_type.startswith("signout")
    )

    rows = [{"log": row, "username": user.username} for row in logs]
    return templates.TemplateResponse(
        "audit_log.html",
        {
            "request": request,
            "user": user,
            "rows": rows,
            "is_admin_view": False,
            "title": "My Audit Log",
            "filters": {
                "event": event_filter,
                "q": text_filter,
                "limit": limit,
                "username": "",
            },
            "summary": {
                "displayed": len(rows),
                "matching": total_matching,
                "signin_events": signin_events,
                "failed_signins": failed_signins,
                "account_events": account_events,
            },
        },
    )


@router.get("/admin/audit")
def admin_audit_log_page(
    request: Request,
    username: str = "",
    event: str = "",
    q: str = "",
    limit: int = 400,
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    username_filter = (username or "").strip()
    event_filter = (event or "").strip()
    text_filter = (q or "").strip()
    limit = max(1, min(limit, 2000))

    query = db.query(AuditLog, User.username).outerjoin(User, AuditLog.user_id == User.id)
    if username_filter:
        query = query.filter(User.username.ilike(f"%{username_filter}%"))
    if event_filter:
        query = query.filter(AuditLog.event_type.ilike(f"%{event_filter}%"))
    if text_filter:
        like = f"%{text_filter}%"
        query = query.filter(
            or_(
                AuditLog.event_type.ilike(like),
                AuditLog.details.ilike(like),
                User.username.ilike(like),
            )
        )

    total_matching = query.count()
    results = query.order_by(AuditLog.event_timestamp.desc(), AuditLog.id.desc()).limit(limit).all()

    rows = []
    signin_events = 0
    failed_signins = 0
    account_events = 0
    users_seen: set[uuid.UUID] = set()
    for log_row, username_value in results:
        if log_row.user_id:
            users_seen.add(log_row.user_id)
        if log_row.event_type.startswith("signin."):
            signin_events += 1
        if log_row.event_type.startswith("signin.failed"):
            failed_signins += 1
        if (
            log_row.event_type.startswith("account.")
            or log_row.event_type.startswith("mfa.")
            or log_row.event_type.startswith("signout")
        ):
            account_events += 1
        rows.append(
            {
                "log": log_row,
                "username": username_value or "(system)",
            }
        )

    return templates.TemplateResponse(
        "audit_log.html",
        {
            "request": request,
            "user": admin_user,
            "rows": rows,
            "is_admin_view": True,
            "title": "Admin Audit Log",
            "filters": {
                "username": username_filter,
                "event": event_filter,
                "q": text_filter,
                "limit": limit,
            },
            "summary": {
                "displayed": len(rows),
                "matching": total_matching,
                "signin_events": signin_events,
                "failed_signins": failed_signins,
                "account_events": account_events,
                "users_seen": len(users_seen),
            },
        },
    )


@router.post("/admin/users/{user_id}/revoke-sessions")
def admin_revoke_sessions(user_id: str, request: Request, db: Session = Depends(get_db)):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        target_id = uuid.UUID(user_id)
    except ValueError:
        return _admin_redirect("Invalid user identifier.", error=True)

    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        return _admin_redirect("User not found.", error=True)

    revoked = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == target.id, SessionModel.is_active.is_(True))
        .update({SessionModel.is_active: False}, synchronize_session=False)
    )
    add_event(
        db,
        admin_user,
        action="admin",
        message=f"Revoked {revoked} active session(s) for '{target.username}'.",
        level="WARN",
    )
    add_audit_log(
        db,
        user=target,
        event_type="account.sessions_revoked_by_admin",
        details=f"Admin '{admin_user.username}' revoked {revoked} active session(s).",
        request=request,
    )
    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.sessions_revoked",
        details=f"Revoked {revoked} active session(s) for '{target.username}'.",
        request=request,
    )
    db.commit()
    return _admin_redirect(f"Revoked {revoked} active session(s) for '{target.username}'.")


@router.post("/admin/users/{user_id}/reset-totp")
def admin_reset_totp(user_id: str, request: Request, db: Session = Depends(get_db)):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        target_id = uuid.UUID(user_id)
    except ValueError:
        return _admin_redirect("Invalid user identifier.", error=True)

    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        return _admin_redirect("User not found.", error=True)

    target.totp_enabled = False
    target.totp_secret_enc = None
    add_event(
        db,
        admin_user,
        action="admin",
        message=f"Reset MFA enrollment for '{target.username}'.",
        level="WARN",
    )
    add_audit_log(
        db,
        user=target,
        event_type="mfa.reset_by_admin",
        details=f"Admin '{admin_user.username}' reset MFA enrollment.",
        request=request,
    )
    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.mfa_reset",
        details=f"Reset MFA enrollment for '{target.username}'.",
        request=request,
    )
    db.commit()
    return _admin_redirect(f"MFA reset for '{target.username}'.")


@router.post("/admin/users/{user_id}/toggle-admin")
def admin_toggle_role(user_id: str, request: Request, db: Session = Depends(get_db)):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        target_id = uuid.UUID(user_id)
    except ValueError:
        return _admin_redirect("Invalid user identifier.", error=True)

    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        return _admin_redirect("User not found.", error=True)

    if target.is_admin:
        admin_count = db.query(func.count(User.id)).filter(User.is_admin.is_(True)).scalar() or 0
        if admin_count <= 1:
            return _admin_redirect("Cannot remove the last system administrator.", error=True)

    target.is_admin = not target.is_admin
    status_label = "granted" if target.is_admin else "removed"
    add_event(
        db,
        admin_user,
        action="admin",
        message=f"System administrator role {status_label} for '{target.username}'.",
        level="SUCCESS",
    )
    add_audit_log(
        db,
        user=target,
        event_type="account.role_admin_granted_by_admin" if target.is_admin else "account.role_admin_removed_by_admin",
        details=f"Admin '{admin_user.username}' {status_label} administrator role.",
        request=request,
    )
    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.role_admin_granted" if target.is_admin else "admin.role_admin_removed",
        details=f"Administrator role {status_label} for '{target.username}'.",
        request=request,
    )
    db.commit()
    return _admin_redirect(f"Administrator role {status_label} for '{target.username}'.")


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
        add_audit_log(
            db,
            user=user,
            event_type="mfa.secret_provisioned",
            details="MFA enrollment secret generated.",
            request=request,
        )
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
        add_audit_log(
            db,
            user=user,
            event_type="mfa.verify_failed",
            details="Invalid MFA verification code during enrollment.",
            request=request,
        )
        db.commit()
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
    add_audit_log(
        db,
        user=user,
        event_type="mfa.enabled",
        details="MFA enabled after verification.",
        request=request,
    )
    db.commit()
    return RedirectResponse(url="/ui/totp", status_code=303)


@router.post("/totp/disable")
def totp_disable(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    user.totp_enabled = False
    user.totp_secret_enc = None
    add_audit_log(
        db,
        user=user,
        event_type="mfa.disabled",
        details="MFA disabled by user.",
        request=request,
    )
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
                "display_name": record.file_name,
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
            "  help\n"
            "  pwd\n"
            "  scope\n"
            "  groups\n"
            "  usegroup <group_id|group_name>\n"
            "  useuser\n"
            "  list [folder]\n"
            "  tree [folder] [depth]\n"
            "  find <pattern> [folder]\n"
            "  stat <path>\n"
            "  view <file> [lines]\n"
            "  hash <file>\n"
            "  quota [folder]\n"
            "  encstatus\n"
            "  encproof <file>\n"
            "  gfiles [pattern]\n"
            "  gdownload <file_id>\n"
            "  move <src> <dst>\n"
            "  copy <src> <dst>\n"
            "  rename <src> <dst>\n"
            "  directory <path>\n"
            "Paths are relative to the active scope. Use usegroup/useuser to switch."
        )
        add_event(db, user, action="terminal", message=message)
        return {"ok": True, "message": message}

    if cmd not in set(_TERMINAL_COMMANDS):
        raise HTTPException(status_code=400, detail="Unsupported command")

    scope = _terminal_get_scope(request)
    root, scope_label = _terminal_root_for_scope(user, scope)
    safe_args = [_normalize_rel_path(a) for a in args]

    if cmd == "pwd":
        message = "/" if scope_label == "user" else f"/  ({scope_label})"
        add_event(db, user, action="terminal", message=f"pwd {message}")
        return {"ok": True, "message": message}

    if cmd == "scope":
        if scope_label == "user":
            message = "Scope: user vault (/)"
        else:
            message = f"Scope: {scope_label} (/)"
        add_event(db, user, action="terminal", message=f"scope\n{message}")
        return {"ok": True, "message": message}

    if cmd == "groups":
        rows = (
            db.query(Group.id, Group.name, GroupMembership.role)
            .join(GroupMembership, GroupMembership.group_id == Group.id)
            .filter(GroupMembership.user_id == user.id)
            .order_by(Group.name.asc())
            .all()
        )
        if not rows:
            message = "(no group memberships)"
        else:
            lines = ["Your groups:"]
            for gid, name, role in rows[:60]:
                lines.append(f"  {name}  ({role})  {gid}")
            if len(rows) > 60:
                lines.append(f"... (+{len(rows) - 60} more)")
            lines.append("")
            lines.append("Tip: usegroup <group_id|group_name>")
            message = "\n".join(lines)
        add_event(db, user, action="terminal", message=f"groups\n{message}")
        return {"ok": True, "message": message}

    if cmd == "useuser":
        _terminal_set_scope_user(request)
        message = "Scope set to user vault (/)."
        add_event(db, user, action="terminal", message=f"useuser\n{message}")
        return {"ok": True, "message": message}

    if cmd == "usegroup":
        if not safe_args:
            raise HTTPException(status_code=400, detail="Missing group identifier")
        raw = (args[0] or "").strip()
        if not raw:
            raise HTTPException(status_code=400, detail="Missing group identifier")
        group_row = None
        try:
            gid = uuid.UUID(raw)
            group_row = (
                db.query(Group, GroupMembership.role)
                .join(GroupMembership, GroupMembership.group_id == Group.id)
                .filter(Group.id == gid, GroupMembership.user_id == user.id)
                .first()
            )
        except ValueError:
            group_row = (
                db.query(Group, GroupMembership.role)
                .join(GroupMembership, GroupMembership.group_id == Group.id)
                .filter(Group.name == raw, GroupMembership.user_id == user.id)
                .first()
            )
        if not group_row:
            raise HTTPException(status_code=404, detail="Group not found or not a member")
        group, role = group_row
        _terminal_set_scope_group(request, group_id=group.id, group_name=group.name)
        message = f"Scope set to group '{group.name}' ({role})."
        add_event(db, user, action="terminal", message=f"usegroup {group.id}\n{message}")
        return {"ok": True, "message": message}

    if cmd in {"directory", "move", "copy", "rename"} and scope_label != "user":
        raise HTTPException(status_code=400, detail="Write commands are disabled in group scope")

    if cmd == "gfiles":
        if scope.get("type") != "group" or not scope.get("group_id"):
            raise HTTPException(status_code=400, detail="gfiles requires group scope (usegroup first)")
        try:
            gid = uuid.UUID(scope["group_id"])
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid group scope")

        # Confirm membership.
        membership = (
            db.query(GroupMembership.role)
            .filter(GroupMembership.group_id == gid, GroupMembership.user_id == user.id)
            .first()
        )
        if not membership:
            raise HTTPException(status_code=403, detail="Not a member of this group")

        pattern = (args[0] or "").strip() if args else ""
        query = db.query(GroupFileRecord).filter(GroupFileRecord.group_id == gid)
        if pattern:
            query = query.filter(GroupFileRecord.file_name.ilike(f"%{pattern}%"))
        rows = query.order_by(GroupFileRecord.uploaded_at.desc()).limit(80).all()
        if not rows:
            message = "(no files)"
        else:
            lines = ["Group files (id, name, size, uploaded UTC):"]
            for r in rows:
                uploaded = r.uploaded_at.isoformat(timespec="seconds") + "Z" if r.uploaded_at else "-"
                lines.append(f"  {r.id}  {r.file_name}  {r.file_size}  {uploaded}")
            lines.append("")
            lines.append("Tip: gdownload <file_id>")
            message = "\n".join(lines)
        add_event(db, user, action="terminal", message=f"gfiles {pattern}\n{message}".strip())
        return {"ok": True, "message": message}

    if cmd == "gdownload":
        if scope.get("type") != "group" or not scope.get("group_id"):
            raise HTTPException(status_code=400, detail="gdownload requires group scope (usegroup first)")
        if not safe_args:
            raise HTTPException(status_code=400, detail="Missing file id")
        try:
            gid = uuid.UUID(scope["group_id"])
            fid = uuid.UUID(safe_args[0])
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid identifier")

        membership = (
            db.query(GroupMembership.role)
            .filter(GroupMembership.group_id == gid, GroupMembership.user_id == user.id)
            .first()
        )
        if not membership:
            raise HTTPException(status_code=403, detail="Not a member of this group")

        record = (
            db.query(GroupFileRecord)
            .filter(GroupFileRecord.group_id == gid, GroupFileRecord.id == fid)
            .first()
        )
        if not record:
            raise HTTPException(status_code=404, detail="File not found")

        url = f"/ui/groups/{gid}/files/{fid}"
        message = f"Download URL:\n  {url}"
        add_event(db, user, action="terminal", message=f"gdownload {fid}\n{message}")
        return {"ok": True, "message": message, "url": url}

    if cmd == "encproof":
        if len(safe_args) < 1:
            raise HTTPException(status_code=400, detail="Missing file path")
        target = safe_args[0]
        path = _safe_join(root, target)
        _ensure_no_symlink(path, root)
        if not path.exists() or not path.is_file():
            raise HTTPException(status_code=400, detail="File not found")

        suffix = path.suffix.lower()
        if suffix not in _TERMINAL_TEXT_EXTS:
            mime_type, _ = mimetypes.guess_type(path.name)
            if not (mime_type or "").startswith("text/"):
                raise HTTPException(status_code=400, detail="encproof supports text files only (.txt/.md/etc)")

        meta_lines: list[str] = []
        meta_lines.append(f"Scope: {scope_label}")
        meta_lines.append(f"Path: {target}")
        meta_lines.append(f"Ciphertext size on disk: {path.stat().st_size} bytes")

        decrypt_iter = None
        if scope.get("type") == "group" and scope.get("group_id"):
            try:
                gid = uuid.UUID(scope["group_id"])
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid group scope")

            membership = (
                db.query(GroupMembership.role)
                .filter(GroupMembership.group_id == gid, GroupMembership.user_id == user.id)
                .first()
            )
            if not membership:
                raise HTTPException(status_code=403, detail="Not a member of this group")

            group = db.query(Group).filter(Group.id == gid).first()
            if not group:
                raise HTTPException(status_code=404, detail="Group not found")

            ensure_group_key(db, group)
            record = (
                db.query(GroupFileRecord)
                .filter(GroupFileRecord.group_id == gid, GroupFileRecord.file_path == str(path))
                .first()
            )
            if not record:
                raise HTTPException(status_code=400, detail="File is not tracked in group DB metadata")
            if not record.is_encrypted:
                raise HTTPException(status_code=400, detail="File is not marked encrypted")
            if not record.enc_nonce or not record.enc_tag:
                raise HTTPException(status_code=500, detail="Encrypted metadata missing nonce/tag")

            dek = get_group_dek(db, group)
            decrypt_iter = decrypt_file_iter(dek, path, record.enc_nonce, record.enc_tag, chunk_size=1024 * 1024)
            meta_lines.append(f"DB record: group_files id={record.id}")
            meta_lines.append("Cipher: AES-256-GCM")
            meta_lines.append(f"Nonce/tag present: yes")
        else:
            record = (
                db.query(FileRecord)
                .filter(FileRecord.user_id == user.id, FileRecord.file_path == str(path))
                .first()
            )
            if not record:
                raise HTTPException(status_code=400, detail="File is not tracked in personal DB metadata")
            if not record.is_encrypted:
                raise HTTPException(status_code=400, detail="File is not marked encrypted")
            if not record.enc_nonce or not record.enc_tag:
                raise HTTPException(status_code=500, detail="Encrypted metadata missing nonce/tag")

            dek = get_user_dek(db, user)
            decrypt_iter = decrypt_file_iter(dek, path, record.enc_nonce, record.enc_tag, chunk_size=1024 * 1024)
            meta_lines.append(f"DB record: files id={record.id}")
            meta_lines.append("Cipher: AES-256-GCM")
            meta_lines.append("Nonce/tag present: yes")

        # Proof 1: ciphertext preview (scrambled view).
        with path.open("rb") as fh:
            head = fh.read(256)
        head_hex = _hex_bytes(head, limit=64)
        contains_null = b"\x00" in head
        naive_text = head.decode("utf-8", errors="replace")
        naive_lines = naive_text.splitlines()[:6]
        naive_preview = "\n".join(naive_lines) if naive_lines else "(no visible text)"

        # Proof 2: decrypted preview (plaintext).
        decrypted = b""
        if decrypt_iter is None:
            raise HTTPException(status_code=500, detail="Decrypt pipeline not available")
        try:
            for chunk in decrypt_iter:
                if not chunk:
                    continue
                decrypted += chunk
                if len(decrypted) >= _TERMINAL_ENCPROOF_MAX_DECRYPT_BYTES:
                    decrypted = decrypted[:_TERMINAL_ENCPROOF_MAX_DECRYPT_BYTES]
                    break
        except Exception:
            raise HTTPException(status_code=400, detail="Decryption failed (invalid tag or key)")

        plain_text = decrypted.decode("utf-8", errors="replace")
        plain_lines = plain_text.splitlines()
        preview_lines = plain_lines[:_TERMINAL_ENCPROOF_PREVIEW_LINES]
        plain_preview = "\n".join(preview_lines) if preview_lines else "(empty)"
        if len(plain_lines) > len(preview_lines):
            plain_preview = f"{plain_preview}\n... ({len(plain_lines) - len(preview_lines)} more lines in preview window)"

        out_lines: list[str] = []
        out_lines.append("Encryption Proof (encproof)")
        out_lines.append("")
        out_lines.extend(meta_lines)
        out_lines.append("")
        out_lines.append("Proof 1: Encrypted At Rest (ciphertext on disk)")
        out_lines.append(f"  Ciphertext head (hex, 64 bytes): {head_hex}")
        out_lines.append(f"  Contains NUL bytes: {'yes' if contains_null else 'no'}")
        out_lines.append("  Naive UTF-8 decode of ciphertext head (first lines):")
        out_lines.append(naive_preview)
        out_lines.append("")
        out_lines.append("Proof 2: Decryption Output (plaintext preview)")
        out_lines.append(f"  Decrypted preview bytes shown: {len(decrypted)}")
        out_lines.append("  Plaintext preview (first lines):")
        out_lines.append(plain_preview)

        message = "\n".join(out_lines)
        add_event(db, user, action="terminal", message=f"encproof {target}\n{message}")
        return {"ok": True, "message": message}

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

    if cmd == "tree":
        target = safe_args[0] if safe_args else ""
        depth = _parse_int_arg(safe_args[1] if len(safe_args) > 1 else "", default=2, minimum=1, maximum=6, name="depth")
        path = _safe_join(root, target)
        _ensure_no_symlink(path, root)
        if not path.exists() or not path.is_dir():
            raise HTTPException(status_code=400, detail="Folder not found")
        lines = _build_tree_lines(root, path, depth=depth)
        if len(lines) > _TERMINAL_RESULT_LIMIT:
            lines = lines[:_TERMINAL_RESULT_LIMIT] + ["... (results truncated)"]
        message = "\n".join(lines)
        add_event(db, user, action="terminal", message=f"tree {target or '/'} depth={depth}\n{message}")
        return {"ok": True, "message": message}

    if cmd == "find":
        if len(safe_args) < 1:
            raise HTTPException(status_code=400, detail="Missing search pattern")
        pattern = safe_args[0].strip().lower()
        if not pattern:
            raise HTTPException(status_code=400, detail="Search pattern cannot be empty")
        if len(pattern) > 120:
            raise HTTPException(status_code=400, detail="Search pattern is too long")
        target = safe_args[1] if len(safe_args) > 1 else ""
        start = _safe_join(root, target)
        _ensure_no_symlink(start, root)
        if not start.exists() or not start.is_dir():
            raise HTTPException(status_code=400, detail="Folder not found")

        matches: list[str] = []
        scanned = 0
        truncated = False
        for dirpath, dirnames, filenames in os.walk(start):
            dir_path = Path(dirpath)
            clean_dirs: list[str] = []
            for dirname in sorted(dirnames):
                candidate = dir_path / dirname
                if candidate.is_symlink():
                    continue
                clean_dirs.append(dirname)
                scanned += 1
                if scanned > _TERMINAL_SCAN_LIMIT:
                    truncated = True
                    break
                if pattern in dirname.lower():
                    rel = f"{_terminal_rel_path(root, candidate)}/"
                    matches.append(rel)
                    if len(matches) >= _TERMINAL_RESULT_LIMIT:
                        truncated = True
                        break
            dirnames[:] = clean_dirs
            if truncated:
                break

            for filename in sorted(filenames):
                candidate = dir_path / filename
                if candidate.is_symlink():
                    continue
                scanned += 1
                if scanned > _TERMINAL_SCAN_LIMIT:
                    truncated = True
                    break
                if pattern in filename.lower():
                    rel = _terminal_rel_path(root, candidate)
                    matches.append(rel)
                    if len(matches) >= _TERMINAL_RESULT_LIMIT:
                        truncated = True
                        break
            if truncated:
                break

        if not matches:
            message = "(no matches)"
        else:
            message = "\n".join(matches)
        if truncated:
            message = f"{message}\n... (results truncated)"
        add_event(db, user, action="terminal", message=f"find '{pattern}' in {target or '/'}\n{message}")
        return {"ok": True, "message": message}

    if cmd == "stat":
        if len(safe_args) < 1:
            raise HTTPException(status_code=400, detail="Missing path")
        target = safe_args[0]
        path = _safe_join(root, target)
        _ensure_no_symlink(path, root)
        if not path.exists():
            raise HTTPException(status_code=400, detail="Path not found")

        rel = _terminal_rel_path(root, path)
        st = path.stat()
        modified = datetime.utcfromtimestamp(st.st_mtime).isoformat(timespec="seconds") + "Z"
        if path.is_dir():
            try:
                entries = [p for p in path.iterdir() if not p.is_symlink()]
            except OSError:
                entries = []
            message = (
                f"Path: {rel if rel == '/' else rel + '/'}\n"
                "Type: directory\n"
                f"Entries: {len(entries)}\n"
                f"Modified (UTC): {modified}"
            )
        else:
            mime_type, _ = mimetypes.guess_type(path.name)
            size_raw = st.st_size
            message = (
                f"Path: {rel}\n"
                "Type: file\n"
                f"Size: {size_raw} bytes ({_format_bytes(size_raw)})\n"
                f"MIME: {mime_type or 'application/octet-stream'}\n"
                f"Modified (UTC): {modified}"
            )
        add_event(db, user, action="terminal", message=f"stat {target}\n{message}")
        return {"ok": True, "message": message}

    if cmd == "view":
        if len(safe_args) < 1:
            raise HTTPException(status_code=400, detail="Missing file path")
        target = safe_args[0]
        max_lines = _parse_int_arg(
            safe_args[1] if len(safe_args) > 1 else "",
            default=40,
            minimum=1,
            maximum=_TERMINAL_PREVIEW_MAX_LINES,
            name="lines",
        )
        path = _safe_join(root, target)
        _ensure_no_symlink(path, root)
        if not path.exists() or not path.is_file():
            raise HTTPException(status_code=400, detail="File not found")

        size_raw = path.stat().st_size
        if size_raw > _TERMINAL_PREVIEW_MAX_BYTES:
            raise HTTPException(status_code=400, detail="File too large for view command")

        raw = path.read_bytes()
        if b"\x00" in raw:
            raise HTTPException(status_code=400, detail="Binary files are not supported by view command")

        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        if not lines:
            message = "(empty file)"
        else:
            preview = lines[:max_lines]
            message = "\n".join(preview)
            remaining = len(lines) - len(preview)
            if remaining > 0:
                message = f"{message}\n... ({remaining} more lines)"
        add_event(db, user, action="terminal", message=f"view {target} ({max_lines} lines)\n{message}")
        return {"ok": True, "message": message}

    if cmd == "hash":
        if len(safe_args) < 1:
            raise HTTPException(status_code=400, detail="Missing file path")
        target = safe_args[0]
        path = _safe_join(root, target)
        _ensure_no_symlink(path, root)
        if not path.exists() or not path.is_file():
            raise HTTPException(status_code=400, detail="File not found")
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        rel = _terminal_rel_path(root, path)
        message = f"SHA256 {rel}\n{digest.hexdigest()}"
        add_event(db, user, action="terminal", message=f"hash {target}\n{message}")
        return {"ok": True, "message": message}

    if cmd == "quota":
        target = safe_args[0] if safe_args else ""
        start = _safe_join(root, target)
        _ensure_no_symlink(start, root)
        if not start.exists() or not start.is_dir():
            raise HTTPException(status_code=400, detail="Folder not found")

        total_files = 0
        total_dirs = 0
        total_bytes = 0
        scanned = 0
        truncated = False
        for dirpath, dirnames, filenames in os.walk(start):
            dir_path = Path(dirpath)
            clean_dirs: list[str] = []
            for dirname in dirnames:
                candidate = dir_path / dirname
                if candidate.is_symlink():
                    continue
                clean_dirs.append(dirname)
            dirnames[:] = clean_dirs

            for dirname in clean_dirs:
                scanned += 1
                if scanned > _TERMINAL_SCAN_LIMIT:
                    truncated = True
                    break
                total_dirs += 1
            if truncated:
                break

            for filename in filenames:
                candidate = dir_path / filename
                if candidate.is_symlink():
                    continue
                scanned += 1
                if scanned > _TERMINAL_SCAN_LIMIT:
                    truncated = True
                    break
                try:
                    total_bytes += candidate.stat().st_size
                except OSError:
                    continue
                total_files += 1
            if truncated:
                break

        message = (
            f"Path: {target or '/'}\n"
            f"Directories: {total_dirs}\n"
            f"Files: {total_files}\n"
            f"Total size: {_format_bytes(total_bytes)} ({total_bytes} bytes)"
        )
        if truncated:
            message = f"{message}\nNote: scan limit reached, results may be partial."
        add_event(db, user, action="terminal", message=f"quota {target or '/'}\n{message}")
        return {"ok": True, "message": message}

    if cmd == "encstatus":
        if safe_args:
            raise HTTPException(status_code=400, detail="encstatus does not take arguments")

        checked_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        key_row = db.query(UserKey).filter(UserKey.user_id == user.id).first()

        key_present = key_row is not None
        key_version = "n/a"
        key_created = "n/a"
        wrap_nonce_state = "n/a"
        wrapped_dek_state = "n/a"
        unwrap_state = "not checked"
        if key_row:
            key_version = str(key_row.key_version)
            if key_row.created_at:
                key_created = key_row.created_at.isoformat(timespec="seconds") + "Z"
            try:
                wrap_nonce_len = len(b64d(key_row.wrap_nonce))
                if wrap_nonce_len == 12:
                    wrap_nonce_state = f"{wrap_nonce_len} bytes (valid)"
                else:
                    wrap_nonce_state = f"{wrap_nonce_len} bytes (unexpected)"
            except Exception:
                wrap_nonce_state = "invalid base64"
            try:
                wrapped_dek_len = len(b64d(key_row.wrapped_dek))
                if wrapped_dek_len >= 33:
                    wrapped_dek_state = f"{wrapped_dek_len} bytes (present)"
                else:
                    wrapped_dek_state = f"{wrapped_dek_len} bytes (unexpected)"
            except Exception:
                wrapped_dek_state = "invalid base64"

            try:
                dek = unwrap_key(
                    master_key_bytes(),
                    key_row.wrap_nonce,
                    key_row.wrapped_dek,
                    aad=str(user.id).encode(),
                )
                unwrap_state = "OK (32-byte DEK)" if len(dek) == 32 else f"FAILED (DEK length {len(dek)})"
            except Exception:
                unwrap_state = "FAILED"

        active_file_filter = [
            FileRecord.user_id == user.id,
            FileRecord.is_trashed.is_(False),
        ]
        active_files = (
            db.query(func.count(FileRecord.id))
            .filter(*active_file_filter)
            .scalar()
            or 0
        )
        active_encrypted = (
            db.query(func.count(FileRecord.id))
            .filter(*active_file_filter, FileRecord.is_encrypted.is_(True))
            .scalar()
            or 0
        )
        active_encrypted_meta_complete = (
            db.query(func.count(FileRecord.id))
            .filter(
                *active_file_filter,
                FileRecord.is_encrypted.is_(True),
                FileRecord.enc_nonce.is_not(None),
                FileRecord.enc_tag.is_not(None),
            )
            .scalar()
            or 0
        )
        active_plaintext = max(0, active_files - active_encrypted)
        active_metadata_issues = max(0, active_encrypted - active_encrypted_meta_complete)
        active_encrypted_bytes = (
            db.query(func.coalesce(func.sum(FileRecord.file_size), 0))
            .filter(*active_file_filter, FileRecord.is_encrypted.is_(True))
            .scalar()
            or 0
        )
        trashed_files = (
            db.query(func.count(FileRecord.id))
            .filter(FileRecord.user_id == user.id, FileRecord.is_trashed.is_(True))
            .scalar()
            or 0
        )

        group_rows = (
            db.query(Group.id, Group.name)
            .join(GroupMembership, GroupMembership.group_id == Group.id)
            .filter(GroupMembership.user_id == user.id)
            .order_by(Group.name.asc())
            .all()
        )
        group_ids = [row.id for row in group_rows]
        group_key_versions: dict[uuid.UUID, int] = {}
        group_file_total = 0
        group_file_encrypted = 0
        group_file_meta_complete = 0
        if group_ids:
            for row in (
                db.query(GroupKey.group_id, GroupKey.key_version)
                .filter(GroupKey.group_id.in_(group_ids))
                .all()
            ):
                group_key_versions[row.group_id] = row.key_version

            group_file_total = (
                db.query(func.count(GroupFileRecord.id))
                .filter(GroupFileRecord.group_id.in_(group_ids))
                .scalar()
                or 0
            )
            group_file_encrypted = (
                db.query(func.count(GroupFileRecord.id))
                .filter(
                    GroupFileRecord.group_id.in_(group_ids),
                    GroupFileRecord.is_encrypted.is_(True),
                )
                .scalar()
                or 0
            )
            group_file_meta_complete = (
                db.query(func.count(GroupFileRecord.id))
                .filter(
                    GroupFileRecord.group_id.in_(group_ids),
                    GroupFileRecord.is_encrypted.is_(True),
                    GroupFileRecord.enc_nonce.is_not(None),
                    GroupFileRecord.enc_tag.is_not(None),
                )
                .scalar()
                or 0
            )

        groups_joined = len(group_rows)
        groups_with_key = len(group_key_versions)
        groups_missing_key = [row.name for row in group_rows if row.id not in group_key_versions]
        group_file_metadata_issues = max(0, group_file_encrypted - group_file_meta_complete)

        group_key_summary = "(none)"
        if group_key_versions:
            summary_parts: list[str] = []
            for row in group_rows:
                version = group_key_versions.get(row.id)
                if version is None:
                    continue
                summary_parts.append(f"{row.name}=v{version}")
                if len(summary_parts) >= 6:
                    break
            remaining = len(group_key_versions) - len(summary_parts)
            group_key_summary = ", ".join(summary_parts)
            if remaining > 0:
                group_key_summary = f"{group_key_summary}, ... (+{remaining} more)"

        missing_group_summary = "(none)"
        if groups_missing_key:
            missing_group_summary = ", ".join(groups_missing_key[:6])
            remaining = len(groups_missing_key) - min(len(groups_missing_key), 6)
            if remaining > 0:
                missing_group_summary = f"{missing_group_summary}, ... (+{remaining} more)"

        issues: list[str] = []
        if not key_present:
            issues.append("User key record is missing.")
        if unwrap_state.startswith("FAILED"):
            issues.append("User DEK unwrap check failed.")
        if active_metadata_issues > 0:
            issues.append(f"{active_metadata_issues} personal encrypted file(s) missing nonce/tag metadata.")
        if group_file_metadata_issues > 0:
            issues.append(f"{group_file_metadata_issues} group encrypted file(s) missing nonce/tag metadata.")
        if groups_missing_key:
            issues.append(f"{len(groups_missing_key)} joined group(s) do not have a group key record.")

        root_key_source = (
            "Passphrase-derived root (Argon2id + HKDF-SHA256)"
            if using_passphrase()
            else "PFV_MASTER_KEY (base64url, 32 bytes)"
        )
        lines = [
            "Encryption Status",
            f"Account: {user.username}",
            f"Checked (UTC): {checked_at}",
            "",
            "Cipher Suite",
            "  File encryption: AES-256-GCM (12-byte nonce, 16-byte tag)",
            "  Key wrapping: AES-256-GCM wrapped DEK (AAD bound to user/group id)",
            "  Direct messages: Fernet tokens (enc:v1 prefix)",
            f"  Root key source: {root_key_source}",
            "",
            "User Key",
            f"  Record present: {'yes' if key_present else 'no'}",
            f"  Key version: {key_version}",
            f"  Created (UTC): {key_created}",
            f"  Wrap nonce: {wrap_nonce_state}",
            f"  Wrapped DEK blob: {wrapped_dek_state}",
            f"  DEK unwrap check: {unwrap_state}",
            "",
            "Personal Vault Coverage",
            f"  Active files: {active_files}",
            f"  Encrypted active files: {active_encrypted}",
            f"  Plaintext active files: {active_plaintext}",
            f"  Encrypted metadata complete: {active_encrypted_meta_complete}/{active_encrypted}",
            f"  Encrypted active data: {_format_bytes(active_encrypted_bytes)} ({active_encrypted_bytes} bytes)",
            f"  Trashed files: {trashed_files}",
            "",
            "Group Encryption Coverage",
            f"  Joined groups: {groups_joined}",
            f"  Groups with key record: {groups_with_key}/{groups_joined}",
            f"  Missing group key records: {missing_group_summary}",
            f"  Group key versions: {group_key_summary}",
            f"  Group files visible: {group_file_total}",
            f"  Group encrypted files: {group_file_encrypted}",
            f"  Group encrypted metadata complete: {group_file_meta_complete}/{group_file_encrypted}",
            "",
            "Health Summary",
        ]
        if issues:
            for issue in issues:
                lines.append(f"  WARN: {issue}")
        else:
            lines.append("  OK: no key or encryption metadata issues detected.")

        message = "\n".join(lines)
        add_event(db, user, action="terminal", message=f"encstatus\n{message}")
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

    scope = _terminal_get_scope(request)
    root, _ = _terminal_root_for_scope(user, scope)
    raw = (prefix or "").strip()
    raw_norm = _normalize_rel_path(raw)
    base_dir = raw_norm
    partial = ""
    if raw_norm and not raw_norm.endswith("/"):
        base_dir = str(Path(raw_norm).parent) if str(Path(raw_norm).parent) != "." else ""
        partial = Path(raw_norm).name

    command_suggestions: list[str] = []
    if "/" not in raw and "\\" not in raw and " " not in raw:
        lowered = raw.lower()
        command_suggestions = [name for name in _TERMINAL_COMMANDS if name.startswith(lowered)]

    target_dir = _safe_join(root, base_dir)
    path_suggestions: list[str] = []
    if target_dir.exists() and target_dir.is_dir():
        for item in sorted(target_dir.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
            name = item.name
            if partial and not name.lower().startswith(partial.lower()):
                continue
            rel = str(Path(base_dir) / name) if base_dir else name
            if item.is_dir():
                rel = f"{rel}/"
            path_suggestions.append(rel)

    merged: list[str] = []
    seen: set[str] = set()
    for value in command_suggestions + path_suggestions:
        if value in seen:
            continue
        seen.add(value)
        merged.append(value)

    return {"suggestions": merged[:50]}


@router.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    session_id = request.cookies.get("pfv_session")
    session = _get_session(db, session_id)
    if session:
        user = db.query(User).filter(User.id == session.user_id).first()
        session.is_active = False
        if user:
            add_event(db, user, action="auth", message="Signed out.")
            add_audit_log(db, user=user, event_type="signout", details="Interactive sign-out completed.", request=request)
        db.commit()
    response = RedirectResponse(url="/ui/login", status_code=303)
    response.delete_cookie("pfv_session")
    return response
