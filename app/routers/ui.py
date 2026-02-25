import os
import re
import secrets
import shlex
import shutil
import io
import uuid
import hashlib
import hmac
import smtplib
import ssl
import base64
import contextvars
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, urlencode, urlsplit
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError, URLError

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
import mimetypes
import logging

from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, case, func, or_, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.db import get_db
from app.models.core import (
    ActivityEvent,
    AuditLog,
    DirectMessage,
    DirectMessageReport,
    FileRecord,
    Group,
    GroupFileRecord,
    GroupInvite,
    GroupKey,
    GroupMembership,
    ConversationKey,
    Session as SessionModel,
    SupportTicket,
    User,
    UserKey,
)
from app.services.crypto import (
    b64d,
    decrypt_file_iter,
    encrypt_file_to_path,
    generate_key_32,
    reencrypt_file_to_path,
    unwrap_key,
    wrap_key,
)
from app.services.key_derivation import master_key_bytes, message_attachment_key_bytes, using_passphrase
from app.services.group_keystore import ensure_group_key, get_group_dek
from app.services.keystore import ensure_user_key, get_user_dek
from app.services.conversation_keystore import conversation_aad, ensure_conversation_key, get_conversation_dek
from app.services.activity import add_event
from app.services.audit import add_audit_log
from app.services.security import decrypt_totp_secret, encrypt_totp_secret, hash_password, verify_password
from app.services.sessions import create_session
from app.services.message_crypto import (
    DM_ATTACHMENT_SCHEME_CONVERSATION,
    DM_ATTACHMENT_SCHEME_RECIPIENT,
    DM_ATTACHMENT_SCHEME_SYSTEM,
    DM_BODY_SCHEME_CONVERSATION,
    DM_BODY_SCHEME_FERNET,
    decrypt_message,
    decrypt_dm_body,
    encrypt_dm_body,
    encrypt_message,
    is_dm_conversation_encrypted,
    is_message_encrypted,
)
from app.services.timezones import (
    DEFAULT_TIMEZONE,
    TIMEZONE_COOKIE,
    format_datetime_for_timezone,
    format_datetime_iso_utc,
    normalize_timezone,
    timezone_options,
)
import pyotp

router = APIRouter(prefix="/ui", tags=["ui"])
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger("uvicorn.error")
_FILE_TOKEN_CACHE: dict[str, dict[str, str]] = {}
_TERMINAL_SCOPE_CACHE: dict[str, dict[str, str]] = {}
_PENDING_LOGIN_CACHE: dict[str, dict[str, object]] = {}
_PENDING_LOGIN_TTL_SECONDS = 10 * 60
_PENDING_PASSWORD_RESET_CACHE: dict[str, dict[str, object]] = {}
_PENDING_PASSWORD_RESET_TTL_SECONDS = 15 * 60
_ACTIVE_TIMEZONE: contextvars.ContextVar[str] = contextvars.ContextVar("pfv_active_timezone", default=DEFAULT_TIMEZONE)
_SESSION_COOKIE_NAME = "pfv_session"

_TERMINAL_COMMANDS = [
    "help",
    "clear",
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
    "enctimeline",
    "encrotate",
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
_TERMINAL_ENCPROOF_MAX_FILES = 200
_TERMINAL_ROTATE_TARGETS = {"all", "files", "messages", "groups"}
_TERMINAL_TIMELINE_DEFAULT_LIMIT = 80
_TERMINAL_TIMELINE_MAX_LIMIT = 200
_TERMINAL_TIMELINE_MESSAGE_LIMIT = 60
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
_DM_BODY_KEY_LABEL = "dm-body:fernet-v1"
_DM_ATTACHMENT_SYSTEM_KEY_LABEL = "dm-attachment:system-key:v1"
_DM_BODY_CONVERSATION_KEY_LABEL = "dm-conversation"
_DM_ATTACHMENT_CONVERSATION_KEY_LABEL = "dm-attachment:conversation"
_DM_BODY_HEAL_REENCRYPT_LEN = 8 * 1024

MESSAGE_ATTACHMENT_MAX_BYTES = 10 * 1024 * 1024
PROFILE_AVATAR_MAX_BYTES = 4 * 1024 * 1024
EMAIL_VERIFY_TTL_MINUTES = 30
MFA_METHOD_TOTP = "totp"
MFA_METHOD_EMAIL = "email"
MFA_METHOD_SMS = "sms"
MFA_METHODS = (MFA_METHOD_TOTP, MFA_METHOD_EMAIL, MFA_METHOD_SMS)
MFA_METHOD_LABELS = {
    MFA_METHOD_TOTP: "Authenticator app (TOTP)",
    MFA_METHOD_EMAIL: "Email code (SMTP)",
    MFA_METHOD_SMS: "SMS code",
}
UI_VIEW_BASE = "base"
UI_VIEW_ADVANCED = "advanced"
UI_VIEW_MODES = (UI_VIEW_BASE, UI_VIEW_ADVANCED)

PROFILE_IMAGE_MIME_ALLOW = {
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
}
PROFILE_TIMEZONE_OPTIONS = timezone_options()

DM_REPORT_REASONS: dict[str, str] = {
    "spam": "Spam / unsolicited advertising",
    "harassment": "Harassment or hate speech",
    "threat": "Threats or violence",
    "impersonation": "Impersonation / fraud",
    "sexual": "Sexual content",
    "other": "Other",
}

SUPPORT_TICKET_CATEGORIES: dict[str, str] = {
    "general": "General support",
    "account": "Account access",
    "bug": "Bug report",
    "feature": "Feature request",
    "security": "Security concern",
}
SUPPORT_TICKET_PRIORITIES: tuple[str, ...] = ("low", "normal", "high", "urgent")
SUPPORT_TICKET_STATUSES: tuple[str, ...] = ("open", "in_progress", "waiting_on_user", "resolved", "closed")
ADMIN_TICKET_SHORTCUTS: dict[str, dict[str, object]] = {
    "take": {"status": "in_progress", "priority": None, "label": "Take ownership"},
    "need_info": {"status": "waiting_on_user", "priority": None, "label": "Need user info"},
    "resolve": {"status": "resolved", "priority": None, "label": "Mark resolved"},
    "close": {"status": "closed", "priority": None, "label": "Close ticket"},
    "reopen": {"status": "open", "priority": None, "label": "Reopen ticket"},
    "escalate": {"status": "in_progress", "priority": "urgent", "label": "Escalate urgent"},
}
ADMIN_TICKET_RESPONSE_TEMPLATES: dict[str, dict[str, object]] = {
    "need_info": {
        "label": "Request more details",
        "shortcut": "need_info",
        "body": (
            "Hello {username},\n\n"
            "We reviewed your request (ticket {ticket_id}) and need more detail to continue:\n"
            "- What exact steps triggered the issue?\n"
            "- Any error message text or screenshot?\n"
            "- Approximate UTC time this occurred?\n\n"
            "Reply in the Help page and we will continue immediately."
        ),
    },
    "investigating": {
        "label": "Investigating update",
        "shortcut": "take",
        "body": (
            "Hello {username},\n\n"
            "Thanks for the report. We have started investigation on ticket {ticket_id} and "
            "will update you as soon as we confirm root cause and remediation steps."
        ),
    },
    "resolved": {
        "label": "Resolved confirmation",
        "shortcut": "resolve",
        "body": (
            "Hello {username},\n\n"
            "We implemented a fix for ticket {ticket_id}. Please verify and confirm the issue is resolved. "
            "If the problem persists, reply with the latest behavior and we will reopen immediately."
        ),
    },
    "closed": {
        "label": "Closed notice",
        "shortcut": "close",
        "body": (
            "Hello {username},\n\n"
            "Ticket {ticket_id} has been closed based on current resolution state. "
            "If you need follow-up, submit a new ticket referencing this id."
        ),
    },
}
ADMIN_SECURITY_PLAYBOOKS: dict[str, dict[str, str]] = {
    "contain": {
        "label": "Contain account",
        "description": "Disable account, revoke sessions, disable messaging, and lock directory writes.",
    },
    "investigate": {
        "label": "Investigate hold",
        "description": "Keep account enabled, revoke sessions, and lock directory writes during investigation.",
    },
    "release": {
        "label": "Release account",
        "description": "Clear compromise flag, enable account/messaging, and unlock directory writes.",
    },
}


def _normalize_ticket_category(value: str | None) -> str:
    key = (value or "").strip().lower()
    return key if key in SUPPORT_TICKET_CATEGORIES else "general"


def _normalize_ticket_priority(value: str | None) -> str:
    key = (value or "").strip().lower()
    return key if key in SUPPORT_TICKET_PRIORITIES else "normal"


def _normalize_ticket_status(value: str | None) -> str:
    key = (value or "").strip().lower()
    return key if key in SUPPORT_TICKET_STATUSES else ""


def _normalize_admin_ticket_shortcut(value: str | None) -> str:
    key = (value or "").strip().lower()
    return key if key in ADMIN_TICKET_SHORTCUTS else ""


def _next_support_ticket_number(db: Session) -> int:
    value: int | None = None
    try:
        raw = db.execute(text("SELECT nextval('support_ticket_number_seq')")).scalar()
        if raw is not None:
            value = int(raw)
    except Exception:
        value = None

    if value is None:
        max_existing = db.query(func.max(SupportTicket.ticket_number)).scalar() or 0
        value = int(max_existing) + 1

    if value > 999_999:
        raise HTTPException(status_code=500, detail="Support ticket number range exhausted.")
    return value


def _support_ticket_display_id(ticket: SupportTicket | None) -> str:
    if not ticket:
        return "000000"
    number_value = getattr(ticket, "ticket_number", None)
    if number_value is not None:
        try:
            normalized = int(number_value)
            if 0 <= normalized <= 999_999:
                return f"{normalized:06d}"
        except (TypeError, ValueError):
            pass
    try:
        raw_uuid = uuid.UUID(str(ticket.id)).hex
        fallback = int(raw_uuid[-6:], 16) % 1_000_000
        return f"{fallback:06d}"
    except Exception:
        return "000000"


def _support_ticket_ref(ticket: SupportTicket | None) -> str:
    return f"#{_support_ticket_display_id(ticket)}"


def _render_admin_ticket_response_template(key: str, ticket: SupportTicket) -> str:
    row = ADMIN_TICKET_RESPONSE_TEMPLATES.get((key or "").strip().lower())
    if not row:
        return ""
    requester_name = ticket.requester.username if ticket.requester else "user"
    body = str(row.get("body", ""))
    return body.format(
        username=requester_name,
        ticket_id=_support_ticket_display_id(ticket),
        subject=ticket.subject or "",
    ).strip()


def _admin_ticket_response_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for key, meta in ADMIN_TICKET_RESPONSE_TEMPLATES.items():
        shortcut_key = _normalize_admin_ticket_shortcut(str(meta.get("shortcut", "")))
        rows.append(
            {
                "key": key,
                "label": str(meta.get("label", key)),
                "shortcut": shortcut_key or "need_info",
            }
        )
    return rows

SMS_PROVIDER_SMTP_GATEWAY = "smtp_gateway"
SMS_PROVIDER_TWILIO = "twilio"
SMS_PROVIDER_AUTO = "auto"
SMS_PROVIDER_LABELS = {
    SMS_PROVIDER_SMTP_GATEWAY: "Carrier email gateway (SMTP)",
    SMS_PROVIDER_TWILIO: "Twilio SMS API",
    SMS_PROVIDER_AUTO: "Auto (carrier gateway first, Twilio fallback)",
}
SMS_CARRIER_OPTIONS: tuple[tuple[str, str, str], ...] = (
    ("att", "AT&T", "txt.att.net"),
    ("att_mms", "AT&T (MMS)", "mms.att.net"),
    ("verizon", "Verizon", "vtext.com"),
    ("verizon_mms", "Verizon (MMS)", "vzwpix.com"),
    ("tmobile", "T-Mobile", "tmomail.net"),
    ("sprint", "Sprint", "messaging.sprintpcs.com"),
    ("cricket", "Cricket", "sms.cricketwireless.net"),
    ("metropcs", "Metro by T-Mobile", "mymetropcs.com"),
    ("uscellular", "US Cellular", "email.uscc.net"),
)
SMS_CARRIER_LABELS = {key: label for key, label, _ in SMS_CARRIER_OPTIONS}
SMS_CARRIER_GATEWAYS = {key: domain for key, _, domain in SMS_CARRIER_OPTIONS}


def _normalize_mfa_method(value: str | None) -> str:
    method = (value or "").strip().lower()
    if method in MFA_METHODS:
        return method
    return ""


def _normalize_ui_view_mode(value: str | None) -> str:
    mode = (value or "").strip().lower()
    if mode in UI_VIEW_MODES:
        return mode
    return UI_VIEW_BASE


def _is_advanced_view_enabled(user: User | None) -> bool:
    if not user:
        return False
    return _normalize_ui_view_mode(getattr(user, "ui_view_mode", None)) == UI_VIEW_ADVANCED


def _advanced_view_redirect(message: str = "Advanced view is required for this page.") -> RedirectResponse:
    return RedirectResponse(url=f"/ui/profile?error={quote_plus(message)}", status_code=303)


def _cleanup_pending_login_cache(now: datetime | None = None) -> None:
    current = now or datetime.utcnow()
    expired_tokens = [
        token
        for token, row in _PENDING_LOGIN_CACHE.items()
        if not isinstance(row.get("expires_at"), datetime) or row["expires_at"] <= current
    ]
    for token in expired_tokens:
        _PENDING_LOGIN_CACHE.pop(token, None)


def _issue_pending_login_token(user: User) -> str:
    _cleanup_pending_login_cache()
    token = secrets.token_urlsafe(32)
    _PENDING_LOGIN_CACHE[token] = {
        "user_id": str(user.id),
        "username": user.username,
        "expires_at": datetime.utcnow() + timedelta(seconds=_PENDING_LOGIN_TTL_SECONDS),
    }
    return token


def _resolve_pending_login(token: str | None) -> dict[str, object] | None:
    value = (token or "").strip()
    if not value:
        return None
    _cleanup_pending_login_cache()
    row = _PENDING_LOGIN_CACHE.get(value)
    if not row:
        return None
    expires_at = row.get("expires_at")
    if not isinstance(expires_at, datetime) or expires_at <= datetime.utcnow():
        _PENDING_LOGIN_CACHE.pop(value, None)
        return None
    return row


def _clear_pending_login(token: str | None) -> None:
    value = (token or "").strip()
    if value:
        _PENDING_LOGIN_CACHE.pop(value, None)


def _cleanup_pending_password_reset_cache(now: datetime | None = None) -> None:
    current = now or datetime.utcnow()
    expired_tokens = [
        token
        for token, row in _PENDING_PASSWORD_RESET_CACHE.items()
        if not isinstance(row.get("expires_at"), datetime) or row["expires_at"] <= current
    ]
    for token in expired_tokens:
        _PENDING_PASSWORD_RESET_CACHE.pop(token, None)


def _issue_pending_password_reset_token(user: User) -> str:
    _cleanup_pending_password_reset_cache()
    token = secrets.token_urlsafe(32)
    _PENDING_PASSWORD_RESET_CACHE[token] = {
        "user_id": str(user.id),
        "username": user.username,
        "expires_at": datetime.utcnow() + timedelta(seconds=_PENDING_PASSWORD_RESET_TTL_SECONDS),
    }
    return token


def _resolve_pending_password_reset(token: str | None) -> dict[str, object] | None:
    value = (token or "").strip()
    if not value:
        return None
    _cleanup_pending_password_reset_cache()
    row = _PENDING_PASSWORD_RESET_CACHE.get(value)
    if not row:
        return None
    expires_at = row.get("expires_at")
    if not isinstance(expires_at, datetime) or expires_at <= datetime.utcnow():
        _PENDING_PASSWORD_RESET_CACHE.pop(value, None)
        return None
    return row


def _clear_pending_password_reset(token: str | None) -> None:
    value = (token or "").strip()
    if value:
        _PENDING_PASSWORD_RESET_CACHE.pop(value, None)


def _mask_email(value: str) -> str:
    cleaned = (value or "").strip()
    if not cleaned or "@" not in cleaned:
        return "email"
    local, domain = cleaned.split("@", 1)
    local = local.strip()
    domain = domain.strip()
    if not local or not domain:
        return "email"
    local_mask = (local[:1] + "***") if len(local) > 1 else "*"
    parts = domain.split(".")
    first = parts[0] if parts else domain
    first_mask = (first[:1] + "***") if len(first) > 1 else "*"
    suffix = "." + ".".join(parts[1:]) if len(parts) > 1 else ""
    return f"{local_mask}@{first_mask}{suffix}"


def _mask_phone(value: str) -> str:
    digits = "".join(ch for ch in (value or "") if ch.isdigit())
    if not digits:
        return "phone"
    if len(digits) <= 4:
        return f"***{digits}"
    return f"***-***-{digits[-4:]}"


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


def _resolve_effective_timezone(request: Request, user: User | None = None) -> str:
    if user:
        user_tz = normalize_timezone(getattr(user, "timezone", None))
        if user_tz:
            return user_tz
    cookie_tz = normalize_timezone(request.cookies.get(TIMEZONE_COOKIE))
    if cookie_tz:
        return cookie_tz
    header_tz = normalize_timezone(request.headers.get("x-timezone"))
    if header_tz:
        return header_tz
    return DEFAULT_TIMEZONE


def _set_active_timezone(request: Request, user: User | None = None) -> str:
    tz_name = _resolve_effective_timezone(request, user)
    _ACTIVE_TIMEZONE.set(tz_name)
    return tz_name


def _get_current_user(db: Session, request: Request) -> User | None:
    _set_active_timezone(request)
    session_id = request.cookies.get(_SESSION_COOKIE_NAME)
    session = _get_session(db, session_id)
    if not session:
        return None
    user = db.query(User).filter(User.id == session.user_id).first()
    if user and getattr(user, "is_disabled", False):
        session.is_active = False
        db.commit()
        return None
    if user:
        _set_active_timezone(request, user)
    return user


def _get_session_id(request: Request) -> str:
    return request.cookies.get(_SESSION_COOKIE_NAME) or ""


def _request_is_secure(request: Request) -> bool:
    proto = (request.headers.get("x-forwarded-proto") or "").split(",", 1)[0].strip().lower()
    if proto:
        return proto == "https"
    return request.url.scheme == "https"


def _session_cookie_samesite() -> str:
    value = (settings.session_cookie_samesite or "lax").strip().lower()
    if value in {"lax", "strict", "none"}:
        return value
    return "lax"


def _set_session_cookie(response: Response, request: Request, session_id: uuid.UUID | str) -> None:
    same_site = _session_cookie_samesite()
    secure = _request_is_secure(request)
    if same_site == "none":
        secure = True
    response.set_cookie(
        _SESSION_COOKIE_NAME,
        str(session_id),
        httponly=True,
        secure=secure,
        samesite=same_site,
        max_age=max(60, int(settings.session_ttl_minutes) * 60),
        path="/",
    )


def _clear_session_cookie(response: Response, request: Request) -> None:
    same_site = _session_cookie_samesite()
    secure = _request_is_secure(request)
    if same_site == "none":
        secure = True
    response.delete_cookie(
        _SESSION_COOKIE_NAME,
        path="/",
        secure=secure,
        httponly=True,
        samesite=same_site,
    )


def _self_service_registration_open(db: Session) -> bool:
    if settings.allow_self_service_registration:
        return True
    return db.query(User.id).first() is None


def _user_root(user: User) -> Path:
    root = Path(settings.staging_path) / str(user.id)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _group_root(group_id: uuid.UUID) -> Path:
    root = Path(settings.staging_path) / "groups" / str(group_id)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _message_attachment_root() -> Path:
    root = Path(settings.staging_path) / "messages"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _safe_message_attachment_path(path_str: str) -> Path:
    root = _message_attachment_root().resolve()
    candidate = Path(path_str).resolve()
    if not candidate.is_relative_to(root):
        raise HTTPException(status_code=400, detail="Invalid attachment path")
    return candidate


def _ensure_message_attachment_encrypted(db: Session, row: DirectMessage, path: Path) -> bool:
    """Best-effort upgrade for legacy plaintext DM attachments."""
    has_nonce_tag = bool(row.attachment_enc_nonce and row.attachment_enc_tag)
    changed = False

    if not has_nonce_tag:
        thread_id = row.thread_id or row.id
        try:
            conversation_key, _ = ensure_conversation_key(
                db,
                thread_id=thread_id,
                user_a_id=row.sender_id,
                user_b_id=row.recipient_id,
            )
        except ValueError:
            raise HTTPException(status_code=409, detail="Conversation key metadata mismatch")
        conversation_dek = get_conversation_dek(conversation_key)
        tmp = path.with_name(f"{path.name}.dmenc.tmp")
        try:
            with path.open("rb") as src:
                nonce_b64, tag_b64, plain_size = encrypt_file_to_path(conversation_dek, src, tmp)
            tmp.replace(path)
        except Exception:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            logger.warning("Failed to encrypt legacy message attachment %s", row.id, exc_info=True)
            raise HTTPException(status_code=500, detail="Attachment encryption failed")

        row.attachment_enc_nonce = nonce_b64
        row.attachment_enc_tag = tag_b64
        row.attachment_size = plain_size
        row.attachment_key_scheme = DM_ATTACHMENT_SCHEME_CONVERSATION
        row.attachment_key_version = int(conversation_key.key_version or 1)
        changed = True

    if row.attachment_enc_nonce and row.attachment_enc_tag and not row.attachment_key_scheme:
        row.attachment_key_scheme = DM_ATTACHMENT_SCHEME_RECIPIENT
        changed = True

    return changed


def _conversation_filter(user_a: uuid.UUID, user_b: uuid.UUID):
    return or_(
        and_(DirectMessage.sender_id == user_a, DirectMessage.recipient_id == user_b),
        and_(DirectMessage.sender_id == user_b, DirectMessage.recipient_id == user_a),
    )


def _resolve_thread_id(
    db: Session,
    *,
    sender_id: uuid.UUID,
    recipient_id: uuid.UUID,
    requested_thread: str | None,
) -> uuid.UUID:
    pair_filter = _conversation_filter(sender_id, recipient_id)
    if requested_thread:
        try:
            tid = uuid.UUID(requested_thread)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid thread id")

        exists = (
            db.query(DirectMessage.id)
            .filter(pair_filter, DirectMessage.thread_id == tid)
            .first()
        )
        if not exists:
            raise HTTPException(status_code=400, detail="Thread not found for this conversation")
        return tid

    latest_thread = (
        db.query(DirectMessage.thread_id)
        .filter(pair_filter, DirectMessage.thread_id.is_not(None))
        .order_by(DirectMessage.created_at.desc())
        .limit(1)
        .scalar()
    )
    return latest_thread or uuid.uuid4()


def _conversation_body_key_label(version: int | None) -> str:
    return f"{_DM_BODY_CONVERSATION_KEY_LABEL}:v{version}" if version else _DM_BODY_CONVERSATION_KEY_LABEL


def _conversation_attachment_key_label(version: int | None) -> str:
    return (
        f"{_DM_ATTACHMENT_CONVERSATION_KEY_LABEL}:v{version}"
        if version
        else _DM_ATTACHMENT_CONVERSATION_KEY_LABEL
    )


def _decrypt_direct_message_body_with_conversation_key(
    row: DirectMessage,
    conversation_key: ConversationKey | None,
) -> str:
    body_value = row.body or ""
    needs_conversation_key = (
        is_dm_conversation_encrypted(body_value)
        or (row.body_key_scheme or "").strip().lower() == DM_BODY_SCHEME_CONVERSATION
    )
    if not needs_conversation_key:
        return decrypt_message(body_value)

    if conversation_key is None:
        # If metadata claims conversation-key but body is plaintext/legacy, keep backward compatibility.
        if not is_dm_conversation_encrypted(body_value):
            return decrypt_message(body_value)
        return "[message unavailable]"

    try:
        conversation_dek = get_conversation_dek(conversation_key)
    except Exception:
        return "[message unavailable]"
    return decrypt_dm_body(body_value, conversation_dek)


def _ensure_conversation_key_for_message(db: Session, row: DirectMessage) -> tuple[ConversationKey, bool]:
    thread_id = row.thread_id or row.id
    created_thread_id = row.thread_id is None
    if created_thread_id:
        row.thread_id = thread_id
    key_row, created = ensure_conversation_key(
        db,
        thread_id=thread_id,
        user_a_id=row.sender_id,
        user_b_id=row.recipient_id,
    )
    return key_row, (created or created_thread_id)


def _format_utc(value: datetime | None) -> str:
    return format_datetime_for_timezone(value, _ACTIVE_TIMEZONE.get())


def _format_utc_iso(value: datetime | None) -> str:
    return format_datetime_iso_utc(value)


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


def _profile_redirect(message: str, *, error: bool = False) -> RedirectResponse:
    key = "error" if error else "notice"
    return RedirectResponse(url=f"/ui/profile?{key}={quote_plus(message)}", status_code=303)


def _profile_avatar_root(user: User) -> Path:
    root = Path(settings.staging_path) / "profiles" / str(user.id)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _safe_profile_asset_path(path_str: str) -> Path:
    root = (Path(settings.staging_path) / "profiles").resolve()
    candidate = Path(path_str).resolve()
    if not candidate.is_relative_to(root):
        raise HTTPException(status_code=400, detail="Invalid profile asset path")
    return candidate


def _profile_timezone_rows() -> list[str]:
    return PROFILE_TIMEZONE_OPTIONS


def _normalize_email(value: str) -> str:
    normalized = (value or "").strip().lower()
    if not normalized:
        return ""
    if len(normalized) > 320:
        raise HTTPException(status_code=400, detail="Email is too long")
    if "@" not in normalized:
        raise HTTPException(status_code=400, detail="Invalid email format")
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", normalized):
        raise HTTPException(status_code=400, detail="Invalid email format")
    return normalized


def _normalize_phone(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if len(raw) > 48:
        raise HTTPException(status_code=400, detail="Phone number is too long")
    if not re.fullmatch(r"[0-9+()\-\s.]{7,48}", raw):
        raise HTTPException(status_code=400, detail="Invalid phone number format")
    return raw


def _normalize_sms_carrier(value: str | None) -> str:
    carrier = (value or "").strip().lower()
    if carrier in SMS_CARRIER_GATEWAYS:
        return carrier
    return ""


def _sms_carrier_rows() -> list[dict[str, str]]:
    return [{"value": key, "label": label} for key, label, _ in SMS_CARRIER_OPTIONS]


def _sms_provider_mode() -> str:
    mode = (settings.sms_provider or "").strip().lower()
    if mode not in {SMS_PROVIDER_SMTP_GATEWAY, SMS_PROVIDER_TWILIO, SMS_PROVIDER_AUTO}:
        return SMS_PROVIDER_SMTP_GATEWAY
    if mode == SMS_PROVIDER_TWILIO and not _twilio_configured() and _smtp_configured():
        # Preserve existing deployments that still have PFV_SMS_PROVIDER=twilio but are moving to SMTP gateways.
        return SMS_PROVIDER_AUTO
    if mode == SMS_PROVIDER_SMTP_GATEWAY and not _smtp_configured() and _twilio_configured():
        # Allow fallback for older environments where Twilio is configured but SMTP is not.
        return SMS_PROVIDER_AUTO
    return mode


def _sms_provider_label() -> str:
    return SMS_PROVIDER_LABELS.get(_sms_provider_mode(), _sms_provider_mode())


def _sms_gateway_digits(phone_number: str, *, strict: bool = True) -> str:
    digits = "".join(ch for ch in (phone_number or "") if ch.isdigit())
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        if strict:
            raise RuntimeError("Carrier gateway SMS requires a US 10-digit phone number.")
        return ""
    return digits


def _sms_gateway_destination(*, phone_number: str, carrier: str) -> str:
    normalized_carrier = _normalize_sms_carrier(carrier)
    domain = SMS_CARRIER_GATEWAYS.get(normalized_carrier)
    if not domain:
        raise RuntimeError("Carrier selection is required for SMS gateway delivery.")
    digits = _sms_gateway_digits(phone_number)
    return f"{digits}@{domain}"


def _email_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _public_origin(request: Request) -> str:
    configured = (settings.public_base_url or "").strip().rstrip("/")
    if configured:
        parsed = urlsplit(configured)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return configured
    return str(request.base_url).rstrip("/")


def _smtp_configured() -> bool:
    return bool(settings.smtp_host and settings.smtp_from)


def _send_email_message(message: EmailMessage) -> None:
    host = settings.smtp_host.strip()
    if not host:
        raise RuntimeError("SMTP host is not configured")

    username = settings.smtp_username.strip()
    password = settings.smtp_password
    port = int(settings.smtp_port)

    if settings.smtp_use_ssl:
        with smtplib.SMTP_SSL(host, port, timeout=15) as client:
            if username:
                client.login(username, password)
            client.send_message(message)
        return

    with smtplib.SMTP(host, port, timeout=15) as client:
        if settings.smtp_use_tls:
            client.starttls(context=ssl.create_default_context())
        if username:
            client.login(username, password)
        client.send_message(message)


def _twilio_configured() -> bool:
    return bool(
        settings.twilio_account_sid.strip()
        and settings.twilio_auth_token
        and settings.twilio_from_number.strip()
    )


def _sms_configuration_error_for_values(*, phone_number: str | None, sms_carrier: str | None) -> str | None:
    mode = _sms_provider_mode()
    phone = (phone_number or "").strip()
    carrier = _normalize_sms_carrier(sms_carrier)

    if mode == SMS_PROVIDER_TWILIO:
        if not _twilio_configured():
            return "Twilio credentials are not configured."
        if not phone:
            return "Phone number is required for SMS MFA."
        return None

    if mode == SMS_PROVIDER_SMTP_GATEWAY:
        if not _smtp_configured():
            return "SMTP is not configured."
        if not phone:
            return "Phone number is required for SMS MFA."
        if not carrier:
            return "Carrier selection is required for SMS MFA."
        if not _sms_gateway_digits(phone, strict=False):
            return "Carrier gateway SMS requires a US 10-digit phone number."
        return None

    # auto mode: allow gateway transport first, then Twilio fallback.
    if not phone:
        return "Phone number is required for SMS MFA."
    if carrier and _smtp_configured() and _sms_gateway_digits(phone, strict=False):
        return None
    if _twilio_configured():
        return None
    if _smtp_configured() and not carrier:
        return "Carrier selection is required for SMS MFA."
    if _smtp_configured() and carrier and not _sms_gateway_digits(phone, strict=False):
        return "Carrier gateway SMS requires a US 10-digit phone number."
    if not _smtp_configured() and not _twilio_configured():
        return "SMS transport is not configured."
    return "SMS transport is not configured."


def _sms_configuration_error(user: User) -> str | None:
    return _sms_configuration_error_for_values(phone_number=user.phone_number, sms_carrier=user.sms_carrier)


def _sms_configured(user: User | None = None) -> bool:
    if user:
        return _sms_configuration_error(user) is None
    mode = _sms_provider_mode()
    if mode == SMS_PROVIDER_TWILIO:
        return _twilio_configured()
    if mode == SMS_PROVIDER_SMTP_GATEWAY:
        return _smtp_configured()
    if mode == SMS_PROVIDER_AUTO:
        return _smtp_configured() or _twilio_configured()
    return False


def _send_sms_via_twilio(*, to_number: str, body: str) -> None:
    account_sid = settings.twilio_account_sid.strip()
    auth_token = settings.twilio_auth_token
    from_number = settings.twilio_from_number.strip()
    if not account_sid or not auth_token or not from_number:
        raise RuntimeError("Twilio SMS credentials are not configured")

    url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
    payload = urlencode({"To": to_number, "From": from_number, "Body": body}).encode()
    req = UrlRequest(url, data=payload, method="POST")
    token = base64.b64encode(f"{account_sid}:{auth_token}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urlopen(req, timeout=15) as resp:
            status = getattr(resp, "status", 200)
            if status >= 400:
                raise RuntimeError(f"Twilio returned status {status}")
    except (HTTPError, URLError) as exc:
        raise RuntimeError(f"Twilio SMS send failed: {exc}") from exc


def _send_sms_message(*, user: User, body: str) -> str:
    mode = _sms_provider_mode()
    phone = (user.phone_number or "").strip()
    carrier = _normalize_sms_carrier(user.sms_carrier)

    if mode in {SMS_PROVIDER_SMTP_GATEWAY, SMS_PROVIDER_AUTO} and carrier and _smtp_configured():
        destination = _sms_gateway_destination(phone_number=phone, carrier=carrier)
        message = EmailMessage()
        message["From"] = settings.smtp_from
        message["To"] = destination
        message["Subject"] = " "
        message.set_content(body)
        _send_email_message(message)
        return "gateway"

    if mode == SMS_PROVIDER_SMTP_GATEWAY:
        raise RuntimeError("Carrier gateway SMS is not configured for this account.")

    if mode in {SMS_PROVIDER_TWILIO, SMS_PROVIDER_AUTO} and _twilio_configured():
        _send_sms_via_twilio(to_number=phone, body=body)
        return "twilio"

    raise RuntimeError("SMS transport is not configured.")


def _mfa_secret_key() -> bytes:
    material = f"{settings.master_key}|{settings.totp_encryption_key}".encode()
    return hashlib.sha256(material).digest()


def _mfa_code_hash(*, user: User, method: str, code: str) -> str:
    payload = f"{user.id}:{method}:{code}".encode()
    return hmac.new(_mfa_secret_key(), payload, hashlib.sha256).hexdigest()


def _clear_mfa_challenge(user: User) -> None:
    user.mfa_challenge_method = None
    user.mfa_challenge_code_hash = None
    user.mfa_challenge_expires_at = None
    user.mfa_challenge_sent_at = None
    user.mfa_challenge_attempts = 0


def _mfa_method_display(method: str) -> str:
    return MFA_METHOD_LABELS.get(method, method.upper())


def _mfa_summary_for_user(user: User) -> str:
    parts: list[str] = []
    if user.totp_enabled:
        parts.append("TOTP")
    if user.email_mfa_enabled:
        parts.append("Email")
    if user.sms_mfa_enabled:
        parts.append("SMS")
    return ", ".join(parts) if parts else "Disabled"


def _available_mfa_methods(user: User, *, transport_ready_only: bool = True) -> list[str]:
    methods: list[str] = []
    if user.totp_enabled and user.totp_secret_enc:
        methods.append(MFA_METHOD_TOTP)
    if user.email_mfa_enabled and user.email and user.email_verified:
        if (not transport_ready_only) or _smtp_configured():
            methods.append(MFA_METHOD_EMAIL)
    if user.sms_mfa_enabled and user.phone_number:
        if (not transport_ready_only) or _sms_configured(user):
            methods.append(MFA_METHOD_SMS)
    return methods


def _resolve_mfa_method(user: User, requested: str | None, available_methods: list[str]) -> str:
    method = _normalize_mfa_method(requested)
    if method in available_methods:
        return method

    preferred = _normalize_mfa_method(user.mfa_preferred_method)
    if preferred in available_methods:
        return preferred

    if MFA_METHOD_TOTP in available_methods:
        return MFA_METHOD_TOTP
    if available_methods:
        return available_methods[0]
    return ""


def _mfa_destination_hint(user: User, method: str) -> str:
    if method == MFA_METHOD_EMAIL:
        return _mask_email(user.email or "")
    if method == MFA_METHOD_SMS:
        carrier = _normalize_sms_carrier(user.sms_carrier)
        if carrier:
            return f"{_mask_phone(user.phone_number or '')} ({SMS_CARRIER_LABELS.get(carrier, carrier)})"
        return _mask_phone(user.phone_number or "")
    return "authenticator app"


def _verify_totp_for_user(user: User, code: str) -> bool:
    if not user.totp_enabled or not user.totp_secret_enc:
        return False
    value = (code or "").strip()
    if not value:
        return False
    secret = decrypt_totp_secret(user.totp_secret_enc)
    return pyotp.TOTP(secret).verify(value)


def _issue_mfa_challenge(user: User, method: str) -> str:
    if method not in {MFA_METHOD_EMAIL, MFA_METHOD_SMS}:
        raise HTTPException(status_code=400, detail="Unsupported MFA challenge method")

    now = datetime.utcnow()
    cooldown = max(0, int(settings.mfa_resend_cooldown_seconds))
    if (
        user.mfa_challenge_method == method
        and user.mfa_challenge_sent_at
        and (now - user.mfa_challenge_sent_at).total_seconds() < cooldown
    ):
        wait_seconds = int(cooldown - (now - user.mfa_challenge_sent_at).total_seconds())
        wait_seconds = max(1, wait_seconds)
        raise HTTPException(status_code=429, detail=f"Please wait {wait_seconds}s before requesting another code.")

    code = f"{secrets.randbelow(1_000_000):06d}"
    ttl_seconds = max(60, int(settings.mfa_code_ttl_seconds))

    if method == MFA_METHOD_EMAIL:
        if not user.email or not user.email_verified:
            raise HTTPException(status_code=400, detail="Verified email is required for email MFA.")
        if not _smtp_configured():
            raise HTTPException(status_code=503, detail="SMTP is not configured.")
        message = EmailMessage()
        message["From"] = settings.smtp_from
        message["To"] = user.email
        message["Subject"] = "Your FileFort sign-in code"
        message.set_content(
            f"Hello {user.username},\n\n"
            f"Your FileFort sign-in code is: {code}\n\n"
            f"The code expires in {ttl_seconds // 60} minute(s).\n"
            "If you did not request this, you can ignore this email."
        )
        _send_email_message(message)
    else:
        if not user.phone_number:
            raise HTTPException(status_code=400, detail="Phone number is required for SMS MFA.")
        sms_error = _sms_configuration_error(user)
        if sms_error:
            status = 503 if "configured" in sms_error.lower() else 400
            raise HTTPException(status_code=status, detail=sms_error)
        _send_sms_message(user=user, body=f"FileFort code: {code}. Expires in {ttl_seconds // 60} min.")

    user.mfa_challenge_method = method
    user.mfa_challenge_code_hash = _mfa_code_hash(user=user, method=method, code=code)
    user.mfa_challenge_expires_at = now + timedelta(seconds=ttl_seconds)
    user.mfa_challenge_sent_at = now
    user.mfa_challenge_attempts = 0
    return _mfa_destination_hint(user, method)


def _verify_mfa_challenge(user: User, method: str, code: str) -> tuple[bool, str]:
    value = (code or "").strip()
    if not value:
        return False, "MFA code is required."

    if method not in {MFA_METHOD_EMAIL, MFA_METHOD_SMS}:
        return False, "Unsupported MFA method."

    if (
        not user.mfa_challenge_method
        or user.mfa_challenge_method != method
        or not user.mfa_challenge_code_hash
        or not user.mfa_challenge_expires_at
    ):
        return False, "No active MFA code. Request a new code."

    now = datetime.utcnow()
    if user.mfa_challenge_expires_at < now:
        _clear_mfa_challenge(user)
        return False, "MFA code expired. Request a new code."

    max_attempts = max(1, int(settings.mfa_max_attempts))
    attempts = int(user.mfa_challenge_attempts or 0)
    if attempts >= max_attempts:
        _clear_mfa_challenge(user)
        return False, "Too many invalid attempts. Request a new code."

    expected = _mfa_code_hash(user=user, method=method, code=value)
    if not hmac.compare_digest(expected, user.mfa_challenge_code_hash):
        user.mfa_challenge_attempts = attempts + 1
        if user.mfa_challenge_attempts >= max_attempts:
            _clear_mfa_challenge(user)
            return False, "Too many invalid attempts. Request a new code."
        return False, "Invalid MFA code."

    _clear_mfa_challenge(user)
    return True, ""


def _directory_lock_message(user: User | None) -> str:
    if not user:
        return "Directory changes are locked by an administrator."
    reason = (getattr(user, "directory_lock_reason", "") or "").strip()
    base = "Directory changes are locked by an administrator."
    if reason:
        return f"{base} Reason: {reason}"
    return f"{base} Request an admin release to continue."


def _admin_redirect(message: str, *, error: bool = False) -> RedirectResponse:
    return _admin_redirect_with_target(message, error=error, target="security")


def _normalize_admin_redirect_target(value: str | None) -> str:
    target = (value or "").strip().lower()
    if target in {"security", "users"}:
        return "security"
    return "security"


def _admin_redirect_with_target(
    message: str,
    *,
    error: bool = False,
    target: str = "users",
) -> RedirectResponse:
    key = "error" if error else "notice"
    _normalize_admin_redirect_target(target)
    base = "/ui/admin/security"
    return RedirectResponse(url=f"{base}?{key}={quote_plus(message)}", status_code=303)


def _admin_reports_redirect(
    message: str,
    *,
    error: bool = False,
    report_id: str | None = None,
) -> RedirectResponse:
    key = "error" if error else "notice"
    base = f"/ui/admin/reports/{report_id}" if report_id else "/ui/admin/reports"
    return RedirectResponse(url=f"{base}?{key}={quote_plus(message)}", status_code=303)


def _help_redirect(message: str, *, error: bool = False) -> RedirectResponse:
    key = "error" if error else "notice"
    return RedirectResponse(url=f"/ui/help?{key}={quote_plus(message)}", status_code=303)


def _admin_help_redirect(message: str, *, error: bool = False, ticket_id: str | None = None) -> RedirectResponse:
    key = "error" if error else "notice"
    base = f"/ui/admin/help/{ticket_id}" if ticket_id else "/ui/admin/help"
    return RedirectResponse(url=f"{base}?{key}={quote_plus(message)}", status_code=303)


def _admin_security_redirect(message: str, *, error: bool = False) -> RedirectResponse:
    key = "error" if error else "notice"
    return RedirectResponse(url=f"/ui/admin/security?{key}={quote_plus(message)}", status_code=303)


def _redirect_with_message(base_url: str, *, message: str, error: bool = False) -> RedirectResponse:
    key = "error" if error else "notice"
    sep = "&" if "?" in base_url else "?"
    return RedirectResponse(url=f"{base_url}{sep}{key}={quote_plus(message)}", status_code=303)


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
    # Use stable identifiers so links survive process reloads/restarts.
    token = str(file_id)
    if session_id:
        _FILE_TOKEN_CACHE.setdefault(session_id, {})[token] = token
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
        "timeline": "enctimeline",
        "enctrace": "enctimeline",
        "rekey": "encrotate",
        "rotate": "encrotate",
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


def _rotation_work_path(path: Path, marker: str) -> Path:
    token = uuid.uuid4().hex
    return path.with_name(f".{path.name}.{marker}.{token}")


def _cleanup_rotation_paths(paths: list[Path]) -> None:
    for path in paths:
        try:
            if path.exists():
                path.unlink()
        except Exception:
            logger.warning("Rotation cleanup failed for %s", path, exc_info=True)


def _restore_rotation_swaps(swapped_paths: list[tuple[Path, Path]]) -> None:
    for active_path, backup_path in reversed(swapped_paths):
        if not backup_path.exists():
            continue
        try:
            if active_path.exists():
                active_path.unlink()
            backup_path.replace(active_path)
        except Exception:
            logger.warning(
                "Failed to restore rotated file from backup (%s <- %s)",
                active_path,
                backup_path,
                exc_info=True,
            )


def _rotate_blob_in_place(
    *,
    old_dek: bytes,
    new_dek: bytes,
    path: Path,
    nonce_b64: str,
    tag_b64: str,
    swapped_paths: list[tuple[Path, Path]],
    temp_paths: list[Path],
) -> tuple[str, str, int]:
    tmp_path = _rotation_work_path(path, "encrotate.tmp")
    backup_path = _rotation_work_path(path, "encrotate.bak")
    temp_paths.append(tmp_path)

    new_nonce, new_tag, plain_size = reencrypt_file_to_path(
        old_dek=old_dek,
        new_dek=new_dek,
        src_path=path,
        src_nonce_b64=nonce_b64,
        src_tag_b64=tag_b64,
        dst_path=tmp_path,
    )

    moved_to_backup = False
    try:
        path.replace(backup_path)
        moved_to_backup = True
        swapped_paths.append((path, backup_path))
        tmp_path.replace(path)
    except Exception:
        if moved_to_backup and backup_path.exists():
            try:
                backup_path.replace(path)
            except Exception:
                logger.warning("Failed to restore original file during rotate rollback: %s", path, exc_info=True)
        raise

    return new_nonce, new_tag, plain_size


def _verify_rotated_ciphertext(dek: bytes, path: Path, nonce_b64: str, tag_b64: str) -> int:
    total_plain = 0
    for chunk in decrypt_file_iter(dek, path, nonce_b64, tag_b64):
        if chunk:
            total_plain += len(chunk)
    return total_plain


def _key_material_fingerprint(dek: bytes) -> str:
    return hashlib.sha256(dek).hexdigest()


def _collect_key_uniqueness_summary(db: Session) -> dict[str, int | bool]:
    master = master_key_bytes()
    user_fingerprints: set[str] = set()
    group_fingerprints: set[str] = set()
    conversation_fingerprints: set[str] = set()
    all_fingerprints: set[str] = set()
    unwrap_errors = 0

    user_rows = db.query(UserKey.user_id, UserKey.wrap_nonce, UserKey.wrapped_dek).all()
    for user_id, wrap_nonce, wrapped_dek in user_rows:
        try:
            dek = unwrap_key(master, wrap_nonce, wrapped_dek, aad=str(user_id).encode())
        except Exception:
            unwrap_errors += 1
            continue
        fp = _key_material_fingerprint(dek)
        user_fingerprints.add(fp)
        all_fingerprints.add(fp)

    group_rows = db.query(GroupKey.group_id, GroupKey.wrap_nonce, GroupKey.wrapped_dek).all()
    for group_id, wrap_nonce, wrapped_dek in group_rows:
        try:
            dek = unwrap_key(master, wrap_nonce, wrapped_dek, aad=f"group:{group_id}".encode())
        except Exception:
            unwrap_errors += 1
            continue
        fp = _key_material_fingerprint(dek)
        group_fingerprints.add(fp)
        all_fingerprints.add(fp)

    conversation_rows = (
        db.query(
            ConversationKey.thread_id,
            ConversationKey.user_low_id,
            ConversationKey.user_high_id,
            ConversationKey.wrap_nonce,
            ConversationKey.wrapped_dek,
        )
        .all()
    )
    for thread_id, user_low_id, user_high_id, wrap_nonce, wrapped_dek in conversation_rows:
        try:
            dek = unwrap_key(
                master,
                wrap_nonce,
                wrapped_dek,
                aad=conversation_aad(thread_id, user_low_id, user_high_id),
            )
        except Exception:
            unwrap_errors += 1
            continue
        fp = _key_material_fingerprint(dek)
        conversation_fingerprints.add(fp)
        all_fingerprints.add(fp)

    total_records = len(user_rows) + len(group_rows) + len(conversation_rows)
    unique_records = len(all_fingerprints)
    duplicate_records = max(0, total_records - unique_records)

    return {
        "key_material_total_records": total_records,
        "key_material_unique_records": unique_records,
        "key_material_duplicate_records": duplicate_records,
        "key_material_errors": unwrap_errors,
        "key_material_not_all_same": bool(total_records <= 1 or unique_records > 1),
        "user_key_material_unique": len(user_fingerprints),
        "group_key_material_unique": len(group_fingerprints),
        "conversation_key_material_unique": len(conversation_fingerprints),
    }


def _rotate_user_key_material(db: Session, user: User) -> dict[str, int]:
    key_row = ensure_user_key(db, user)
    old_key_version = int(key_row.key_version or 1)

    old_dek = get_user_dek(db, user)
    new_dek = generate_key_32()

    summary = {
        "files_total": 0,
        "files_rotated": 0,
        "files_plain_skipped": 0,
        "files_missing_meta": 0,
        "files_missing_path": 0,
        "files_invalid_path": 0,
        "avatar_rotated": 0,
        "avatar_missing_meta": 0,
        "avatar_missing_path": 0,
        "avatar_invalid_path": 0,
        "recipient_attachments_total": 0,
        "recipient_attachments_rotated": 0,
        "recipient_attachments_missing_meta": 0,
        "recipient_attachments_missing_path": 0,
        "recipient_attachments_invalid_path": 0,
        "recipient_attachments_non_recipient_scheme": 0,
        "verification_checks_total": 0,
        "verification_checks_passed": 0,
        "verification_bytes_checked": 0,
        "key_version_from": old_key_version,
        "key_version_to": old_key_version + 1,
    }

    swapped_paths: list[tuple[Path, Path]] = []
    temp_paths: list[Path] = []
    rotated_user_targets: list[tuple[Path, str, str]] = []
    rotated_recipient_attachment_targets: list[tuple[Path, str, str]] = []
    rotated_avatar_targets: list[tuple[Path, str, str]] = []
    committed = False

    try:
        user_root = _user_root(user)
        file_rows = db.query(FileRecord).filter(FileRecord.user_id == user.id).all()
        summary["files_total"] = len(file_rows)
        for row in file_rows:
            if not row.is_encrypted:
                summary["files_plain_skipped"] += 1
                continue
            if not row.enc_nonce or not row.enc_tag:
                summary["files_missing_meta"] += 1
                continue

            try:
                path = _resolve_user_file_path(user, row.file_path)
            except HTTPException:
                summary["files_invalid_path"] += 1
                continue

            if not path.exists() or not path.is_file():
                summary["files_missing_path"] += 1
                continue

            _ensure_no_symlink(path, user_root)
            nonce_b64, tag_b64, plain_size = _rotate_blob_in_place(
                old_dek=old_dek,
                new_dek=new_dek,
                path=path,
                nonce_b64=row.enc_nonce,
                tag_b64=row.enc_tag,
                swapped_paths=swapped_paths,
                temp_paths=temp_paths,
            )
            row.enc_nonce = nonce_b64
            row.enc_tag = tag_b64
            row.file_size = plain_size
            rotated_user_targets.append((path, nonce_b64, tag_b64))
            summary["files_rotated"] += 1

        if user.profile_image_path:
            if not user.profile_image_nonce or not user.profile_image_tag:
                summary["avatar_missing_meta"] += 1
            else:
                try:
                    avatar_path = _safe_profile_asset_path(user.profile_image_path)
                except HTTPException:
                    summary["avatar_invalid_path"] += 1
                else:
                    if not avatar_path.exists() or not avatar_path.is_file():
                        summary["avatar_missing_path"] += 1
                    else:
                        nonce_b64, tag_b64, _ = _rotate_blob_in_place(
                            old_dek=old_dek,
                            new_dek=new_dek,
                            path=avatar_path,
                            nonce_b64=user.profile_image_nonce,
                            tag_b64=user.profile_image_tag,
                            swapped_paths=swapped_paths,
                            temp_paths=temp_paths,
                        )
                        user.profile_image_nonce = nonce_b64
                        user.profile_image_tag = tag_b64
                        rotated_avatar_targets.append((avatar_path, nonce_b64, tag_b64))
                        summary["avatar_rotated"] = 1

        dm_rows = (
            db.query(DirectMessage)
            .filter(
                DirectMessage.recipient_id == user.id,
                DirectMessage.attachment_path.is_not(None),
            )
            .all()
        )
        summary["recipient_attachments_total"] = len(dm_rows)
        for row in dm_rows:
            scheme = (row.attachment_key_scheme or "").strip().lower()
            if scheme and scheme != DM_ATTACHMENT_SCHEME_RECIPIENT:
                summary["recipient_attachments_non_recipient_scheme"] += 1
                continue
            if not row.attachment_enc_nonce or not row.attachment_enc_tag:
                summary["recipient_attachments_missing_meta"] += 1
                continue
            if not row.attachment_path:
                summary["recipient_attachments_missing_path"] += 1
                continue

            try:
                attachment_path = _safe_message_attachment_path(row.attachment_path)
            except HTTPException:
                summary["recipient_attachments_invalid_path"] += 1
                continue

            if not attachment_path.exists() or not attachment_path.is_file():
                summary["recipient_attachments_missing_path"] += 1
                continue

            nonce_b64, tag_b64, plain_size = _rotate_blob_in_place(
                old_dek=old_dek,
                new_dek=new_dek,
                path=attachment_path,
                nonce_b64=row.attachment_enc_nonce,
                tag_b64=row.attachment_enc_tag,
                swapped_paths=swapped_paths,
                temp_paths=temp_paths,
            )
            row.attachment_enc_nonce = nonce_b64
            row.attachment_enc_tag = tag_b64
            row.attachment_size = plain_size
            row.attachment_key_scheme = DM_ATTACHMENT_SCHEME_RECIPIENT
            rotated_recipient_attachment_targets.append((attachment_path, nonce_b64, tag_b64))
            summary["recipient_attachments_rotated"] += 1

        verification_targets = rotated_user_targets + rotated_recipient_attachment_targets + rotated_avatar_targets
        summary["verification_checks_total"] = len(verification_targets)
        for path, nonce_b64, tag_b64 in verification_targets:
            verified_size = _verify_rotated_ciphertext(new_dek, path, nonce_b64, tag_b64)
            summary["verification_checks_passed"] += 1
            summary["verification_bytes_checked"] += verified_size

        master = master_key_bytes()
        wrap_nonce, wrapped_dek = wrap_key(master, new_dek, aad=str(user.id).encode())
        unwrap_probe = unwrap_key(master, wrap_nonce, wrapped_dek, aad=str(user.id).encode())
        if unwrap_probe != new_dek:
            raise RuntimeError("User key wrap verification failed after rotation")
        key_row.wrap_nonce = wrap_nonce
        key_row.wrapped_dek = wrapped_dek
        key_row.key_version = old_key_version + 1
        key_row.created_at = datetime.utcnow()
        db.add(
            AuditLog(
                user_id=user.id,
                event_type="encryption.user_key_rotated",
                details=(
                    f"Rotated user key id={key_row.id} user={user.id} "
                    f"version={old_key_version}->{key_row.key_version}, "
                    f"files_rotated={summary['files_rotated']}, "
                    f"recipient_attachments_rotated={summary['recipient_attachments_rotated']}, "
                    f"avatar_rotated={summary['avatar_rotated']}."
                ),
            )
        )

        db.commit()
        committed = True
        return summary
    except Exception:
        db.rollback()
        _restore_rotation_swaps(swapped_paths)
        raise
    finally:
        _cleanup_rotation_paths(temp_paths)
        if committed:
            _cleanup_rotation_paths([backup_path for _, backup_path in swapped_paths])


def _rotate_message_ciphertexts(
    db: Session,
    user: User,
    *,
    include_recipient_attachments: bool = True,
) -> dict[str, int]:
    summary = {
        "messages_total": 0,
        "messages_rotated": 0,
        "messages_upgraded_plaintext": 0,
        "messages_unavailable": 0,
        "conversation_keys_touched": 0,
        "attachments_total": 0,
        "attachments_conversation_rotated": 0,
        "attachments_system_rotated": 0,
        "attachments_recipient_rotated": 0,
        "attachments_recipient_skipped": 0,
        "attachments_missing_meta": 0,
        "attachments_missing_path": 0,
        "attachments_invalid_path": 0,
        "attachments_unknown_scheme": 0,
    }

    swapped_paths: list[tuple[Path, Path]] = []
    temp_paths: list[Path] = []
    committed = False

    try:
        dm_rows = (
            db.query(DirectMessage)
            .filter(or_(DirectMessage.sender_id == user.id, DirectMessage.recipient_id == user.id))
            .all()
        )
        summary["messages_total"] = len(dm_rows)

        system_attachment_key = message_attachment_key_bytes()
        recipient_dek = get_user_dek(db, user) if include_recipient_attachments else b""
        conversation_dek_by_thread: dict[uuid.UUID, bytes] = {}
        touched_thread_ids: set[uuid.UUID] = set()

        for row in dm_rows:
            thread_id = row.thread_id or row.id
            if row.thread_id is None:
                row.thread_id = thread_id
            conversation_key, _ = ensure_conversation_key(
                db,
                thread_id=thread_id,
                user_a_id=row.sender_id,
                user_b_id=row.recipient_id,
            )
            conversation_version = int(conversation_key.key_version or 1)
            conversation_dek = conversation_dek_by_thread.get(thread_id)
            if conversation_dek is None:
                conversation_dek = get_conversation_dek(conversation_key)
                conversation_dek_by_thread[thread_id] = conversation_dek
            touched_thread_ids.add(thread_id)

            body = row.body or ""
            if body:
                if is_dm_conversation_encrypted(body):
                    plain = decrypt_dm_body(body, conversation_dek)
                    if plain == "[message unavailable]":
                        summary["messages_unavailable"] += 1
                    else:
                        row.body = encrypt_dm_body(plain, conversation_dek)
                        row.body_key_scheme = DM_BODY_SCHEME_CONVERSATION
                        row.body_key_version = conversation_version
                        summary["messages_rotated"] += 1
                elif is_message_encrypted(body):
                    plain = decrypt_message(body)
                    if plain == "[message unavailable]":
                        summary["messages_unavailable"] += 1
                    else:
                        row.body = encrypt_dm_body(plain, conversation_dek)
                        row.body_key_scheme = DM_BODY_SCHEME_CONVERSATION
                        row.body_key_version = conversation_version
                        summary["messages_upgraded_plaintext"] += 1
                else:
                    row.body = encrypt_dm_body(body, conversation_dek)
                    row.body_key_scheme = DM_BODY_SCHEME_CONVERSATION
                    row.body_key_version = conversation_version
                    summary["messages_upgraded_plaintext"] += 1
            elif (
                row.body_key_scheme != DM_BODY_SCHEME_CONVERSATION
                or row.body_key_version != conversation_version
            ):
                row.body_key_scheme = DM_BODY_SCHEME_CONVERSATION
                row.body_key_version = conversation_version

            if not row.attachment_path:
                continue

            summary["attachments_total"] += 1
            if not row.attachment_enc_nonce or not row.attachment_enc_tag:
                summary["attachments_missing_meta"] += 1
                continue

            try:
                attachment_path = _safe_message_attachment_path(row.attachment_path)
            except HTTPException:
                summary["attachments_invalid_path"] += 1
                continue

            if not attachment_path.exists() or not attachment_path.is_file():
                summary["attachments_missing_path"] += 1
                continue

            scheme = (row.attachment_key_scheme or "").strip().lower()
            if scheme in {"", DM_ATTACHMENT_SCHEME_RECIPIENT}:
                if not include_recipient_attachments or row.recipient_id != user.id:
                    summary["attachments_recipient_skipped"] += 1
                    continue

                nonce_b64, tag_b64, plain_size = _rotate_blob_in_place(
                    old_dek=recipient_dek,
                    new_dek=recipient_dek,
                    path=attachment_path,
                    nonce_b64=row.attachment_enc_nonce,
                    tag_b64=row.attachment_enc_tag,
                    swapped_paths=swapped_paths,
                    temp_paths=temp_paths,
                )
                row.attachment_enc_nonce = nonce_b64
                row.attachment_enc_tag = tag_b64
                row.attachment_size = plain_size
                row.attachment_key_scheme = DM_ATTACHMENT_SCHEME_CONVERSATION
                row.attachment_key_version = conversation_version
                summary["attachments_recipient_rotated"] += 1
                continue

            if scheme == DM_ATTACHMENT_SCHEME_SYSTEM:
                nonce_b64, tag_b64, plain_size = _rotate_blob_in_place(
                    old_dek=system_attachment_key,
                    new_dek=conversation_dek,
                    path=attachment_path,
                    nonce_b64=row.attachment_enc_nonce,
                    tag_b64=row.attachment_enc_tag,
                    swapped_paths=swapped_paths,
                    temp_paths=temp_paths,
                )
                row.attachment_enc_nonce = nonce_b64
                row.attachment_enc_tag = tag_b64
                row.attachment_size = plain_size
                row.attachment_key_scheme = DM_ATTACHMENT_SCHEME_CONVERSATION
                row.attachment_key_version = conversation_version
                summary["attachments_system_rotated"] += 1
                continue

            if scheme == DM_ATTACHMENT_SCHEME_CONVERSATION:
                nonce_b64, tag_b64, plain_size = _rotate_blob_in_place(
                    old_dek=conversation_dek,
                    new_dek=conversation_dek,
                    path=attachment_path,
                    nonce_b64=row.attachment_enc_nonce,
                    tag_b64=row.attachment_enc_tag,
                    swapped_paths=swapped_paths,
                    temp_paths=temp_paths,
                )
                row.attachment_enc_nonce = nonce_b64
                row.attachment_enc_tag = tag_b64
                row.attachment_size = plain_size
                row.attachment_key_scheme = DM_ATTACHMENT_SCHEME_CONVERSATION
                row.attachment_key_version = conversation_version
                summary["attachments_conversation_rotated"] += 1
                continue

            summary["attachments_unknown_scheme"] += 1

        summary["conversation_keys_touched"] = len(touched_thread_ids)
        db.commit()
        committed = True
        return summary
    except Exception:
        db.rollback()
        _restore_rotation_swaps(swapped_paths)
        raise
    finally:
        _cleanup_rotation_paths(temp_paths)
        if committed:
            _cleanup_rotation_paths([backup_path for _, backup_path in swapped_paths])


def _rotate_group_key_material(db: Session, group: Group) -> dict[str, int | str]:
    group_key = ensure_group_key(db, group)
    old_key_version = int(group_key.key_version or 1)
    old_dek = get_group_dek(db, group)
    new_dek = generate_key_32()

    summary: dict[str, int | str] = {
        "group_id": str(group.id),
        "group_name": group.name,
        "files_total": 0,
        "files_rotated": 0,
        "files_plain_skipped": 0,
        "files_missing_meta": 0,
        "files_missing_path": 0,
        "files_invalid_path": 0,
        "verification_checks_total": 0,
        "verification_checks_passed": 0,
        "verification_bytes_checked": 0,
        "key_version_from": old_key_version,
        "key_version_to": old_key_version + 1,
    }

    swapped_paths: list[tuple[Path, Path]] = []
    temp_paths: list[Path] = []
    rotated_group_targets: list[tuple[Path, str, str]] = []
    committed = False

    try:
        root = _group_root(group.id)
        rows = db.query(GroupFileRecord).filter(GroupFileRecord.group_id == group.id).all()
        summary["files_total"] = len(rows)
        for row in rows:
            if not row.is_encrypted:
                summary["files_plain_skipped"] += 1
                continue
            if not row.enc_nonce or not row.enc_tag:
                summary["files_missing_meta"] += 1
                continue
            try:
                path = Path(row.file_path).resolve()
            except Exception:
                summary["files_invalid_path"] += 1
                continue
            if not path.is_relative_to(root.resolve()):
                summary["files_invalid_path"] += 1
                continue

            if not path.exists() or not path.is_file():
                summary["files_missing_path"] += 1
                continue

            _ensure_no_symlink(path, root)
            nonce_b64, tag_b64, plain_size = _rotate_blob_in_place(
                old_dek=old_dek,
                new_dek=new_dek,
                path=path,
                nonce_b64=row.enc_nonce,
                tag_b64=row.enc_tag,
                swapped_paths=swapped_paths,
                temp_paths=temp_paths,
            )
            row.enc_nonce = nonce_b64
            row.enc_tag = tag_b64
            row.file_size = plain_size
            rotated_group_targets.append((path, nonce_b64, tag_b64))
            summary["files_rotated"] += 1

        summary["verification_checks_total"] = len(rotated_group_targets)
        for path, nonce_b64, tag_b64 in rotated_group_targets:
            verified_size = _verify_rotated_ciphertext(new_dek, path, nonce_b64, tag_b64)
            summary["verification_checks_passed"] += 1
            summary["verification_bytes_checked"] += verified_size

        master = master_key_bytes()
        wrap_nonce, wrapped_dek = wrap_key(master, new_dek, aad=f"group:{group.id}".encode())
        unwrap_probe = unwrap_key(master, wrap_nonce, wrapped_dek, aad=f"group:{group.id}".encode())
        if unwrap_probe != new_dek:
            raise RuntimeError("Group key wrap verification failed after rotation")
        group_key.wrap_nonce = wrap_nonce
        group_key.wrapped_dek = wrapped_dek
        group_key.key_version = old_key_version + 1
        group_key.created_at = datetime.utcnow()
        db.add(
            AuditLog(
                user_id=None,
                event_type="encryption.group_key_rotated",
                details=(
                    f"Rotated group key id={group_key.id} group={group.id} "
                    f"version={old_key_version}->{group_key.key_version}, "
                    f"files_rotated={summary['files_rotated']}."
                ),
            )
        )

        db.commit()
        committed = True
        return summary
    except Exception:
        db.rollback()
        _restore_rotation_swaps(swapped_paths)
        raise
    finally:
        _cleanup_rotation_paths(temp_paths)
        if committed:
            _cleanup_rotation_paths([backup_path for _, backup_path in swapped_paths])


def _rotate_conversation_key_material(db: Session, *, thread_id: uuid.UUID) -> dict[str, int | str]:
    key_row = db.query(ConversationKey).filter(ConversationKey.thread_id == thread_id).first()
    if key_row is None:
        seed = (
            db.query(DirectMessage)
            .filter(
                or_(
                    DirectMessage.thread_id == thread_id,
                    and_(DirectMessage.thread_id.is_(None), DirectMessage.id == thread_id),
                )
            )
            .order_by(DirectMessage.created_at.asc(), DirectMessage.id.asc())
            .first()
        )
        if seed is None:
            raise ValueError("Conversation thread was not found")
        key_row, _ = ensure_conversation_key(
            db,
            thread_id=thread_id,
            user_a_id=seed.sender_id,
            user_b_id=seed.recipient_id,
        )

    old_key_version = int(key_row.key_version or 1)
    old_dek = get_conversation_dek(key_row)
    new_dek = generate_key_32()
    new_key_version = old_key_version + 1

    summary: dict[str, int | str] = {
        "thread_id": str(thread_id),
        "messages_total": 0,
        "messages_rotated": 0,
        "messages_upgraded_plaintext": 0,
        "messages_unavailable": 0,
        "attachments_total": 0,
        "attachments_rotated": 0,
        "attachments_from_conversation": 0,
        "attachments_from_system": 0,
        "attachments_from_recipient": 0,
        "attachments_missing_meta": 0,
        "attachments_missing_path": 0,
        "attachments_invalid_path": 0,
        "attachments_unknown_scheme": 0,
        "attachments_missing_recipient_key": 0,
        "verification_checks_total": 0,
        "verification_checks_passed": 0,
        "verification_bytes_checked": 0,
        "key_version_from": old_key_version,
        "key_version_to": new_key_version,
    }

    swapped_paths: list[tuple[Path, Path]] = []
    temp_paths: list[Path] = []
    rotated_attachment_targets: list[tuple[Path, str, str]] = []
    recipient_dek_cache: dict[uuid.UUID, bytes] = {}
    recipient_user_cache: dict[uuid.UUID, User | None] = {}
    system_attachment_key = message_attachment_key_bytes()
    committed = False

    try:
        expected_pair = {key_row.user_low_id, key_row.user_high_id}
        dm_rows = (
            db.query(DirectMessage)
            .filter(
                or_(
                    DirectMessage.thread_id == thread_id,
                    and_(DirectMessage.thread_id.is_(None), DirectMessage.id == thread_id),
                )
            )
            .order_by(DirectMessage.created_at.asc(), DirectMessage.id.asc())
            .all()
        )
        summary["messages_total"] = len(dm_rows)

        for row in dm_rows:
            if row.thread_id is None:
                row.thread_id = thread_id
            if {row.sender_id, row.recipient_id} != expected_pair:
                raise RuntimeError("Conversation participants mismatch for thread rotation")

            body_value = row.body or ""
            if body_value:
                if is_dm_conversation_encrypted(body_value):
                    plain = decrypt_dm_body(body_value, old_dek)
                    if plain == "[message unavailable]":
                        summary["messages_unavailable"] += 1
                        raise RuntimeError("Conversation body decrypt failed during key rotation")
                    row.body = encrypt_dm_body(plain, new_dek)
                    row.body_key_scheme = DM_BODY_SCHEME_CONVERSATION
                    row.body_key_version = new_key_version
                    summary["messages_rotated"] += 1
                elif is_message_encrypted(body_value):
                    plain = decrypt_message(body_value)
                    if plain == "[message unavailable]":
                        summary["messages_unavailable"] += 1
                        raise RuntimeError("Legacy encrypted body decrypt failed during key rotation")
                    row.body = encrypt_dm_body(plain, new_dek)
                    row.body_key_scheme = DM_BODY_SCHEME_CONVERSATION
                    row.body_key_version = new_key_version
                    summary["messages_upgraded_plaintext"] += 1
                else:
                    row.body = encrypt_dm_body(body_value, new_dek)
                    row.body_key_scheme = DM_BODY_SCHEME_CONVERSATION
                    row.body_key_version = new_key_version
                    summary["messages_upgraded_plaintext"] += 1
            elif (
                row.body_key_scheme != DM_BODY_SCHEME_CONVERSATION
                or row.body_key_version != new_key_version
            ):
                row.body_key_scheme = DM_BODY_SCHEME_CONVERSATION
                row.body_key_version = new_key_version

            if not row.attachment_path:
                continue

            summary["attachments_total"] += 1
            if not row.attachment_enc_nonce or not row.attachment_enc_tag:
                summary["attachments_missing_meta"] += 1
                continue

            try:
                attachment_path = _safe_message_attachment_path(row.attachment_path)
            except HTTPException:
                summary["attachments_invalid_path"] += 1
                continue
            if not attachment_path.exists() or not attachment_path.is_file():
                summary["attachments_missing_path"] += 1
                continue

            scheme = (row.attachment_key_scheme or "").strip().lower()
            old_attachment_dek: bytes
            if scheme in {"", DM_ATTACHMENT_SCHEME_RECIPIENT}:
                recipient_user = recipient_user_cache.get(row.recipient_id)
                if row.recipient_id not in recipient_user_cache:
                    recipient_user = db.query(User).filter(User.id == row.recipient_id).first()
                    recipient_user_cache[row.recipient_id] = recipient_user
                if recipient_user is None:
                    summary["attachments_missing_recipient_key"] += 1
                    continue
                old_attachment_dek = recipient_dek_cache.get(row.recipient_id) or b""
                if not old_attachment_dek:
                    old_attachment_dek = get_user_dek(db, recipient_user)
                    recipient_dek_cache[row.recipient_id] = old_attachment_dek
                summary["attachments_from_recipient"] += 1
            elif scheme == DM_ATTACHMENT_SCHEME_SYSTEM:
                old_attachment_dek = system_attachment_key
                summary["attachments_from_system"] += 1
            elif scheme == DM_ATTACHMENT_SCHEME_CONVERSATION:
                old_attachment_dek = old_dek
                summary["attachments_from_conversation"] += 1
            else:
                summary["attachments_unknown_scheme"] += 1
                continue

            nonce_b64, tag_b64, plain_size = _rotate_blob_in_place(
                old_dek=old_attachment_dek,
                new_dek=new_dek,
                path=attachment_path,
                nonce_b64=row.attachment_enc_nonce,
                tag_b64=row.attachment_enc_tag,
                swapped_paths=swapped_paths,
                temp_paths=temp_paths,
            )
            row.attachment_enc_nonce = nonce_b64
            row.attachment_enc_tag = tag_b64
            row.attachment_size = plain_size
            row.attachment_key_scheme = DM_ATTACHMENT_SCHEME_CONVERSATION
            row.attachment_key_version = new_key_version
            rotated_attachment_targets.append((attachment_path, nonce_b64, tag_b64))
            summary["attachments_rotated"] += 1

        summary["verification_checks_total"] = len(rotated_attachment_targets)
        for path, nonce_b64, tag_b64 in rotated_attachment_targets:
            verified_size = _verify_rotated_ciphertext(new_dek, path, nonce_b64, tag_b64)
            summary["verification_checks_passed"] += 1
            summary["verification_bytes_checked"] += verified_size

        master = master_key_bytes()
        aad = conversation_aad(thread_id, key_row.user_low_id, key_row.user_high_id)
        wrap_nonce, wrapped_dek = wrap_key(master, new_dek, aad=aad)
        unwrap_probe = unwrap_key(master, wrap_nonce, wrapped_dek, aad=aad)
        if unwrap_probe != new_dek:
            raise RuntimeError("Conversation key wrap verification failed after rotation")
        key_row.wrap_nonce = wrap_nonce
        key_row.wrapped_dek = wrapped_dek
        key_row.key_version = new_key_version
        key_row.created_at = datetime.utcnow()
        db.add(
            AuditLog(
                user_id=None,
                event_type="encryption.conversation_key_rotated",
                details=(
                    f"Rotated conversation key id={key_row.id} thread={thread_id} "
                    f"version={old_key_version}->{new_key_version}, "
                    f"messages_rotated={summary['messages_rotated']}, "
                    f"messages_upgraded={summary['messages_upgraded_plaintext']}, "
                    f"attachments_rotated={summary['attachments_rotated']}."
                ),
            )
        )

        db.commit()
        committed = True
        return summary
    except Exception:
        db.rollback()
        _restore_rotation_swaps(swapped_paths)
        raise
    finally:
        _cleanup_rotation_paths(temp_paths)
        if committed:
            _cleanup_rotation_paths([backup_path for _, backup_path in swapped_paths])


def _render_login_page(
    request: Request,
    *,
    error: str | None = None,
    notice: str | None = None,
    username: str = "",
    status_code: int = 200,
):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": error,
            "notice": notice,
            "username": username,
        },
        status_code=status_code,
    )


def _render_login_mfa_page(
    request: Request,
    *,
    pending_token: str,
    username: str,
    error: str | None = None,
    notice: str | None = None,
    mfa_method: str = MFA_METHOD_TOTP,
    mfa_methods: list[str] | None = None,
    status_code: int = 200,
):
    selected = _normalize_mfa_method(mfa_method) or MFA_METHOD_TOTP
    methods = list(mfa_methods or list(MFA_METHODS))
    if selected not in methods and methods:
        selected = methods[0]
    method_rows = [{"value": item, "label": _mfa_method_display(item)} for item in methods]
    return templates.TemplateResponse(
        "login_mfa.html",
        {
            "request": request,
            "error": error,
            "notice": notice,
            "username": username,
            "pending_token": pending_token,
            "mfa_method": selected,
            "mfa_methods": method_rows,
        },
        status_code=status_code,
    )


def _render_forgot_password_page(
    request: Request,
    *,
    error: str | None = None,
    notice: str | None = None,
    username: str = "",
    status_code: int = 200,
):
    return templates.TemplateResponse(
        "forgot_password.html",
        {
            "request": request,
            "error": error,
            "notice": notice,
            "username": username,
        },
        status_code=status_code,
    )


def _render_forgot_password_mfa_page(
    request: Request,
    *,
    pending_token: str,
    username: str,
    error: str | None = None,
    notice: str | None = None,
    mfa_method: str = MFA_METHOD_TOTP,
    mfa_methods: list[str] | None = None,
    status_code: int = 200,
):
    selected = _normalize_mfa_method(mfa_method) or MFA_METHOD_TOTP
    methods = list(mfa_methods or list(MFA_METHODS))
    if selected not in methods and methods:
        selected = methods[0]
    method_rows = [{"value": item, "label": _mfa_method_display(item)} for item in methods]
    return templates.TemplateResponse(
        "forgot_password_mfa.html",
        {
            "request": request,
            "error": error,
            "notice": notice,
            "username": username,
            "pending_token": pending_token,
            "mfa_method": selected,
            "mfa_methods": method_rows,
        },
        status_code=status_code,
    )


def _create_forgot_password_ticket(db: Session, user: User, request: Request) -> tuple[SupportTicket, bool]:
    now = datetime.utcnow()
    existing = (
        db.query(SupportTicket)
        .filter(
            SupportTicket.user_id == user.id,
            SupportTicket.subject == "Password reset request",
            SupportTicket.status.in_(("open", "in_progress", "waiting_on_user")),
        )
        .order_by(SupportTicket.created_at.desc(), SupportTicket.id.desc())
        .first()
    )
    if existing:
        ticket_ref = _support_ticket_ref(existing)
        add_audit_log(
            db,
            user=user,
            event_type="account.password_reset_ticket_reused",
            details=f"Reused existing open password reset support ticket {ticket_ref}.",
            request=request,
        )
        db.commit()
        return existing, False

    detail_text = (
        f"User '{user.username}' requested password reset from the sign-in page, "
        "but no MFA methods are configured on the account. "
        "Admin verification and manual reset are required."
    )
    ticket = SupportTicket(
        ticket_number=_next_support_ticket_number(db),
        user_id=user.id,
        subject="Password reset request",
        category="account",
        priority="high",
        description=encrypt_message(detail_text),
        status="open",
        created_at=now,
        updated_at=now,
        closed_at=None,
        last_admin_update_at=None,
    )
    db.add(ticket)
    db.flush()
    ticket_ref = _support_ticket_ref(ticket)
    add_event(
        db,
        user,
        action="support",
        message=f"Opened support ticket {ticket_ref} '{ticket.subject}' (high) from forgot-password flow.",
        level="WARN",
    )
    add_audit_log(
        db,
        user=user,
        event_type="account.password_reset_ticket_created",
        details=f"Created password reset support ticket {ticket_ref} (no MFA methods configured).",
        request=request,
    )
    db.commit()
    return ticket, True


def _complete_signin(request: Request, db: Session, user: User) -> RedirectResponse:
    ensure_user_key(db, user)
    add_event(db, user, action="auth", message=f"Signed in as '{user.username}'.")
    add_audit_log(db, user=user, event_type="signin.success", details="Interactive sign-in completed.", request=request)
    session = create_session(db, user)
    user.last_login = datetime.utcnow()
    db.commit()

    response = RedirectResponse(url="/ui", status_code=303)
    _set_session_cookie(response, request, session.id)
    return response


@router.get("/login")
def login_page(request: Request):
    return _render_login_page(request)


@router.get("/forgot-password")
def forgot_password_page(request: Request):
    return _render_forgot_password_page(request)


@router.post("/forgot-password")
def forgot_password_start(
    request: Request,
    username: str = Form(...),
    db: Session = Depends(get_db),
):
    normalized_username = (username or "").strip()
    if not normalized_username:
        return _render_forgot_password_page(
            request,
            error="Username is required.",
            username=normalized_username,
            status_code=400,
        )

    user = db.query(User).filter(User.username == normalized_username).first()
    if not user:
        return _render_forgot_password_page(
            request,
            notice="If the account exists, recovery steps have been initiated.",
            username=normalized_username,
            status_code=200,
        )

    if getattr(user, "is_disabled", False):
        add_audit_log(
            db,
            user=user,
            event_type="account.password_reset_blocked_disabled",
            details="Forgot-password reset attempt blocked (account disabled).",
            request=request,
        )
        db.commit()
        return _render_forgot_password_page(
            request,
            error="Account is disabled. Contact an administrator.",
            username=normalized_username,
            status_code=403,
        )

    configured_methods = _available_mfa_methods(user, transport_ready_only=False)
    if configured_methods:
        effective_method = _resolve_mfa_method(user, user.mfa_preferred_method, configured_methods)
        if not effective_method:
            add_audit_log(
                db,
                user=user,
                event_type="account.password_reset_failed_mfa_unavailable",
                details="Forgot-password flow could not resolve an MFA method.",
                request=request,
            )
            db.commit()
            return _render_forgot_password_page(
                request,
                error="MFA is enabled but no recovery method is currently available.",
                username=normalized_username,
                status_code=400,
            )

        pending_token = _issue_pending_password_reset_token(user)
        add_audit_log(
            db,
            user=user,
            event_type="account.password_reset_started",
            details=f"Forgot-password flow started with MFA method {effective_method}.",
            request=request,
        )
        db.commit()
        return _render_forgot_password_mfa_page(
            request,
            pending_token=pending_token,
            username=user.username,
            notice=f"Recovery started. Verify with {_mfa_method_display(effective_method)} and set a new password.",
            mfa_method=effective_method,
            mfa_methods=configured_methods,
            status_code=200,
        )

    ticket, created = _create_forgot_password_ticket(db, user, request)
    ticket_ref = _support_ticket_ref(ticket)
    message = (
        f"No MFA methods are configured. Support ticket {ticket_ref} was opened for manual password reset."
        if created
        else f"No MFA methods are configured. Existing support ticket {ticket_ref} is still open."
    )
    return _render_forgot_password_page(
        request,
        notice=message,
        username=user.username,
        status_code=200,
    )


@router.post("/forgot-password/mfa")
def forgot_password_mfa_action(
    request: Request,
    pending_token: str = Form(...),
    mfa_method: str | None = Form(None),
    mfa_code: str | None = Form(None),
    send_mfa_code: str | None = Form(None),
    totp_code: str | None = Form(None),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    db: Session = Depends(get_db),
):
    pending = _resolve_pending_password_reset(pending_token)
    if not pending:
        return _render_forgot_password_page(
            request,
            error="Recovery session expired. Start again from username.",
            status_code=401,
        )

    user_id_raw = str(pending.get("user_id") or "").strip()
    username_hint = str(pending.get("username") or "").strip()
    try:
        user_id = uuid.UUID(user_id_raw)
    except ValueError:
        _clear_pending_password_reset(pending_token)
        return _render_forgot_password_page(
            request,
            error="Recovery session expired. Start again from username.",
            username=username_hint,
            status_code=401,
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        _clear_pending_password_reset(pending_token)
        return _render_forgot_password_page(
            request,
            error="Recovery session expired. Start again from username.",
            username=username_hint,
            status_code=401,
        )

    if getattr(user, "is_disabled", False):
        add_audit_log(
            db,
            user=user,
            event_type="account.password_reset_blocked_disabled",
            details="Forgot-password reset attempt blocked (account disabled).",
            request=request,
        )
        db.commit()
        _clear_pending_password_reset(pending_token)
        return _render_forgot_password_page(
            request,
            error="Account is disabled. Contact an administrator.",
            username=user.username,
            status_code=403,
        )

    configured_methods = _available_mfa_methods(user, transport_ready_only=False)
    if not configured_methods:
        _clear_pending_password_reset(pending_token)
        ticket, created = _create_forgot_password_ticket(db, user, request)
        ticket_ref = _support_ticket_ref(ticket)
        notice = (
            f"No MFA methods are configured. Support ticket {ticket_ref} was opened for manual password reset."
            if created
            else f"No MFA methods are configured. Existing support ticket {ticket_ref} is still open."
        )
        return _render_forgot_password_page(request, notice=notice, username=user.username, status_code=200)

    selected_method = _resolve_mfa_method(user, mfa_method, configured_methods)
    if not selected_method:
        add_audit_log(
            db,
            user=user,
            event_type="account.password_reset_failed_mfa_unavailable",
            details="Forgot-password flow could not resolve an MFA method during verification.",
            request=request,
        )
        db.commit()
        return _render_forgot_password_mfa_page(
            request,
            pending_token=pending_token,
            username=user.username,
            error="MFA method unavailable for password recovery.",
            mfa_method=MFA_METHOD_TOTP,
            mfa_methods=configured_methods,
            status_code=400,
        )

    code_value = (mfa_code or totp_code or "").strip()
    wants_send_code = (send_mfa_code or "").strip().lower() in {"1", "true", "yes", "on", "send"}

    if not wants_send_code:
        if new_password != confirm_password:
            return _render_forgot_password_mfa_page(
                request,
                pending_token=pending_token,
                username=user.username,
                error="New passwords did not match.",
                mfa_method=selected_method,
                mfa_methods=configured_methods,
                status_code=400,
            )
        if len(new_password or "") < 10:
            return _render_forgot_password_mfa_page(
                request,
                pending_token=pending_token,
                username=user.username,
                error="New password must be at least 10 characters.",
                mfa_method=selected_method,
                mfa_methods=configured_methods,
                status_code=400,
            )

    if selected_method == MFA_METHOD_TOTP:
        if not code_value:
            add_audit_log(
                db,
                user=user,
                event_type="account.password_reset_failed_totp_required",
                details="Forgot-password reset blocked: TOTP code required.",
                request=request,
            )
            db.commit()
            return _render_forgot_password_mfa_page(
                request,
                pending_token=pending_token,
                username=user.username,
                error="Authenticator app code is required.",
                mfa_method=selected_method,
                mfa_methods=configured_methods,
                status_code=401,
            )
        if not _verify_totp_for_user(user, code_value):
            add_audit_log(
                db,
                user=user,
                event_type="account.password_reset_failed_totp_invalid",
                details="Forgot-password reset blocked: invalid TOTP code.",
                request=request,
            )
            db.commit()
            return _render_forgot_password_mfa_page(
                request,
                pending_token=pending_token,
                username=user.username,
                error="Invalid authenticator app code.",
                mfa_method=selected_method,
                mfa_methods=configured_methods,
                status_code=401,
            )
    else:
        if wants_send_code or not code_value:
            try:
                destination_hint = _issue_mfa_challenge(user, selected_method)
            except HTTPException as exc:
                db.rollback()
                return _render_forgot_password_mfa_page(
                    request,
                    pending_token=pending_token,
                    username=user.username,
                    error=str(exc.detail),
                    mfa_method=selected_method,
                    mfa_methods=configured_methods,
                    status_code=exc.status_code,
                )
            except Exception as exc:
                db.rollback()
                logger.warning("Failed to send %s password-reset MFA code for user %s: %s", selected_method, user.id, exc)
                return _render_forgot_password_mfa_page(
                    request,
                    pending_token=pending_token,
                    username=user.username,
                    error=f"Could not send {_mfa_method_display(selected_method).lower()} code right now.",
                    mfa_method=selected_method,
                    mfa_methods=configured_methods,
                    status_code=503,
                )

            add_audit_log(
                db,
                user=user,
                event_type=f"account.password_reset_challenge_sent_{selected_method}",
                details=f"Sent forgot-password MFA challenge via {selected_method} to {destination_hint}.",
                request=request,
            )
            db.commit()
            return _render_forgot_password_mfa_page(
                request,
                pending_token=pending_token,
                username=user.username,
                notice=f"A 6-digit code was sent to {destination_hint}. Enter it with your new password.",
                mfa_method=selected_method,
                mfa_methods=configured_methods,
                status_code=200,
            )

        challenge_ok, reason = _verify_mfa_challenge(user, selected_method, code_value)
        if not challenge_ok:
            add_audit_log(
                db,
                user=user,
                event_type=f"account.password_reset_failed_{selected_method}",
                details=f"{selected_method.upper()} MFA verification failed during forgot-password flow: {reason}",
                request=request,
            )
            db.commit()
            return _render_forgot_password_mfa_page(
                request,
                pending_token=pending_token,
                username=user.username,
                error=reason,
                mfa_method=selected_method,
                mfa_methods=configured_methods,
                status_code=401,
            )

    user.password_hash = hash_password(new_password)
    user.mfa_preferred_method = selected_method
    _clear_mfa_challenge(user)
    revoked = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == user.id, SessionModel.is_active.is_(True))
        .update({SessionModel.is_active: False}, synchronize_session=False)
    )
    _clear_pending_password_reset(pending_token)
    add_event(
        db,
        user,
        action="auth",
        message=f"Password reset via forgot-password flow (revoked {revoked} session(s)).",
        level="WARN",
    )
    add_audit_log(
        db,
        user=user,
        event_type="account.password_reset_completed",
        details=f"Forgot-password reset completed with MFA method {selected_method}; revoked {revoked} active session(s).",
        request=request,
    )
    db.commit()
    return _render_login_page(
        request,
        notice="Password reset complete. Sign in with your new password.",
        username=user.username,
        status_code=200,
    )


@router.get("/register")
def register_page(request: Request, db: Session = Depends(get_db)):
    if not _self_service_registration_open(db):
        return _render_login_page(
            request,
            error="Self-service registration is disabled. Contact an administrator.",
            status_code=403,
        )
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
    if not _self_service_registration_open(db):
        return _render_login_page(
            request,
            error="Self-service registration is disabled. Contact an administrator.",
            username=username,
            status_code=403,
        )

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
        is_superadmin=is_first_user,
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
    if user.is_superadmin:
        add_event(db, user, action="auth", message="Superadmin role granted to first account.", level="SUCCESS")
        add_audit_log(db, user=user, event_type="account.role_superadmin_granted", details="Superadmin role granted.", request=request)
    session = create_session(db, user)
    user.last_login = datetime.utcnow()
    add_audit_log(db, user=user, event_type="signin.success", details="Signed in after registration.", request=request)
    db.commit()

    response = RedirectResponse(url="/ui", status_code=303)
    _set_session_cookie(response, request, session.id)
    return response


@router.post("/login")
def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    normalized_username = (username or "").strip()

    user = db.query(User).filter(User.username == normalized_username).first()
    if not user:
        return _render_login_page(
            request,
            error="Invalid username or password",
            username=normalized_username,
            status_code=401,
        )
    if not verify_password(password, user.password_hash):
        add_audit_log(db, user=user, event_type="signin.failed_password", details="Password verification failed.", request=request)
        db.commit()
        return _render_login_page(
            request,
            error="Invalid username or password",
            username=normalized_username,
            status_code=401,
        )

    if getattr(user, "is_disabled", False):
        add_audit_log(db, user=user, event_type="signin.blocked_disabled", details="Interactive sign-in blocked (account disabled).", request=request)
        db.commit()
        return _render_login_page(
            request,
            error="Account disabled. Please contact an administrator.",
            username=normalized_username,
            status_code=403,
        )

    configured_methods = _available_mfa_methods(user, transport_ready_only=False)
    if configured_methods:
        effective_method = _resolve_mfa_method(user, user.mfa_preferred_method, configured_methods)
        if not effective_method:
            add_audit_log(
                db,
                user=user,
                event_type="signin.failed_mfa_unavailable",
                details="No MFA method is currently available for this account.",
                request=request,
            )
            db.commit()
            return _render_login_page(
                request,
                error="MFA is enabled but no method is available. Contact an administrator.",
                username=normalized_username,
                status_code=401,
            )

        pending_token = _issue_pending_login_token(user)
        return _render_login_mfa_page(
            request,
            pending_token=pending_token,
            username=normalized_username,
            notice=f"Password accepted. Complete MFA using {_mfa_method_display(effective_method)}.",
            mfa_method=effective_method,
            mfa_methods=configured_methods,
            status_code=200,
        )

    return _complete_signin(request, db, user)


@router.post("/login/mfa")
def login_mfa_action(
    request: Request,
    pending_token: str = Form(...),
    mfa_method: str | None = Form(None),
    mfa_code: str | None = Form(None),
    send_mfa_code: str | None = Form(None),
    totp_code: str | None = Form(None),
    db: Session = Depends(get_db),
):
    pending = _resolve_pending_login(pending_token)
    if not pending:
        return _render_login_page(
            request,
            error="Sign-in session expired. Enter your username and password again.",
            status_code=401,
        )

    user_id_raw = str(pending.get("user_id") or "").strip()
    username_hint = str(pending.get("username") or "").strip()
    try:
        user_id = uuid.UUID(user_id_raw)
    except ValueError:
        _clear_pending_login(pending_token)
        return _render_login_page(
            request,
            error="Sign-in session expired. Enter your username and password again.",
            username=username_hint,
            status_code=401,
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        _clear_pending_login(pending_token)
        return _render_login_page(
            request,
            error="Sign-in session expired. Enter your username and password again.",
            username=username_hint,
            status_code=401,
        )

    if getattr(user, "is_disabled", False):
        add_audit_log(db, user=user, event_type="signin.blocked_disabled", details="Interactive sign-in blocked (account disabled).", request=request)
        db.commit()
        _clear_pending_login(pending_token)
        return _render_login_page(
            request,
            error="Account disabled. Please contact an administrator.",
            username=user.username,
            status_code=403,
        )

    configured_methods = _available_mfa_methods(user, transport_ready_only=False)
    if not configured_methods:
        _clear_pending_login(pending_token)
        return _complete_signin(request, db, user)

    selected_method = _resolve_mfa_method(user, mfa_method, configured_methods)
    if not selected_method:
        add_audit_log(
            db,
            user=user,
            event_type="signin.failed_mfa_unavailable",
            details="No MFA method is currently available for this account.",
            request=request,
        )
        db.commit()
        return _render_login_mfa_page(
            request,
            pending_token=pending_token,
            username=user.username,
            error="MFA is enabled but no method is available. Contact an administrator.",
            mfa_method=MFA_METHOD_TOTP,
            mfa_methods=configured_methods,
            status_code=401,
        )

    code_value = (mfa_code or totp_code or "").strip()
    wants_send_code = (send_mfa_code or "").strip().lower() in {"1", "true", "yes", "on", "send"}

    if selected_method == MFA_METHOD_TOTP:
        if not code_value:
            add_audit_log(db, user=user, event_type="signin.failed_totp_required", details="TOTP code required.", request=request)
            db.commit()
            return _render_login_mfa_page(
                request,
                pending_token=pending_token,
                username=user.username,
                error="Authenticator app code is required.",
                mfa_method=selected_method,
                mfa_methods=configured_methods,
                status_code=401,
            )
        if not _verify_totp_for_user(user, code_value):
            add_audit_log(db, user=user, event_type="signin.failed_totp_invalid", details="Invalid TOTP code.", request=request)
            db.commit()
            return _render_login_mfa_page(
                request,
                pending_token=pending_token,
                username=user.username,
                error="Invalid authenticator app code.",
                mfa_method=selected_method,
                mfa_methods=configured_methods,
                status_code=401,
            )

        add_audit_log(
            db,
            user=user,
            event_type="mfa.verified_totp",
            details="TOTP MFA verified during sign-in.",
            request=request,
        )
    else:
        if wants_send_code or not code_value:
            try:
                destination_hint = _issue_mfa_challenge(user, selected_method)
            except HTTPException as exc:
                db.rollback()
                return _render_login_mfa_page(
                    request,
                    pending_token=pending_token,
                    username=user.username,
                    error=str(exc.detail),
                    mfa_method=selected_method,
                    mfa_methods=configured_methods,
                    status_code=exc.status_code,
                )
            except Exception as exc:
                db.rollback()
                logger.warning("Failed to send %s MFA code for user %s: %s", selected_method, user.id, exc)
                return _render_login_mfa_page(
                    request,
                    pending_token=pending_token,
                    username=user.username,
                    error=f"Could not send {_mfa_method_display(selected_method).lower()} code right now.",
                    mfa_method=selected_method,
                    mfa_methods=configured_methods,
                    status_code=503,
                )

            add_audit_log(
                db,
                user=user,
                event_type=f"mfa.challenge_sent_{selected_method}",
                details=f"Sent MFA challenge via {selected_method} to {destination_hint}.",
                request=request,
            )
            db.commit()
            return _render_login_mfa_page(
                request,
                pending_token=pending_token,
                username=user.username,
                notice=f"A 6-digit code was sent to {destination_hint}. Enter it to complete sign in.",
                mfa_method=selected_method,
                mfa_methods=configured_methods,
                status_code=200,
            )

        challenge_ok, reason = _verify_mfa_challenge(user, selected_method, code_value)
        if not challenge_ok:
            add_audit_log(
                db,
                user=user,
                event_type=f"signin.failed_{selected_method}_mfa",
                details=f"{selected_method.upper()} MFA verification failed: {reason}",
                request=request,
            )
            db.commit()
            return _render_login_mfa_page(
                request,
                pending_token=pending_token,
                username=user.username,
                error=reason,
                mfa_method=selected_method,
                mfa_methods=configured_methods,
                status_code=401,
            )

        add_audit_log(
            db,
            user=user,
            event_type=f"mfa.verified_{selected_method}",
            details=f"{selected_method.upper()} MFA challenge verified during sign-in.",
            request=request,
        )

    user.mfa_preferred_method = selected_method
    _clear_pending_login(pending_token)
    return _complete_signin(request, db, user)


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
    user_key_row = ensure_user_key(db, user)
    user_key_version = int(user_key_row.key_version or 1)
    user_key_label = f"user-dek:v{user_key_version}"
    user_key_record_id = str(user_key_row.id)
    user_key_created_utc = _format_utc(user_key_row.created_at)
    file_rows = []
    for idx, record in enumerate(files, start=1):
        try:
            rel = Path(record.file_path).resolve().relative_to(root)
            rel_path = str(rel)
        except ValueError:
            rel_path = record.file_path
        token = _issue_file_token(session_id, record.id)
        if record.is_encrypted and record.enc_nonce and record.enc_tag:
            enc_key_label = f"user-dek:v{user_key_version}" if user_key_version else "user-dek"
        elif record.is_encrypted:
            enc_key_label = "user-dek (metadata incomplete)"
        else:
            enc_key_label = "plaintext"
        file_rows.append(
            {
                "record": record,
                "rel_path": rel_path,
                "token": token,
                "display_name": record.file_name,
                "enc_key_label": enc_key_label,
                "uploaded_at_display": _format_utc(record.uploaded_at),
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
            "user_key_label": user_key_label,
            "user_key_record_id": user_key_record_id,
            "user_key_created_utc": user_key_created_utc,
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


@router.get("/help")
def help_page(
    request: Request,
    status: str = "",
    limit: int = 80,
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    status_filter = _normalize_ticket_status(status)
    limit = max(1, min(limit, 300))

    counts = {
        (s or "open"): int(c)
        for s, c in (
            db.query(SupportTicket.status, func.count(SupportTicket.id))
            .filter(SupportTicket.user_id == user.id)
            .group_by(SupportTicket.status)
            .all()
        )
    }

    query = (
        db.query(SupportTicket)
        .options(joinedload(SupportTicket.assigned_admin))
        .filter(SupportTicket.user_id == user.id)
        .order_by(
            case((SupportTicket.priority == "urgent", 0), else_=1),
            SupportTicket.updated_at.desc(),
            SupportTicket.created_at.desc(),
            SupportTicket.id.desc(),
        )
    )
    if status_filter:
        query = query.filter(SupportTicket.status == status_filter)
    tickets = query.limit(limit).all()

    rows = []
    for ticket in tickets:
        body = decrypt_message(ticket.description or "").strip()
        body_preview = body if len(body) <= 220 else f"{body[:217]}..."
        admin_reply = decrypt_message(ticket.admin_reply or "").strip() if ticket.admin_reply else ""
        admin_reply_preview = admin_reply if len(admin_reply) <= 220 else f"{admin_reply[:217]}..."
        rows.append(
            {
                "ticket": ticket,
                "ticket_display_id": _support_ticket_display_id(ticket),
                "requester_username": user.username,
                "assigned_admin_username": ticket.assigned_admin.username if ticket.assigned_admin else "",
                "description": body,
                "description_preview": body_preview,
                "admin_reply": admin_reply,
                "admin_reply_preview": admin_reply_preview,
                "category_label": SUPPORT_TICKET_CATEGORIES.get(ticket.category, ticket.category),
                "created_utc": _format_utc(ticket.created_at),
                "updated_utc": _format_utc(ticket.updated_at),
                "created_iso": _format_utc_iso(ticket.created_at),
                "updated_iso": _format_utc_iso(ticket.updated_at),
            }
        )

    total = sum(counts.values())
    return templates.TemplateResponse(
        "help.html",
        {
            "request": request,
            "user": user,
            "rows": rows,
            "counts": {
                "total": total,
                "open": counts.get("open", 0),
                "in_progress": counts.get("in_progress", 0),
                "waiting_on_user": counts.get("waiting_on_user", 0),
                "resolved": counts.get("resolved", 0),
                "closed": counts.get("closed", 0),
            },
            "filters": {
                "status": status_filter,
                "limit": limit,
            },
            "category_options": SUPPORT_TICKET_CATEGORIES,
            "priority_options": SUPPORT_TICKET_PRIORITIES,
            "status_options": SUPPORT_TICKET_STATUSES,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/help/tickets")
def help_create_ticket(
    request: Request,
    subject: str = Form(...),
    category: str = Form("general"),
    priority: str = Form("normal"),
    details: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    subject_value = (subject or "").strip()
    details_value = (details or "").strip()
    if not subject_value:
        return _help_redirect("Subject is required.", error=True)
    if len(subject_value) > 200:
        return _help_redirect("Subject is too long (max 200 characters).", error=True)
    if not details_value:
        return _help_redirect("Ticket details are required.", error=True)
    if len(details_value) > 8000:
        return _help_redirect("Ticket details are too long (max 8000 characters).", error=True)

    normalized_category = _normalize_ticket_category(category)
    normalized_priority = _normalize_ticket_priority(priority)
    now = datetime.utcnow()
    ticket = SupportTicket(
        ticket_number=_next_support_ticket_number(db),
        user_id=user.id,
        subject=subject_value,
        category=normalized_category,
        priority=normalized_priority,
        description=encrypt_message(details_value),
        status="open",
        created_at=now,
        updated_at=now,
        closed_at=None,
        last_admin_update_at=None,
    )
    db.add(ticket)
    db.flush()
    ticket_ref = _support_ticket_ref(ticket)

    add_event(
        db,
        user,
        action="support",
        message=f"Opened support ticket {ticket_ref} '{subject_value}' ({normalized_priority}).",
        level="INFO",
    )
    add_audit_log(
        db,
        user=user,
        event_type="support.ticket_created",
        details=(
            f"Created support ticket {ticket_ref} '{subject_value}' "
            f"(category={normalized_category}, priority={normalized_priority})."
        ),
        request=request,
    )
    db.commit()
    return _help_redirect(f"Support ticket {ticket_ref} submitted. The admin inbox has been notified.")


def _messages_redirect(message: str, *, error: bool = False, thread: str | None = None) -> RedirectResponse:
    key = "error" if error else "notice"
    base = "/ui/messages"
    if thread:
        return RedirectResponse(url=f"{base}?thread={thread}&{key}={quote_plus(message)}", status_code=303)
    return RedirectResponse(url=f"{base}?{key}={quote_plus(message)}", status_code=303)


@router.get("/messages")
def messages_home(
    request: Request,
    thread: str | None = None,
    notice: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    messages = (
        db.query(DirectMessage)
        .options(joinedload(DirectMessage.sender), joinedload(DirectMessage.recipient))
        .filter(or_(DirectMessage.sender_id == user.id, DirectMessage.recipient_id == user.id))
        .order_by(DirectMessage.created_at.desc())
        .limit(300)
        .all()
    )
    participant_ids: set[uuid.UUID] = set()
    thread_ids: set[uuid.UUID] = set()
    for row in messages:
        participant_ids.add(row.sender_id)
        participant_ids.add(row.recipient_id)
        thread_ids.add(row.thread_id or row.id)
    user_key_versions: dict[uuid.UUID, int] = {}
    if participant_ids:
        user_key_rows = db.query(UserKey).filter(UserKey.user_id.in_(participant_ids)).all()
        for key_row in user_key_rows:
            user_key_versions[key_row.user_id] = int(key_row.key_version or 1)
    conversation_keys_by_thread: dict[uuid.UUID, ConversationKey] = {}
    if thread_ids:
        for key_row in db.query(ConversationKey).filter(ConversationKey.thread_id.in_(thread_ids)).all():
            conversation_keys_by_thread[key_row.thread_id] = key_row
    conversation_dek_by_thread: dict[uuid.UUID, bytes] = {}

    thread_buckets: dict[uuid.UUID, list[DirectMessage]] = {}
    thread_summaries: dict[uuid.UUID, dict] = {}
    message_rows_changed = False
    for row in messages:
        thread_uuid = row.thread_id or row.id
        if row.thread_id is None:
            row.thread_id = thread_uuid
            message_rows_changed = True

        conversation_key = conversation_keys_by_thread.get(thread_uuid)
        conversation_key_version: int | None = None
        conversation_dek: bytes | None = None
        if conversation_key is None:
            try:
                conversation_key, key_created = ensure_conversation_key(
                    db,
                    thread_id=thread_uuid,
                    user_a_id=row.sender_id,
                    user_b_id=row.recipient_id,
                )
            except ValueError:
                logger.warning("Direct-message thread %s has mismatched participants; skipping conversation-key attach", thread_uuid)
                conversation_key = None
            else:
                conversation_keys_by_thread[thread_uuid] = conversation_key
                if key_created:
                    message_rows_changed = True
        if conversation_key is not None:
            conversation_key_version = int(conversation_key.key_version or 1)
            conversation_dek = conversation_dek_by_thread.get(thread_uuid)
            if conversation_dek is None:
                conversation_dek = get_conversation_dek(conversation_key)
                conversation_dek_by_thread[thread_uuid] = conversation_dek

        body_value = row.body or ""
        if (
            conversation_key is not None
            and conversation_dek is not None
            and is_dm_conversation_encrypted(body_value)
            and len(body_value) > _DM_BODY_HEAL_REENCRYPT_LEN
        ):
            healed_plaintext = decrypt_dm_body(body_value, conversation_dek)
            if healed_plaintext != "[message unavailable]":
                healed_cipher = encrypt_dm_body(healed_plaintext, conversation_dek)
                if healed_cipher != body_value:
                    row.body = healed_cipher
                    row.body_key_scheme = DM_BODY_SCHEME_CONVERSATION
                    row.body_key_version = conversation_key_version
                    body_value = row.body or ""
                    message_rows_changed = True

        if conversation_key is not None and conversation_dek is not None and not is_dm_conversation_encrypted(body_value):
            plaintext = decrypt_message(body_value)
            if plaintext != "[message unavailable]":
                row.body = encrypt_dm_body(plaintext, conversation_dek)
                row.body_key_scheme = DM_BODY_SCHEME_CONVERSATION
                row.body_key_version = conversation_key_version
                message_rows_changed = True
        elif (
            conversation_key is not None
            and conversation_dek is not None
            and (row.body_key_scheme != DM_BODY_SCHEME_CONVERSATION or row.body_key_version != conversation_key_version)
        ):
            row.body_key_scheme = DM_BODY_SCHEME_CONVERSATION
            row.body_key_version = conversation_key_version
            message_rows_changed = True
        elif conversation_key is None and not is_message_encrypted(row.body or ""):
            row.body = encrypt_message(row.body or "")
            row.body_key_scheme = DM_BODY_SCHEME_FERNET
            row.body_key_version = 1
            message_rows_changed = True

        thread_buckets.setdefault(thread_uuid, []).append(row)

        partner = row.recipient if row.sender_id == user.id else row.sender
        if thread_uuid not in thread_summaries:
            preview = (
                decrypt_dm_body(row.body or "", conversation_dek)
                if conversation_dek is not None
                else decrypt_message(row.body or "")
            ).replace("\n", " ").strip()
            if len(preview) > 82:
                preview = f"{preview[:79]}..."
            partner_email = ""
            if partner.email and partner.email_visible and partner.email_verified:
                partner_email = partner.email
            thread_summaries[thread_uuid] = {
                "thread_uuid": thread_uuid,
                "thread_id": str(thread_uuid),
                "partner_username": partner.username,
                "partner_email": partner_email,
                "latest_preview": preview or "(attachment)",
                "latest_created_at": row.created_at,
                "latest_created_at_utc": _format_utc(row.created_at),
                "unread_count": 0,
            }

        if row.recipient_id == user.id and row.read_at is None:
            thread_summaries[thread_uuid]["unread_count"] += 1

    threads = sorted(
        thread_summaries.values(),
        key=lambda item: item["latest_created_at"] or datetime.min,
        reverse=True,
    )

    active_thread_uuid: uuid.UUID | None = None
    if thread:
        try:
            requested = uuid.UUID(thread)
            if requested in thread_buckets:
                active_thread_uuid = requested
        except ValueError:
            active_thread_uuid = None
    if not active_thread_uuid and threads:
        active_thread_uuid = threads[0]["thread_uuid"]

    active_thread_messages: list[DirectMessage] = []
    active_thread_summary: dict | None = None
    if active_thread_uuid:
        active_thread_messages = sorted(
            thread_buckets.get(active_thread_uuid, []),
            key=lambda row: row.created_at or datetime.min,
        )
        active_thread_summary = thread_summaries.get(active_thread_uuid)
    active_conversation_key_label = "-"
    active_conversation_key_record_id = "-"
    active_conversation_key_created_utc = "-"
    if active_thread_uuid:
        active_conversation_key = conversation_keys_by_thread.get(active_thread_uuid)
        if active_conversation_key:
            active_conversation_key_label = _conversation_body_key_label(
                int(active_conversation_key.key_version or 1)
            )
            active_conversation_key_record_id = str(active_conversation_key.id)
            active_conversation_key_created_utc = _format_utc(active_conversation_key.created_at)

    read_updates = 0
    for row in active_thread_messages:
        if row.recipient_id == user.id and row.read_at is None:
            row.read_at = datetime.utcnow()
            read_updates += 1
    if read_updates or message_rows_changed:
        db.commit()
        if read_updates and active_thread_summary:
            active_thread_summary["unread_count"] = 0

    thread_messages = []
    for row in active_thread_messages:
        outbound = row.sender_id == user.id
        thread_uuid = row.thread_id or row.id
        conversation_key = conversation_keys_by_thread.get(thread_uuid)
        conversation_dek = conversation_dek_by_thread.get(thread_uuid)
        if conversation_dek is None and conversation_key is not None:
            conversation_dek = get_conversation_dek(conversation_key)
            conversation_dek_by_thread[thread_uuid] = conversation_dek

        body_key_label = _DM_BODY_KEY_LABEL
        if row.body_key_scheme == DM_BODY_SCHEME_CONVERSATION or is_dm_conversation_encrypted(row.body or ""):
            if conversation_key is not None:
                body_key_label = _conversation_body_key_label(
                    int(row.body_key_version or conversation_key.key_version or 1)
                )
            else:
                body_key_label = f"{_DM_BODY_CONVERSATION_KEY_LABEL}:missing-key"
        attachment_key_label = ""
        if row.attachment_name and row.attachment_path:
            scheme = (row.attachment_key_scheme or "").strip().lower()
            if scheme == DM_ATTACHMENT_SCHEME_CONVERSATION:
                attachment_version = int(
                    row.attachment_key_version
                    or (conversation_key.key_version if conversation_key else 0)
                    or 0
                )
                if attachment_version > 0:
                    attachment_key_label = _conversation_attachment_key_label(attachment_version)
                else:
                    attachment_key_label = f"{_DM_ATTACHMENT_CONVERSATION_KEY_LABEL}:missing-key"
            elif scheme in {"", DM_ATTACHMENT_SCHEME_RECIPIENT}:
                recipient_key_version = user_key_versions.get(row.recipient_id)
                attachment_key_label = (
                    f"dm-attachment:recipient-user-dek:v{recipient_key_version}"
                    if recipient_key_version
                    else "dm-attachment:recipient-user-dek"
                )
            elif scheme == DM_ATTACHMENT_SCHEME_SYSTEM:
                attachment_key_label = _DM_ATTACHMENT_SYSTEM_KEY_LABEL
            else:
                attachment_key_label = f"dm-attachment:{scheme}"
        thread_messages.append(
            {
                "id": str(row.id),
                "thread_id": str(row.thread_id or row.id),
                "sender_username": row.sender.username,
                "recipient_username": row.recipient.username,
                "body": (
                    decrypt_dm_body(row.body or "", conversation_dek)
                    if conversation_dek is not None
                    else ("[message unavailable]" if is_dm_conversation_encrypted(row.body or "") else decrypt_message(row.body))
                ),
                "created_at": row.created_at,
                "created_at_utc": _format_utc(row.created_at),
                "direction": "Sent" if outbound else "Received",
                "is_outbound": outbound,
                "receipt": (
                    f"Read {_format_utc(row.read_at)}"
                    if outbound and row.read_at
                    else ("Delivered" if outbound else ("Read" if row.read_at else "Unread"))
                ),
                "has_attachment": bool(row.attachment_name and row.attachment_path),
                "attachment_name": row.attachment_name,
                "attachment_size": row.attachment_size,
                "attachment_mime_type": row.attachment_mime_type or "",
                "attachment_url": f"/ui/messages/{row.id}/attachment"
                if row.attachment_name and row.attachment_path
                else None,
                "attachment_preview_url": f"/ui/messages/{row.id}/attachment"
                if row.attachment_name and row.attachment_path
                else None,
                "attachment_download_url": f"/ui/messages/{row.id}/attachment?download=1"
                if row.attachment_name and row.attachment_path
                else None,
                "body_key_label": body_key_label,
                "attachment_key_label": attachment_key_label,
            }
        )

    return templates.TemplateResponse(
        "messages.html",
        {
            "request": request,
            "user": user,
            "threads": threads,
            "thread_messages": thread_messages,
            "active_thread_id": str(active_thread_uuid) if active_thread_uuid else "",
            "active_partner_username": active_thread_summary["partner_username"] if active_thread_summary else "",
            "active_conversation_key_label": active_conversation_key_label,
            "active_conversation_key_record_id": active_conversation_key_record_id,
            "active_conversation_key_created_utc": active_conversation_key_created_utc,
            "unread_thread_total": sum(item["unread_count"] for item in threads),
            "notice": notice or request.query_params.get("notice"),
            "error": error or request.query_params.get("error"),
        },
    )


@router.post("/messages/send")
def send_message(
    request: Request,
    username: str = Form(""),
    message: str = Form(""),
    thread_id: str | None = Form(None),
    attachment: UploadFile | None = File(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if getattr(user, "messaging_disabled", False):
        add_audit_log(
            db,
            user=user,
            event_type="message.send_blocked_restricted",
            details="Direct message send blocked (messaging disabled).",
            request=request,
        )
        db.commit()
        return _messages_redirect("Direct messaging has been disabled on your account.", error=True, thread=thread_id)

    target_username = (username or "").strip()
    body = (message or "").strip()

    recipient: User | None = None
    if target_username:
        recipient = db.query(User).filter(User.username == target_username).first()
    elif thread_id:
        try:
            parsed_thread = uuid.UUID(thread_id)
        except ValueError:
            return _messages_redirect("Invalid thread id.", error=True)
        seed = (
            db.query(DirectMessage)
            .options(joinedload(DirectMessage.sender), joinedload(DirectMessage.recipient))
            .filter(
                DirectMessage.thread_id == parsed_thread,
                or_(DirectMessage.sender_id == user.id, DirectMessage.recipient_id == user.id),
            )
            .order_by(DirectMessage.created_at.desc())
            .first()
        )
        if seed:
            recipient = seed.sender if seed.sender_id != user.id else seed.recipient

    if not recipient:
        return _messages_redirect("Recipient username is required.", error=True, thread=thread_id)
    if recipient.id == user.id:
        return _messages_redirect("Cannot message yourself.", error=True, thread=thread_id)
    if getattr(recipient, "is_disabled", False):
        return _messages_redirect("Recipient account is disabled.", error=True, thread=thread_id)

    has_attachment = bool(attachment and (attachment.filename or "").strip())
    if not body and not has_attachment:
        return _messages_redirect("Message cannot be empty.", error=True, thread=thread_id)
    if len(body) > 4000:
        return _messages_redirect("Message too long.", error=True, thread=thread_id)

    resolved_thread_id = _resolve_thread_id(
        db,
        sender_id=user.id,
        recipient_id=recipient.id,
        requested_thread=thread_id,
    )
    try:
        conversation_key, conversation_key_created = ensure_conversation_key(
            db,
            thread_id=resolved_thread_id,
            user_a_id=user.id,
            user_b_id=recipient.id,
        )
    except ValueError:
        return _messages_redirect(
            "Thread key metadata conflict detected; start a new conversation thread.",
            error=True,
            thread=str(resolved_thread_id),
        )
    conversation_dek = get_conversation_dek(conversation_key)

    dm = DirectMessage(
        id=uuid.uuid4(),
        thread_id=resolved_thread_id,
        sender_id=user.id,
        recipient_id=recipient.id,
        body=encrypt_dm_body(body, conversation_dek),
        body_key_scheme=DM_BODY_SCHEME_CONVERSATION,
        body_key_version=int(conversation_key.key_version or 1),
    )

    if has_attachment and attachment:
        safe_name = Path(attachment.filename or "").name.strip()
        if not safe_name:
            return _messages_redirect("Invalid attachment name.", error=True, thread=str(resolved_thread_id))

        attach_dir = _message_attachment_root() / str(recipient.id) / str(dm.id)
        attach_dir.mkdir(parents=True, exist_ok=True)
        storage_name = f"{uuid.uuid4().hex}.dmenc"
        dest = attach_dir / storage_name

        nonce_b64, tag_b64, plain_size = encrypt_file_to_path(conversation_dek, attachment.file, dest)
        if plain_size > MESSAGE_ATTACHMENT_MAX_BYTES:
            try:
                dest.unlink()
            except FileNotFoundError:
                pass
            return _messages_redirect("Attachment is too large (max 10 MB).", error=True, thread=str(resolved_thread_id))

        mime_type, _ = mimetypes.guess_type(safe_name)
        dm.attachment_name = safe_name
        dm.attachment_path = str(dest)
        dm.attachment_size = plain_size
        dm.attachment_enc_nonce = nonce_b64
        dm.attachment_enc_tag = tag_b64
        dm.attachment_key_scheme = DM_ATTACHMENT_SCHEME_CONVERSATION
        dm.attachment_key_version = int(conversation_key.key_version or 1)
        dm.attachment_mime_type = mime_type

    db.add(dm)
    add_event(
        db,
        user,
        action="message",
        message=(
            f"Sent message to '{recipient.username}'"
            f"{' with attachment' if dm.attachment_name else ''}."
        ),
        level="SUCCESS",
    )
    if conversation_key_created:
        add_event(
            db,
            user,
            action="crypto",
            message=(
                f"Provisioned shared conversation key for thread '{resolved_thread_id}' "
                f"with '{recipient.username}' (v{conversation_key.key_version})."
            ),
            level="INFO",
        )
        add_audit_log(
            db,
            user=user,
            event_type="encryption.conversation_key_created",
            details=(
                f"Created conversation key thread={resolved_thread_id}, peer={recipient.username}, "
                f"version={conversation_key.key_version}."
            ),
            request=request,
        )
    db.commit()

    return RedirectResponse(url=f"/ui/messages?thread={resolved_thread_id}", status_code=303)


@router.post("/messages/report")
def report_message(
    request: Request,
    message_id: str = Form(...),
    reason: str = Form("other"),
    details: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    try:
        mid = uuid.UUID(message_id)
    except ValueError:
        return _messages_redirect("Message not found.", error=True)

    message = (
        db.query(DirectMessage)
        .options(joinedload(DirectMessage.sender), joinedload(DirectMessage.recipient))
        .filter(DirectMessage.id == mid)
        .first()
    )
    if not message:
        return _messages_redirect("Message not found.", error=True)

    if user.id not in {message.sender_id, message.recipient_id}:
        raise HTTPException(status_code=403, detail="Forbidden")

    if message.sender_id == user.id:
        return _messages_redirect("Cannot report your own message.", error=True, thread=str(message.thread_id or message.id))

    normalized_reason = (reason or "").strip().lower()
    if normalized_reason not in DM_REPORT_REASONS:
        normalized_reason = "other"

    note = (details or "").strip()
    if len(note) > 2000:
        return _messages_redirect("Details too long.", error=True, thread=str(message.thread_id or message.id))

    thread_uuid = message.thread_id or message.id
    report = DirectMessageReport(
        message_id=message.id,
        thread_id=thread_uuid,
        reporter_id=user.id,
        reported_user_id=message.sender_id,
        reason=normalized_reason,
        details=encrypt_message(note) if note else None,
        status="open",
    )
    db.add(report)
    add_event(
        db,
        user,
        action="report",
        message=f"Reported a direct message from '{message.sender.username}' (reason: {normalized_reason}).",
        level="WARN",
    )
    add_audit_log(
        db,
        user=user,
        event_type="message.reported",
        details=f"Reported direct message {message.id} from '{message.sender.username}' (reason: {normalized_reason}).",
        request=request,
    )

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return _messages_redirect("You already reported that message.", error=False, thread=str(thread_uuid))

    return _messages_redirect(
        "Report submitted. An administrator will review it.",
        error=False,
        thread=str(thread_uuid),
    )


@router.get("/messages/{message_id}/attachment")
def open_message_attachment(
    message_id: str,
    request: Request,
    download: bool = False,
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    try:
        mid = uuid.UUID(message_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Message not found")

    message = db.query(DirectMessage).filter(DirectMessage.id == mid).first()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    if user.id not in {message.sender_id, message.recipient_id}:
        raise HTTPException(status_code=403, detail="Forbidden")

    if not message.attachment_name or not message.attachment_path:
        raise HTTPException(status_code=404, detail="Attachment not found")

    path = _safe_message_attachment_path(message.attachment_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Attachment missing on disk")

    _ensure_message_attachment_encrypted(db, message, path)

    disposition = "attachment" if download else "inline"
    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": f'{disposition}; filename="{message.attachment_name}"',
    }

    if not message.attachment_enc_nonce or not message.attachment_enc_tag:
        raise HTTPException(status_code=409, detail="Attachment encryption metadata missing")

    scheme = (message.attachment_key_scheme or "").strip().lower()
    thread_id = message.thread_id or message.id
    conversation_key: ConversationKey | None = None
    conversation_dek: bytes | None = None
    recipient_dek: bytes | None = None
    system_dek: bytes | None = None

    def _conversation_material() -> tuple[ConversationKey, bytes]:
        nonlocal conversation_key, conversation_dek
        if conversation_key is not None and conversation_dek is not None:
            return conversation_key, conversation_dek
        key_row = db.query(ConversationKey).filter(ConversationKey.thread_id == thread_id).first()
        if not key_row:
            try:
                key_row, _ = ensure_conversation_key(
                    db,
                    thread_id=thread_id,
                    user_a_id=message.sender_id,
                    user_b_id=message.recipient_id,
                )
            except ValueError as exc:
                raise HTTPException(status_code=409, detail="Conversation key metadata mismatch") from exc
        conversation_key = key_row
        conversation_dek = get_conversation_dek(key_row)
        return conversation_key, conversation_dek

    def _recipient_material() -> bytes:
        nonlocal recipient_dek
        if recipient_dek is not None:
            return recipient_dek
        recipient = db.query(User).filter(User.id == message.recipient_id).first()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")
        recipient_dek = get_user_dek(db, recipient)
        return recipient_dek

    def _system_material() -> bytes:
        nonlocal system_dek
        if system_dek is None:
            system_dek = message_attachment_key_bytes()
        return system_dek

    def _decrypt_attachment_bytes(dek: bytes) -> bytes:
        chunks: list[bytes] = []
        for chunk in decrypt_file_iter(
            dek,
            path,
            message.attachment_enc_nonce or "",
            message.attachment_enc_tag or "",
        ):
            chunks.append(chunk)
        return b"".join(chunks)

    if scheme == DM_ATTACHMENT_SCHEME_CONVERSATION:
        candidate_labels = ("conversation", "recipient", "system")
    elif scheme in {"", DM_ATTACHMENT_SCHEME_RECIPIENT}:
        candidate_labels = ("recipient", "conversation", "system")
    elif scheme == DM_ATTACHMENT_SCHEME_SYSTEM:
        candidate_labels = ("system", "conversation", "recipient")
    else:
        raise HTTPException(status_code=500, detail="Unknown attachment encryption scheme")

    plaintext_bytes: bytes | None = None
    used_label = ""
    for label in candidate_labels:
        try:
            if label == "conversation":
                _, dek = _conversation_material()
            elif label == "recipient":
                dek = _recipient_material()
            else:
                dek = _system_material()
            plaintext_bytes = _decrypt_attachment_bytes(dek)
            used_label = label
            break
        except HTTPException:
            if label == "conversation":
                continue
            raise
        except Exception:
            continue

    if plaintext_bytes is None:
        detail = (
            "Attachment decryption failed. "
            "Stored attachment metadata does not match the ciphertext on disk."
        )
        if download:
            raise HTTPException(status_code=409, detail=detail)
        return Response(
            content=(
                "<html><body style='font-family: sans-serif; padding: 1rem;'>"
                "<h3>Attachment unavailable</h3>"
                f"<p>{detail}</p>"
                "</body></html>"
            ),
            media_type="text/html",
            status_code=409,
            headers={"Cache-Control": "no-store"},
        )

    changed = False
    if used_label != "conversation":
        try:
            key_row, conv_dek = _conversation_material()
        except HTTPException:
            key_row = None
            conv_dek = None
        if key_row is not None and conv_dek is not None:
            tmp = path.with_name(f"{path.name}.convheal.tmp")
            try:
                with io.BytesIO(plaintext_bytes) as src:
                    nonce_b64, tag_b64, plain_size = encrypt_file_to_path(conv_dek, src, tmp)
                tmp.replace(path)
            except Exception:
                try:
                    if tmp.exists():
                        tmp.unlink()
                except OSError:
                    pass
            else:
                message.attachment_enc_nonce = nonce_b64
                message.attachment_enc_tag = tag_b64
                message.attachment_size = plain_size
                message.attachment_key_scheme = DM_ATTACHMENT_SCHEME_CONVERSATION
                message.attachment_key_version = int(key_row.key_version or 1)
                changed = True
        elif used_label == "recipient" and scheme != DM_ATTACHMENT_SCHEME_RECIPIENT:
            message.attachment_key_scheme = DM_ATTACHMENT_SCHEME_RECIPIENT
            message.attachment_key_version = None
            changed = True
        elif used_label == "system" and scheme != DM_ATTACHMENT_SCHEME_SYSTEM:
            message.attachment_key_scheme = DM_ATTACHMENT_SCHEME_SYSTEM
            message.attachment_key_version = None
            changed = True
    elif scheme != DM_ATTACHMENT_SCHEME_CONVERSATION and conversation_key is not None:
        message.attachment_key_scheme = DM_ATTACHMENT_SCHEME_CONVERSATION
        message.attachment_key_version = int(conversation_key.key_version or 1)
        changed = True

    add_event(
        db,
        user,
        action="message",
        message=(
            f"{'Downloaded' if download else 'Previewed'} "
            f"message attachment '{message.attachment_name}'."
        ),
    )
    db.commit()

    return Response(
        content=plaintext_bytes,
        media_type=message.attachment_mime_type or "application/octet-stream",
        headers=headers,
    )


@router.get("/admin/users")
def admin_users_page(request: Request, db: Session = Depends(get_db)):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)
    q = request.url.query
    target = "/ui/admin/security"
    if q:
        target = f"{target}?{q}"
    return RedirectResponse(url=target, status_code=303)


@router.get("/admin/security")
def admin_security_page(
    request: Request,
    q: str = "",
    limit: int = 250,
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    text_filter = (q or "").strip()
    limit = max(1, min(limit, 500))

    query = db.query(User)
    if text_filter:
        like = f"%{text_filter}%"
        query = query.filter(or_(User.username.ilike(like), User.email.ilike(like)))
    users = query.order_by(User.username.asc()).limit(limit).all()
    user_ids = [row.id for row in users]
    system_admin_count = db.query(func.count(User.id)).filter(User.is_admin.is_(True)).scalar() or 0
    system_superadmin_count = db.query(func.count(User.id)).filter(User.is_superadmin.is_(True)).scalar() or 0

    active_sessions_by_user: dict[uuid.UUID, int] = {}
    files_by_user: dict[uuid.UUID, int] = {}
    roles_map: dict[uuid.UUID, list[str]] = {}
    user_key_meta: dict[uuid.UUID, tuple[uuid.UUID, int, datetime | None]] = {}
    auto_backfilled_user_keys = 0
    auto_backfilled_group_keys = 0
    if user_ids:
        now = datetime.utcnow()
        active_sessions_by_user = {
            user_id: int(count)
            for user_id, count in (
                db.query(SessionModel.user_id, func.count(SessionModel.id))
                .filter(
                    SessionModel.user_id.in_(user_ids),
                    SessionModel.is_active.is_(True),
                    SessionModel.expires_at > now,
                )
                .group_by(SessionModel.user_id)
                .all()
            )
        }
        files_by_user = {
            owner_id: int(count)
            for owner_id, count in (
                db.query(FileRecord.user_id, func.count(FileRecord.id))
                .filter(FileRecord.user_id.in_(user_ids))
                .group_by(FileRecord.user_id)
                .all()
            )
        }
        membership_rows = (
            db.query(GroupMembership.user_id, Group.name, GroupMembership.role)
            .join(Group, Group.id == GroupMembership.group_id)
            .filter(GroupMembership.user_id.in_(user_ids))
            .order_by(Group.name.asc())
            .all()
        )
        for user_id, group_name, role in membership_rows:
            roles_map.setdefault(user_id, []).append(f"{group_name} ({(role or 'member').lower()})")

        missing_user_key_rows = (
            db.query(User)
            .outerjoin(UserKey, UserKey.user_id == User.id)
            .filter(User.id.in_(user_ids), UserKey.id.is_(None))
            .all()
        )
        for missing_target in missing_user_key_rows:
            try:
                ensure_user_key(db, missing_target)
                auto_backfilled_user_keys += 1
            except Exception:
                db.rollback()
                logger.warning("Failed to auto-backfill user key for %s", missing_target.id, exc_info=True)

        key_rows = (
            db.query(UserKey.user_id, UserKey.id, UserKey.key_version, UserKey.created_at)
            .filter(UserKey.user_id.in_(user_ids))
            .all()
        )
        for user_id, key_id, key_version, created_at in key_rows:
            user_key_meta[user_id] = (key_id, int(key_version or 1), created_at)

    missing_group_key_rows = (
        db.query(Group)
        .outerjoin(GroupKey, GroupKey.group_id == Group.id)
        .filter(GroupKey.id.is_(None))
        .all()
    )
    for missing_group in missing_group_key_rows:
        try:
            ensure_group_key(db, missing_group)
            auto_backfilled_group_keys += 1
        except Exception:
            db.rollback()
            logger.warning("Failed to auto-backfill group key for %s", missing_group.id, exc_info=True)

    rows: list[dict[str, object]] = []
    compromised_count = 0
    directory_locked_count = 0
    email_configured_count = 0
    user_key_record_count = 0
    mfa_enabled_count = 0
    for target in users:
        email_value = (target.email or "").strip()
        if email_value:
            email_configured_count += 1

        compromised = bool(getattr(target, "security_compromised", False))
        if compromised:
            compromised_count += 1

        directory_locked = bool(getattr(target, "directory_locked", False))
        if directory_locked:
            directory_locked_count += 1

        has_mfa = bool(target.totp_enabled or target.email_mfa_enabled or target.sms_mfa_enabled)
        if has_mfa:
            mfa_enabled_count += 1

        group_roles = roles_map.get(target.id, [])
        key_id, key_version, key_created_at = user_key_meta.get(target.id, (None, 0, None))
        has_user_key = key_version > 0
        if has_user_key:
            user_key_record_count += 1
        role_label = "Superadmin" if target.is_superadmin else ("Administrator" if target.is_admin else "Standard")
        admin_toggle_locked = bool(target.is_superadmin or (target.is_admin and system_admin_count <= 1))
        rows.append(
            {
                "user": target,
                "active_sessions": active_sessions_by_user.get(target.id, 0),
                "file_count": files_by_user.get(target.id, 0),
                "mfa_summary": _mfa_summary_for_user(target),
                "role_label": role_label,
                "admin_toggle_locked": admin_toggle_locked,
                "group_roles": group_roles,
                "group_roles_count": len(group_roles),
                "group_roles_preview": ", ".join(group_roles[:4]) if group_roles else "(none)",
                "email_value": email_value,
                "directory_locked": directory_locked,
                "compromised": compromised,
                "user_key_present": has_user_key,
                "user_key_record_id": str(key_id) if key_id else "-",
                "user_key_version": key_version if has_user_key else None,
                "user_key_label": f"user-dek:v{key_version}" if has_user_key else "missing",
                "user_key_created_utc": _format_utc(key_created_at),
                "created_utc": _format_utc(target.created_at),
                "last_login_utc": _format_utc(target.last_login),
            }
        )

    group_inventory_limit = 500
    total_group_count = db.query(func.count(Group.id)).scalar() or 0
    group_rows_raw = (
        db.query(
            Group.id,
            Group.name,
            Group.owner_id,
            GroupKey.id,
            GroupKey.key_version,
            GroupKey.created_at,
        )
        .outerjoin(GroupKey, GroupKey.group_id == Group.id)
        .order_by(Group.name.asc())
        .limit(group_inventory_limit)
        .all()
    )
    group_ids_for_counts = [group_id for group_id, *_ in group_rows_raw]
    group_owner_ids = {owner_id for _, _, owner_id, _, _, _ in group_rows_raw if owner_id}
    owner_name_map: dict[uuid.UUID, str] = {}
    if group_owner_ids:
        owner_name_map = {
            owner_id: username
            for owner_id, username in (
                db.query(User.id, User.username)
                .filter(User.id.in_(group_owner_ids))
                .all()
            )
        }
    group_member_counts: dict[uuid.UUID, int] = {}
    group_file_counts: dict[uuid.UUID, int] = {}
    if group_ids_for_counts:
        group_member_counts = {
            group_id: int(count)
            for group_id, count in (
                db.query(GroupMembership.group_id, func.count(GroupMembership.id))
                .filter(GroupMembership.group_id.in_(group_ids_for_counts))
                .group_by(GroupMembership.group_id)
                .all()
            )
        }
        group_file_counts = {
            group_id: int(count)
            for group_id, count in (
                db.query(GroupFileRecord.group_id, func.count(GroupFileRecord.id))
                .filter(GroupFileRecord.group_id.in_(group_ids_for_counts))
                .group_by(GroupFileRecord.group_id)
                .all()
            )
        }
    group_key_rows: list[dict[str, object]] = []
    for group_id, group_name, owner_id, key_id, key_version, key_created_at in group_rows_raw:
        has_key = key_id is not None and key_version is not None
        version = int(key_version or 0)
        group_key_rows.append(
            {
                "group_id": str(group_id),
                "group_name": group_name,
                "owner_username": owner_name_map.get(owner_id, "-"),
                "member_count": group_member_counts.get(group_id, 0),
                "file_count": group_file_counts.get(group_id, 0),
                "key_present": has_key,
                "key_record_id": str(key_id) if key_id else "-",
                "key_label": f"group-dek:v{version}" if has_key else "missing",
                "key_created_utc": _format_utc(key_created_at),
            }
        )
    group_key_record_total = db.query(func.count(GroupKey.id)).scalar() or 0

    conversation_inventory_limit = 500
    conversation_total = db.query(func.count(ConversationKey.id)).scalar() or 0
    conversation_rows_raw = (
        db.query(
            ConversationKey.id,
            ConversationKey.thread_id,
            ConversationKey.user_low_id,
            ConversationKey.user_high_id,
            ConversationKey.key_version,
            ConversationKey.created_at,
        )
        .order_by(ConversationKey.created_at.desc(), ConversationKey.thread_id.asc())
        .limit(conversation_inventory_limit)
        .all()
    )
    participant_ids: set[uuid.UUID] = set()
    thread_ids_for_counts: list[uuid.UUID] = []
    for _, thread_id, user_low_id, user_high_id, _, _ in conversation_rows_raw:
        participant_ids.add(user_low_id)
        participant_ids.add(user_high_id)
        thread_ids_for_counts.append(thread_id)
    participant_name_map: dict[uuid.UUID, str] = {}
    if participant_ids:
        participant_name_map = {
            pid: uname
            for pid, uname in (
                db.query(User.id, User.username)
                .filter(User.id.in_(participant_ids))
                .all()
            )
        }
    thread_message_counts: dict[uuid.UUID, int] = {}
    if thread_ids_for_counts:
        thread_message_counts = {
            thread_id: int(count)
            for thread_id, count in (
                db.query(DirectMessage.thread_id, func.count(DirectMessage.id))
                .filter(DirectMessage.thread_id.in_(thread_ids_for_counts))
                .group_by(DirectMessage.thread_id)
                .all()
            )
        }
    conversation_key_rows: list[dict[str, object]] = []
    for key_id, thread_id, user_low_id, user_high_id, key_version, key_created_at in conversation_rows_raw:
        low_name = participant_name_map.get(user_low_id, str(user_low_id)[:8])
        high_name = participant_name_map.get(user_high_id, str(user_high_id)[:8])
        conversation_key_rows.append(
            {
                "thread_id": str(thread_id),
                "participants": f"{low_name} <-> {high_name}",
                "message_count": thread_message_counts.get(thread_id, 0),
                "key_record_id": str(key_id),
                "key_label": _conversation_body_key_label(int(key_version or 1)),
                "key_created_utc": _format_utc(key_created_at),
            }
        )
    dm_thread_total = (
        db.query(func.count(func.distinct(DirectMessage.thread_id)))
        .filter(DirectMessage.thread_id.is_not(None))
        .scalar()
        or 0
    )
    dm_threads_with_key = (
        db.query(func.count(func.distinct(DirectMessage.thread_id)))
        .join(ConversationKey, ConversationKey.thread_id == DirectMessage.thread_id)
        .scalar()
        or 0
    )
    dm_threads_missing_key = max(0, dm_thread_total - dm_threads_with_key)
    user_key_duplicate_users = (
        db.query(func.count())
        .select_from(
            db.query(UserKey.user_id)
            .group_by(UserKey.user_id)
            .having(func.count(UserKey.id) > 1)
            .subquery()
        )
        .scalar()
        or 0
    )
    group_key_duplicate_groups = (
        db.query(func.count())
        .select_from(
            db.query(GroupKey.group_id)
            .group_by(GroupKey.group_id)
            .having(func.count(GroupKey.id) > 1)
            .subquery()
        )
        .scalar()
        or 0
    )
    conversation_key_duplicate_threads = (
        db.query(func.count())
        .select_from(
            db.query(ConversationKey.thread_id)
            .group_by(ConversationKey.thread_id)
            .having(func.count(ConversationKey.id) > 1)
            .subquery()
        )
        .scalar()
        or 0
    )
    key_duplicate_total = user_key_duplicate_users + group_key_duplicate_groups + conversation_key_duplicate_threads
    key_material_summary = _collect_key_uniqueness_summary(db)

    key_repair_parts: list[str] = []
    if auto_backfilled_user_keys:
        key_repair_parts.append(f"user keys repaired: {auto_backfilled_user_keys}")
    if auto_backfilled_group_keys:
        key_repair_parts.append(f"group keys repaired: {auto_backfilled_group_keys}")
    key_repair_notice = ", ".join(key_repair_parts)

    notice_message = request.query_params.get("notice")
    if key_repair_notice:
        notice_message = f"{notice_message} | {key_repair_notice}" if notice_message else key_repair_notice

    return templates.TemplateResponse(
        "admin_security.html",
        {
            "request": request,
            "user": admin_user,
            "rows": rows,
            "group_key_rows": group_key_rows,
            "group_inventory_limit": group_inventory_limit,
            "group_inventory_truncated": total_group_count > len(group_key_rows),
            "conversation_key_rows": conversation_key_rows,
            "conversation_inventory_limit": conversation_inventory_limit,
            "conversation_inventory_truncated": conversation_total > len(conversation_key_rows),
            "filters": {
                "q": text_filter,
                "limit": limit,
            },
            "playbooks": [
                {"key": key, "label": meta["label"], "description": meta["description"]}
                for key, meta in ADMIN_SECURITY_PLAYBOOKS.items()
            ],
            "summary": {
                "displayed_users": len(rows),
                "admins": system_admin_count,
                "superadmins": system_superadmin_count,
                "mfa_enabled": mfa_enabled_count,
                "compromised": compromised_count,
                "directory_locked": directory_locked_count,
                "email_configured": email_configured_count,
                "user_key_records": user_key_record_count,
                "group_key_records": group_key_record_total,
                "group_total": total_group_count,
                "conversation_key_records": conversation_total,
                "conversation_threads": dm_thread_total,
                "conversation_threads_missing_key": dm_threads_missing_key,
                "key_duplicate_total": key_duplicate_total,
                "user_key_duplicate_users": user_key_duplicate_users,
                "group_key_duplicate_groups": group_key_duplicate_groups,
                "conversation_key_duplicate_threads": conversation_key_duplicate_threads,
                **key_material_summary,
            },
            "can_self_promote_superadmin": bool(
                admin_user.is_admin and not admin_user.is_superadmin and system_superadmin_count == 0
            ),
            "notice": notice_message,
            "error": request.query_params.get("error"),
            "title": "Admin Security",
        },
    )


@router.post("/admin/security/{user_id}/directory-lock")
def admin_security_directory_lock(
    user_id: str,
    request: Request,
    action: str = Form(...),
    reason: str = Form(""),
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        target_id = uuid.UUID(user_id)
    except ValueError:
        return _admin_security_redirect("Invalid user identifier.", error=True)

    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        return _admin_security_redirect("User not found.", error=True)

    action_key = (action or "").strip().lower()
    note = (reason or "").strip()
    now = datetime.utcnow()

    if action_key == "lock":
        target.directory_locked = True
        target.directory_locked_at = now
        target.directory_lock_reason = note or "Locked by admin security action."
        target.directory_locked_by_admin_id = admin_user.id
        add_audit_log(
            db,
            user=target,
            event_type="account.directory_locked_by_admin",
            details=f"Admin '{admin_user.username}' locked directory writes. {target.directory_lock_reason}",
            request=request,
        )
        add_audit_log(
            db,
            user=admin_user,
            event_type="admin.directory_locked",
            details=f"Locked directory writes for '{target.username}'.",
            request=request,
        )
        db.commit()
        return _admin_security_redirect(f"Directory writes locked for '{target.username}'.")

    if action_key == "unlock":
        target.directory_locked = False
        target.directory_locked_at = None
        target.directory_lock_reason = None
        target.directory_locked_by_admin_id = None
        add_audit_log(
            db,
            user=target,
            event_type="account.directory_unlocked_by_admin",
            details=f"Admin '{admin_user.username}' unlocked directory writes.",
            request=request,
        )
        add_audit_log(
            db,
            user=admin_user,
            event_type="admin.directory_unlocked",
            details=f"Unlocked directory writes for '{target.username}'.",
            request=request,
        )
        db.commit()
        return _admin_security_redirect(f"Directory writes unlocked for '{target.username}'.")

    return _admin_security_redirect("Invalid directory lock action.", error=True)


@router.post("/admin/security/{user_id}/playbook")
def admin_security_playbook(
    user_id: str,
    request: Request,
    playbook: str = Form(...),
    note: str = Form(""),
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        target_id = uuid.UUID(user_id)
    except ValueError:
        return _admin_security_redirect("Invalid user identifier.", error=True)

    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        return _admin_security_redirect("User not found.", error=True)

    playbook_key = (playbook or "").strip().lower()
    if playbook_key not in ADMIN_SECURITY_PLAYBOOKS:
        return _admin_security_redirect("Unknown security playbook.", error=True)

    note_value = (note or "").strip()
    now = datetime.utcnow()
    revoked = 0

    if playbook_key == "contain":
        if getattr(target, "is_superadmin", False) and not getattr(admin_user, "is_superadmin", False):
            return _admin_security_redirect(
                "Only a superadmin can apply containment that disables a superadmin account.",
                error=True,
            )
        target.security_compromised = True
        target.security_compromised_at = now
        target.security_compromise_note = note_value or "Containment playbook applied by admin."
        target.is_disabled = True
        target.disabled_at = now
        target.disabled_reason = note_value or f"Containment playbook applied by admin '{admin_user.username}'."
        target.messaging_disabled = True
        target.messaging_disabled_at = now
        target.directory_locked = True
        target.directory_locked_at = now
        target.directory_lock_reason = note_value or "Containment playbook directory lock."
        target.directory_locked_by_admin_id = admin_user.id
        _clear_mfa_challenge(target)
        revoked = (
            db.query(SessionModel)
            .filter(SessionModel.user_id == target.id, SessionModel.is_active.is_(True))
            .update({SessionModel.is_active: False}, synchronize_session=False)
        )
    elif playbook_key == "investigate":
        target.security_compromised = True
        if not target.security_compromised_at:
            target.security_compromised_at = now
        target.security_compromise_note = note_value or target.security_compromise_note or "Investigate hold applied."
        target.directory_locked = True
        target.directory_locked_at = now
        target.directory_lock_reason = note_value or "Investigate hold directory lock."
        target.directory_locked_by_admin_id = admin_user.id
        revoked = (
            db.query(SessionModel)
            .filter(SessionModel.user_id == target.id, SessionModel.is_active.is_(True))
            .update({SessionModel.is_active: False}, synchronize_session=False)
        )
    else:  # release
        target.security_compromised = False
        target.security_compromised_at = None
        target.security_compromise_note = note_value or None
        target.is_disabled = False
        target.disabled_at = None
        target.disabled_reason = None
        target.messaging_disabled = False
        target.messaging_disabled_at = None
        target.directory_locked = False
        target.directory_locked_at = None
        target.directory_lock_reason = None
        target.directory_locked_by_admin_id = None

    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.security_playbook_applied",
        details=(
            f"Applied security playbook '{playbook_key}' to '{target.username}' "
            f"(revoked_sessions={revoked})."
        ),
        request=request,
    )
    add_audit_log(
        db,
        user=target,
        event_type="account.security_playbook_applied_by_admin",
        details=f"Admin '{admin_user.username}' applied security playbook '{playbook_key}'.",
        request=request,
    )
    db.commit()

    playbook_label = ADMIN_SECURITY_PLAYBOOKS[playbook_key]["label"]
    return _admin_security_redirect(f"Applied playbook '{playbook_label}' to '{target.username}'.")


@router.post("/admin/security/{user_id}/rotate-user-key")
def admin_security_rotate_user_key(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        target_id = uuid.UUID(user_id)
    except ValueError:
        return _admin_security_redirect("Invalid user identifier.", error=True)

    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        return _admin_security_redirect("User not found.", error=True)

    try:
        summary = _rotate_user_key_material(db, target)
    except Exception as exc:
        logger.warning("Admin user key rotation failed for %s", target.id, exc_info=True)
        return _admin_security_redirect(
            f"Failed to rotate user key for '{target.username}' ({exc.__class__.__name__}).",
            error=True,
        )

    add_event(
        db,
        admin_user,
        action="admin_security",
        message=(
            f"Rotated user key for '{target.username}' "
            f"v{summary['key_version_from']}->v{summary['key_version_to']} "
            f"(files={summary['files_rotated']}, recipient_attachments={summary['recipient_attachments_rotated']})."
        ),
        level="WARN",
    )
    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.user_key_rotated",
        details=(
            f"Rotated user key for '{target.username}' (user_id={target.id}) "
            f"v{summary['key_version_from']}->v{summary['key_version_to']}, "
            f"files={summary['files_rotated']}/{summary['files_total']}, "
            f"recipient_attachments={summary['recipient_attachments_rotated']}/{summary['recipient_attachments_total']}."
        ),
        request=request,
    )
    add_audit_log(
        db,
        user=target,
        event_type="account.user_key_rotated_by_admin",
        details=(
            f"Admin '{admin_user.username}' rotated your user key "
            f"v{summary['key_version_from']}->v{summary['key_version_to']}."
        ),
        request=request,
    )
    db.commit()
    return _admin_security_redirect(
        f"Rotated user key for '{target.username}' (v{summary['key_version_from']}->v{summary['key_version_to']})."
    )


@router.post("/admin/security/group/{group_id}/rotate-key")
def admin_security_rotate_group_key(
    group_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        group_uuid = uuid.UUID(group_id)
    except ValueError:
        return _admin_security_redirect("Invalid group identifier.", error=True)

    group = db.query(Group).filter(Group.id == group_uuid).first()
    if not group:
        return _admin_security_redirect("Group not found.", error=True)

    try:
        summary = _rotate_group_key_material(db, group)
    except Exception as exc:
        logger.warning("Admin group key rotation failed for %s", group.id, exc_info=True)
        return _admin_security_redirect(
            f"Failed to rotate group key for '{group.name}' ({exc.__class__.__name__}).",
            error=True,
        )

    owner = db.query(User).filter(User.id == group.owner_id).first() if group.owner_id else None
    add_event(
        db,
        admin_user,
        action="admin_security",
        message=(
            f"Rotated group key for '{group.name}' "
            f"v{summary['key_version_from']}->v{summary['key_version_to']} "
            f"(files={summary['files_rotated']})."
        ),
        level="WARN",
    )
    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.group_key_rotated",
        details=(
            f"Rotated group key for '{group.name}' (group_id={group.id}) "
            f"v{summary['key_version_from']}->v{summary['key_version_to']}, "
            f"files={summary['files_rotated']}/{summary['files_total']}."
        ),
        request=request,
    )
    if owner:
        add_audit_log(
            db,
            user=owner,
            event_type="account.group_key_rotated_by_admin",
            details=(
                f"Admin '{admin_user.username}' rotated key for group '{group.name}' "
                f"v{summary['key_version_from']}->v{summary['key_version_to']}."
            ),
            request=request,
        )
    db.commit()
    return _admin_security_redirect(
        f"Rotated group key for '{group.name}' (v{summary['key_version_from']}->v{summary['key_version_to']})."
    )


@router.post("/admin/security/conversation/{thread_id}/rotate-key")
def admin_security_rotate_conversation_key(
    thread_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        thread_uuid = uuid.UUID(thread_id)
    except ValueError:
        return _admin_security_redirect("Invalid conversation thread identifier.", error=True)

    try:
        summary = _rotate_conversation_key_material(db, thread_id=thread_uuid)
    except ValueError as exc:
        return _admin_security_redirect(str(exc), error=True)
    except Exception as exc:
        logger.warning("Admin conversation key rotation failed for %s", thread_uuid, exc_info=True)
        return _admin_security_redirect(
            f"Failed to rotate conversation key for thread '{thread_uuid}' ({exc.__class__.__name__}).",
            error=True,
        )

    key_row = db.query(ConversationKey).filter(ConversationKey.thread_id == thread_uuid).first()
    participant_names = "unknown"
    participant_users: list[User] = []
    if key_row:
        users = (
            db.query(User)
            .filter(User.id.in_([key_row.user_low_id, key_row.user_high_id]))
            .order_by(User.username.asc())
            .all()
        )
        participant_users = users
        if users:
            participant_names = " <-> ".join(u.username for u in users)

    add_event(
        db,
        admin_user,
        action="admin_security",
        message=(
            f"Rotated conversation key for thread {thread_uuid} "
            f"v{summary['key_version_from']}->v{summary['key_version_to']} "
            f"(messages={summary['messages_rotated'] + summary['messages_upgraded_plaintext']}, "
            f"attachments={summary['attachments_rotated']})."
        ),
        level="WARN",
    )
    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.conversation_key_rotated",
        details=(
            f"Rotated conversation key for thread={thread_uuid} participants={participant_names} "
            f"v{summary['key_version_from']}->v{summary['key_version_to']}, "
            f"messages={summary['messages_rotated'] + summary['messages_upgraded_plaintext']}/{summary['messages_total']}, "
            f"attachments={summary['attachments_rotated']}/{summary['attachments_total']}."
        ),
        request=request,
    )
    for participant in participant_users:
        add_audit_log(
            db,
            user=participant,
            event_type="account.conversation_key_rotated_by_admin",
            details=(
                f"Admin '{admin_user.username}' rotated conversation key for thread {thread_uuid} "
                f"v{summary['key_version_from']}->v{summary['key_version_to']}."
            ),
            request=request,
        )
    db.commit()
    return _admin_security_redirect(
        f"Rotated conversation key for thread '{thread_uuid}' (v{summary['key_version_from']}->v{summary['key_version_to']})."
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
    if not _is_advanced_view_enabled(user):
        return _advanced_view_redirect("Enable advanced view in Profile to access Audit.")

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

    rows = [
        {
            "log": row,
            "username": user.username,
            "event_timestamp_display": _format_utc(row.event_timestamp),
        }
        for row in logs
    ]
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
    if not _is_advanced_view_enabled(admin_user):
        return _advanced_view_redirect("Enable advanced view in Profile to access Admin Audit.")

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
                "event_timestamp_display": _format_utc(log_row.event_timestamp),
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


@router.get("/admin/help")
def admin_help_inbox(
    request: Request,
    status: str = "",
    priority: str = "",
    q: str = "",
    limit: int = 200,
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    status_filter = _normalize_ticket_status(status)
    priority_raw = (priority or "").strip().lower()
    priority_filter = priority_raw if priority_raw in SUPPORT_TICKET_PRIORITIES else ""
    text_filter = (q or "").strip()
    limit = max(1, min(limit, 500))

    counts = {
        (s or "open"): int(c)
        for s, c in (
            db.query(SupportTicket.status, func.count(SupportTicket.id))
            .group_by(SupportTicket.status)
            .all()
        )
    }
    total_tickets = sum(counts.values())

    query = (
        db.query(SupportTicket)
        .join(User, SupportTicket.user_id == User.id)
        .options(
            joinedload(SupportTicket.requester),
            joinedload(SupportTicket.assigned_admin),
        )
        .order_by(
            case((SupportTicket.priority == "urgent", 0), else_=1),
            SupportTicket.updated_at.desc(),
            SupportTicket.created_at.desc(),
            SupportTicket.id.desc(),
        )
    )
    if status_filter:
        query = query.filter(SupportTicket.status == status_filter)
    if priority_filter:
        query = query.filter(SupportTicket.priority == priority_filter)
    if text_filter:
        like = f"%{text_filter}%"
        query = query.filter(
            or_(
                SupportTicket.subject.ilike(like),
                User.username.ilike(like),
            )
        )

    tickets = query.limit(limit).all()
    rows = []
    for ticket in tickets:
        body = decrypt_message(ticket.description or "").replace("\n", " ").strip()
        if len(body) > 160:
            body = f"{body[:157]}..."
        reply = decrypt_message(ticket.admin_reply or "").replace("\n", " ").strip() if ticket.admin_reply else ""
        if len(reply) > 120:
            reply = f"{reply[:117]}..."
        requester = ticket.requester
        rows.append(
            {
                "ticket": ticket,
                "ticket_display_id": _support_ticket_display_id(ticket),
                "requester_username": requester.username if requester else "(unknown)",
                "requester_email": requester.email if requester and requester.email else "",
                "requester_mfa_summary": _mfa_summary_for_user(requester) if requester else "Unknown",
                "assigned_admin_username": ticket.assigned_admin.username if ticket.assigned_admin else "",
                "description_preview": body or "-",
                "admin_reply_preview": reply or "",
                "category_label": SUPPORT_TICKET_CATEGORIES.get(ticket.category, ticket.category),
                "description_full": decrypt_message(ticket.description or ""),
                "admin_reply_full": decrypt_message(ticket.admin_reply or "") if ticket.admin_reply else "",
                "created_utc": _format_utc(ticket.created_at),
                "updated_utc": _format_utc(ticket.updated_at),
                "last_admin_update_utc": _format_utc(ticket.last_admin_update_at),
                "closed_utc": _format_utc(ticket.closed_at),
                "created_iso": _format_utc_iso(ticket.created_at),
                "updated_iso": _format_utc_iso(ticket.updated_at),
                "last_admin_update_iso": _format_utc_iso(ticket.last_admin_update_at),
                "closed_iso": _format_utc_iso(ticket.closed_at),
            }
        )

    return templates.TemplateResponse(
        "admin_help.html",
        {
            "request": request,
            "user": admin_user,
            "rows": rows,
            "counts": {
                "total": total_tickets,
                "open": counts.get("open", 0),
                "in_progress": counts.get("in_progress", 0),
                "waiting_on_user": counts.get("waiting_on_user", 0),
                "resolved": counts.get("resolved", 0),
                "closed": counts.get("closed", 0),
            },
            "filters": {
                "status": status_filter,
                "priority": priority_filter,
                "q": text_filter,
                "limit": limit,
            },
            "status_options": SUPPORT_TICKET_STATUSES,
            "priority_options": SUPPORT_TICKET_PRIORITIES,
            "category_options": SUPPORT_TICKET_CATEGORIES,
            "shortcut_rows": [
                {
                    "key": key,
                    "label": str(meta.get("label", key)),
                    "status": str(meta.get("status", "")),
                    "priority": str(meta.get("priority", "")) if meta.get("priority") else "",
                }
                for key, meta in ADMIN_TICKET_SHORTCUTS.items()
            ],
            "response_templates": _admin_ticket_response_rows(),
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
            "title": "Admin Help Inbox",
        },
    )


@router.get("/admin/help/{ticket_id}")
def admin_help_detail(ticket_id: str, request: Request, db: Session = Depends(get_db)):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        tid = uuid.UUID(ticket_id)
    except ValueError:
        return _admin_help_redirect("Invalid ticket id.", error=True)

    ticket = (
        db.query(SupportTicket)
        .options(
            joinedload(SupportTicket.requester),
            joinedload(SupportTicket.assigned_admin),
        )
        .filter(SupportTicket.id == tid)
        .first()
    )
    if not ticket:
        return _admin_help_redirect("Ticket not found.", error=True)

    return templates.TemplateResponse(
        "admin_help_detail.html",
        {
            "request": request,
            "user": admin_user,
            "ticket": ticket,
            "ticket_display_id": _support_ticket_display_id(ticket),
            "requester_username": ticket.requester.username if ticket.requester else "(unknown)",
            "requester_email": (ticket.requester.email or "") if ticket.requester else "",
            "requester_phone": (ticket.requester.phone_number or "") if ticket.requester else "",
            "requester_mfa_summary": _mfa_summary_for_user(ticket.requester) if ticket.requester else "Unknown",
            "description": decrypt_message(ticket.description or ""),
            "admin_reply": decrypt_message(ticket.admin_reply or "") if ticket.admin_reply else "",
            "category_label": SUPPORT_TICKET_CATEGORIES.get(ticket.category, ticket.category),
            "created_utc": _format_utc(ticket.created_at),
            "updated_utc": _format_utc(ticket.updated_at),
            "last_admin_update_utc": _format_utc(ticket.last_admin_update_at),
            "closed_utc": _format_utc(ticket.closed_at),
            "created_iso": _format_utc_iso(ticket.created_at),
            "updated_iso": _format_utc_iso(ticket.updated_at),
            "last_admin_update_iso": _format_utc_iso(ticket.last_admin_update_at),
            "closed_iso": _format_utc_iso(ticket.closed_at),
            "status_options": SUPPORT_TICKET_STATUSES,
            "priority_options": SUPPORT_TICKET_PRIORITIES,
            "category_options": SUPPORT_TICKET_CATEGORIES,
            "shortcut_rows": [
                {
                    "key": key,
                    "label": str(meta.get("label", key)),
                    "status": str(meta.get("status", "")),
                    "priority": str(meta.get("priority", "")) if meta.get("priority") else "",
                }
                for key, meta in ADMIN_TICKET_SHORTCUTS.items()
            ],
            "response_templates": [
                {
                    "key": row["key"],
                    "label": row["label"],
                    "shortcut": row["shortcut"],
                    "body": _render_admin_ticket_response_template(row["key"], ticket),
                }
                for row in _admin_ticket_response_rows()
            ],
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
            "title": "Help ticket detail",
        },
    )


@router.post("/admin/help/{ticket_id}/update")
def admin_help_update_ticket(
    ticket_id: str,
    request: Request,
    status: str = Form(...),
    priority: str = Form(...),
    category: str = Form(""),
    admin_reply: str = Form(""),
    clear_reply: str | None = Form(None),
    response_template: str | None = Form(None),
    append_template: str | None = Form(None),
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        tid = uuid.UUID(ticket_id)
    except ValueError:
        return _admin_help_redirect("Invalid ticket id.", error=True)

    ticket = (
        db.query(SupportTicket)
        .options(joinedload(SupportTicket.requester))
        .filter(SupportTicket.id == tid)
        .first()
    )
    if not ticket:
        return _admin_help_redirect("Ticket not found.", error=True)

    status_value = _normalize_ticket_status(status)
    if not status_value:
        return _admin_help_redirect("Invalid ticket status.", error=True, ticket_id=str(ticket.id))

    priority_value = (priority or "").strip().lower()
    if priority_value not in SUPPORT_TICKET_PRIORITIES:
        return _admin_help_redirect("Invalid ticket priority.", error=True, ticket_id=str(ticket.id))

    category_value = (category or ticket.category or "general").strip().lower()
    if category_value not in SUPPORT_TICKET_CATEGORIES:
        return _admin_help_redirect("Invalid ticket category.", error=True, ticket_id=str(ticket.id))

    reply_text = (admin_reply or "").strip()
    template_key = (response_template or "").strip().lower()
    template_text = _render_admin_ticket_response_template(template_key, ticket) if template_key else ""
    append_template_flag = (append_template or "").strip().lower() in {"1", "true", "on", "yes"}
    if template_text:
        if append_template_flag and reply_text:
            reply_text = f"{reply_text}\n\n{template_text}".strip()
        elif not reply_text:
            reply_text = template_text
    if len(reply_text) > 8000:
        return _admin_help_redirect("Admin response is too long (max 8000 characters).", error=True, ticket_id=str(ticket.id))

    now = datetime.utcnow()
    ticket.status = status_value
    ticket.priority = priority_value
    ticket.category = category_value
    ticket.assigned_admin_id = admin_user.id
    ticket.updated_at = now
    ticket.last_admin_update_at = now

    clear_flag = (clear_reply or "").strip().lower() in {"1", "true", "on", "yes"}
    if clear_flag:
        ticket.admin_reply = None
    elif reply_text:
        ticket.admin_reply = encrypt_message(reply_text)

    if status_value in {"resolved", "closed"}:
        ticket.closed_at = now
    else:
        ticket.closed_at = None

    requester_name = ticket.requester.username if ticket.requester else "(unknown)"
    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.support_ticket_updated",
        details=(
            f"Updated support ticket {_support_ticket_ref(ticket)} for '{requester_name}' "
            f"(status={status_value}, priority={priority_value}, category={category_value})."
        ),
        request=request,
    )
    if ticket.requester:
        add_audit_log(
            db,
            user=ticket.requester,
            event_type="support.ticket_updated_by_admin",
            details=f"Support ticket {_support_ticket_ref(ticket)} updated to status '{status_value}'.",
            request=request,
        )
    db.commit()
    return _admin_help_redirect("Ticket updated.", ticket_id=str(ticket.id))


@router.post("/admin/help/{ticket_id}/shortcut")
def admin_help_shortcut_ticket(
    ticket_id: str,
    request: Request,
    action: str = Form(...),
    response_template: str | None = Form(None),
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        tid = uuid.UUID(ticket_id)
    except ValueError:
        return _admin_help_redirect("Invalid ticket id.", error=True)

    ticket = (
        db.query(SupportTicket)
        .options(joinedload(SupportTicket.requester), joinedload(SupportTicket.assigned_admin))
        .filter(SupportTicket.id == tid)
        .first()
    )
    if not ticket:
        return _admin_help_redirect("Ticket not found.", error=True)

    action_key = _normalize_admin_ticket_shortcut(action)
    if not action_key:
        return _admin_help_redirect("Unsupported shortcut action.", error=True, ticket_id=str(ticket.id))

    action_meta = ADMIN_TICKET_SHORTCUTS[action_key]
    status_value = _normalize_ticket_status(str(action_meta.get("status", "")))
    if not status_value:
        return _admin_help_redirect("Shortcut action is missing a valid status target.", error=True, ticket_id=str(ticket.id))

    priority_value = (str(action_meta.get("priority", "")) or ticket.priority or "normal").strip().lower()
    if priority_value not in SUPPORT_TICKET_PRIORITIES:
        priority_value = ticket.priority if ticket.priority in SUPPORT_TICKET_PRIORITIES else "normal"

    now = datetime.utcnow()
    ticket.status = status_value
    ticket.priority = priority_value
    ticket.assigned_admin_id = admin_user.id
    ticket.updated_at = now
    ticket.last_admin_update_at = now
    if status_value in {"resolved", "closed"}:
        ticket.closed_at = now
    else:
        ticket.closed_at = None

    template_key = (response_template or "").strip().lower()
    template_text = _render_admin_ticket_response_template(template_key, ticket) if template_key else ""
    if template_text:
        existing_reply = decrypt_message(ticket.admin_reply or "").strip() if ticket.admin_reply else ""
        merged = f"{existing_reply}\n\n{template_text}".strip() if existing_reply else template_text
        if len(merged) > 8000:
            return _admin_help_redirect(
                "Shortcut response would exceed 8000 characters.",
                error=True,
                ticket_id=str(ticket.id),
            )
        ticket.admin_reply = encrypt_message(merged)

    requester_name = ticket.requester.username if ticket.requester else "(unknown)"
    shortcut_label = str(action_meta.get("label", action_key))
    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.support_ticket_shortcut",
        details=(
            f"Applied shortcut '{action_key}' on support ticket {_support_ticket_ref(ticket)} "
            f"for '{requester_name}' (status={status_value}, priority={priority_value}, "
            f"template={'none' if not template_key else template_key})."
        ),
        request=request,
    )
    if ticket.requester:
        add_audit_log(
            db,
            user=ticket.requester,
            event_type="support.ticket_updated_by_admin",
            details=(
                f"Support ticket {_support_ticket_ref(ticket)} updated via admin shortcut '{shortcut_label}' "
                f"(status={status_value})."
            ),
            request=request,
        )
    db.commit()
    return _admin_help_redirect(f"Shortcut applied: {shortcut_label}.", ticket_id=str(ticket.id))


@router.get("/admin/reports")
def admin_reports_page(
    request: Request,
    status: str = "",
    q: str = "",
    limit: int = 200,
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    status_filter = (status or "").strip().lower()
    text_filter = (q or "").strip().lower()
    limit = max(1, min(limit, 500))

    allowed_statuses = ("open", "reviewing", "resolved", "dismissed")
    if status_filter and status_filter not in allowed_statuses:
        status_filter = ""

    counts = {
        (s or "open"): int(c)
        for s, c in (
            db.query(DirectMessageReport.status, func.count(DirectMessageReport.id))
            .group_by(DirectMessageReport.status)
            .all()
        )
    }
    total_reports = sum(counts.values())

    query = (
        db.query(DirectMessageReport)
        .options(
            joinedload(DirectMessageReport.reporter),
            joinedload(DirectMessageReport.reported_user),
            joinedload(DirectMessageReport.reviewed_by_admin),
            joinedload(DirectMessageReport.message).joinedload(DirectMessage.sender),
            joinedload(DirectMessageReport.message).joinedload(DirectMessage.recipient),
        )
        .order_by(DirectMessageReport.created_at.desc(), DirectMessageReport.id.desc())
    )
    if status_filter:
        query = query.filter(DirectMessageReport.status == status_filter)

    reports = query.limit(limit).all()
    report_thread_ids: set[uuid.UUID] = set()
    for report in reports:
        msg = report.message
        if not msg:
            continue
        body_value = msg.body or ""
        if is_dm_conversation_encrypted(body_value) or (msg.body_key_scheme or "").strip().lower() == DM_BODY_SCHEME_CONVERSATION:
            report_thread_ids.add(msg.thread_id or msg.id)

    report_conversation_keys: dict[uuid.UUID, ConversationKey] = {}
    if report_thread_ids:
        for key_row in db.query(ConversationKey).filter(ConversationKey.thread_id.in_(report_thread_ids)).all():
            report_conversation_keys[key_row.thread_id] = key_row

    rows = []
    for report in reports:
        reporter_name = report.reporter.username if report.reporter else "(unknown)"
        reported_name = report.reported_user.username if report.reported_user else "(unknown)"

        preview = ""
        if report.message:
            msg = report.message
            thread_uuid = msg.thread_id or msg.id
            preview = _decrypt_direct_message_body_with_conversation_key(
                msg,
                report_conversation_keys.get(thread_uuid),
            ).replace("\n", " ").strip()
        if not preview and report.message and report.message.attachment_name:
            preview = "(attachment)"
        if len(preview) > 120:
            preview = f"{preview[:117]}..."

        if text_filter:
            hay = f"{reporter_name} {reported_name} {report.reason or ''} {report.status or ''} {preview}".lower()
            if text_filter not in hay:
                continue

        rows.append(
            {
                "report": report,
                "reporter_username": reporter_name,
                "reported_username": reported_name,
                "message_preview": preview or "-",
                "created_at_display": _format_utc(report.created_at),
            }
        )

    return templates.TemplateResponse(
        "admin_reports.html",
        {
            "request": request,
            "user": admin_user,
            "rows": rows,
            "counts": {
                "total": total_reports,
                "open": counts.get("open", 0),
                "reviewing": counts.get("reviewing", 0),
                "resolved": counts.get("resolved", 0),
                "dismissed": counts.get("dismissed", 0),
            },
            "filters": {
                "status": status_filter,
                "q": (q or "").strip(),
                "limit": limit,
            },
            "allowed_statuses": allowed_statuses,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
            "title": "Admin Reports",
        },
    )


@router.get("/admin/reports/{report_id}")
def admin_report_detail_page(report_id: str, request: Request, db: Session = Depends(get_db)):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        rid = uuid.UUID(report_id)
    except ValueError:
        return _admin_reports_redirect("Invalid report id.", error=True)

    report = (
        db.query(DirectMessageReport)
        .options(
            joinedload(DirectMessageReport.reporter),
            joinedload(DirectMessageReport.reported_user),
            joinedload(DirectMessageReport.reviewed_by_admin),
            joinedload(DirectMessageReport.message).joinedload(DirectMessage.sender),
            joinedload(DirectMessageReport.message).joinedload(DirectMessage.recipient),
        )
        .filter(DirectMessageReport.id == rid)
        .first()
    )
    if not report:
        return _admin_reports_redirect("Report not found.", error=True)

    msg = report.message
    message_conversation_key = None
    if msg:
        thread_uuid = msg.thread_id or msg.id
        message_conversation_key = (
            db.query(ConversationKey)
            .filter(ConversationKey.thread_id == thread_uuid)
            .first()
        )
    message_body = _decrypt_direct_message_body_with_conversation_key(msg, message_conversation_key) if msg else ""
    report_details = decrypt_message(report.details) if report.details else ""
    admin_notes = decrypt_message(report.admin_notes) if report.admin_notes else ""

    allowed_statuses = ("open", "reviewing", "resolved", "dismissed")
    return templates.TemplateResponse(
        "admin_report_detail.html",
        {
            "request": request,
            "user": admin_user,
            "report": report,
            "message": msg,
            "message_body": message_body,
            "report_details": report_details,
            "admin_notes": admin_notes,
            "allowed_statuses": allowed_statuses,
            "report_created_at_display": _format_utc(report.created_at),
            "message_created_at_display": _format_utc(msg.created_at) if msg else "-",
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
            "title": "Report detail",
        },
    )


@router.post("/admin/reports/{report_id}/status")
def admin_report_update_status(
    report_id: str,
    request: Request,
    status: str = Form(...),
    admin_notes: str = Form(""),
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        rid = uuid.UUID(report_id)
    except ValueError:
        return _admin_reports_redirect("Invalid report id.", error=True)

    report = db.query(DirectMessageReport).filter(DirectMessageReport.id == rid).first()
    if not report:
        return _admin_reports_redirect("Report not found.", error=True)

    normalized_status = (status or "").strip().lower()
    allowed_statuses = {"open", "reviewing", "resolved", "dismissed"}
    if normalized_status not in allowed_statuses:
        return _admin_reports_redirect("Invalid status.", error=True, report_id=str(report.id))

    notes = (admin_notes or "").strip()
    report.status = normalized_status
    report.admin_notes = encrypt_message(notes) if notes else None
    report.reviewed_by_admin_id = admin_user.id
    report.reviewed_at = datetime.utcnow()
    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.dm_report_status_updated",
        details=f"Updated DM report {report.id} status to '{normalized_status}'.",
        request=request,
    )
    db.commit()
    return _admin_reports_redirect("Report updated.", report_id=str(report.id))


@router.post("/admin/reports/{report_id}/action")
def admin_report_action(
    report_id: str,
    request: Request,
    action: str = Form(...),
    note: str = Form(""),
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)

    try:
        rid = uuid.UUID(report_id)
    except ValueError:
        return _admin_reports_redirect("Invalid report id.", error=True)

    report = (
        db.query(DirectMessageReport)
        .options(joinedload(DirectMessageReport.reported_user))
        .filter(DirectMessageReport.id == rid)
        .first()
    )
    if not report or not report.reported_user:
        return _admin_reports_redirect("Report not found.", error=True)

    target = report.reported_user
    action_key = (action or "").strip().lower()
    note_value = (note or "").strip()
    target_is_superadmin = bool(getattr(target, "is_superadmin", False))

    if action_key == "disable_account" and target_is_superadmin:
        add_audit_log(
            db,
            user=admin_user,
            event_type="admin.dm_report_action_blocked_superadmin",
            details=f"Blocked action '{action_key}' against superadmin '{target.username}' for DM report {report.id}.",
            request=request,
        )
        db.commit()
        return _admin_reports_redirect("Superadmin accounts cannot be disabled by administrators.", error=True, report_id=str(report.id))

    if report.status == "open":
        report.status = "reviewing"
    report.reviewed_by_admin_id = admin_user.id
    report.reviewed_at = datetime.utcnow()
    report.action_taken = action_key
    report.action_at = datetime.utcnow()

    if action_key == "warn":
        warning = note_value or "Administrator warning: your direct messaging activity has been reported."
        add_event(db, target, action="admin", message=warning, level="WARN")
        add_audit_log(
            db,
            user=target,
            event_type="account.warning_by_admin",
            details=f"Admin '{admin_user.username}' issued a warning. {warning}",
            request=request,
        )
    elif action_key == "restrict_messaging":
        if not target.messaging_disabled:
            target.messaging_disabled = True
            target.messaging_disabled_at = datetime.utcnow()
        add_audit_log(
            db,
            user=target,
            event_type="account.messaging_disabled_by_admin",
            details=f"Admin '{admin_user.username}' disabled direct messaging.",
            request=request,
        )
    elif action_key == "unrestrict_messaging":
        if target.messaging_disabled:
            target.messaging_disabled = False
            target.messaging_disabled_at = None
        add_audit_log(
            db,
            user=target,
            event_type="account.messaging_enabled_by_admin",
            details=f"Admin '{admin_user.username}' re-enabled direct messaging.",
            request=request,
        )
    elif action_key == "disable_account":
        if not target.is_disabled:
            target.is_disabled = True
            target.disabled_at = datetime.utcnow()
            target.disabled_reason = note_value or f"Disabled by admin '{admin_user.username}' (DM report {report.id})."
        revoked = (
            db.query(SessionModel)
            .filter(SessionModel.user_id == target.id, SessionModel.is_active.is_(True))
            .update({SessionModel.is_active: False}, synchronize_session=False)
        )
        add_audit_log(
            db,
            user=target,
            event_type="account.disabled_by_admin",
            details=f"Admin '{admin_user.username}' disabled the account and revoked {revoked} session(s).",
            request=request,
        )
    elif action_key == "enable_account":
        if target.is_disabled:
            target.is_disabled = False
            target.disabled_at = None
            target.disabled_reason = None
        add_audit_log(
            db,
            user=target,
            event_type="account.enabled_by_admin",
            details=f"Admin '{admin_user.username}' re-enabled the account.",
            request=request,
        )
    elif action_key == "revoke_sessions":
        revoked = (
            db.query(SessionModel)
            .filter(SessionModel.user_id == target.id, SessionModel.is_active.is_(True))
            .update({SessionModel.is_active: False}, synchronize_session=False)
        )
        add_audit_log(
            db,
            user=target,
            event_type="account.sessions_revoked_by_admin",
            details=f"Admin '{admin_user.username}' revoked {revoked} active session(s).",
            request=request,
        )
    else:
        return _admin_reports_redirect("Unknown action.", error=True, report_id=str(report.id))

    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.dm_report_action",
        details=f"Applied action '{action_key}' to user '{target.username}' for DM report {report.id}.",
        request=request,
    )
    db.commit()
    return _admin_reports_redirect("Action applied.", report_id=str(report.id))


@router.post("/admin/users/{user_id}/revoke-sessions")
def admin_revoke_sessions(
    user_id: str,
    request: Request,
    redirect_to: str = Form("security"),
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)
    redirect_target = _normalize_admin_redirect_target(redirect_to)

    try:
        target_id = uuid.UUID(user_id)
    except ValueError:
        return _admin_redirect_with_target("Invalid user identifier.", error=True, target=redirect_target)

    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        return _admin_redirect_with_target("User not found.", error=True, target=redirect_target)

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
    return _admin_redirect_with_target(
        f"Revoked {revoked} active session(s) for '{target.username}'.",
        target=redirect_target,
    )


@router.post("/admin/users/{user_id}/reset-totp")
def admin_reset_totp(
    user_id: str,
    request: Request,
    redirect_to: str = Form("security"),
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)
    redirect_target = _normalize_admin_redirect_target(redirect_to)

    try:
        target_id = uuid.UUID(user_id)
    except ValueError:
        return _admin_redirect_with_target("Invalid user identifier.", error=True, target=redirect_target)

    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        return _admin_redirect_with_target("User not found.", error=True, target=redirect_target)

    target.totp_enabled = False
    target.totp_secret_enc = None
    target.email_mfa_enabled = False
    target.sms_mfa_enabled = False
    target.mfa_preferred_method = None
    _clear_mfa_challenge(target)
    add_event(
        db,
        admin_user,
        action="admin",
        message=f"Reset all MFA methods for '{target.username}'.",
        level="WARN",
    )
    add_audit_log(
        db,
        user=target,
        event_type="mfa.reset_by_admin",
        details=f"Admin '{admin_user.username}' reset all MFA methods.",
        request=request,
    )
    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.mfa_reset",
        details=f"Reset all MFA methods for '{target.username}'.",
        request=request,
    )
    db.commit()
    return _admin_redirect_with_target(
        f"All MFA methods reset for '{target.username}'.",
        target=redirect_target,
    )


@router.post("/admin/users/{user_id}/reset-password")
def admin_reset_password(
    user_id: str,
    request: Request,
    password: str = Form(...),
    confirm_password: str = Form(...),
    redirect_to: str = Form("security"),
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)
    redirect_target = _normalize_admin_redirect_target(redirect_to)

    try:
        target_id = uuid.UUID(user_id)
    except ValueError:
        return _admin_redirect_with_target("Invalid user identifier.", error=True, target=redirect_target)

    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        return _admin_redirect_with_target("User not found.", error=True, target=redirect_target)

    if password != confirm_password:
        return _admin_redirect_with_target("Passwords did not match.", error=True, target=redirect_target)

    if len(password) < 10:
        return _admin_redirect_with_target(
            "Password must be at least 10 characters.",
            error=True,
            target=redirect_target,
        )

    target.password_hash = hash_password(password)
    revoked = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == target.id, SessionModel.is_active.is_(True))
        .update({SessionModel.is_active: False}, synchronize_session=False)
    )
    add_event(
        db,
        admin_user,
        action="admin",
        message=f"Reset password for '{target.username}' (revoked {revoked} session(s)).",
        level="WARN",
    )
    add_audit_log(
        db,
        user=target,
        event_type="account.password_reset_by_admin",
        details=f"Admin '{admin_user.username}' reset the account password and revoked {revoked} active session(s).",
        request=request,
    )
    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.password_reset",
        details=f"Reset password for '{target.username}' and revoked {revoked} active session(s).",
        request=request,
    )
    db.commit()
    return _admin_redirect_with_target(
        f"Password reset for '{target.username}'.",
        target=redirect_target,
    )


@router.post("/admin/users/{user_id}/toggle-admin")
def admin_toggle_role(
    user_id: str,
    request: Request,
    redirect_to: str = Form("security"),
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)
    redirect_target = _normalize_admin_redirect_target(redirect_to)

    try:
        target_id = uuid.UUID(user_id)
    except ValueError:
        return _admin_redirect_with_target("Invalid user identifier.", error=True, target=redirect_target)

    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        return _admin_redirect_with_target("User not found.", error=True, target=redirect_target)

    if getattr(target, "is_superadmin", False):
        add_audit_log(
            db,
            user=admin_user,
            event_type="admin.role_admin_change_blocked_superadmin",
            details=f"Blocked administrator role change for superadmin '{target.username}'.",
            request=request,
        )
        db.commit()
        return _admin_redirect_with_target(
            "Superadmin role cannot be changed by administrators.",
            error=True,
            target=redirect_target,
        )

    if target.is_admin:
        admin_count = db.query(func.count(User.id)).filter(User.is_admin.is_(True)).scalar() or 0
        if admin_count <= 1:
            return _admin_redirect_with_target(
                "Cannot remove the last system administrator.",
                error=True,
                target=redirect_target,
            )

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
    return _admin_redirect_with_target(
        f"Administrator role {status_label} for '{target.username}'.",
        target=redirect_target,
    )


@router.post("/admin/users/promote-self-superadmin")
def admin_promote_self_superadmin(
    request: Request,
    redirect_to: str = Form("security"),
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)
    redirect_target = _normalize_admin_redirect_target(redirect_to)

    if getattr(admin_user, "is_superadmin", False):
        return _admin_redirect_with_target("Your account is already a superadmin.", target=redirect_target)

    superadmin_count = db.query(func.count(User.id)).filter(User.is_superadmin.is_(True)).scalar() or 0
    if superadmin_count > 0:
        return _admin_redirect_with_target(
            "A superadmin already exists. Self-promotion is disabled.",
            error=True,
            target=redirect_target,
        )

    admin_user.is_superadmin = True
    admin_user.is_admin = True
    add_event(
        db,
        admin_user,
        action="admin",
        message="Claimed superadmin role because no superadmin account existed.",
        level="WARN",
    )
    add_audit_log(
        db,
        user=admin_user,
        event_type="account.role_superadmin_claimed",
        details="Claimed superadmin role because no superadmin account existed.",
        request=request,
    )
    add_audit_log(
        db,
        user=admin_user,
        event_type="admin.role_superadmin_claimed",
        details=f"Admin '{admin_user.username}' promoted their own account to superadmin because no superadmin account existed.",
        request=request,
    )
    db.commit()
    return _admin_redirect_with_target(
        "Your account has been promoted to superadmin.",
        target=redirect_target,
    )


@router.get("/admin/users/promote-self-superadmin")
def admin_promote_self_superadmin_get(
    request: Request,
    redirect_to: str = "security",
    db: Session = Depends(get_db),
):
    admin_user = _get_current_user(db, request)
    if not admin_user:
        return RedirectResponse(url="/ui/login", status_code=303)
    if not admin_user.is_admin:
        return RedirectResponse(url="/ui", status_code=303)
    redirect_target = _normalize_admin_redirect_target(redirect_to)

    if getattr(admin_user, "is_superadmin", False):
        return _admin_redirect_with_target("Your account is already a superadmin.", target=redirect_target)

    superadmin_count = db.query(func.count(User.id)).filter(User.is_superadmin.is_(True)).scalar() or 0
    if superadmin_count == 0:
        return _admin_redirect_with_target(
            "Use the Promote button to submit superadmin recovery.",
            target=redirect_target,
        )
    return _admin_redirect_with_target(
        f"Self-promotion is unavailable because {superadmin_count} superadmin account(s) already exist.",
        error=True,
        target=redirect_target,
    )


@router.get("/totp")
@router.get("/mfa")
def totp_setup(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    secret = None
    provisioning_uri = None
    if not user.totp_enabled:
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

    active_methods = _available_mfa_methods(user, transport_ready_only=False)
    preferred_method = _resolve_mfa_method(user, user.mfa_preferred_method, active_methods)

    return templates.TemplateResponse(
        "totp_setup.html",
        {
            "request": request,
            "user": user,
            "enabled": user.totp_enabled,
            "secret": secret,
            "provisioning_uri": provisioning_uri,
            "error": request.query_params.get("error"),
            "notice": request.query_params.get("notice"),
            "smtp_ready": _smtp_configured(),
            "sms_ready": _sms_configured(user),
            "sms_provider_mode": _sms_provider_mode(),
            "sms_provider_label": _sms_provider_label(),
            "sms_carrier_label": SMS_CARRIER_LABELS.get(_normalize_sms_carrier(user.sms_carrier), ""),
            "active_methods": active_methods,
            "preferred_method": preferred_method,
            "email_mfa_enabled": bool(user.email_mfa_enabled),
            "sms_mfa_enabled": bool(user.sms_mfa_enabled),
            "mfa_method_labels": MFA_METHOD_LABELS,
        },
    )


@router.post("/totp/verify")
@router.post("/mfa/verify")
def totp_verify(
    request: Request,
    code: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    if not user.totp_secret_enc:
        return RedirectResponse(url="/ui/mfa", status_code=303)

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
        return RedirectResponse(
            url=f"/ui/mfa?error={quote_plus('Invalid code. Try the current code from your authenticator app.')}",
            status_code=303,
        )

    user.totp_enabled = True
    methods_after_enable = _available_mfa_methods(user, transport_ready_only=False)
    preferred = _resolve_mfa_method(user, user.mfa_preferred_method, methods_after_enable)
    user.mfa_preferred_method = preferred or MFA_METHOD_TOTP
    add_audit_log(
        db,
        user=user,
        event_type="mfa.enabled",
        details="MFA enabled after verification.",
        request=request,
    )
    db.commit()
    return RedirectResponse(url="/ui/mfa", status_code=303)


@router.post("/totp/disable")
@router.post("/mfa/disable")
def totp_disable(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    user.totp_enabled = False
    user.totp_secret_enc = None
    if user.mfa_preferred_method == MFA_METHOD_TOTP:
        methods_now = _available_mfa_methods(user, transport_ready_only=False)
        user.mfa_preferred_method = _resolve_mfa_method(user, user.mfa_preferred_method, methods_now) or None
    add_audit_log(
        db,
        user=user,
        event_type="mfa.disabled",
        details="MFA disabled by user.",
        request=request,
    )
    db.commit()
    return RedirectResponse(url="/ui/mfa", status_code=303)


@router.post("/mfa/challenge/send")
def mfa_send_challenge(
    request: Request,
    method: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    selected = _normalize_mfa_method(method)
    if selected not in {MFA_METHOD_EMAIL, MFA_METHOD_SMS}:
        return RedirectResponse(url=f"/ui/mfa?error={quote_plus('Select email or SMS for challenge delivery.')}", status_code=303)

    available = _available_mfa_methods(user, transport_ready_only=False)
    if selected not in available:
        return RedirectResponse(
            url=f"/ui/mfa?error={quote_plus('That MFA method is not enabled for this account.')}",
            status_code=303,
        )

    try:
        destination = _issue_mfa_challenge(user, selected)
    except HTTPException as exc:
        db.rollback()
        return RedirectResponse(url=f"/ui/mfa?error={quote_plus(str(exc.detail))}", status_code=303)
    except Exception as exc:
        db.rollback()
        logger.warning("MFA send challenge failed (%s) for user %s: %s", selected, user.id, exc)
        return RedirectResponse(url=f"/ui/mfa?error={quote_plus('Challenge could not be sent right now.')}", status_code=303)

    add_audit_log(
        db,
        user=user,
        event_type=f"mfa.challenge_sent_{selected}",
        details=f"User requested MFA challenge via {selected} to {destination}.",
        request=request,
    )
    db.commit()
    return RedirectResponse(
        url=f"/ui/mfa?notice={quote_plus(f'Code sent to {destination}.')}",
        status_code=303,
    )


@router.get("/profile")
def profile_page(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    active_methods = _available_mfa_methods(user, transport_ready_only=False)
    effective_timezone = _resolve_effective_timezone(request, user)

    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "user": user,
            "ui_view_mode": _normalize_ui_view_mode(user.ui_view_mode),
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
            "smtp_ready": _smtp_configured(),
            "sms_ready": _sms_configured(user),
            "sms_provider_mode": _sms_provider_mode(),
            "sms_provider_label": _sms_provider_label(),
            "sms_carrier_label": SMS_CARRIER_LABELS.get(_normalize_sms_carrier(user.sms_carrier), ""),
            "mfa_methods_active": active_methods,
            "mfa_method_preferred": _resolve_mfa_method(user, user.mfa_preferred_method, active_methods),
            "mfa_method_labels": MFA_METHOD_LABELS,
            "sms_carrier_options": _sms_carrier_rows(),
            "timezone_options": _profile_timezone_rows(),
            "effective_timezone": effective_timezone,
        },
    )


@router.get("/profile/avatar")
def profile_avatar(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    if not user.profile_image_path:
        raise HTTPException(status_code=404, detail="Avatar not configured")

    path = _safe_profile_asset_path(user.profile_image_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Avatar missing on disk")

    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    if not user.profile_image_nonce or not user.profile_image_tag:
        return FileResponse(
            path=path,
            media_type=user.profile_image_mime_type or "application/octet-stream",
            headers=headers,
        )

    ensure_user_key(db, user)
    dek = get_user_dek(db, user)
    return StreamingResponse(
        decrypt_file_iter(dek, path, user.profile_image_nonce, user.profile_image_tag),
        media_type=user.profile_image_mime_type or "application/octet-stream",
        headers=headers,
    )


@router.post("/profile/avatar")
def profile_update_avatar(
    request: Request,
    avatar: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    filename = Path((avatar.filename or "").strip()).name
    if not filename:
        return _profile_redirect("Select an image file first.", error=True)

    mime_type = (avatar.content_type or "").strip().lower()
    if mime_type not in PROFILE_IMAGE_MIME_ALLOW:
        return _profile_redirect("Only PNG, JPEG, WEBP, and GIF images are supported.", error=True)

    ensure_user_key(db, user)
    dek = get_user_dek(db, user)
    avatar_root = _profile_avatar_root(user)
    target = avatar_root / "avatar.enc"

    nonce_b64, tag_b64, plain_size = encrypt_file_to_path(dek, avatar.file, target)
    if plain_size > PROFILE_AVATAR_MAX_BYTES:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        return _profile_redirect("Avatar is too large (max 4 MB).", error=True)

    old_path = user.profile_image_path
    user.profile_image_path = str(target)
    user.profile_image_nonce = nonce_b64
    user.profile_image_tag = tag_b64
    user.profile_image_mime_type = mime_type
    add_audit_log(
        db,
        user=user,
        event_type="account.profile_avatar_updated",
        details=f"Updated profile avatar ({plain_size} bytes, {mime_type}).",
        request=request,
    )
    db.commit()

    if old_path and old_path != str(target):
        try:
            _safe_profile_asset_path(old_path).unlink(missing_ok=True)
        except Exception:
            logger.warning("Could not remove stale avatar path for user %s", user.id)

    return _profile_redirect("Profile picture updated.")


@router.post("/profile/avatar/remove")
def profile_remove_avatar(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    old_path = user.profile_image_path
    user.profile_image_path = None
    user.profile_image_nonce = None
    user.profile_image_tag = None
    user.profile_image_mime_type = None
    add_audit_log(
        db,
        user=user,
        event_type="account.profile_avatar_removed",
        details="Removed profile avatar.",
        request=request,
    )
    db.commit()

    if old_path:
        try:
            _safe_profile_asset_path(old_path).unlink(missing_ok=True)
        except Exception:
            logger.warning("Could not remove avatar file for user %s", user.id)

    return _profile_redirect("Profile picture removed.")


@router.post("/profile/view-mode")
def profile_update_view_mode(
    request: Request,
    advanced_view: str | None = Form(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    wants_advanced_view = (advanced_view or "").strip().lower() in {"1", "true", "on", "yes"}
    requested_ui_mode = UI_VIEW_ADVANCED if wants_advanced_view else UI_VIEW_BASE
    current_ui_mode = _normalize_ui_view_mode(user.ui_view_mode)
    if current_ui_mode == requested_ui_mode and (user.ui_view_mode or "") == requested_ui_mode:
        return _profile_redirect("View mode is already set.")

    user.ui_view_mode = requested_ui_mode
    add_audit_log(
        db,
        user=user,
        event_type="account.profile_view_mode_updated",
        details=f"Updated interface view mode to {requested_ui_mode}.",
        request=request,
    )
    db.commit()
    label = "Advanced" if requested_ui_mode == UI_VIEW_ADVANCED else "Base"
    return _profile_redirect(f"View mode updated to {label}.")


@router.get("/profile/view-mode")
def profile_view_mode_redirect(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)
    return RedirectResponse(url="/ui/profile", status_code=303)


@router.post("/profile/preferences")
def profile_update_preferences(
    request: Request,
    email: str = Form(""),
    email_visible: str | None = Form(None),
    phone_number: str = Form(""),
    sms_carrier: str = Form(""),
    timezone: str = Form(""),
    email_mfa_enabled: str | None = Form(None),
    sms_mfa_enabled: str | None = Form(None),
    mfa_method: str | None = Form(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    try:
        normalized_email = _normalize_email(email)
        normalized_phone = _normalize_phone(phone_number)
        normalized_sms_carrier = _normalize_sms_carrier(sms_carrier)
    except HTTPException as exc:
        return _profile_redirect(str(exc.detail), error=True)

    normalized_timezone = normalize_timezone(timezone)
    if (timezone or "").strip() and not normalized_timezone:
        return _profile_redirect("Select a valid IANA timezone.", error=True)

    if (sms_carrier or "").strip() and not normalized_sms_carrier:
        return _profile_redirect("Select a supported SMS carrier.", error=True)

    wants_email_visible = (email_visible or "").strip().lower() in {"1", "true", "on", "yes"}
    wants_email_mfa = (email_mfa_enabled or "").strip().lower() in {"1", "true", "on", "yes"}
    wants_sms_mfa = (sms_mfa_enabled or "").strip().lower() in {"1", "true", "on", "yes"}
    requested_method = _normalize_mfa_method(mfa_method)

    if wants_email_visible and not normalized_email:
        return _profile_redirect("Add an email before enabling visibility.", error=True)
    if wants_email_visible and not user.email_verified and normalized_email == (user.email or ""):
        return _profile_redirect("Verify your email before making it visible to other users.", error=True)
    if wants_email_mfa and not normalized_email:
        return _profile_redirect("Add an email before enabling email MFA.", error=True)
    if wants_email_mfa and not (user.email_verified and normalized_email == (user.email or "")):
        return _profile_redirect("Verify your email before enabling email MFA.", error=True)
    if wants_email_mfa and not _smtp_configured():
        return _profile_redirect("Email MFA is unavailable until SMTP is configured on the server.", error=True)
    if wants_sms_mfa:
        sms_error = _sms_configuration_error_for_values(
            phone_number=normalized_phone,
            sms_carrier=normalized_sms_carrier,
        )
        if sms_error:
            return _profile_redirect(sms_error, error=True)

    changed = False
    if normalized_email != (user.email or ""):
        user.email = normalized_email or None
        user.email_verified = False if normalized_email else False
        user.email_verification_token_hash = None
        user.email_verification_sent_at = None
        user.email_verification_expires_at = None
        if user.email_mfa_enabled:
            user.email_mfa_enabled = False
        changed = True

    target_visible = wants_email_visible and bool(user.email_verified and (user.email or ""))
    if user.email_visible != target_visible:
        user.email_visible = target_visible
        changed = True

    if normalized_phone != (user.phone_number or ""):
        user.phone_number = normalized_phone or None
        if not user.phone_number and user.sms_mfa_enabled:
            user.sms_mfa_enabled = False
        changed = True

    if normalized_sms_carrier != (user.sms_carrier or ""):
        user.sms_carrier = normalized_sms_carrier or None
        changed = True

    existing_timezone = normalize_timezone(user.timezone)
    existing_timezone_raw = (user.timezone or "").strip() or None
    target_timezone = normalized_timezone or None
    if existing_timezone != target_timezone or existing_timezone_raw != target_timezone:
        user.timezone = target_timezone
        _set_active_timezone(request, user)
        changed = True

    email_mfa_effective = wants_email_mfa and bool(user.email and user.email_verified and _smtp_configured())
    if user.email_mfa_enabled != email_mfa_effective:
        user.email_mfa_enabled = email_mfa_effective
        changed = True

    sms_enabled_effective = wants_sms_mfa and _sms_configured(user)
    if user.sms_mfa_enabled != sms_enabled_effective:
        user.sms_mfa_enabled = sms_enabled_effective
        changed = True

    methods_now = _available_mfa_methods(user, transport_ready_only=False)
    resolved_preferred = _resolve_mfa_method(user, requested_method, methods_now)
    if user.mfa_preferred_method != (resolved_preferred or None):
        user.mfa_preferred_method = resolved_preferred or None
        changed = True

    if user.mfa_challenge_method and user.mfa_challenge_method not in methods_now:
        _clear_mfa_challenge(user)
        changed = True

    if not changed:
        return _profile_redirect("No profile preference changes were detected.")

    add_audit_log(
        db,
        user=user,
        event_type="account.profile_preferences_updated",
        details=(
            f"Updated profile preferences (email={'set' if user.email else 'unset'}, "
            f"email_visible={'on' if user.email_visible else 'off'}, "
            f"phone={'set' if user.phone_number else 'unset'}, "
            f"sms_carrier={user.sms_carrier or 'unset'}, "
            f"timezone={normalize_timezone(user.timezone) or 'auto'}, "
            f"email_mfa={'on' if user.email_mfa_enabled else 'off'}, "
            f"sms_mfa={'on' if user.sms_mfa_enabled else 'off'})."
        ),
        request=request,
    )
    db.commit()

    note = "Profile preferences updated."
    if wants_email_visible and not user.email_visible:
        note = "Profile preferences updated. Email visibility remains off until verification."
    if wants_email_mfa and not user.email_mfa_enabled:
        note = "Profile preferences updated. Email MFA remains off until email is verified and SMTP is configured."
    if wants_sms_mfa and not user.sms_mfa_enabled:
        note = "Profile preferences updated. SMS MFA stays off until phone, carrier, and SMS transport are configured."
    return _profile_redirect(note)


@router.post("/profile/email/send-verification")
def profile_send_email_verification(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    if not user.email:
        return _profile_redirect("Add an email address first.", error=True)

    token = secrets.token_urlsafe(32)
    token_hash = _email_token_hash(token)
    now = datetime.utcnow()
    expires_at = now + timedelta(minutes=EMAIL_VERIFY_TTL_MINUTES)

    user.email_verification_token_hash = token_hash
    user.email_verification_sent_at = now
    user.email_verification_expires_at = expires_at

    verify_link = (
        f"{_public_origin(request)}/ui/profile/email/verify?token={quote_plus(token)}"
    )
    subject = "Verify your FileFort email"
    body = (
        f"Hello {user.username},\n\n"
        "Use the link below to verify this email for your FileFort account.\n\n"
        f"{verify_link}\n\n"
        f"This link expires in {EMAIL_VERIFY_TTL_MINUTES} minutes."
    )

    if _smtp_configured():
        message = EmailMessage()
        message["From"] = settings.smtp_from
        message["To"] = user.email
        message["Subject"] = subject
        message.set_content(body)
        try:
            _send_email_message(message)
        except Exception as exc:
            db.rollback()
            logger.warning("Email verification send failed for user %s: %s", user.id, exc)
            return _profile_redirect(
                "Verification email could not be sent. Check SMTP settings and retry.",
                error=True,
            )
        add_audit_log(
            db,
            user=user,
            event_type="account.email_verification_sent",
            details=f"Verification email sent to '{user.email}'.",
            request=request,
        )
        db.commit()
        return _profile_redirect("Verification email sent.")

    add_audit_log(
        db,
        user=user,
        event_type="account.email_verification_link_generated",
        details="SMTP not configured; verification link generated in-browser.",
        request=request,
    )
    db.commit()
    return _profile_redirect(f"SMTP is not configured yet. Open this verification link: {verify_link}")


@router.get("/profile/email/verify")
def profile_verify_email(
    request: Request,
    token: str = "",
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    value = (token or "").strip()
    if not value:
        return _profile_redirect("Verification token is missing.", error=True)

    token_hash = _email_token_hash(value)
    if user.email_verification_token_hash != token_hash:
        add_audit_log(
            db,
            user=user,
            event_type="account.email_verification_failed",
            details="Email verification failed (token mismatch).",
            request=request,
        )
        db.commit()
        return _profile_redirect("Invalid verification token.", error=True)

    if not user.email_verification_expires_at or user.email_verification_expires_at < datetime.utcnow():
        return _profile_redirect("Verification token expired. Send a new verification email.", error=True)

    user.email_verified = True
    user.email_verification_token_hash = None
    user.email_verification_sent_at = None
    user.email_verification_expires_at = None
    add_audit_log(
        db,
        user=user,
        event_type="account.email_verified",
        details=f"Email '{user.email}' verified.",
        request=request,
    )
    db.commit()
    return _profile_redirect("Email verified.")


@router.post("/profile/username")
def profile_update_username(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    mfa_code: str | None = Form(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    new_username = (username or "").strip()
    if not new_username:
        return RedirectResponse(url=f"/ui/profile?error={quote_plus('Username is required.')}", status_code=303)
    if new_username == user.username:
        return RedirectResponse(url=f"/ui/profile?notice={quote_plus('Username unchanged.')}", status_code=303)

    if not verify_password(password or "", user.password_hash):
        add_audit_log(
            db,
            user=user,
            event_type="account.username_change_failed_password",
            details="Username change blocked: password verification failed.",
            request=request,
        )
        db.commit()
        return RedirectResponse(url=f"/ui/profile?error={quote_plus('Current password was incorrect.')}", status_code=303)

    if user.totp_enabled:
        code = (mfa_code or "").strip()
        if not code:
            return RedirectResponse(url=f"/ui/profile?error={quote_plus('MFA code is required.')}", status_code=303)
        secret = decrypt_totp_secret(user.totp_secret_enc or "")
        if not pyotp.TOTP(secret).verify(code):
            add_audit_log(
                db,
                user=user,
                event_type="account.username_change_failed_mfa",
                details="Username change blocked: MFA verification failed.",
                request=request,
            )
            db.commit()
            return RedirectResponse(url=f"/ui/profile?error={quote_plus('Invalid MFA code.')}", status_code=303)

    existing = db.query(User).filter(User.username == new_username).first()
    if existing:
        return RedirectResponse(url=f"/ui/profile?error={quote_plus('Username is already taken.')}", status_code=303)

    old_username = user.username
    user.username = new_username
    add_event(
        db,
        user,
        action="auth",
        message=f"Username changed: '{old_username}' -> '{new_username}'.",
        level="SUCCESS",
    )
    add_audit_log(
        db,
        user=user,
        event_type="account.username_changed",
        details=f"Username changed from '{old_username}' to '{new_username}'.",
        request=request,
    )
    db.commit()
    return RedirectResponse(url=f"/ui/profile?notice={quote_plus('Username updated.')}", status_code=303)


@router.post("/profile/password")
def profile_update_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    mfa_code: str | None = Form(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    if not verify_password(current_password or "", user.password_hash):
        add_audit_log(
            db,
            user=user,
            event_type="account.password_change_failed_password",
            details="Password change blocked: current password verification failed.",
            request=request,
        )
        db.commit()
        return RedirectResponse(url=f"/ui/profile?error={quote_plus('Current password was incorrect.')}", status_code=303)

    if new_password != confirm_password:
        return RedirectResponse(url=f"/ui/profile?error={quote_plus('New passwords did not match.')}", status_code=303)

    if len(new_password or "") < 10:
        return RedirectResponse(url=f"/ui/profile?error={quote_plus('New password must be at least 10 characters.')}", status_code=303)

    if user.totp_enabled:
        code = (mfa_code or "").strip()
        if not code:
            return RedirectResponse(url=f"/ui/profile?error={quote_plus('MFA code is required.')}", status_code=303)
        secret = decrypt_totp_secret(user.totp_secret_enc or "")
        if not pyotp.TOTP(secret).verify(code):
            add_audit_log(
                db,
                user=user,
                event_type="account.password_change_failed_mfa",
                details="Password change blocked: MFA verification failed.",
                request=request,
            )
            db.commit()
            return RedirectResponse(url=f"/ui/profile?error={quote_plus('Invalid MFA code.')}", status_code=303)

    session_id = _get_session_id(request)
    user.password_hash = hash_password(new_password)
    revoked = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == user.id, SessionModel.is_active.is_(True))
        .update({SessionModel.is_active: False}, synchronize_session=False)
    )
    add_event(
        db,
        user,
        action="auth",
        message=f"Password updated (revoked {revoked} session(s)).",
        level="WARN",
    )
    add_audit_log(
        db,
        user=user,
        event_type="account.password_changed",
        details=f"Password changed; revoked {revoked} active session(s).",
        request=request,
    )
    db.commit()

    # Re-issue a session so the user stays signed in after the revoke.
    session = create_session(db, user)
    response = RedirectResponse(url=f"/ui/profile?notice={quote_plus('Password updated.')}", status_code=303)
    _set_session_cookie(response, request, session.id)
    return response


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


@router.get("/preview-frame/{file_token}")
def preview_file_frame(file_token: str, request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    record = _get_user_file_by_token(db, user, request, file_token)
    resolved = _resolve_user_file_path(user, record.file_path)
    if not resolved.exists():
        raise HTTPException(status_code=404, detail="File missing on disk")

    mime_type = (record.mime_type or mimetypes.guess_type(record.file_name)[0] or "application/octet-stream").lower()
    ext = Path(record.file_name or "").suffix.lower()
    theme = (request.query_params.get("theme") or "").strip().lower()
    if theme not in {"light", "dark"}:
        theme = "light"

    return templates.TemplateResponse(
        "preview_frame.html",
        {
            "request": request,
            "title": f"Preview {record.file_name}",
            "raw_url": f"/ui/preview/{file_token}?v={int(datetime.utcnow().timestamp())}",
            "file_name": record.file_name,
            "mime_type": mime_type,
            "file_ext": ext,
            "theme": theme,
        },
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
    page_context: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not _is_advanced_view_enabled(user):
        raise HTTPException(status_code=403, detail="Terminal is available only in advanced view.")

    cmd, args = _parse_terminal_command(command)
    if cmd == "help":
        help_mode = (args[0] if args else "").strip().lower()
        if len(args) > 1 or (args and help_mode not in {"verbose", "-v", "--verbose"}):
            raise HTTPException(status_code=400, detail="Usage: help [verbose]")

        if help_mode in {"verbose", "-v", "--verbose"}:
            message = (
                "Commands (verbose)\n"
                "\n"
                "  help [verbose]\n"
                "    Show command list. Use 'help verbose' for detailed explanations.\n"
                "  clear\n"
                "    Clear terminal output in the UI.\n"
                "  pwd\n"
                "    Show active logical root path for current scope.\n"
                "  scope\n"
                "    Show whether you are in user scope or group scope.\n"
                "  groups\n"
                "    List your group memberships and roles.\n"
                "  usegroup <group_id|group_name>\n"
                "    Switch scope to a specific group you belong to.\n"
                "  useuser\n"
                "    Switch scope back to your personal vault.\n"
                "  list [folder]\n"
                "    List folder entries in active scope (alias: ls).\n"
                "  tree [folder] [depth]\n"
                "    Show a tree view up to depth 1..6 (default 2).\n"
                "  find <pattern> [folder]\n"
                "    Search names recursively for matching files/folders.\n"
                "  stat <path>\n"
                "    Show metadata for file/folder (size, type, modified time).\n"
                "  view <file> [lines]\n"
                "    Show text preview (default 40 lines; max 200).\n"
                "  hash <file>\n"
                "    Compute SHA-256 hash of ciphertext file bytes at rest.\n"
                "  quota [folder]\n"
                "    Summarize folder usage (files, dirs, total bytes).\n"
                "  encstatus\n"
                "    Show encryption/key health for user and joined groups.\n"
                "  encproof file <file>\n"
                "    Demonstrate at-rest encryption and decrypted preview for one text file.\n"
                "  encproof dir <directory>\n"
                "    Run proof checks for all files under a directory in the active scope.\n"
                "  encproof user\n"
                "    Run proof checks for all files owned by your account.\n"
                "  enctimeline [limit]\n"
                "    Show per-item encryption status and timestamps for messages + filesystem entries.\n"
                "    limit: max rows to scan from current scope (default 80, max 200).\n"
                "  encrotate [all|files|messages|groups]\n"
                "    Rotate encryption materials.\n"
                "    files: rotate your user DEK and re-encrypt personal files.\n"
                "    messages: re-encrypt message payloads and attachment ciphertexts.\n"
                "    groups: rotate group DEKs only where you are owner/admin.\n"
                "    all: run files + messages + groups.\n"
                "  gfiles [pattern]\n"
                "    List group file records in current group scope.\n"
                "  gdownload <file_id>\n"
                "    Return direct group download URL for a group file id.\n"
                "  move <src> <dst>\n"
                "    Move file/folder path (alias: mv). User scope only.\n"
                "  copy <src> <dst>\n"
                "    Copy file/folder path (alias: cp). User scope only.\n"
                "  rename <src> <dst>\n"
                "    Rename/move path. User scope only.\n"
                "  directory <path>\n"
                "    Create directory (alias: mkdir). User scope only.\n"
                "\n"
                "Notes:\n"
                "  Paths are relative to active scope.\n"
                "  Use usegroup/useuser to switch scope roots.\n"
                "  Aliases: ls, mv, cp, mkdir, cat, sha256, du, encryption, cryptostatus, keys, timeline, enctrace, rotate, rekey."
            )
        else:
            message = (
                "Commands:\n"
                "  help [verbose]\n"
                "  clear\n"
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
                "  encproof file <file>\n"
                "  encproof dir <directory>\n"
                "  encproof user\n"
                "  enctimeline [limit]\n"
                "  encrotate [all|files|messages|groups]\n"
                "  gfiles [pattern]\n"
                "  gdownload <file_id>\n"
                "  move <src> <dst>\n"
                "  copy <src> <dst>\n"
                "  rename <src> <dst>\n"
                "  directory <path>\n"
                "Paths are relative to the active scope. Use usegroup/useuser to switch.\n"
                "Tip: run 'help verbose' for command-by-command details."
            )
        add_event(db, user, action="terminal", message=f"help {'verbose' if help_mode else ''}\n{message}".rstrip())
        return {"ok": True, "message": message}

    if cmd == "clear":
        # UI may handle this client-side, but keep it supported for API consistency.
        message = "Cleared terminal output."
        add_event(db, user, action="terminal", message="clear")
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
            lines = ["Group files (id, name, size, uploaded):"]
            for r in rows:
                uploaded = _format_utc(r.uploaded_at) if r.uploaded_at else "-"
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
        if not safe_args:
            raise HTTPException(
                status_code=400,
                detail="Usage: encproof file <file> | encproof dir <directory> | encproof user",
            )

        requested_mode = safe_args[0].strip().lower()
        mode_args = safe_args[1:]
        if requested_mode in {"file", "dir", "user"}:
            mode = requested_mode
        else:
            # Backward compatibility: treat "encproof <path>" as file mode.
            mode = "file"
            mode_args = safe_args

        proof_kind = "group" if scope.get("type") == "group" and scope.get("group_id") and mode != "user" else "user"
        proof_root = root if proof_kind == "group" else _user_root(user).resolve()
        proof_scope_label = scope_label if proof_kind == "group" else "user"

        proof_group_id: uuid.UUID | None = None
        proof_group_dek: bytes | None = None
        proof_user_dek: bytes | None = None
        if proof_kind == "group":
            try:
                proof_group_id = uuid.UUID(scope["group_id"] or "")
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid group scope")

            membership = (
                db.query(GroupMembership.role)
                .filter(GroupMembership.group_id == proof_group_id, GroupMembership.user_id == user.id)
                .first()
            )
            if not membership:
                raise HTTPException(status_code=403, detail="Not a member of this group")

            group = db.query(Group).filter(Group.id == proof_group_id).first()
            if not group:
                raise HTTPException(status_code=404, detail="Group not found")

            ensure_group_key(db, group)
            proof_group_dek = get_group_dek(db, group)
        else:
            proof_user_dek = get_user_dek(db, user)

        def _is_text_like_file(path: Path) -> bool:
            suffix = path.suffix.lower()
            if suffix in _TERMINAL_TEXT_EXTS:
                return True
            mime_type, _ = mimetypes.guess_type(path.name)
            return (mime_type or "").startswith("text/")

        def _collect_file_proof(
            path: Path,
            logical_target: str,
            *,
            require_text_preview: bool,
        ) -> dict[str, object]:
            resolved_path = path.resolve()
            _ensure_no_symlink(resolved_path, proof_root)
            if not resolved_path.exists() or not resolved_path.is_file():
                raise HTTPException(status_code=400, detail="File not found")
            if require_text_preview and not _is_text_like_file(resolved_path):
                raise HTTPException(status_code=400, detail="encproof file supports text files only (.txt/.md/etc)")

            meta_lines: list[str] = []
            meta_lines.append(f"Scope: {proof_scope_label}")
            meta_lines.append(f"Path: {logical_target}")
            meta_lines.append(f"Ciphertext size on disk: {resolved_path.stat().st_size} bytes")

            decrypt_iter = None
            record_label = ""
            if proof_kind == "group":
                if proof_group_id is None or proof_group_dek is None:
                    raise HTTPException(status_code=500, detail="Group proof context missing")
                record = (
                    db.query(GroupFileRecord)
                    .filter(
                        GroupFileRecord.group_id == proof_group_id,
                        GroupFileRecord.file_path == str(resolved_path),
                    )
                    .first()
                )
                if not record:
                    raise HTTPException(status_code=400, detail="File is not tracked in group DB metadata")
                if not record.is_encrypted:
                    raise HTTPException(status_code=400, detail="File is not marked encrypted")
                if not record.enc_nonce or not record.enc_tag:
                    raise HTTPException(status_code=500, detail="Encrypted metadata missing nonce/tag")

                decrypt_iter = decrypt_file_iter(
                    proof_group_dek,
                    resolved_path,
                    record.enc_nonce,
                    record.enc_tag,
                    chunk_size=1024 * 1024,
                )
                record_label = f"group_files id={record.id}"
            else:
                if proof_user_dek is None:
                    raise HTTPException(status_code=500, detail="User proof context missing")
                record = (
                    db.query(FileRecord)
                    .filter(
                        FileRecord.user_id == user.id,
                        FileRecord.file_path == str(resolved_path),
                    )
                    .order_by(FileRecord.uploaded_at.desc())
                    .first()
                )
                if not record:
                    raise HTTPException(status_code=400, detail="File is not tracked in personal DB metadata")
                if not record.is_encrypted:
                    raise HTTPException(status_code=400, detail="File is not marked encrypted")
                if not record.enc_nonce or not record.enc_tag:
                    raise HTTPException(status_code=500, detail="Encrypted metadata missing nonce/tag")

                decrypt_iter = decrypt_file_iter(
                    proof_user_dek,
                    resolved_path,
                    record.enc_nonce,
                    record.enc_tag,
                    chunk_size=1024 * 1024,
                )
                record_label = f"files id={record.id}"

            meta_lines.append(f"DB record: {record_label}")
            meta_lines.append("Cipher: AES-256-GCM")
            meta_lines.append("Nonce/tag present: yes")

            with resolved_path.open("rb") as fh:
                head = fh.read(256)
            head_hex = _hex_bytes(head, limit=64)
            contains_null = b"\x00" in head

            naive_preview = ""
            if require_text_preview:
                naive_text = head.decode("utf-8", errors="replace")
                naive_lines = naive_text.splitlines()[:6]
                naive_preview = "\n".join(naive_lines) if naive_lines else "(no visible text)"

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

            plain_preview = ""
            if require_text_preview:
                plain_text = decrypted.decode("utf-8", errors="replace")
                plain_lines = plain_text.splitlines()
                preview_lines = plain_lines[:_TERMINAL_ENCPROOF_PREVIEW_LINES]
                plain_preview = "\n".join(preview_lines) if preview_lines else "(empty)"
                if len(plain_lines) > len(preview_lines):
                    plain_preview = (
                        f"{plain_preview}\n"
                        f"... ({len(plain_lines) - len(preview_lines)} more lines in preview window)"
                    )

            return {
                "logical_target": logical_target,
                "meta_lines": meta_lines,
                "record_label": record_label,
                "ciphertext_size": resolved_path.stat().st_size,
                "head_hex": head_hex,
                "contains_null": contains_null,
                "naive_preview": naive_preview,
                "decrypted_bytes": len(decrypted),
                "decrypted_sha256": hashlib.sha256(decrypted).hexdigest(),
                "plain_preview": plain_preview,
            }

        raw_args = " ".join(args).strip()
        if mode == "file":
            if len(mode_args) < 1:
                raise HTTPException(status_code=400, detail="Missing file path")
            target = mode_args[0]
            path = _safe_join(proof_root, target)
            proof = _collect_file_proof(path, target, require_text_preview=True)

            out_lines: list[str] = []
            out_lines.append("Encryption Proof (encproof)")
            out_lines.append("")
            out_lines.extend(proof["meta_lines"])
            out_lines.append("")
            out_lines.append("Proof 1: Encrypted At Rest (ciphertext on disk)")
            out_lines.append(f"  Ciphertext head (hex, 64 bytes): {proof['head_hex']}")
            out_lines.append(f"  Contains NUL bytes: {'yes' if proof['contains_null'] else 'no'}")
            out_lines.append("  Naive UTF-8 decode of ciphertext head (first lines):")
            out_lines.append(str(proof["naive_preview"]))
            out_lines.append("")
            out_lines.append("Proof 2: Decryption Output (plaintext preview)")
            out_lines.append(f"  Decrypted preview bytes shown: {proof['decrypted_bytes']}")
            out_lines.append(f"  Decrypted preview SHA-256: {proof['decrypted_sha256']}")
            out_lines.append("  Plaintext preview (first lines):")
            out_lines.append(str(proof["plain_preview"]))

            message = "\n".join(out_lines)
            add_event(db, user, action="terminal", message=f"encproof {raw_args}\n{message}".rstrip())
            return {"ok": True, "message": message}

        targets: list[tuple[str, Path]] = []
        pre_failures: list[str] = []
        scan_truncated = False

        if mode == "dir":
            if len(mode_args) < 1:
                raise HTTPException(status_code=400, detail="Missing directory path")
            dir_target = mode_args[0]
            dir_path = _safe_join(proof_root, dir_target)
            _ensure_no_symlink(dir_path, proof_root)
            if not dir_path.exists() or not dir_path.is_dir():
                raise HTTPException(status_code=400, detail="Directory not found")

            scanned = 0
            for dirpath, dirnames, filenames in os.walk(dir_path):
                dir_path_obj = Path(dirpath)
                clean_dirs: list[str] = []
                for dirname in sorted(dirnames):
                    candidate_dir = dir_path_obj / dirname
                    if candidate_dir.is_symlink():
                        continue
                    clean_dirs.append(dirname)
                dirnames[:] = clean_dirs

                for filename in sorted(filenames):
                    candidate = dir_path_obj / filename
                    if candidate.is_symlink():
                        continue
                    scanned += 1
                    if scanned > _TERMINAL_SCAN_LIMIT or len(targets) >= _TERMINAL_ENCPROOF_MAX_FILES:
                        scan_truncated = True
                        break
                    rel = _terminal_rel_path(proof_root, candidate)
                    targets.append((rel, candidate))
                if scan_truncated:
                    break
        elif mode == "user":
            if mode_args:
                raise HTTPException(status_code=400, detail="Usage: encproof user")
            rows = (
                db.query(FileRecord)
                .filter(FileRecord.user_id == user.id)
                .order_by(FileRecord.uploaded_at.desc(), FileRecord.file_name.asc())
                .all()
            )
            if not rows:
                message = "Encryption Proof (encproof)\n\nMode: user\nScope: user\n(no user files)"
                add_event(db, user, action="terminal", message=f"encproof {raw_args}\n{message}".rstrip())
                return {"ok": True, "message": message}

            seen_paths: set[str] = set()
            for row in rows:
                try:
                    candidate = _resolve_user_file_path(user, row.file_path).resolve()
                except HTTPException:
                    pre_failures.append(f"{row.file_name}: invalid file path metadata")
                    continue

                key = str(candidate)
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                rel = _terminal_rel_path(proof_root, candidate)
                if row.is_trashed:
                    rel = f"{rel} [trashed]"
                targets.append((rel, candidate))
                if len(targets) >= _TERMINAL_ENCPROOF_MAX_FILES:
                    scan_truncated = True
                    break
        else:
            raise HTTPException(status_code=400, detail="Unsupported encproof mode")

        if not targets:
            out_lines = [
                "Encryption Proof (encproof)",
                "",
                f"Mode: {mode}",
                f"Scope: {proof_scope_label}",
                "(no files found)",
            ]
            if pre_failures:
                out_lines.append("")
                out_lines.append("Failures")
                for item in pre_failures[:200]:
                    out_lines.append(f"  [FAIL] {item}")
                if len(pre_failures) > 200:
                    out_lines.append(f"  ... (+{len(pre_failures) - 200} more)")
            message = "\n".join(out_lines)
            level = "SUCCESS" if not pre_failures else "WARN"
            add_event(
                db,
                user,
                action="terminal",
                message=f"encproof {raw_args}\n{message}".rstrip(),
                level=level,
            )
            return {"ok": not pre_failures, "message": message}

        success_rows: list[dict[str, object]] = []
        failures: list[str] = pre_failures[:]
        for logical_target, path in targets:
            try:
                proof = _collect_file_proof(path, logical_target, require_text_preview=False)
                success_rows.append(proof)
            except HTTPException as exc:
                detail = exc.detail if isinstance(exc.detail, str) else "proof failed"
                failures.append(f"{logical_target}: {detail}")
            except Exception as exc:
                failures.append(f"{logical_target}: proof failed ({exc.__class__.__name__})")

        out_lines = [
            "Encryption Proof (encproof)",
            "",
            f"Mode: {mode}",
            f"Scope: {proof_scope_label}",
            f"Files targeted: {len(targets)}",
            f"Proof OK: {len(success_rows)}",
            f"Proof failed: {len(failures)}",
        ]
        if scan_truncated:
            out_lines.append(f"Note: proof target list truncated to {_TERMINAL_ENCPROOF_MAX_FILES} files.")

        out_lines.append("")
        out_lines.append("Per-file cryptographic checks")
        for item in success_rows:
            out_lines.append(
                f"  [OK] {item['logical_target']} | "
                f"{item['record_label']} | ciphertext={item['ciphertext_size']} bytes"
            )
            out_lines.append(
                "       "
                f"cipher_head_hex={item['head_hex']} | "
                f"contains_nul={'yes' if item['contains_null'] else 'no'} | "
                f"decrypt_probe={item['decrypted_bytes']} bytes | "
                f"probe_sha256={item['decrypted_sha256']}"
            )

        if failures:
            out_lines.append("")
            out_lines.append("Failures")
            fail_limit = 200
            for item in failures[:fail_limit]:
                out_lines.append(f"  [FAIL] {item}")
            if len(failures) > fail_limit:
                out_lines.append(f"  ... (+{len(failures) - fail_limit} more)")

        message = "\n".join(out_lines)
        level = "SUCCESS" if not failures else "WARN"
        add_event(
            db,
            user,
            action="terminal",
            message=f"encproof {raw_args}\n{message}".rstrip(),
            level=level,
        )
        return {"ok": not failures, "message": message}

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
        modified = _format_utc(datetime.utcfromtimestamp(st.st_mtime))
        if path.is_dir():
            try:
                entries = [p for p in path.iterdir() if not p.is_symlink()]
            except OSError:
                entries = []
            message = (
                f"Path: {rel if rel == '/' else rel + '/'}\n"
                "Type: directory\n"
                f"Entries: {len(entries)}\n"
                f"Modified: {modified}"
            )
        else:
            mime_type, _ = mimetypes.guess_type(path.name)
            size_raw = st.st_size
            message = (
                f"Path: {rel}\n"
                "Type: file\n"
                f"Size: {size_raw} bytes ({_format_bytes(size_raw)})\n"
                f"MIME: {mime_type or 'application/octet-stream'}\n"
                f"Modified: {modified}"
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

        checked_at = _format_utc(datetime.utcnow())
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

        dm_rows = (
            db.query(
                DirectMessage.id,
                DirectMessage.thread_id,
                DirectMessage.body,
                DirectMessage.body_key_scheme,
                DirectMessage.attachment_path,
                DirectMessage.attachment_key_scheme,
            )
            .filter(or_(DirectMessage.sender_id == user.id, DirectMessage.recipient_id == user.id))
            .all()
        )
        dm_thread_ids = {row.thread_id or row.id for row in dm_rows}
        dm_total_threads = len(dm_thread_ids)
        conversation_key_versions: dict[uuid.UUID, int] = {}
        if dm_thread_ids:
            for row in (
                db.query(ConversationKey.thread_id, ConversationKey.key_version)
                .filter(ConversationKey.thread_id.in_(dm_thread_ids))
                .all()
            ):
                conversation_key_versions[row.thread_id] = int(row.key_version or 1)
        dm_threads_with_key = sum(1 for tid in dm_thread_ids if tid in conversation_key_versions)
        dm_threads_missing_key = max(0, dm_total_threads - dm_threads_with_key)
        dm_body_conversation = sum(
            1
            for row in dm_rows
            if row.body_key_scheme == DM_BODY_SCHEME_CONVERSATION or is_dm_conversation_encrypted(row.body or "")
        )
        dm_body_legacy = sum(
            1
            for row in dm_rows
            if row.body_key_scheme == DM_BODY_SCHEME_FERNET
            or (
                row.body_key_scheme != DM_BODY_SCHEME_CONVERSATION
                and is_message_encrypted(row.body or "")
                and not is_dm_conversation_encrypted(row.body or "")
            )
        )
        dm_body_plaintext = max(0, len(dm_rows) - dm_body_conversation - dm_body_legacy)
        dm_attachment_total = sum(1 for row in dm_rows if row.attachment_path)
        dm_attachment_conversation = sum(
            1
            for row in dm_rows
            if row.attachment_path and (row.attachment_key_scheme or "").strip().lower() == DM_ATTACHMENT_SCHEME_CONVERSATION
        )

        dm_conversation_summary = "(none)"
        if conversation_key_versions:
            ordered_versions = sorted(conversation_key_versions.items(), key=lambda item: str(item[0]))
            parts = [f"{str(thread_id)[:8]}=v{version}" for thread_id, version in ordered_versions[:6]]
            dm_conversation_summary = ", ".join(parts)
            remaining = len(ordered_versions) - len(parts)
            if remaining > 0:
                dm_conversation_summary = f"{dm_conversation_summary}, ... (+{remaining} more)"

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
        if dm_threads_missing_key > 0:
            issues.append(f"{dm_threads_missing_key} direct-message thread(s) do not have a conversation key record.")
        if dm_body_legacy > 0:
            issues.append(f"{dm_body_legacy} direct-message body row(s) still use legacy Fernet encryption.")
        if dm_body_plaintext > 0:
            issues.append(f"{dm_body_plaintext} direct-message body row(s) are plaintext.")

        root_key_source = (
            "Passphrase-derived root (Argon2id + HKDF-SHA256)"
            if using_passphrase()
            else "PFV_MASTER_KEY (base64url, 32 bytes)"
        )
        lines = [
            "Encryption Status",
            f"Account: {user.username}",
            f"Checked: {checked_at}",
            "",
            "Cipher Suite",
            "  File encryption: AES-256-GCM (12-byte nonce, 16-byte tag)",
            "  Key wrapping: AES-256-GCM wrapped DEK (AAD bound to user/group id)",
            "  Direct messages: Conversation AES-256-GCM (dmenc:v2); legacy Fernet read support",
            f"  Root key source: {root_key_source}",
            "",
            "User Key",
            f"  Record present: {'yes' if key_present else 'no'}",
            f"  Key version: {key_version}",
            f"  Created: {key_created}",
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
            "Conversation Encryption Coverage",
            f"  Direct-message rows: {len(dm_rows)}",
            f"  Distinct threads: {dm_total_threads}",
            f"  Threads with conversation key: {dm_threads_with_key}/{dm_total_threads}",
            f"  Thread key versions: {dm_conversation_summary}",
            f"  Body rows using conversation key: {dm_body_conversation}",
            f"  Body rows using legacy Fernet: {dm_body_legacy}",
            f"  Body rows plaintext: {dm_body_plaintext}",
            f"  Attachments in conversation scheme: {dm_attachment_conversation}/{dm_attachment_total}",
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

    if cmd == "enctimeline":
        if len(args) > 1:
            raise HTTPException(status_code=400, detail="Usage: enctimeline [limit]")

        requested_limit = safe_args[0] if safe_args else ""
        item_limit = _parse_int_arg(
            requested_limit,
            default=_TERMINAL_TIMELINE_DEFAULT_LIMIT,
            minimum=10,
            maximum=_TERMINAL_TIMELINE_MAX_LIMIT,
            name="limit",
        )

        page_hint_raw = (page_context or "").strip()
        page_hint = page_hint_raw[:220] if page_hint_raw else "(not provided)"
        page_path = ""
        thread_filter: uuid.UUID | None = None
        if page_hint_raw:
            try:
                parsed = urlsplit(page_hint_raw)
                page_path = (parsed.path or "").strip()
                thread_values = parse_qs(parsed.query).get("thread", [])
                if thread_values:
                    thread_raw = (thread_values[0] or "").strip()
                    if thread_raw:
                        thread_filter = uuid.UUID(thread_raw)
            except Exception:
                page_path = page_hint_raw.split("?", 1)[0].strip()

        checked_at = _format_utc(datetime.utcnow())
        lines = [
            "Encryption Timeline",
            f"Account: {user.username}",
            f"Checked: {checked_at}",
            f"Scope: {scope_label}",
            f"Page context: {page_hint}",
            "",
            "Messages",
        ]

        message_query = (
            db.query(DirectMessage)
            .options(joinedload(DirectMessage.sender), joinedload(DirectMessage.recipient))
            .filter(or_(DirectMessage.sender_id == user.id, DirectMessage.recipient_id == user.id))
        )
        if thread_filter is not None:
            message_query = message_query.filter(DirectMessage.thread_id == thread_filter)

        message_rows = (
            message_query
            .order_by(DirectMessage.created_at.desc())
            .limit(min(_TERMINAL_TIMELINE_MESSAGE_LIMIT, item_limit))
            .all()
        )
        if not message_rows:
            lines.append("  (no direct messages in scope)")
        else:
            thread_ids = {row.thread_id or row.id for row in message_rows}
            conversation_versions: dict[uuid.UUID, int] = {}
            if thread_ids:
                for key_row in db.query(ConversationKey).filter(ConversationKey.thread_id.in_(thread_ids)).all():
                    conversation_versions[key_row.thread_id] = int(key_row.key_version or 1)

            lines.append(f"  Rows scanned: {len(message_rows)}")
            for row in message_rows:
                thread_uuid = row.thread_id or row.id
                direction = "outbound" if row.sender_id == user.id else "inbound"
                partner = row.recipient.username if row.sender_id == user.id else row.sender.username
                conversation_version = conversation_versions.get(thread_uuid)
                is_conversation_body = (
                    row.body_key_scheme == DM_BODY_SCHEME_CONVERSATION
                    or is_dm_conversation_encrypted(row.body or "")
                )
                if is_conversation_body:
                    body_status = "encrypted"
                    body_key = _conversation_body_key_label(
                        int(row.body_key_version or conversation_version or 0) or None
                    )
                elif is_message_encrypted(row.body or ""):
                    body_status = "encrypted"
                    body_key = _DM_BODY_KEY_LABEL
                else:
                    body_status = "plaintext"
                    body_key = "plaintext"

                attachment_status = "none"
                attachment_key = "-"
                attachment_mtime = "-"
                if row.attachment_name and row.attachment_path:
                    scheme = (row.attachment_key_scheme or DM_ATTACHMENT_SCHEME_RECIPIENT).strip().lower()
                    has_meta = bool(row.attachment_enc_nonce and row.attachment_enc_tag)
                    path_state = "missing"
                    try:
                        attach_path = _safe_message_attachment_path(row.attachment_path)
                    except HTTPException:
                        path_state = "invalid-path"
                    else:
                        if attach_path.exists() and attach_path.is_file():
                            path_state = "present"
                            attachment_mtime = datetime.utcfromtimestamp(attach_path.stat().st_mtime).isoformat(
                                timespec="seconds"
                            ) + "Z"
                    if scheme == DM_ATTACHMENT_SCHEME_CONVERSATION:
                        attachment_key = _conversation_attachment_key_label(
                            int(row.attachment_key_version or conversation_version or 0) or None
                        )
                    elif scheme in {"", DM_ATTACHMENT_SCHEME_RECIPIENT}:
                        attachment_key = "dm-attachment:recipient-user-dek"
                    elif scheme == DM_ATTACHMENT_SCHEME_SYSTEM:
                        attachment_key = _DM_ATTACHMENT_SYSTEM_KEY_LABEL
                    else:
                        attachment_key = f"dm-attachment:{scheme}"
                    attachment_status = (
                        f"{'encrypted' if has_meta else 'metadata-missing'}"
                        f" ({scheme}, {path_state})"
                    )

                lines.append(
                    "  "
                    f"{str(row.id)[:8]} {direction} {partner}: "
                    f"body={body_status}, body_key={body_key}, attachment={attachment_status}, attachment_key={attachment_key}"
                )
                lines.append(
                    "    "
                    f"created={_format_utc(row.created_at)}, "
                    f"read={_format_utc(row.read_at) if row.read_at else '-'}, "
                    f"attachment_mtime={attachment_mtime}"
                )

        lines.extend(["", "Files and Directories"])

        file_rows_scanned = 0
        dir_rows_scanned = 0
        file_encrypted = 0
        file_plaintext = 0
        file_unknown = 0

        file_record_map: dict[Path, FileRecord | GroupFileRecord] = {}
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

            group_root = _group_root(gid).resolve()
            for row in db.query(GroupFileRecord).filter(GroupFileRecord.group_id == gid).all():
                try:
                    resolved = Path(row.file_path).resolve()
                    if not resolved.is_relative_to(group_root):
                        continue
                except Exception:
                    continue
                file_record_map[resolved] = row
        else:
            for row in (
                db.query(FileRecord)
                .filter(
                    FileRecord.user_id == user.id,
                    FileRecord.is_trashed.is_(False),
                )
                .all()
            ):
                try:
                    resolved = _resolve_user_file_path(user, row.file_path)
                except HTTPException:
                    continue
                file_record_map[resolved.resolve()] = row

        filesystem_lines: list[str] = []
        for dirpath, dirnames, filenames in os.walk(root):
            current_dir = Path(dirpath)
            dirnames[:] = sorted([name for name in dirnames if not (current_dir / name).is_symlink()], key=str.lower)
            file_names = sorted(filenames, key=str.lower)

            if len(filesystem_lines) >= item_limit:
                break

            if current_dir == root or not page_path.startswith("/ui/messages"):
                rel_dir = _terminal_rel_path(root, current_dir)
                rel_label = "/" if rel_dir == "/" else f"{rel_dir}/"
                try:
                    modified = _format_utc(datetime.utcfromtimestamp(current_dir.stat().st_mtime))
                except OSError:
                    modified = "n/a"
                filesystem_lines.append(f"  {rel_label} type=directory, state=container, modified={modified}")
                dir_rows_scanned += 1
                if len(filesystem_lines) >= item_limit:
                    break

            for filename in file_names:
                if len(filesystem_lines) >= item_limit:
                    break
                candidate = current_dir / filename
                if candidate.is_symlink():
                    continue
                rel = _terminal_rel_path(root, candidate)
                modified = "n/a"
                try:
                    modified = _format_utc(datetime.utcfromtimestamp(candidate.stat().st_mtime))
                except OSError:
                    pass

                record = file_record_map.get(candidate.resolve())
                if record is None:
                    state = "untracked"
                    uploaded = "-"
                    file_unknown += 1
                else:
                    is_encrypted = bool(getattr(record, "is_encrypted", False))
                    has_meta = bool(getattr(record, "enc_nonce", None) and getattr(record, "enc_tag", None))
                    if is_encrypted and has_meta:
                        state = "encrypted"
                        file_encrypted += 1
                    elif is_encrypted and not has_meta:
                        state = "encrypted-metadata-missing"
                        file_unknown += 1
                    else:
                        state = "plaintext"
                        file_plaintext += 1

                    uploaded_at = getattr(record, "uploaded_at", None)
                    uploaded = _format_utc(uploaded_at) if uploaded_at else "-"

                filesystem_lines.append(
                    f"  {rel} type=file, state={state}, uploaded={uploaded}, modified={modified}"
                )
                file_rows_scanned += 1

        if filesystem_lines:
            lines.append(f"  Rows scanned: {len(filesystem_lines)} (files={file_rows_scanned}, dirs={dir_rows_scanned})")
            lines.append(
                "  Status summary: "
                f"encrypted={file_encrypted}, plaintext={file_plaintext}, unknown={file_unknown}"
            )
            lines.extend(filesystem_lines[:item_limit])
            if len(filesystem_lines) >= item_limit:
                lines.append("  ... (output truncated by limit)")
        else:
            lines.append("  (no filesystem entries)")

        message = "\n".join(lines)
        add_event(db, user, action="terminal", message=f"enctimeline {requested_limit or ''}\n{message}".rstrip())
        return {"ok": True, "message": message}

    if cmd == "encrotate":
        if len(args) > 1:
            raise HTTPException(status_code=400, detail="Usage: encrotate [all|files|messages|groups]")

        raw_target = (args[0] if args else "all").strip().lower()
        target = raw_target or "all"
        if target not in _TERMINAL_ROTATE_TARGETS:
            raise HTTPException(status_code=400, detail="Target must be one of: all, files, messages, groups")

        rotate_files = target in {"all", "files"}
        rotate_messages = target in {"all", "messages"}
        rotate_groups = target in {"all", "groups"}
        started_at = _format_utc(datetime.utcnow())

        user_summary: dict[str, int] | None = None
        message_summary: dict[str, int] | None = None
        group_summaries: list[dict[str, int | str]] = []
        group_failures: list[str] = []
        failed_sections: list[str] = []

        if rotate_files:
            try:
                user_summary = _rotate_user_key_material(db, user)
            except Exception as exc:
                logger.warning("User encryption rotation failed for %s", user.id, exc_info=True)
                failed_sections.append(f"files/user-key rotation failed ({exc.__class__.__name__})")

        if rotate_messages:
            include_recipient_attachments = not (rotate_files and user_summary is not None)
            try:
                message_summary = _rotate_message_ciphertexts(
                    db,
                    user,
                    include_recipient_attachments=include_recipient_attachments,
                )
            except Exception as exc:
                logger.warning("Message encryption rotation failed for %s", user.id, exc_info=True)
                failed_sections.append(f"message rotation failed ({exc.__class__.__name__})")

        group_memberships: list[tuple[Group, str]] = []
        eligible_groups: list[tuple[Group, str]] = []
        if rotate_groups:
            membership_rows = (
                db.query(Group, GroupMembership.role)
                .join(GroupMembership, GroupMembership.group_id == Group.id)
                .filter(GroupMembership.user_id == user.id)
                .order_by(Group.name.asc())
                .all()
            )
            for group, role in membership_rows:
                normalized_role = (role or "").strip().lower() or "member"
                group_memberships.append((group, normalized_role))
                if normalized_role in {"owner", "admin"}:
                    eligible_groups.append((group, normalized_role))

            for group, role in eligible_groups:
                try:
                    summary = _rotate_group_key_material(db, group)
                    summary["membership_role"] = role
                    group_summaries.append(summary)
                except Exception as exc:
                    logger.warning("Group encryption rotation failed for group %s", group.id, exc_info=True)
                    group_failures.append(f"{group.name} ({role}) - {exc.__class__.__name__}")

        completed_at = _format_utc(datetime.utcnow())
        lines = [
            "Encryption Rotation",
            f"Account: {user.username}",
            f"Target: {target}",
            f"Started: {started_at}",
            f"Completed: {completed_at}",
            "",
        ]

        if user_summary is not None:
            lines.extend(
                [
                    "Personal Key Rotation",
                    f"  User key version: v{user_summary['key_version_from']} -> v{user_summary['key_version_to']}",
                    (
                        f"  Personal files rotated: {user_summary['files_rotated']}/{user_summary['files_total']}"
                        f" (plaintext skipped: {user_summary['files_plain_skipped']})"
                    ),
                    (
                        "  Recipient-key message attachments rotated: "
                        f"{user_summary['recipient_attachments_rotated']}/{user_summary['recipient_attachments_total']}"
                    ),
                    f"  Profile avatar rotated: {'yes' if user_summary['avatar_rotated'] else 'no'}",
                    (
                        "  Verification probes: "
                        f"{user_summary['verification_checks_passed']}/{user_summary['verification_checks_total']}"
                        f" (bytes checked: {user_summary['verification_bytes_checked']})"
                    ),
                ]
            )
            if user_summary["files_missing_meta"] or user_summary["files_missing_path"] or user_summary["files_invalid_path"]:
                lines.append(
                    "  WARN personal file rows skipped: "
                    f"missing-meta={user_summary['files_missing_meta']}, "
                    f"missing-path={user_summary['files_missing_path']}, "
                    f"invalid-path={user_summary['files_invalid_path']}"
                )
            if (
                user_summary["recipient_attachments_missing_meta"]
                or user_summary["recipient_attachments_missing_path"]
                or user_summary["recipient_attachments_invalid_path"]
                or user_summary["recipient_attachments_non_recipient_scheme"]
            ):
                lines.append(
                    "  WARN recipient attachment rows skipped: "
                    f"missing-meta={user_summary['recipient_attachments_missing_meta']}, "
                    f"missing-path={user_summary['recipient_attachments_missing_path']}, "
                    f"invalid-path={user_summary['recipient_attachments_invalid_path']}, "
                    f"other-scheme={user_summary['recipient_attachments_non_recipient_scheme']}"
                )
            if user_summary["avatar_missing_meta"] or user_summary["avatar_missing_path"] or user_summary["avatar_invalid_path"]:
                lines.append(
                    "  WARN avatar skipped: "
                    f"missing-meta={user_summary['avatar_missing_meta']}, "
                    f"missing-path={user_summary['avatar_missing_path']}, "
                    f"invalid-path={user_summary['avatar_invalid_path']}"
                )
            lines.append("")
        elif rotate_files:
            lines.extend(["Personal Key Rotation", "  ERROR: personal key rotation failed.", ""])

        if message_summary is not None:
            lines.extend(
                [
                    "Message Rotation",
                    (
                        "  Message bodies rotated: "
                        f"{message_summary['messages_rotated']}/{message_summary['messages_total']}"
                        f" (plaintext upgraded: {message_summary['messages_upgraded_plaintext']})"
                    ),
                    f"  Conversation keys touched: {message_summary['conversation_keys_touched']}",
                    (
                        "  Attachments rotated: "
                        f"conversation={message_summary['attachments_conversation_rotated']}, "
                        f"system={message_summary['attachments_system_rotated']}, "
                        f"recipient={message_summary['attachments_recipient_rotated']}, "
                        f"recipient-skipped={message_summary['attachments_recipient_skipped']}"
                    ),
                ]
            )
            if message_summary["messages_unavailable"] > 0:
                lines.append(f"  WARN undecryptable message bodies skipped: {message_summary['messages_unavailable']}")
            if (
                message_summary["attachments_missing_meta"]
                or message_summary["attachments_missing_path"]
                or message_summary["attachments_invalid_path"]
                or message_summary["attachments_unknown_scheme"]
            ):
                lines.append(
                    "  WARN attachment rows skipped: "
                    f"missing-meta={message_summary['attachments_missing_meta']}, "
                    f"missing-path={message_summary['attachments_missing_path']}, "
                    f"invalid-path={message_summary['attachments_invalid_path']}, "
                    f"unknown-scheme={message_summary['attachments_unknown_scheme']}"
                )
            lines.append("")
        elif rotate_messages:
            lines.extend(["Message Rotation", "  ERROR: message rotation failed.", ""])

        if rotate_groups:
            lines.append("Group Key Rotation")
            lines.append(
                f"  Eligible groups (owner/admin): {len(eligible_groups)}/{len(group_memberships)}"
            )
            if group_summaries:
                max_rows = 12
                for summary in group_summaries[:max_rows]:
                    lines.append(
                        "  "
                        f"{summary['group_name']} ({summary['membership_role']}): "
                        f"v{summary['key_version_from']} -> v{summary['key_version_to']}, "
                        f"files {summary['files_rotated']}/{summary['files_total']}, "
                        f"verify {summary['verification_checks_passed']}/{summary['verification_checks_total']}"
                    )
                    if summary["files_missing_meta"] or summary["files_missing_path"] or summary["files_invalid_path"]:
                        lines.append(
                            "    WARN "
                            f"missing-meta={summary['files_missing_meta']}, "
                            f"missing-path={summary['files_missing_path']}, "
                            f"invalid-path={summary['files_invalid_path']}"
                        )
                if len(group_summaries) > max_rows:
                    lines.append(f"  ... (+{len(group_summaries) - max_rows} more groups)")
            if group_failures:
                lines.append("  ERROR groups failed:")
                for item in group_failures[:12]:
                    lines.append(f"    {item}")
                if len(group_failures) > 12:
                    lines.append(f"    ... (+{len(group_failures) - 12} more)")
            lines.append("")

        if failed_sections:
            lines.append("Status: PARTIAL")
            for item in failed_sections:
                lines.append(f"  ERROR: {item}")
        elif group_failures:
            lines.append("Status: PARTIAL")
            lines.append(f"  ERROR: {len(group_failures)} group rotation(s) failed.")
        else:
            lines.append("Status: OK")

        message = "\n".join(lines)
        level = "SUCCESS" if not failed_sections and not group_failures else "WARN"
        add_event(db, user, action="terminal", message=f"encrotate {target}\n{message}", level=level)
        add_audit_log(
            db,
            user=user,
            event_type="encryption.rotate",
            details=(
                f"Terminal encrotate target={target}, "
                f"user_ok={'yes' if user_summary is not None else 'no'}, "
                f"messages_ok={'yes' if message_summary is not None else 'no'}, "
                f"groups_ok={len(group_summaries)}, "
                f"group_failures={len(group_failures)}, "
                f"section_failures={len(failed_sections)}."
            ),
            request=request,
        )
        db.commit()
        return {"ok": not failed_sections and not group_failures, "message": message}

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
    if not _is_advanced_view_enabled(user):
        raise HTTPException(status_code=403, detail="Terminal is available only in advanced view.")

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
    session_id = request.cookies.get(_SESSION_COOKIE_NAME)
    session = _get_session(db, session_id)
    if session:
        user = db.query(User).filter(User.id == session.user_id).first()
        session.is_active = False
        if user:
            add_event(db, user, action="auth", message="Signed out.")
            add_audit_log(db, user=user, event_type="signout", details="Interactive sign-out completed.", request=request)
        db.commit()
    response = RedirectResponse(url="/ui/login", status_code=303)
    _clear_session_cookie(response, request)
    return response
