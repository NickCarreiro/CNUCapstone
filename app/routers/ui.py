import os
import re
import secrets
import shlex
import shutil
import uuid
import hashlib
import hmac
import smtplib
import ssl
import base64
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import quote_plus, urlencode
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError, URLError

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
import mimetypes
import logging

from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, func, or_
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
from app.services.message_crypto import decrypt_message, encrypt_message
import pyotp

router = APIRouter(prefix="/ui", tags=["ui"])
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger("uvicorn.error")
_FILE_TOKEN_CACHE: dict[str, dict[str, str]] = {}
_TERMINAL_SCOPE_CACHE: dict[str, dict[str, str]] = {}

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

PROFILE_IMAGE_MIME_ALLOW = {
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
}

DM_REPORT_REASONS: dict[str, str] = {
    "spam": "Spam / unsolicited advertising",
    "harassment": "Harassment or hate speech",
    "threat": "Threats or violence",
    "impersonation": "Impersonation / fraud",
    "sexual": "Sexual content",
    "other": "Other",
}

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


def _get_current_user(db: Session, request: Request) -> User | None:
    session_id = request.cookies.get("pfv_session")
    session = _get_session(db, session_id)
    if not session:
        return None
    user = db.query(User).filter(User.id == session.user_id).first()
    if user and getattr(user, "is_disabled", False):
        session.is_active = False
        db.commit()
        return None
    return user


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


def _format_utc(value: datetime | None) -> str:
    if not value:
        return "-"
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


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
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "http").strip()
    host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc).strip()
    if not host:
        base = str(request.base_url).rstrip("/")
        return base
    return f"{proto}://{host}"


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


def _admin_redirect(message: str, *, error: bool = False) -> RedirectResponse:
    key = "error" if error else "notice"
    return RedirectResponse(url=f"/ui/admin/users?{key}={quote_plus(message)}", status_code=303)


def _admin_reports_redirect(
    message: str,
    *,
    error: bool = False,
    report_id: str | None = None,
) -> RedirectResponse:
    key = "error" if error else "notice"
    base = f"/ui/admin/reports/{report_id}" if report_id else "/ui/admin/reports"
    return RedirectResponse(url=f"{base}?{key}={quote_plus(message)}", status_code=303)


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


def _render_login_page(
    request: Request,
    *,
    error: str | None = None,
    notice: str | None = None,
    username: str = "",
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
        "login.html",
        {
            "request": request,
            "error": error,
            "notice": notice,
            "username": username,
            "mfa_method": selected,
            "mfa_methods": method_rows,
        },
        status_code=status_code,
    )


@router.get("/login")
def login_page(request: Request):
    return _render_login_page(request)


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
    mfa_method: str | None = Form(None),
    mfa_code: str | None = Form(None),
    send_mfa_code: str | None = Form(None),
    totp_code: str | None = Form(None),
    db: Session = Depends(get_db),
):
    normalized_username = (username or "").strip()
    selected_method = _normalize_mfa_method(mfa_method) or MFA_METHOD_TOTP
    code_value = (mfa_code or totp_code or "").strip()
    wants_send_code = (send_mfa_code or "").strip().lower() in {"1", "true", "yes", "on", "send"}

    user = db.query(User).filter(User.username == normalized_username).first()
    if not user:
        return _render_login_page(
            request,
            error="Invalid username or password",
            username=normalized_username,
            mfa_method=selected_method,
            status_code=401,
        )
    if not verify_password(password, user.password_hash):
        add_audit_log(db, user=user, event_type="signin.failed_password", details="Password verification failed.", request=request)
        db.commit()
        return _render_login_page(
            request,
            error="Invalid username or password",
            username=normalized_username,
            mfa_method=selected_method,
            status_code=401,
        )

    if getattr(user, "is_disabled", False):
        add_audit_log(db, user=user, event_type="signin.blocked_disabled", details="Interactive sign-in blocked (account disabled).", request=request)
        db.commit()
        return _render_login_page(
            request,
            error="Account disabled. Please contact an administrator.",
            username=normalized_username,
            mfa_method=selected_method,
            status_code=403,
        )

    configured_methods = _available_mfa_methods(user, transport_ready_only=False)
    if configured_methods:
        effective_method = _resolve_mfa_method(user, selected_method, configured_methods)
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
                mfa_method=selected_method,
                mfa_methods=configured_methods,
                status_code=401,
            )

        if effective_method == MFA_METHOD_TOTP:
            if not code_value:
                add_audit_log(db, user=user, event_type="signin.failed_totp_required", details="TOTP code required.", request=request)
                db.commit()
                return _render_login_page(
                    request,
                    error="Authenticator app code is required.",
                    username=normalized_username,
                    mfa_method=effective_method,
                    mfa_methods=configured_methods,
                    status_code=401,
                )
            if not _verify_totp_for_user(user, code_value):
                add_audit_log(db, user=user, event_type="signin.failed_totp_invalid", details="Invalid TOTP code.", request=request)
                db.commit()
                return _render_login_page(
                    request,
                    error="Invalid authenticator app code.",
                    username=normalized_username,
                    mfa_method=effective_method,
                    mfa_methods=configured_methods,
                    status_code=401,
                )
        else:
            if wants_send_code or not code_value:
                try:
                    destination_hint = _issue_mfa_challenge(user, effective_method)
                except HTTPException as exc:
                    db.rollback()
                    return _render_login_page(
                        request,
                        error=str(exc.detail),
                        username=normalized_username,
                        mfa_method=effective_method,
                        mfa_methods=configured_methods,
                        status_code=exc.status_code,
                    )
                except Exception as exc:
                    db.rollback()
                    logger.warning("Failed to send %s MFA code for user %s: %s", effective_method, user.id, exc)
                    return _render_login_page(
                        request,
                        error=f"Could not send {_mfa_method_display(effective_method).lower()} code right now.",
                        username=normalized_username,
                        mfa_method=effective_method,
                        mfa_methods=configured_methods,
                        status_code=503,
                    )

                add_audit_log(
                    db,
                    user=user,
                    event_type=f"mfa.challenge_sent_{effective_method}",
                    details=f"Sent MFA challenge via {effective_method} to {destination_hint}.",
                    request=request,
                )
                db.commit()
                return _render_login_page(
                    request,
                    notice=f"A 6-digit code was sent to {destination_hint}. Enter it to complete sign in.",
                    username=normalized_username,
                    mfa_method=effective_method,
                    mfa_methods=configured_methods,
                    status_code=401,
                )

            challenge_ok, reason = _verify_mfa_challenge(user, effective_method, code_value)
            if not challenge_ok:
                add_audit_log(
                    db,
                    user=user,
                    event_type=f"signin.failed_{effective_method}_mfa",
                    details=f"{effective_method.upper()} MFA verification failed: {reason}",
                    request=request,
                )
                db.commit()
                return _render_login_page(
                    request,
                    error=reason,
                    username=normalized_username,
                    mfa_method=effective_method,
                    mfa_methods=configured_methods,
                    status_code=401,
                )

            add_audit_log(
                db,
                user=user,
                event_type=f"mfa.verified_{effective_method}",
                details=f"{effective_method.upper()} MFA challenge verified during sign-in.",
                request=request,
            )
            db.commit()

        user.mfa_preferred_method = effective_method

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

    thread_buckets: dict[uuid.UUID, list[DirectMessage]] = {}
    thread_summaries: dict[uuid.UUID, dict] = {}
    for row in messages:
        thread_uuid = row.thread_id or row.id
        thread_buckets.setdefault(thread_uuid, []).append(row)

        partner = row.recipient if row.sender_id == user.id else row.sender
        preview = decrypt_message(row.body).replace("\n", " ").strip()
        if len(preview) > 82:
            preview = f"{preview[:79]}..."

        if thread_uuid not in thread_summaries:
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

    read_updates = 0
    for row in active_thread_messages:
        if row.recipient_id == user.id and row.read_at is None:
            row.read_at = datetime.utcnow()
            read_updates += 1
    if read_updates:
        db.commit()
        if active_thread_summary:
            active_thread_summary["unread_count"] = 0

    thread_messages = []
    for row in active_thread_messages:
        outbound = row.sender_id == user.id
        thread_messages.append(
            {
                "id": str(row.id),
                "thread_id": str(row.thread_id or row.id),
                "sender_username": row.sender.username,
                "recipient_username": row.recipient.username,
                "body": decrypt_message(row.body),
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
                "attachment_url": f"/ui/messages/{row.id}/attachment"
                if row.attachment_name and row.attachment_path
                else None,
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

    dm = DirectMessage(
        id=uuid.uuid4(),
        thread_id=resolved_thread_id,
        sender_id=user.id,
        recipient_id=recipient.id,
        body=encrypt_message(body),
    )

    if has_attachment and attachment:
        safe_name = Path(attachment.filename or "").name.strip()
        if not safe_name:
            return _messages_redirect("Invalid attachment name.", error=True, thread=str(resolved_thread_id))

        recipient_dek = get_user_dek(db, recipient)
        attach_dir = _message_attachment_root() / str(recipient.id) / str(dm.id)
        attach_dir.mkdir(parents=True, exist_ok=True)
        dest = attach_dir / safe_name

        nonce_b64, tag_b64, plain_size = encrypt_file_to_path(recipient_dek, attachment.file, dest)
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
def open_message_attachment(message_id: str, request: Request, db: Session = Depends(get_db)):
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

    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": f'attachment; filename="{message.attachment_name}"',
    }

    if not message.attachment_enc_nonce or not message.attachment_enc_tag:
        return FileResponse(
            path=path,
            filename=message.attachment_name,
            media_type=message.attachment_mime_type or "application/octet-stream",
            headers=headers,
        )

    recipient = db.query(User).filter(User.id == message.recipient_id).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    add_event(
        db,
        user,
        action="message",
        message=f"Downloaded message attachment '{message.attachment_name}'.",
    )
    db.commit()

    dek = get_user_dek(db, recipient)
    return StreamingResponse(
        decrypt_file_iter(dek, path, message.attachment_enc_nonce, message.attachment_enc_tag),
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
            "mfa_summary": _mfa_summary_for_user(target),
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
            "mfa_enabled_count": sum(
                1 for u in users if (u.totp_enabled or u.email_mfa_enabled or u.sms_mfa_enabled)
            ),
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
    rows = []
    for report in reports:
        reporter_name = report.reporter.username if report.reporter else "(unknown)"
        reported_name = report.reported_user.username if report.reported_user else "(unknown)"

        preview = ""
        if report.message:
            preview = decrypt_message(report.message.body).replace("\n", " ").strip()
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
    message_body = decrypt_message(msg.body) if msg else ""
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
    return _admin_redirect(f"All MFA methods reset for '{target.username}'.")


@router.post("/admin/users/{user_id}/reset-password")
def admin_reset_password(
    user_id: str,
    request: Request,
    password: str = Form(...),
    confirm_password: str = Form(...),
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
        return _admin_redirect("Invalid user identifier.", error=True)

    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        return _admin_redirect("User not found.", error=True)

    if password != confirm_password:
        return _admin_redirect("Passwords did not match.", error=True)

    if len(password) < 10:
        return _admin_redirect("Password must be at least 10 characters.", error=True)

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
    return _admin_redirect(f"Password reset for '{target.username}'.")


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

    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "user": user,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
            "smtp_ready": _smtp_configured(),
            "sms_ready": _sms_configured(user),
            "sms_provider_mode": _sms_provider_mode(),
            "sms_provider_label": _sms_provider_label(),
            "mfa_methods_active": active_methods,
            "mfa_method_preferred": _resolve_mfa_method(user, user.mfa_preferred_method, active_methods),
            "mfa_method_labels": MFA_METHOD_LABELS,
            "sms_carrier_options": _sms_carrier_rows(),
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


@router.post("/profile/preferences")
def profile_update_preferences(
    request: Request,
    email: str = Form(""),
    email_visible: str | None = Form(None),
    phone_number: str = Form(""),
    sms_carrier: str = Form(""),
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
    response.set_cookie("pfv_session", str(session.id), httponly=True)
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
