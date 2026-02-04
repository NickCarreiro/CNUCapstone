from datetime import datetime, timedelta

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from passlib.context import CryptContext

from app.config import settings
from app.services.key_derivation import totp_fernet_key_str

pwd_context = CryptContext(schemes=[settings.password_hash_scheme], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def get_totp() -> pyotp.TOTP:
    return pyotp.TOTP(pyotp.random_base32(), issuer=settings.totp_issuer)


def _fernet() -> Fernet:
    return Fernet(totp_fernet_key_str().encode())


def encrypt_totp_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_totp_secret(secret_enc: str) -> str:
    try:
        return _fernet().decrypt(secret_enc.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Invalid TOTP secret encryption key") from exc


def session_expiry() -> datetime:
    return datetime.utcnow() + timedelta(minutes=settings.session_ttl_minutes)
