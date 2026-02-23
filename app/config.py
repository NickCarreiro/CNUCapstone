from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(_PROJECT_ROOT / ".env"), env_prefix="PFV_")

    app_name: str = "FileFort"
    environment: str = "dev"

    database_url: str = "postgresql+psycopg://pfv:pfv@localhost:5432/pfv"

    # Security
    password_hash_scheme: str = "argon2"
    totp_issuer: str = "FileFort"
    totp_encryption_key: str = "CHANGE_ME"
    # 32-byte AES key, base64url-encoded (generated). Used to wrap per-user file keys.
    master_key: str = "CHANGE_ME"
    # Optional: derive keys from a passphrase file + managed salt.
    passphrase_file: str | None = None
    salt_file: str = "/var/lib/pfv/salt.bin"

    # Storage paths
    vault_base_path: str = "/var/lib/pfv"
    staging_path: str = "/var/lib/pfv_staging"

    # Session settings
    session_ttl_minutes: int = 60

    # MFA challenge settings
    mfa_code_ttl_seconds: int = 300
    mfa_resend_cooldown_seconds: int = 30
    mfa_max_attempts: int = 5

    # Optional outgoing mail transport for profile email verification + email MFA.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False

    # SMS MFA transport mode: smtp_gateway, twilio, or auto.
    sms_provider: str = "smtp_gateway"
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_from_number: str = ""


settings = Settings()
