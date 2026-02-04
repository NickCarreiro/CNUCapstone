from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="PFV_")

    app_name: str = "Personal File Vault"
    environment: str = "dev"

    database_url: str = "postgresql+psycopg://pfv:pfv@localhost:5432/pfv"

    # Security
    password_hash_scheme: str = "argon2"
    totp_issuer: str = "Personal File Vault"
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


settings = Settings()
