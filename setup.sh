#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

CURRENT_USER="${SUDO_USER:-$(id -un)}"

log() {
  printf "[setup] %s\n" "$1"
}

warn() {
  printf "[setup][warn] %s\n" "$1"
}

fail() {
  printf "[setup][error] %s\n" "$1" >&2
  exit 1
}

run_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
    return
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    fail "sudo is required for: $*"
  fi
  sudo "$@"
}

psql_postgres() {
  local sql="$1"
  if [[ "$(id -u)" -eq 0 ]]; then
    su postgres -c "psql -v ON_ERROR_STOP=1 -tAc \"$sql\""
  else
    sudo -u postgres psql -v ON_ERROR_STOP=1 -tAc "$sql"
  fi
}

ensure_dir() {
  local dir="$1"
  if mkdir -p "$dir" 2>/dev/null; then
    return 0
  fi
  run_sudo mkdir -p "$dir"
  run_sudo chown "$CURRENT_USER":"$CURRENT_USER" "$dir" || true
}

set_env_var() {
  local key="$1"
  local value="$2"
  if grep -q "^${key}=" .env 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${value}|g" .env
  else
    printf "%s=%s\n" "$key" "$value" >> .env
  fi
}

read_env_value() {
  local key="$1"
  local raw
  raw="$(grep "^${key}=" .env 2>/dev/null | tail -n1 | cut -d= -f2- || true)"
  raw="${raw%\"}"
  raw="${raw#\"}"
  printf "%s" "$raw"
}

env_value_is_missing_or_placeholder() {
  local key="$1"
  local value
  value="$(read_env_value "$key")"
  [[ -z "$value" || "$value" == "CHANGE_ME" ]]
}

if ! command -v python3 >/dev/null 2>&1; then
  fail "python3 not found. Install Python 3 first."
fi

if ! python3 -m pip --version >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    log "python3-pip not found. Installing..."
    run_sudo apt-get update
    run_sudo apt-get install -y python3-pip
  else
    fail "python3-pip is required and apt-get is not available."
  fi
fi

log "Installing Python dependencies (global python3)"
python3 -m pip install --upgrade pip --break-system-packages || python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt --break-system-packages || python3 -m pip install -r requirements.txt

if [[ ! -f .env ]]; then
  log "Creating .env (no .env.example found in repo)."
  : > .env
fi

# Core defaults
set_env_var "PFV_ENVIRONMENT" "\"production\""
set_env_var "PFV_DATABASE_URL" "\"postgresql+psycopg://pfv:pfv@localhost:5432/pfv\""
set_env_var "PFV_VAULT_BASE_PATH" "\"/var/lib/pfv\""
set_env_var "PFV_STAGING_PATH" "\"/var/lib/pfv_staging\""
set_env_var "PFV_PASSPHRASE_FILE" "\"passphrase.txt\""
set_env_var "PFV_SALT_FILE" "\"/var/lib/pfv/salt.bin\""
set_env_var "PFV_SESSION_COOKIE_SAMESITE" "\"lax\""
set_env_var "PFV_ALLOW_SELF_SERVICE_REGISTRATION" "false"
set_env_var "PFV_CSRF_PROTECTION_ENABLED" "true"
set_env_var "PFV_AUTH_RATE_LIMIT_ENABLED" "true"
set_env_var "PFV_AUTH_RATE_LIMIT_ATTEMPTS" "20"
set_env_var "PFV_AUTH_RATE_LIMIT_WINDOW_SECONDS" "300"
set_env_var "PFV_ENFORCE_HTTPS" "false"
set_env_var "PFV_TRUSTED_HOSTS" "\"\""
set_env_var "PFV_PUBLIC_BASE_URL" "\"\""

# MFA defaults
set_env_var "PFV_MFA_CODE_TTL_SECONDS" "300"
set_env_var "PFV_MFA_RESEND_COOLDOWN_SECONDS" "30"
set_env_var "PFV_MFA_MAX_ATTEMPTS" "5"

# SMTP defaults
set_env_var "PFV_SMTP_HOST" "\"\""
set_env_var "PFV_SMTP_PORT" "587"
set_env_var "PFV_SMTP_USERNAME" "\"\""
set_env_var "PFV_SMTP_PASSWORD" "\"\""
set_env_var "PFV_SMTP_FROM" "\"\""
set_env_var "PFV_SMTP_USE_TLS" "true"
set_env_var "PFV_SMTP_USE_SSL" "false"

# SMS defaults
set_env_var "PFV_SMS_PROVIDER" "\"smtp_gateway\""
set_env_var "PFV_TWILIO_ACCOUNT_SID" "\"\""
set_env_var "PFV_TWILIO_AUTH_TOKEN" "\"\""
set_env_var "PFV_TWILIO_FROM_NUMBER" "\"\""

# Required crypto keys
if env_value_is_missing_or_placeholder "PFV_TOTP_ENCRYPTION_KEY"; then
  log "Generating PFV_TOTP_ENCRYPTION_KEY"
  set_env_var "PFV_TOTP_ENCRYPTION_KEY" "\"$(python3 scripts/generate_fernet_key.py)\""
fi

if env_value_is_missing_or_placeholder "PFV_MASTER_KEY"; then
  log "Generating PFV_MASTER_KEY"
  set_env_var "PFV_MASTER_KEY" "\"$(python3 scripts/generate_aes_key.py)\""
fi

# Ensure passphrase file exists
PASSFILE="$(read_env_value PFV_PASSPHRASE_FILE)"
if [[ -n "$PASSFILE" && ! -f "$PASSFILE" ]]; then
  log "Creating passphrase file at $PASSFILE"
  ensure_dir "$(dirname "$PASSFILE")"
  umask 077
  python3 - <<'PY' > "$PASSFILE"
import secrets
print(secrets.token_urlsafe(48))
PY
  chmod 600 "$PASSFILE" || true
fi

# Ensure storage directories + salt path exist
VAULT_PATH="$(read_env_value PFV_VAULT_BASE_PATH)"
STAGING_PATH="$(read_env_value PFV_STAGING_PATH)"
SALTFILE="$(read_env_value PFV_SALT_FILE)"

log "Ensuring storage directories"
ensure_dir "${VAULT_PATH:-/var/lib/pfv}"
ensure_dir "${STAGING_PATH:-/var/lib/pfv_staging}"
ensure_dir "$(dirname "${SALTFILE:-/var/lib/pfv/salt.bin}")"

if [[ -n "$SALTFILE" && ! -f "$SALTFILE" ]]; then
  log "Generating salt file at $SALTFILE"
  umask 077
  if ! python3 - "$SALTFILE" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
with path.open("xb") as fh:
    fh.write(os.urandom(16))
PY
  then
    run_sudo python3 - "$SALTFILE" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
with path.open("xb") as fh:
    fh.write(os.urandom(16))
PY
    run_sudo chown "$CURRENT_USER":"$CURRENT_USER" "$SALTFILE" || true
  fi
  chmod 600 "$SALTFILE" || true
fi

# PostgreSQL setup
if ! command -v psql >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    log "psql not found. Installing PostgreSQL packages..."
    run_sudo apt-get update
    run_sudo apt-get install -y postgresql postgresql-client
  else
    fail "psql not found and apt-get is unavailable."
  fi
fi

if command -v systemctl >/dev/null 2>&1; then
  if ! systemctl is-active --quiet postgresql; then
    log "Starting PostgreSQL service"
    run_sudo systemctl start postgresql
  fi
else
  warn "systemctl not found; ensure PostgreSQL service is running."
fi

log "Ensuring PostgreSQL role/database (pfv/pfv)"
if [[ "$(psql_postgres "SELECT 1 FROM pg_roles WHERE rolname='pfv';" | tr -d '[:space:]')" != "1" ]]; then
  psql_postgres "CREATE USER pfv WITH PASSWORD 'pfv';"
else
  log "Role pfv already exists."
fi

if [[ "$(psql_postgres "SELECT 1 FROM pg_database WHERE datname='pfv';" | tr -d '[:space:]')" != "1" ]]; then
  psql_postgres "CREATE DATABASE pfv OWNER pfv;"
else
  log "Database pfv already exists."
fi

log "Running schema initialization/migrations"
python3 -c 'from app.db_init import init_db; print(init_db())'

log "Setup complete."
log "Start server with:"
log "  ./start_script.sh --restart"
