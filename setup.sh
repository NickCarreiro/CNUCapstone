#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

log() {
  printf "[setup] %s\n" "$1"
}

ensure_dir() {
  local dir="$1"
  if [ -d "$dir" ]; then
    return 0
  fi
  if mkdir -p "$dir" 2>/dev/null; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo mkdir -p "$dir"
    sudo chown "$USER" "$dir"
    return 0
  fi
  log "Could not create $dir (no permissions)."
  return 1
}

if ! command -v python3 >/dev/null 2>&1; then
  log "python3 not found. Install Python 3."
  exit 1
fi

# --- VENV SECTION REMOVED ---
# Using global python3 and pip as per user request
# ----------------------------

log "Installing Python dependencies (Global)"
python3 -m pip install --upgrade pip --break-system-packages || true
python3 -m pip install -r requirements.txt --break-system-packages

if [ ! -f .env ]; then
  log "Creating .env from .env.example"
  cp .env.example .env
  TOTP_KEY="$(python3 scripts/generate_fernet_key.py)"
  sed -i "s/^PFV_TOTP_ENCRYPTION_KEY=.*/PFV_TOTP_ENCRYPTION_KEY=\"$TOTP_KEY\"/" .env
  MASTER_KEY="$(python3 scripts/generate_aes_key.py)"
  sed -i "s/^PFV_MASTER_KEY=.*/PFV_MASTER_KEY=\"$MASTER_KEY\"/" .env
fi

# Ensure keys are set in .env
for KEY_TYPE in TOTP_ENCRYPTION MASTER; do
    if ! grep -q "^PFV_${KEY_TYPE}_KEY=" .env || grep -q "^PFV_${KEY_TYPE}_KEY=\"CHANGE_ME\"$" .env; then
      log "Setting PFV_${KEY_TYPE}_KEY in .env"
      VAL="$(python3 scripts/generate_$(echo $KEY_TYPE | tr '[:upper:]' '[:lower:]')_key.py)"
      sed -i "s/^PFV_${KEY_TYPE}_KEY=.*/PFV_${KEY_TYPE}_KEY=\"$VAL\"/" .env
    fi
done

if ! grep -q '^PFV_PASSPHRASE_FILE=' .env; then
  log "Setting PFV_PASSPHRASE_FILE in .env"
  printf '\nPFV_PASSPHRASE_FILE=\"%s\"\n' "passphrase.txt" >> .env
fi

if ! grep -q '^PFV_SALT_FILE=' .env; then
  log "Setting PFV_SALT_FILE in .env"
  printf '\nPFV_SALT_FILE=\"%s\"\n' "/var/lib/pfv/salt.bin" >> .env
fi

# Extract settings using global python
PASSFILE="$(python3 - <<'PY'
from app.config import settings
print(settings.passphrase_file or "")
PY
)"
SALTFILE="$(python3 - <<'PY'
from app.config import settings
print(settings.salt_file)
PY
)"

if [ -n "$PASSFILE" ] && [ ! -f "$PASSFILE" ]; then
  log "Passphrase file not found: $PASSFILE. Creating dummy passphrase.txt..."
  echo "change_this_secret_passphrase" > passphrase.txt
fi

if [ -n "$PASSFILE" ] && [ ! -f "$SALTFILE" ]; then
    log "Generating salt file at $SALTFILE"
    SALT_DIR="$(dirname "$SALTFILE")"
    ensure_dir "$SALT_DIR" || true
    sudo python3 -c "import os; p=r'$SALTFILE'; os.makedirs(os.path.dirname(p), exist_ok=True); open(p,'xb').write(os.urandom(16))"
    sudo chmod 600 "$SALTFILE" || true
    sudo chown "$USER" "$SALTFILE" || true
fi

log "Ensuring storage directories"
ensure_dir "/var/lib/pfv" || true
ensure_dir "/var/lib/pfv_staging" || true

if ! command -v psql >/dev/null 2>&1; then
  log "psql not found. Installing PostgreSQL..."
  sudo apt update && sudo apt install -y postgresql
fi

if ! systemctl is-active --quiet postgresql; then
    log "Starting PostgreSQL service"
    sudo systemctl start postgresql
fi

log "Setting up PostgreSQL Database and User"
sudo -u postgres psql -c "ALTER DATABASE template1 REFRESH COLLATION VERSION;" >/dev/null || true
sudo -u postgres psql -c "CREATE USER pfv WITH PASSWORD 'pfv';" 2>/dev/null || log "User pfv already exists."
sudo -u postgres psql -c "CREATE DATABASE pfv OWNER pfv;" 2>/dev/null || log "Database pfv already exists."

log "Creating database tables + ensuring schema"
python3 -c 'from app.db_init import init_db; print(init_db())'

log "Setup complete. Start the server with:"
log "  python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000"
