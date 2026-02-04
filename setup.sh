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

if [ ! -d .venv ]; then
  log "Creating virtual environment"
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

log "Installing Python dependencies"
python -m pip install --upgrade pip >/dev/null
pip install -r requirements.txt

if [ ! -f .env ]; then
  log "Creating .env from .env.example"
  cp .env.example .env
  # If you use passphrase-based key derivation, you only need to manage passphrase.txt.
  # Salt is generated below (if missing) at PFV_SALT_FILE.
  TOTP_KEY="$(python scripts/generate_fernet_key.py)"
  sed -i "s/^PFV_TOTP_ENCRYPTION_KEY=.*/PFV_TOTP_ENCRYPTION_KEY=\"$TOTP_KEY\"/" .env
  MASTER_KEY="$(python scripts/generate_aes_key.py)"
  sed -i "s/^PFV_MASTER_KEY=.*/PFV_MASTER_KEY=\"$MASTER_KEY\"/" .env
fi

if ! grep -q '^PFV_TOTP_ENCRYPTION_KEY=' .env || grep -q '^PFV_TOTP_ENCRYPTION_KEY="CHANGE_ME"$' .env; then
  log "Setting PFV_TOTP_ENCRYPTION_KEY in .env"
  TOTP_KEY="$(python scripts/generate_fernet_key.py)"
  if grep -q '^PFV_TOTP_ENCRYPTION_KEY=' .env; then
    sed -i "s/^PFV_TOTP_ENCRYPTION_KEY=.*/PFV_TOTP_ENCRYPTION_KEY=\"$TOTP_KEY\"/" .env
  else
    printf '\nPFV_TOTP_ENCRYPTION_KEY=\"%s\"\n' "$TOTP_KEY" >> .env
  fi
fi

if ! grep -q '^PFV_MASTER_KEY=' .env || grep -q '^PFV_MASTER_KEY="CHANGE_ME"$' .env; then
  log "Setting PFV_MASTER_KEY in .env"
  MASTER_KEY="$(python scripts/generate_aes_key.py)"
  if grep -q '^PFV_MASTER_KEY=' .env; then
    sed -i "s/^PFV_MASTER_KEY=.*/PFV_MASTER_KEY=\"$MASTER_KEY\"/" .env
  else
    printf '\nPFV_MASTER_KEY=\"%s\"\n' "$MASTER_KEY" >> .env
  fi
fi

if ! grep -q '^PFV_PASSPHRASE_FILE=' .env; then
  log "Setting PFV_PASSPHRASE_FILE in .env (passphrase-derived keys)"
  printf '\nPFV_PASSPHRASE_FILE=\"%s\"\n' "passphrase.txt" >> .env
fi

if ! grep -q '^PFV_SALT_FILE=' .env; then
  log "Setting PFV_SALT_FILE in .env"
  printf '\nPFV_SALT_FILE=\"%s\"\n' "/var/lib/pfv/salt.bin" >> .env
fi

PASSFILE="$(python - <<'PY'
from app.config import settings
print(settings.passphrase_file or "")
PY
)"
SALTFILE="$(python - <<'PY'
from app.config import settings
print(settings.salt_file)
PY
)"

if [ -n "$PASSFILE" ] && [ ! -f "$PASSFILE" ]; then
  log "Passphrase file not found: $PASSFILE"
  log "Create it (one line, keep it secret) and rerun setup."
  exit 1
fi

if [ -n "$PASSFILE" ]; then
  if [ ! -f "$SALTFILE" ]; then
    log "Generating salt file at $SALTFILE"
    SALT_DIR="$(dirname "$SALTFILE")"
    ensure_dir "$SALT_DIR" || true

    if python - <<PY
import os
p=r"$SALTFILE"
os.makedirs(os.path.dirname(p), exist_ok=True)
open(p,"xb").write(os.urandom(16))
print("wrote", p)
PY
    then
      true
    elif command -v sudo >/dev/null 2>&1; then
      sudo python3 - <<PY
import os
p=r"$SALTFILE"
os.makedirs(os.path.dirname(p), exist_ok=True)
open(p,"xb").write(os.urandom(16))
print("wrote", p)
PY
      sudo chmod 600 "$SALTFILE" || true
      sudo chown "$USER" "$SALTFILE" || true
    else
      log "Could not create salt file (no permissions)."
      exit 1
    fi
  fi
fi

log "Ensuring storage directories"
ensure_dir "/var/lib/pfv" || true
ensure_dir "/var/lib/pfv_staging" || true

if ! command -v psql >/dev/null 2>&1; then
  log "psql not found. Install PostgreSQL and rerun: sudo apt install -y postgresql"
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  if ! systemctl is-active --quiet postgresql; then
    log "Starting PostgreSQL service"
    if command -v sudo >/dev/null 2>&1; then
      sudo systemctl start postgresql
    else
      log "Cannot start PostgreSQL (sudo not available). Start it manually."
      exit 1
    fi
  fi
fi

if command -v sudo >/dev/null 2>&1; then
  log "Refreshing PostgreSQL collation metadata (safe if already up to date)"
  sudo -u postgres psql -c "ALTER DATABASE template1 REFRESH COLLATION VERSION;" >/dev/null || true
  sudo -u postgres psql -c "ALTER DATABASE postgres REFRESH COLLATION VERSION;" >/dev/null || true

  if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='pfv'" | grep -q 1; then
    log "Creating database role 'pfv'"
    sudo -u postgres psql -c "CREATE USER pfv WITH PASSWORD 'pfv';"
  fi

  if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='pfv'" | grep -q 1; then
    log "Creating database 'pfv'"
    sudo -u postgres psql -c "CREATE DATABASE pfv OWNER pfv;"
  fi
else
  log "sudo not available. Create the pfv role and database manually."
  log "Example: sudo -u postgres psql -c \"CREATE USER pfv WITH PASSWORD 'pfv';\""
  log "Example: sudo -u postgres psql -c \"CREATE DATABASE pfv OWNER pfv;\""
  exit 1
fi

log "Creating database tables + ensuring schema"
python -c 'from app.db_init import init_db; print(init_db())'

log "Setup complete. Start the server with:"
log "  python -m uvicorn app.main:app --reload --port 8001"
