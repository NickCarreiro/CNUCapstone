import sys
from pathlib import Path

# Allow running as `python scripts/ensure_schema.py` from repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db_init import init_db  # noqa: E402


if __name__ == "__main__":
    print(init_db())
