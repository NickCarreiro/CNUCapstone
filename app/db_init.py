from __future__ import annotations

from sqlalchemy import inspect, text

from app.db import Base, engine
from app.models import core as _core  # noqa: F401  (register models)


def ensure_schema() -> str:
    insp = inspect(engine)

    def has_column(table: str, col: str) -> bool:
        return any(c["name"] == col for c in insp.get_columns(table))

    stmts: list[str] = []

    # Create missing tables early (Base.metadata.create_all handles most, but keep this explicit for safety).
    # user_keys is new and should exist if DB was created before the model was added.

    if "files" in insp.get_table_names():
        if not has_column("files", "original_path"):
            stmts.append("ALTER TABLE files ADD COLUMN original_path TEXT")
        if not has_column("files", "is_trashed"):
            stmts.append("ALTER TABLE files ADD COLUMN is_trashed BOOLEAN NOT NULL DEFAULT FALSE")
        if not has_column("files", "trashed_at"):
            stmts.append("ALTER TABLE files ADD COLUMN trashed_at TIMESTAMP")
        if not has_column("files", "is_encrypted"):
            stmts.append("ALTER TABLE files ADD COLUMN is_encrypted BOOLEAN NOT NULL DEFAULT FALSE")
        if not has_column("files", "enc_nonce"):
            stmts.append("ALTER TABLE files ADD COLUMN enc_nonce VARCHAR(64)")
        if not has_column("files", "enc_tag"):
            stmts.append("ALTER TABLE files ADD COLUMN enc_tag VARCHAR(64)")
        if not has_column("files", "mime_type"):
            stmts.append("ALTER TABLE files ADD COLUMN mime_type VARCHAR(255)")

    if not stmts:
        # Best-effort cleanup for earlier dev DBs where is_encrypted might have been defaulted incorrectly.
        with engine.begin() as conn:
            conn.execute(text("UPDATE files SET is_encrypted = FALSE WHERE enc_nonce IS NULL OR enc_tag IS NULL"))
            conn.execute(text("UPDATE files SET is_encrypted = TRUE WHERE enc_nonce IS NOT NULL AND enc_tag IS NOT NULL"))
        return "schema ok"

    with engine.begin() as conn:
        for stmt in stmts:
            conn.execute(text(stmt))
        conn.execute(text("UPDATE files SET is_encrypted = FALSE WHERE enc_nonce IS NULL OR enc_tag IS NULL"))
        conn.execute(text("UPDATE files SET is_encrypted = TRUE WHERE enc_nonce IS NOT NULL AND enc_tag IS NOT NULL"))

    return "schema updated"


def init_db() -> str:
    Base.metadata.create_all(engine)
    return ensure_schema()
