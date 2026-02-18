from __future__ import annotations

from sqlalchemy import inspect, text

from app.db import Base, engine
from app.models import core as _core  # noqa: F401  (register models)


def ensure_schema() -> str:
    insp = inspect(engine)
    table_names = set(insp.get_table_names())

    def has_column(table: str, col: str) -> bool:
        return any(c["name"] == col for c in insp.get_columns(table))

    stmts: list[str] = []

    # Create missing tables early (Base.metadata.create_all handles most, but keep this explicit for safety).
    # user_keys is new and should exist if DB was created before the model was added.

    if "files" in table_names:
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

    if "users" in table_names:
        if not has_column("users", "is_admin"):
            stmts.append("ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE")
        if not has_column("users", "is_disabled"):
            stmts.append("ALTER TABLE users ADD COLUMN is_disabled BOOLEAN NOT NULL DEFAULT FALSE")
        if not has_column("users", "disabled_at"):
            stmts.append("ALTER TABLE users ADD COLUMN disabled_at TIMESTAMP")
        if not has_column("users", "disabled_reason"):
            stmts.append("ALTER TABLE users ADD COLUMN disabled_reason TEXT")
        if not has_column("users", "messaging_disabled"):
            stmts.append("ALTER TABLE users ADD COLUMN messaging_disabled BOOLEAN NOT NULL DEFAULT FALSE")
        if not has_column("users", "messaging_disabled_at"):
            stmts.append("ALTER TABLE users ADD COLUMN messaging_disabled_at TIMESTAMP")

    if "direct_messages" in table_names:
        if not has_column("direct_messages", "thread_id"):
            stmts.append("ALTER TABLE direct_messages ADD COLUMN thread_id UUID")
        if not has_column("direct_messages", "attachment_name"):
            stmts.append("ALTER TABLE direct_messages ADD COLUMN attachment_name VARCHAR(255)")
        if not has_column("direct_messages", "attachment_path"):
            stmts.append("ALTER TABLE direct_messages ADD COLUMN attachment_path TEXT")
        if not has_column("direct_messages", "attachment_size"):
            stmts.append("ALTER TABLE direct_messages ADD COLUMN attachment_size INTEGER")
        if not has_column("direct_messages", "attachment_enc_nonce"):
            stmts.append("ALTER TABLE direct_messages ADD COLUMN attachment_enc_nonce VARCHAR(64)")
        if not has_column("direct_messages", "attachment_enc_tag"):
            stmts.append("ALTER TABLE direct_messages ADD COLUMN attachment_enc_tag VARCHAR(64)")
        if not has_column("direct_messages", "attachment_mime_type"):
            stmts.append("ALTER TABLE direct_messages ADD COLUMN attachment_mime_type VARCHAR(255)")

    if "audit_logs" in table_names:
        if not has_column("audit_logs", "ip_address"):
            stmts.append("ALTER TABLE audit_logs ADD COLUMN ip_address VARCHAR(64)")

    schema_changed = False
    with engine.begin() as conn:
        if stmts:
            schema_changed = True
            for stmt in stmts:
                conn.execute(text(stmt))

        # Best-effort cleanup for earlier dev DBs where is_encrypted might have been defaulted incorrectly.
        if "files" in table_names:
            conn.execute(text("UPDATE files SET is_encrypted = FALSE WHERE enc_nonce IS NULL OR enc_tag IS NULL"))
            conn.execute(text("UPDATE files SET is_encrypted = TRUE WHERE enc_nonce IS NOT NULL AND enc_tag IS NOT NULL"))

        if "direct_messages" in table_names:
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_direct_messages_thread_id ON direct_messages (thread_id)"))
            # Keep legacy rows queryable in threads without destructive rewrites.
            conn.execute(text("UPDATE direct_messages SET thread_id = id WHERE thread_id IS NULL"))

        # Ensure at least one system administrator exists for admin UI bootstrap.
        if "users" in table_names:
            has_admin = conn.execute(text("SELECT EXISTS(SELECT 1 FROM users WHERE is_admin = TRUE)")).scalar()
            if not has_admin:
                promoted = conn.execute(
                    text(
                        """
                        UPDATE users
                        SET is_admin = TRUE
                        WHERE id = (
                            SELECT id
                            FROM users
                            ORDER BY created_at ASC NULLS LAST, id ASC
                            LIMIT 1
                        )
                        """
                    )
                )
                if promoted.rowcount and promoted.rowcount > 0:
                    schema_changed = True

    return "schema updated" if schema_changed else "schema ok"


def init_db() -> str:
    Base.metadata.create_all(engine)
    return ensure_schema()
