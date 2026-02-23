from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import inspect, or_, text

from app.config import settings
from app.db import Base, SessionLocal, engine
from app.models import core as _core  # noqa: F401  (register models)
from app.models.core import DirectMessage, DirectMessageReport
from app.services.message_crypto import (
    DM_ATTACHMENT_SCHEME_RECIPIENT,
    DM_ATTACHMENT_SCHEME_SYSTEM,
    encrypt_message,
    encrypt_message_attachment_to_path,
)

logger = logging.getLogger(__name__)


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
        if not has_column("users", "email"):
            stmts.append("ALTER TABLE users ADD COLUMN email VARCHAR(320)")
        if not has_column("users", "email_visible"):
            stmts.append("ALTER TABLE users ADD COLUMN email_visible BOOLEAN NOT NULL DEFAULT FALSE")
        if not has_column("users", "email_verified"):
            stmts.append("ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE")
        if not has_column("users", "email_verification_token_hash"):
            stmts.append("ALTER TABLE users ADD COLUMN email_verification_token_hash VARCHAR(128)")
        if not has_column("users", "email_verification_sent_at"):
            stmts.append("ALTER TABLE users ADD COLUMN email_verification_sent_at TIMESTAMP")
        if not has_column("users", "email_verification_expires_at"):
            stmts.append("ALTER TABLE users ADD COLUMN email_verification_expires_at TIMESTAMP")
        if not has_column("users", "phone_number"):
            stmts.append("ALTER TABLE users ADD COLUMN phone_number VARCHAR(48)")
        if not has_column("users", "sms_carrier"):
            stmts.append("ALTER TABLE users ADD COLUMN sms_carrier VARCHAR(32)")
        if not has_column("users", "email_mfa_enabled"):
            stmts.append("ALTER TABLE users ADD COLUMN email_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE")
        if not has_column("users", "sms_mfa_enabled"):
            stmts.append("ALTER TABLE users ADD COLUMN sms_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE")
        if not has_column("users", "mfa_preferred_method"):
            stmts.append("ALTER TABLE users ADD COLUMN mfa_preferred_method VARCHAR(16)")
        if not has_column("users", "mfa_challenge_method"):
            stmts.append("ALTER TABLE users ADD COLUMN mfa_challenge_method VARCHAR(16)")
        if not has_column("users", "mfa_challenge_code_hash"):
            stmts.append("ALTER TABLE users ADD COLUMN mfa_challenge_code_hash VARCHAR(128)")
        if not has_column("users", "mfa_challenge_expires_at"):
            stmts.append("ALTER TABLE users ADD COLUMN mfa_challenge_expires_at TIMESTAMP")
        if not has_column("users", "mfa_challenge_sent_at"):
            stmts.append("ALTER TABLE users ADD COLUMN mfa_challenge_sent_at TIMESTAMP")
        if not has_column("users", "mfa_challenge_attempts"):
            stmts.append("ALTER TABLE users ADD COLUMN mfa_challenge_attempts INTEGER NOT NULL DEFAULT 0")
        if not has_column("users", "profile_image_path"):
            stmts.append("ALTER TABLE users ADD COLUMN profile_image_path TEXT")
        if not has_column("users", "profile_image_nonce"):
            stmts.append("ALTER TABLE users ADD COLUMN profile_image_nonce VARCHAR(64)")
        if not has_column("users", "profile_image_tag"):
            stmts.append("ALTER TABLE users ADD COLUMN profile_image_tag VARCHAR(64)")
        if not has_column("users", "profile_image_mime_type"):
            stmts.append("ALTER TABLE users ADD COLUMN profile_image_mime_type VARCHAR(255)")
        if not has_column("users", "ui_view_mode"):
            stmts.append("ALTER TABLE users ADD COLUMN ui_view_mode VARCHAR(16) NOT NULL DEFAULT 'base'")
        if not has_column("users", "is_admin"):
            stmts.append("ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE")
        if not has_column("users", "is_superadmin"):
            stmts.append("ALTER TABLE users ADD COLUMN is_superadmin BOOLEAN NOT NULL DEFAULT FALSE")
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
        if not has_column("users", "security_compromised"):
            stmts.append("ALTER TABLE users ADD COLUMN security_compromised BOOLEAN NOT NULL DEFAULT FALSE")
        if not has_column("users", "security_compromised_at"):
            stmts.append("ALTER TABLE users ADD COLUMN security_compromised_at TIMESTAMP")
        if not has_column("users", "security_compromise_note"):
            stmts.append("ALTER TABLE users ADD COLUMN security_compromise_note TEXT")
        if not has_column("users", "directory_locked"):
            stmts.append("ALTER TABLE users ADD COLUMN directory_locked BOOLEAN NOT NULL DEFAULT FALSE")
        if not has_column("users", "directory_locked_at"):
            stmts.append("ALTER TABLE users ADD COLUMN directory_locked_at TIMESTAMP")
        if not has_column("users", "directory_lock_reason"):
            stmts.append("ALTER TABLE users ADD COLUMN directory_lock_reason TEXT")
        if not has_column("users", "directory_locked_by_admin_id"):
            stmts.append("ALTER TABLE users ADD COLUMN directory_locked_by_admin_id UUID")

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
        if not has_column("direct_messages", "attachment_key_scheme"):
            stmts.append("ALTER TABLE direct_messages ADD COLUMN attachment_key_scheme VARCHAR(32)")
        if not has_column("direct_messages", "attachment_mime_type"):
            stmts.append("ALTER TABLE direct_messages ADD COLUMN attachment_mime_type VARCHAR(255)")

    if "audit_logs" in table_names:
        if not has_column("audit_logs", "ip_address"):
            stmts.append("ALTER TABLE audit_logs ADD COLUMN ip_address VARCHAR(64)")

    if "support_tickets" in table_names:
        if not has_column("support_tickets", "ticket_number"):
            stmts.append("ALTER TABLE support_tickets ADD COLUMN ticket_number INTEGER")

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
            conn.execute(
                text(
                    """
                    UPDATE direct_messages
                    SET attachment_key_scheme = :scheme
                    WHERE attachment_path IS NOT NULL
                      AND attachment_enc_nonce IS NOT NULL
                      AND attachment_enc_tag IS NOT NULL
                      AND attachment_key_scheme IS NULL
                    """
                ),
                {"scheme": DM_ATTACHMENT_SCHEME_RECIPIENT},
            )

        if "support_tickets" in table_names:
            # Human-readable 6-digit ticket number (starts at 000001).
            conn.execute(text("CREATE SEQUENCE IF NOT EXISTS support_ticket_number_seq START WITH 1 INCREMENT BY 1"))
            conn.execute(
                text(
                    """
                    WITH duplicate_rows AS (
                        SELECT id
                        FROM (
                            SELECT
                                id,
                                row_number() OVER (PARTITION BY ticket_number ORDER BY created_at ASC NULLS LAST, id ASC) AS rn
                            FROM support_tickets
                            WHERE ticket_number BETWEEN 1 AND 999999
                        ) ranked
                        WHERE ranked.rn > 1
                    )
                    UPDATE support_tickets st
                    SET ticket_number = NULL
                    FROM duplicate_rows d
                    WHERE st.id = d.id
                    """
                )
            )
            conn.execute(
                text(
                    """
                    WITH bounds AS (
                        SELECT MAX(ticket_number) AS max_number
                        FROM support_tickets
                        WHERE ticket_number BETWEEN 1 AND 999999
                    )
                    SELECT setval(
                        'support_ticket_number_seq',
                        COALESCE((SELECT max_number FROM bounds), 1),
                        (SELECT max_number IS NOT NULL FROM bounds)
                    )
                    """
                )
            )
            conn.execute(
                text(
                    """
                    UPDATE support_tickets
                    SET ticket_number = nextval('support_ticket_number_seq')
                    WHERE ticket_number IS NULL
                       OR ticket_number < 1
                       OR ticket_number > 999999
                    """
                )
            )
            conn.execute(
                text(
                    """
                    ALTER TABLE support_tickets
                    ALTER COLUMN ticket_number
                    SET DEFAULT nextval('support_ticket_number_seq')
                    """
                )
            )
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_support_tickets_ticket_number ON support_tickets (ticket_number)"))

        # Ensure at least one system administrator exists for admin UI bootstrap.
        if "users" in table_names:
            conn.execute(
                text(
                    """
                    UPDATE users
                    SET ui_view_mode = 'base'
                    WHERE ui_view_mode IS NULL
                       OR ui_view_mode NOT IN ('base', 'advanced')
                    """
                )
            )
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

            # Ensure at least one superadmin exists and that superadmins remain admins.
            has_superadmin = conn.execute(text("SELECT EXISTS(SELECT 1 FROM users WHERE is_superadmin = TRUE)")).scalar()
            if not has_superadmin:
                promoted_super = conn.execute(
                    text(
                        """
                        UPDATE users
                        SET is_superadmin = TRUE,
                            is_admin = TRUE
                        WHERE id = (
                            SELECT id
                            FROM users
                            ORDER BY is_admin DESC, created_at ASC NULLS LAST, id ASC
                            LIMIT 1
                        )
                        """
                    )
                )
                if promoted_super.rowcount and promoted_super.rowcount > 0:
                    schema_changed = True
            else:
                normalized = conn.execute(
                    text(
                        """
                        UPDATE users
                        SET is_admin = TRUE
                        WHERE is_superadmin = TRUE
                          AND is_admin IS DISTINCT FROM TRUE
                        """
                    )
                )
                if normalized.rowcount and normalized.rowcount > 0:
                    schema_changed = True

    return "schema updated" if schema_changed else "schema ok"


def _message_attachment_root() -> Path:
    root = Path(settings.staging_path) / "messages"
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def _safe_message_attachment_path(path_str: str) -> Path | None:
    root = _message_attachment_root()
    try:
        candidate = Path(path_str).resolve()
    except OSError:
        return None
    if not candidate.is_relative_to(root):
        return None
    return candidate


def _migrate_message_payload_encryption() -> bool:
    db = SessionLocal()
    changed = False
    try:
        unencrypted_messages = (
            db.query(DirectMessage)
            .filter(~DirectMessage.body.like("enc:v1:%"))
            .all()
        )
        for row in unencrypted_messages:
            row.body = encrypt_message(row.body or "")
            changed = True

        unencrypted_report_details = (
            db.query(DirectMessageReport)
            .filter(
                DirectMessageReport.details.is_not(None),
                ~DirectMessageReport.details.like("enc:v1:%"),
            )
            .all()
        )
        for row in unencrypted_report_details:
            row.details = encrypt_message(row.details or "")
            changed = True

        unencrypted_admin_notes = (
            db.query(DirectMessageReport)
            .filter(
                DirectMessageReport.admin_notes.is_not(None),
                ~DirectMessageReport.admin_notes.like("enc:v1:%"),
            )
            .all()
        )
        for row in unencrypted_admin_notes:
            row.admin_notes = encrypt_message(row.admin_notes or "")
            changed = True

        legacy_plain_attachments = (
            db.query(DirectMessage)
            .filter(
                DirectMessage.attachment_path.is_not(None),
                or_(DirectMessage.attachment_enc_nonce.is_(None), DirectMessage.attachment_enc_tag.is_(None)),
            )
            .all()
        )
        for row in legacy_plain_attachments:
            if not row.attachment_path:
                continue

            path = _safe_message_attachment_path(row.attachment_path)
            if not path or not path.exists() or not path.is_file():
                continue

            tmp = path.with_name(f"{path.name}.dmenc.tmp")
            try:
                with path.open("rb") as src:
                    nonce_b64, tag_b64, plain_size = encrypt_message_attachment_to_path(src, tmp)
                tmp.replace(path)
            except Exception:
                logger.warning("Failed to migrate direct-message attachment %s", row.id, exc_info=True)
                try:
                    if tmp.exists():
                        tmp.unlink()
                except OSError:
                    pass
                continue

            row.attachment_enc_nonce = nonce_b64
            row.attachment_enc_tag = tag_b64
            row.attachment_size = plain_size
            row.attachment_key_scheme = DM_ATTACHMENT_SCHEME_SYSTEM
            changed = True

        scheme_missing_rows = (
            db.query(DirectMessage)
            .filter(
                DirectMessage.attachment_path.is_not(None),
                DirectMessage.attachment_enc_nonce.is_not(None),
                DirectMessage.attachment_enc_tag.is_not(None),
                DirectMessage.attachment_key_scheme.is_(None),
            )
            .all()
        )
        for row in scheme_missing_rows:
            row.attachment_key_scheme = DM_ATTACHMENT_SCHEME_RECIPIENT
            changed = True

        if changed:
            db.commit()
            logger.info("Direct-message encryption migration applied.")
        return changed
    except Exception:
        db.rollback()
        logger.warning("Direct-message encryption migration failed; continuing startup.", exc_info=True)
        return False
    finally:
        db.close()


def init_db() -> str:
    Base.metadata.create_all(engine)
    schema_status = ensure_schema()
    migrated = _migrate_message_payload_encryption()
    if migrated:
        return f"{schema_status}; message encryption migrated"
    return schema_status
