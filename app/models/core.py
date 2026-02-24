import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    email_visible: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verification_token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    email_verification_sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    email_verification_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    phone_number: Mapped[str | None] = mapped_column(String(48), nullable=True)
    sms_carrier: Mapped[str | None] = mapped_column(String(32), nullable=True)
    email_mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    sms_mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_preferred_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    mfa_challenge_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    mfa_challenge_code_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mfa_challenge_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    mfa_challenge_sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    mfa_challenge_attempts: Mapped[int] = mapped_column(Integer, default=0)
    profile_image_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    profile_image_nonce: Mapped[str | None] = mapped_column(String(64), nullable=True)
    profile_image_tag: Mapped[str | None] = mapped_column(String(64), nullable=True)
    profile_image_mime_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ui_view_mode: Mapped[str] = mapped_column(String(16), default="base")
    password_hash: Mapped[str] = mapped_column(String(255))
    totp_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_superadmin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    disabled_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    messaging_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    messaging_disabled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    security_compromised: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    security_compromised_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    security_compromise_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    directory_locked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    directory_locked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    directory_lock_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    directory_locked_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    sessions: Mapped[list["Session"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    files: Mapped[list["FileRecord"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    key: Mapped["UserKey | None"] = relationship(back_populates="user", cascade="all, delete-orphan", uselist=False)
    activity: Mapped[list["ActivityEvent"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    groups_owned: Mapped[list["Group"]] = relationship(
        back_populates="owner",
        cascade="all, delete-orphan",
        foreign_keys="Group.owner_id",
    )
    group_memberships: Mapped[list["GroupMembership"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    group_invites_sent: Mapped[list["GroupInvite"]] = relationship(
        back_populates="inviter",
        cascade="all, delete-orphan",
        foreign_keys="GroupInvite.inviter_id",
    )
    group_invites_received: Mapped[list["GroupInvite"]] = relationship(
        back_populates="invitee",
        cascade="all, delete-orphan",
        foreign_keys="GroupInvite.invitee_id",
    )
    messages_sent: Mapped[list["DirectMessage"]] = relationship(
        back_populates="sender",
        cascade="all, delete-orphan",
        foreign_keys="DirectMessage.sender_id",
    )
    messages_received: Mapped[list["DirectMessage"]] = relationship(
        back_populates="recipient",
        cascade="all, delete-orphan",
        foreign_keys="DirectMessage.recipient_id",
    )
    support_tickets_created: Mapped[list["SupportTicket"]] = relationship(
        back_populates="requester",
        cascade="all, delete-orphan",
        foreign_keys="SupportTicket.user_id",
    )
    support_tickets_assigned: Mapped[list["SupportTicket"]] = relationship(
        back_populates="assigned_admin",
        foreign_keys="SupportTicket.assigned_admin_id",
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    user: Mapped["User"] = relationship(back_populates="sessions")


class FileRecord(Base):
    __tablename__ = "files"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    file_name: Mapped[str] = mapped_column(String(255))
    file_path: Mapped[str] = mapped_column(Text)
    original_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_size: Mapped[int] = mapped_column(Integer)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_trashed: Mapped[bool] = mapped_column(Boolean, default=False)
    trashed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    enc_nonce: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enc_tag: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mime_type: Mapped[str | None] = mapped_column(String(255), nullable=True)

    user: Mapped["User"] = relationship(back_populates="files")


class UserKey(Base):
    __tablename__ = "user_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), unique=True, index=True)
    # base64url strings (nonce + ciphertext) wrapping the 32-byte DEK
    wrap_nonce: Mapped[str] = mapped_column(String(64))
    wrapped_dek: Mapped[str] = mapped_column(Text)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped["User"] = relationship(back_populates="key")


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(150), index=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    owner: Mapped["User"] = relationship(back_populates="groups_owned", foreign_keys=[owner_id])
    memberships: Mapped[list["GroupMembership"]] = relationship(back_populates="group", cascade="all, delete-orphan")
    invites: Mapped[list["GroupInvite"]] = relationship(back_populates="group", cascade="all, delete-orphan")
    key: Mapped["GroupKey | None"] = relationship(back_populates="group", cascade="all, delete-orphan", uselist=False)
    files: Mapped[list["GroupFileRecord"]] = relationship(back_populates="group", cascade="all, delete-orphan")


class GroupMembership(Base):
    __tablename__ = "group_memberships"
    __table_args__ = (UniqueConstraint("group_id", "user_id", name="uq_group_member"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("groups.id"), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(20), default="member")
    joined_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    group: Mapped["Group"] = relationship(back_populates="memberships")
    user: Mapped["User"] = relationship(back_populates="group_memberships")


class GroupInvite(Base):
    __tablename__ = "group_invites"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("groups.id"), index=True)
    inviter_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    invitee_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    responded_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    group: Mapped["Group"] = relationship(back_populates="invites")
    inviter: Mapped["User"] = relationship(back_populates="group_invites_sent", foreign_keys=[inviter_id])
    invitee: Mapped["User"] = relationship(back_populates="group_invites_received", foreign_keys=[invitee_id])


class DirectMessage(Base):
    __tablename__ = "direct_messages"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    thread_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    sender_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    recipient_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    body: Mapped[str] = mapped_column(Text)
    body_key_scheme: Mapped[str | None] = mapped_column(String(32), nullable=True)
    body_key_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attachment_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attachment_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    attachment_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attachment_enc_nonce: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attachment_enc_tag: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attachment_key_scheme: Mapped[str | None] = mapped_column(String(32), nullable=True)
    attachment_key_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attachment_mime_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    sender: Mapped["User"] = relationship(back_populates="messages_sent", foreign_keys=[sender_id])
    recipient: Mapped["User"] = relationship(back_populates="messages_received", foreign_keys=[recipient_id])


class DirectMessageReport(Base):
    __tablename__ = "direct_message_reports"
    __table_args__ = (UniqueConstraint("message_id", "reporter_id", name="uq_dm_report_once"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("direct_messages.id"), index=True)
    thread_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    reporter_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    reported_user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    reason: Mapped[str] = mapped_column(String(64))
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    reviewed_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    admin_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    action_taken: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    message: Mapped["DirectMessage"] = relationship(foreign_keys=[message_id])
    reporter: Mapped["User"] = relationship(foreign_keys=[reporter_id])
    reported_user: Mapped["User"] = relationship(foreign_keys=[reported_user_id])
    reviewed_by_admin: Mapped["User | None"] = relationship(foreign_keys=[reviewed_by_admin_id])


class SupportTicket(Base):
    __tablename__ = "support_tickets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ticket_number: Mapped[int | None] = mapped_column(Integer, unique=True, index=True, nullable=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    assigned_admin_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    subject: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(32), default="general", index=True)
    priority: Mapped[str] = mapped_column(String(16), default="normal", index=True)
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    admin_reply: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_admin_update_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    requester: Mapped["User"] = relationship(back_populates="support_tickets_created", foreign_keys=[user_id])
    assigned_admin: Mapped["User | None"] = relationship(back_populates="support_tickets_assigned", foreign_keys=[assigned_admin_id])


class GroupKey(Base):
    __tablename__ = "group_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("groups.id"), unique=True, index=True)
    wrap_nonce: Mapped[str] = mapped_column(String(64))
    wrapped_dek: Mapped[str] = mapped_column(Text)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    group: Mapped["Group"] = relationship(back_populates="key")


class ConversationKey(Base):
    __tablename__ = "conversation_keys"
    __table_args__ = (UniqueConstraint("thread_id", name="uq_conversation_key_thread"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    thread_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    user_low_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    user_high_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    wrap_nonce: Mapped[str] = mapped_column(String(64))
    wrapped_dek: Mapped[str] = mapped_column(Text)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class GroupFileRecord(Base):
    __tablename__ = "group_files"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("groups.id"), index=True)
    uploader_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    file_name: Mapped[str] = mapped_column(String(255))
    file_path: Mapped[str] = mapped_column(Text)
    file_size: Mapped[int] = mapped_column(Integer)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=True)
    enc_nonce: Mapped[str] = mapped_column(String(64))
    enc_tag: Mapped[str] = mapped_column(String(64))
    mime_type: Mapped[str | None] = mapped_column(String(255), nullable=True)

    group: Mapped["Group"] = relationship(back_populates="files")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(120))
    event_timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)


class ActivityEvent(Base):
    __tablename__ = "activity_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    level: Mapped[str] = mapped_column(String(16), default="INFO")
    action: Mapped[str] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(Text)

    user: Mapped["User"] = relationship(back_populates="activity")
