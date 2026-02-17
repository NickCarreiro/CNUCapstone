from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
import mimetypes

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.db import get_db
from app.models.core import (
    DirectMessage,
    Group,
    GroupFileRecord,
    GroupInvite,
    GroupMembership,
    User,
)
from app.services.activity import add_event
from app.services.authn import get_current_user as resolve_current_user
from app.services.crypto import decrypt_file_iter, encrypt_file_to_path
from app.services.group_keystore import ensure_group_key, get_group_dek
from app.services.keystore import get_user_dek
from app.services.message_crypto import decrypt_message, encrypt_message

router = APIRouter(prefix="/ui/groups", tags=["groups"])
templates = Jinja2Templates(directory="templates")

ROLE_OWNER = "owner"
ROLE_ADMIN = "admin"
ROLE_MEMBER = "member"
ROLE_VIEWER = "viewer"

ROLE_RANK = {
    ROLE_VIEWER: 1,
    ROLE_MEMBER: 2,
    ROLE_ADMIN: 3,
    ROLE_OWNER: 4,
}

MANAGE_MEMBER_ROLES = (ROLE_VIEWER, ROLE_MEMBER, ROLE_ADMIN)
MESSAGE_ATTACHMENT_MAX_BYTES = 10 * 1024 * 1024


def _get_current_user(db: Session, request: Request) -> User | None:
    try:
        return resolve_current_user(request=request, db=db)
    except HTTPException:
        return None


def _must_user(db: Session, request: Request) -> User:
    user = _get_current_user(db, request)
    if not user:
        raise HTTPException(
            status_code=303,
            detail="Authentication required",
            headers={"Location": "/ui/login"},
        )
    return user


def _normalize_role(role: str | None) -> str:
    value = (role or "").strip().lower()
    return value if value in ROLE_RANK else ROLE_MEMBER


def _role_at_least(role: str | None, minimum: str) -> bool:
    return ROLE_RANK.get(_normalize_role(role), 0) >= ROLE_RANK[minimum]


def _get_group_membership(db: Session, group_id: uuid.UUID, user_id: uuid.UUID) -> GroupMembership | None:
    return (
        db.query(GroupMembership)
        .filter(GroupMembership.group_id == group_id, GroupMembership.user_id == user_id)
        .first()
    )


def _must_group_role(
    db: Session,
    user: User,
    group_id: str,
    minimum_role: str,
) -> tuple[Group, GroupMembership]:
    try:
        gid = uuid.UUID(group_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Group not found")

    group = db.query(Group).filter(Group.id == gid).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    membership = _get_group_membership(db, group.id, user.id)
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this group")

    if not _role_at_least(membership.role, minimum_role):
        raise HTTPException(status_code=403, detail="Insufficient group permissions")

    return group, membership


def _must_group_file(db: Session, group: Group, file_id: str) -> GroupFileRecord:
    try:
        fid = uuid.UUID(file_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="File not found")
    record = (
        db.query(GroupFileRecord)
        .filter(GroupFileRecord.id == fid, GroupFileRecord.group_id == group.id)
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="File not found")
    return record


def _group_root(group: Group) -> Path:
    root = Path(settings.staging_path) / "groups" / str(group.id)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _safe_group_path(group: Group, path_str: str) -> Path:
    root = _group_root(group).resolve()
    candidate = Path(path_str).resolve()
    if not candidate.is_relative_to(root):
        raise HTTPException(status_code=400, detail="Invalid file path")
    return candidate


def _message_attachment_root() -> Path:
    root = Path(settings.staging_path) / "messages"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _safe_message_attachment_path(path_str: str) -> Path:
    root = _message_attachment_root().resolve()
    candidate = Path(path_str).resolve()
    if not candidate.is_relative_to(root):
        raise HTTPException(status_code=400, detail="Invalid attachment path")
    return candidate


def _conversation_filter(user_a: uuid.UUID, user_b: uuid.UUID):
    return or_(
        and_(DirectMessage.sender_id == user_a, DirectMessage.recipient_id == user_b),
        and_(DirectMessage.sender_id == user_b, DirectMessage.recipient_id == user_a),
    )


def _resolve_thread_id(
    db: Session,
    *,
    sender_id: uuid.UUID,
    recipient_id: uuid.UUID,
    requested_thread: str | None,
) -> uuid.UUID:
    pair_filter = _conversation_filter(sender_id, recipient_id)
    if requested_thread:
        try:
            tid = uuid.UUID(requested_thread)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid thread id")

        exists = (
            db.query(DirectMessage.id)
            .filter(pair_filter, DirectMessage.thread_id == tid)
            .first()
        )
        if not exists:
            raise HTTPException(status_code=400, detail="Thread not found for this conversation")
        return tid

    latest_thread = (
        db.query(DirectMessage.thread_id)
        .filter(pair_filter, DirectMessage.thread_id.is_not(None))
        .order_by(DirectMessage.created_at.desc())
        .limit(1)
        .scalar()
    )
    return latest_thread or uuid.uuid4()


def _format_utc(value: datetime | None) -> str:
    if not value:
        return "-"
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


@router.get("")
def groups_home(
    request: Request,
    thread: str | None = None,
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    memberships = (
        db.query(GroupMembership)
        .options(joinedload(GroupMembership.group))
        .filter(GroupMembership.user_id == user.id)
        .order_by(GroupMembership.joined_at.desc())
        .all()
    )

    pending_invites = (
        db.query(GroupInvite)
        .options(joinedload(GroupInvite.group), joinedload(GroupInvite.inviter))
        .filter(GroupInvite.invitee_id == user.id, GroupInvite.status == "pending")
        .order_by(GroupInvite.created_at.desc())
        .all()
    )

    messages = (
        db.query(DirectMessage)
        .options(joinedload(DirectMessage.sender), joinedload(DirectMessage.recipient))
        .filter(or_(DirectMessage.sender_id == user.id, DirectMessage.recipient_id == user.id))
        .order_by(DirectMessage.created_at.desc())
        .limit(300)
        .all()
    )

    thread_buckets: dict[uuid.UUID, list[DirectMessage]] = {}
    thread_summaries: dict[uuid.UUID, dict] = {}
    for row in messages:
        thread_id = row.thread_id or row.id
        thread_buckets.setdefault(thread_id, []).append(row)

        partner = row.recipient if row.sender_id == user.id else row.sender
        preview = decrypt_message(row.body).replace("\n", " ").strip()
        if len(preview) > 82:
            preview = f"{preview[:79]}..."

        if thread_id not in thread_summaries:
            thread_summaries[thread_id] = {
                "thread_uuid": thread_id,
                "thread_id": str(thread_id),
                "partner_username": partner.username,
                "latest_preview": preview or "(attachment)",
                "latest_created_at": row.created_at,
                "latest_created_at_utc": _format_utc(row.created_at),
                "unread_count": 0,
            }

        if row.recipient_id == user.id and row.read_at is None:
            thread_summaries[thread_id]["unread_count"] += 1

    threads = sorted(
        thread_summaries.values(),
        key=lambda item: item["latest_created_at"] or datetime.min,
        reverse=True,
    )

    active_thread_uuid: uuid.UUID | None = None
    if thread:
        try:
            requested = uuid.UUID(thread)
            if requested in thread_buckets:
                active_thread_uuid = requested
        except ValueError:
            active_thread_uuid = None
    if not active_thread_uuid and threads:
        active_thread_uuid = threads[0]["thread_uuid"]

    active_thread_messages: list[DirectMessage] = []
    active_thread_summary: dict | None = None
    if active_thread_uuid:
        active_thread_messages = sorted(
            thread_buckets.get(active_thread_uuid, []),
            key=lambda row: row.created_at or datetime.min,
        )
        active_thread_summary = thread_summaries.get(active_thread_uuid)

    read_updates = 0
    for row in active_thread_messages:
        if row.recipient_id == user.id and row.read_at is None:
            row.read_at = datetime.utcnow()
            read_updates += 1
    if read_updates:
        db.commit()
        if active_thread_summary:
            active_thread_summary["unread_count"] = 0

    thread_messages = []
    for row in active_thread_messages:
        outbound = row.sender_id == user.id
        thread_messages.append(
            {
                "id": str(row.id),
                "thread_id": str(row.thread_id or row.id),
                "sender_username": row.sender.username,
                "recipient_username": row.recipient.username,
                "body": decrypt_message(row.body),
                "created_at": row.created_at,
                "created_at_utc": _format_utc(row.created_at),
                "direction": "Sent" if outbound else "Received",
                "is_outbound": outbound,
                "receipt": (
                    f"Read {_format_utc(row.read_at)}"
                    if outbound and row.read_at
                    else ("Delivered" if outbound else ("Read" if row.read_at else "Unread"))
                ),
                "has_attachment": bool(row.attachment_name and row.attachment_path),
                "attachment_name": row.attachment_name,
                "attachment_size": row.attachment_size,
                "attachment_url": f"/ui/groups/messages/{row.id}/attachment"
                if row.attachment_name and row.attachment_path
                else None,
            }
        )

    return templates.TemplateResponse(
        "groups.html",
        {
            "request": request,
            "user": user,
            "memberships": memberships,
            "pending_invites": pending_invites,
            "threads": threads,
            "thread_messages": thread_messages,
            "active_thread_id": str(active_thread_uuid) if active_thread_uuid else "",
            "active_partner_username": active_thread_summary["partner_username"] if active_thread_summary else "",
            "unread_thread_total": sum(item["unread_count"] for item in threads),
            "error": None,
        },
    )


@router.post("/create")
def create_group(
    request: Request,
    name: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    group_name = name.strip()
    if not group_name:
        raise HTTPException(status_code=400, detail="Group name is required")

    group = Group(name=group_name, owner_id=user.id)
    db.add(group)
    db.flush()

    db.add(GroupMembership(group_id=group.id, user_id=user.id, role=ROLE_OWNER))
    _group_root(group)
    ensure_group_key(db, group)
    add_event(db, user, action="group", message=f"Created group '{group_name}'.", level="SUCCESS")
    db.commit()

    return RedirectResponse(url="/ui/groups", status_code=303)


@router.post("/{group_id}/invite")
def invite_to_group(
    group_id: str,
    request: Request,
    username: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _must_user(db, request)
    group, membership = _must_group_role(db, user, group_id, ROLE_ADMIN)

    target_username = username.strip()
    invitee = db.query(User).filter(User.username == target_username).first()
    if not invitee:
        raise HTTPException(status_code=404, detail="User not found")
    if invitee.id == user.id:
        raise HTTPException(status_code=400, detail="You are already in this group")

    if _get_group_membership(db, group.id, invitee.id):
        raise HTTPException(status_code=400, detail="User is already a group member")

    existing_pending = (
        db.query(GroupInvite)
        .filter(
            GroupInvite.group_id == group.id,
            GroupInvite.invitee_id == invitee.id,
            GroupInvite.status == "pending",
        )
        .first()
    )
    if existing_pending:
        raise HTTPException(status_code=409, detail="User already has a pending invite")

    invite = GroupInvite(
        group_id=group.id,
        inviter_id=user.id,
        invitee_id=invitee.id,
        status="pending",
    )
    db.add(invite)
    add_event(
        db,
        user,
        action="group",
        message=f"Invited '{invitee.username}' to '{group.name}' ({_normalize_role(membership.role)}).",
    )
    db.commit()
    return RedirectResponse(url=f"/ui/groups/{group.id}", status_code=303)


@router.post("/invites/{invite_id}/accept")
def accept_invite(invite_id: str, request: Request, db: Session = Depends(get_db)):
    user = _must_user(db, request)

    try:
        iid = uuid.UUID(invite_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Invite not found")

    invite = (
        db.query(GroupInvite)
        .options(joinedload(GroupInvite.group))
        .filter(GroupInvite.id == iid, GroupInvite.invitee_id == user.id)
        .first()
    )
    if not invite:
        raise HTTPException(status_code=404, detail="Invite not found")
    if invite.status != "pending":
        raise HTTPException(status_code=400, detail="Invite already handled")

    if not _get_group_membership(db, invite.group_id, user.id):
        db.add(GroupMembership(group_id=invite.group_id, user_id=user.id, role=ROLE_MEMBER))

    _group_root(invite.group)
    ensure_group_key(db, invite.group)

    invite.status = "accepted"
    invite.responded_at = datetime.utcnow()
    add_event(db, user, action="group", message=f"Joined group '{invite.group.name}'.", level="SUCCESS")
    db.commit()
    return RedirectResponse(url="/ui/groups", status_code=303)


@router.post("/invites/{invite_id}/decline")
def decline_invite(invite_id: str, request: Request, db: Session = Depends(get_db)):
    user = _must_user(db, request)

    try:
        iid = uuid.UUID(invite_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Invite not found")

    invite = (
        db.query(GroupInvite)
        .options(joinedload(GroupInvite.group))
        .filter(GroupInvite.id == iid, GroupInvite.invitee_id == user.id)
        .first()
    )
    if not invite:
        raise HTTPException(status_code=404, detail="Invite not found")
    if invite.status != "pending":
        raise HTTPException(status_code=400, detail="Invite already handled")

    invite.status = "declined"
    invite.responded_at = datetime.utcnow()
    add_event(db, user, action="group", message=f"Declined invite to '{invite.group.name}'.", level="WARN")
    db.commit()
    return RedirectResponse(url="/ui/groups", status_code=303)


@router.post("/{group_id}/members/{member_user_id}/role")
def update_member_role(
    group_id: str,
    member_user_id: str,
    request: Request,
    role: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _must_user(db, request)
    group, actor_membership = _must_group_role(db, user, group_id, ROLE_ADMIN)

    try:
        target_user_id = uuid.UUID(member_user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Member not found")

    target_membership = (
        db.query(GroupMembership)
        .options(joinedload(GroupMembership.user))
        .filter(GroupMembership.group_id == group.id, GroupMembership.user_id == target_user_id)
        .first()
    )
    if not target_membership:
        raise HTTPException(status_code=404, detail="Member not found")

    current_role = _normalize_role(target_membership.role)
    new_role = _normalize_role(role)
    if new_role not in MANAGE_MEMBER_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")

    if current_role == ROLE_OWNER:
        raise HTTPException(status_code=400, detail="Owner role cannot be changed")
    if target_membership.user_id == user.id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    actor_role = _normalize_role(actor_membership.role)
    if actor_role == ROLE_ADMIN:
        if current_role in {ROLE_OWNER, ROLE_ADMIN}:
            raise HTTPException(status_code=403, detail="Administrators cannot modify this member")
        if new_role == ROLE_ADMIN:
            raise HTTPException(status_code=403, detail="Only owner can grant administrator role")

    if current_role == new_role:
        return RedirectResponse(url=f"/ui/groups/{group.id}", status_code=303)

    target_membership.role = new_role
    add_event(
        db,
        user,
        action="group",
        message=(
            f"Changed role for '{target_membership.user.username}' "
            f"from '{current_role}' to '{new_role}' in '{group.name}'."
        ),
        level="SUCCESS",
    )
    db.commit()
    return RedirectResponse(url=f"/ui/groups/{group.id}", status_code=303)


@router.post("/{group_id}/members/{member_user_id}/remove")
def remove_member(
    group_id: str,
    member_user_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    user = _must_user(db, request)
    group, actor_membership = _must_group_role(db, user, group_id, ROLE_ADMIN)

    try:
        target_user_id = uuid.UUID(member_user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Member not found")

    target_membership = (
        db.query(GroupMembership)
        .options(joinedload(GroupMembership.user))
        .filter(GroupMembership.group_id == group.id, GroupMembership.user_id == target_user_id)
        .first()
    )
    if not target_membership:
        raise HTTPException(status_code=404, detail="Member not found")

    target_role = _normalize_role(target_membership.role)
    actor_role = _normalize_role(actor_membership.role)

    if target_role == ROLE_OWNER:
        raise HTTPException(status_code=400, detail="Owner cannot be removed")
    if target_membership.user_id == user.id:
        raise HTTPException(status_code=400, detail="Cannot remove your own membership")

    if actor_role == ROLE_ADMIN and target_role in {ROLE_OWNER, ROLE_ADMIN}:
        raise HTTPException(status_code=403, detail="Administrators cannot remove this member")

    removed_username = target_membership.user.username
    db.delete(target_membership)
    add_event(
        db,
        user,
        action="group",
        message=f"Removed '{removed_username}' from group '{group.name}'.",
        level="WARN",
    )
    db.commit()
    return RedirectResponse(url=f"/ui/groups/{group.id}", status_code=303)


@router.post("/messages/send")
def send_message(
    request: Request,
    username: str = Form(""),
    message: str = Form(""),
    thread_id: str | None = Form(None),
    attachment: UploadFile | None = File(None),
    db: Session = Depends(get_db),
):
    user = _must_user(db, request)
    target_username = (username or "").strip()
    body = (message or "").strip()

    recipient: User | None = None
    if target_username:
        recipient = db.query(User).filter(User.username == target_username).first()
    elif thread_id:
        try:
            parsed_thread = uuid.UUID(thread_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid thread id")
        seed = (
            db.query(DirectMessage)
            .options(joinedload(DirectMessage.sender), joinedload(DirectMessage.recipient))
            .filter(
                DirectMessage.thread_id == parsed_thread,
                or_(DirectMessage.sender_id == user.id, DirectMessage.recipient_id == user.id),
            )
            .order_by(DirectMessage.created_at.desc())
            .first()
        )
        if seed:
            recipient = seed.sender if seed.sender_id != user.id else seed.recipient

    if not recipient:
        raise HTTPException(status_code=400, detail="Recipient username is required")
    if recipient.id == user.id:
        raise HTTPException(status_code=400, detail="Cannot message yourself")

    has_attachment = bool(attachment and (attachment.filename or "").strip())
    if not body and not has_attachment:
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    if len(body) > 4000:
        raise HTTPException(status_code=400, detail="Message too long")

    resolved_thread_id = _resolve_thread_id(
        db,
        sender_id=user.id,
        recipient_id=recipient.id,
        requested_thread=thread_id,
    )

    dm = DirectMessage(
        id=uuid.uuid4(),
        thread_id=resolved_thread_id,
        sender_id=user.id,
        recipient_id=recipient.id,
        body=encrypt_message(body),
    )

    if has_attachment and attachment:
        safe_name = Path(attachment.filename or "").name.strip()
        if not safe_name:
            raise HTTPException(status_code=400, detail="Invalid attachment name")

        recipient_dek = get_user_dek(db, recipient)
        attach_dir = _message_attachment_root() / str(recipient.id) / str(dm.id)
        attach_dir.mkdir(parents=True, exist_ok=True)
        dest = attach_dir / safe_name

        nonce_b64, tag_b64, plain_size = encrypt_file_to_path(recipient_dek, attachment.file, dest)
        if plain_size > MESSAGE_ATTACHMENT_MAX_BYTES:
            try:
                dest.unlink()
            except FileNotFoundError:
                pass
            raise HTTPException(status_code=400, detail="Attachment is too large (max 10 MB)")

        mime_type, _ = mimetypes.guess_type(safe_name)
        dm.attachment_name = safe_name
        dm.attachment_path = str(dest)
        dm.attachment_size = plain_size
        dm.attachment_enc_nonce = nonce_b64
        dm.attachment_enc_tag = tag_b64
        dm.attachment_mime_type = mime_type

    db.add(dm)
    add_event(
        db,
        user,
        action="message",
        message=(
            f"Sent message to '{recipient.username}'"
            f"{' with attachment' if dm.attachment_name else ''}."
        ),
        level="SUCCESS",
    )
    db.commit()

    return RedirectResponse(url=f"/ui/groups?thread={resolved_thread_id}", status_code=303)


@router.get("/messages/{message_id}/attachment")
def open_message_attachment(message_id: str, request: Request, db: Session = Depends(get_db)):
    user = _must_user(db, request)

    try:
        mid = uuid.UUID(message_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Message not found")

    message = (
        db.query(DirectMessage)
        .filter(DirectMessage.id == mid)
        .first()
    )
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    if user.id not in {message.sender_id, message.recipient_id}:
        raise HTTPException(status_code=403, detail="Forbidden")

    if not message.attachment_name or not message.attachment_path:
        raise HTTPException(status_code=404, detail="Attachment not found")

    path = _safe_message_attachment_path(message.attachment_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Attachment missing on disk")

    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": f'attachment; filename="{message.attachment_name}"',
    }

    if not message.attachment_enc_nonce or not message.attachment_enc_tag:
        return FileResponse(
            path=path,
            filename=message.attachment_name,
            media_type=message.attachment_mime_type or "application/octet-stream",
            headers=headers,
        )

    recipient = db.query(User).filter(User.id == message.recipient_id).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    add_event(
        db,
        user,
        action="message",
        message=f"Downloaded message attachment '{message.attachment_name}'.",
    )
    db.commit()

    dek = get_user_dek(db, recipient)
    return StreamingResponse(
        decrypt_file_iter(dek, path, message.attachment_enc_nonce, message.attachment_enc_tag),
        media_type=message.attachment_mime_type or "application/octet-stream",
        headers=headers,
    )


@router.get("/{group_id}")
def group_detail(
    group_id: str,
    request: Request,
    file_q: str = "",
    file_sort: str = "newest",
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    group, membership = _must_group_role(db, user, group_id, ROLE_VIEWER)
    _group_root(group)
    ensure_group_key(db, group)

    normalized_role = _normalize_role(membership.role)
    can_upload = _role_at_least(normalized_role, ROLE_MEMBER)
    can_invite = _role_at_least(normalized_role, ROLE_ADMIN)
    can_manage_members = _role_at_least(normalized_role, ROLE_ADMIN)

    members = (
        db.query(GroupMembership)
        .options(joinedload(GroupMembership.user))
        .filter(GroupMembership.group_id == group.id)
        .order_by(GroupMembership.joined_at.asc())
        .all()
    )

    pending_invites = []
    if can_invite:
        pending_invites = (
            db.query(GroupInvite)
            .options(joinedload(GroupInvite.invitee), joinedload(GroupInvite.inviter))
            .filter(GroupInvite.group_id == group.id, GroupInvite.status == "pending")
            .order_by(GroupInvite.created_at.desc())
            .all()
        )

    normalized_file_q = (file_q or "").strip()
    normalized_file_sort = (file_sort or "newest").strip().lower()
    files_query = db.query(GroupFileRecord).filter(GroupFileRecord.group_id == group.id)
    if normalized_file_q:
        files_query = files_query.filter(GroupFileRecord.file_name.ilike(f"%{normalized_file_q}%"))

    if normalized_file_sort == "oldest":
        files_query = files_query.order_by(GroupFileRecord.uploaded_at.asc())
    elif normalized_file_sort == "name_asc":
        files_query = files_query.order_by(GroupFileRecord.file_name.asc(), GroupFileRecord.uploaded_at.desc())
    elif normalized_file_sort == "name_desc":
        files_query = files_query.order_by(GroupFileRecord.file_name.desc(), GroupFileRecord.uploaded_at.desc())
    elif normalized_file_sort == "size_asc":
        files_query = files_query.order_by(GroupFileRecord.file_size.asc(), GroupFileRecord.uploaded_at.desc())
    elif normalized_file_sort == "size_desc":
        files_query = files_query.order_by(GroupFileRecord.file_size.desc(), GroupFileRecord.uploaded_at.desc())
    else:
        normalized_file_sort = "newest"
        files_query = files_query.order_by(GroupFileRecord.uploaded_at.desc())

    files = files_query.all()

    return templates.TemplateResponse(
        "group_detail.html",
        {
            "request": request,
            "user": user,
            "group": group,
            "members": members,
            "pending_invites": pending_invites,
            "files": files,
            "is_owner": normalized_role == ROLE_OWNER,
            "membership_role": normalized_role,
            "can_invite": can_invite,
            "can_manage_members": can_manage_members,
            "can_upload": can_upload,
            "member_role_options": MANAGE_MEMBER_ROLES,
            "file_q": normalized_file_q,
            "file_sort": normalized_file_sort,
        },
    )


@router.post("/{group_id}/upload")
def upload_group_file(
    group_id: str,
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    user = _must_user(db, request)
    group, _ = _must_group_role(db, user, group_id, ROLE_MEMBER)
    _group_root(group)
    ensure_group_key(db, group)
    dek = get_group_dek(db, group)

    safe_name = Path(file.filename).name
    dest = _group_root(group) / safe_name
    nonce_b64, tag_b64, plain_size = encrypt_file_to_path(dek, file.file, dest)
    mime_type, _ = mimetypes.guess_type(safe_name)

    record = GroupFileRecord(
        group_id=group.id,
        uploader_id=user.id,
        file_name=safe_name,
        file_path=str(dest),
        file_size=plain_size,
        is_encrypted=True,
        enc_nonce=nonce_b64,
        enc_tag=tag_b64,
        mime_type=mime_type,
    )
    db.add(record)
    add_event(
        db,
        user,
        action="group",
        message=f"Uploaded file '{safe_name}' to group '{group.name}'.",
        level="SUCCESS",
    )
    db.commit()
    return RedirectResponse(url=f"/ui/groups/{group.id}", status_code=303)


@router.get("/{group_id}/files/{file_id}")
def open_group_file(group_id: str, file_id: str, request: Request, db: Session = Depends(get_db)):
    user = _must_user(db, request)
    group, _ = _must_group_role(db, user, group_id, ROLE_VIEWER)
    record = _must_group_file(db, group, file_id)
    path = _safe_group_path(group, record.file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="File missing on disk")

    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": f'attachment; filename="{record.file_name}"',
    }
    if not record.is_encrypted:
        return FileResponse(
            path=path,
            filename=record.file_name,
            media_type=record.mime_type or "application/octet-stream",
            headers=headers,
        )
    if not record.enc_nonce or not record.enc_tag:
        raise HTTPException(status_code=500, detail="Encrypted file metadata is incomplete")

    add_event(db, user, action="decrypt", message=f"Decrypting group file '{record.file_name}' for download...")
    db.commit()
    dek = get_group_dek(db, group)
    return StreamingResponse(
        decrypt_file_iter(dek, path, record.enc_nonce, record.enc_tag),
        media_type=record.mime_type or "application/octet-stream",
        headers=headers,
    )
