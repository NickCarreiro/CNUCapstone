from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
import mimetypes
import os
from urllib.parse import quote_plus

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.db import get_db
from app.models.core import (
    DirectMessage,
    DirectMessageReport,
    Group,
    GroupFileRecord,
    GroupInvite,
    GroupMembership,
    User,
)
from app.services.activity import add_event
from app.services.authn import get_current_user as resolve_current_user
from app.services.audit import add_audit_log
from app.services.crypto import decrypt_file_iter, encrypt_file_to_path
from app.services.group_keystore import ensure_group_key, get_group_dek
from app.services.keystore import get_user_dek
from app.services.message_crypto import encrypt_message

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

DM_REPORT_REASONS: dict[str, str] = {
    "spam": "Spam / unsolicited advertising",
    "harassment": "Harassment or hate speech",
    "threat": "Threats or violence",
    "impersonation": "Impersonation / fraud",
    "sexual": "Sexual content",
    "other": "Other",
}


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


def _safe_group_join(group: Group, rel_path: str) -> Path:
    root = _group_root(group).resolve()
    rel = (rel_path or "").strip().lstrip("/").replace("\\", "/")
    candidate = (root / rel).resolve()
    if not candidate.is_relative_to(root):
        raise HTTPException(status_code=400, detail="Invalid path")
    return candidate


def _group_detail_redirect(group: Group, message: str, *, error: bool = False) -> RedirectResponse:
    key = "error" if error else "notice"
    return RedirectResponse(url=f"/ui/groups/{group.id}?{key}={quote_plus(message)}", status_code=303)


def _can_edit_group_file(user: User, membership: GroupMembership, record: GroupFileRecord) -> bool:
    role = _normalize_role(membership.role)
    if not _role_at_least(role, ROLE_MEMBER):
        return False
    if _role_at_least(role, ROLE_ADMIN):
        return True
    return record.uploader_id == user.id


def _ensure_tree_node(node: dict) -> dict:
    if "__files__" not in node:
        node["__files__"] = []
    return node


def _build_group_vault_tree(root: Path, files: list[GroupFileRecord]) -> dict:
    tree: dict[str, dict] = {}
    _ensure_tree_node(tree)

    for dirpath, dirnames, _ in os.walk(root):
        rel = Path(dirpath).resolve().relative_to(root)
        if str(rel) == ".":
            node = tree
        else:
            node = tree
            for part in rel.parts:
                node = node.setdefault(part, {})
                _ensure_tree_node(node)
        dirnames.sort()

    for record in files:
        try:
            rel = Path(record.file_path).resolve().relative_to(root)
        except ValueError:
            continue
        parts = rel.parts
        if not parts:
            continue
        *folders, filename = parts
        node = tree
        for part in folders:
            node = node.setdefault(part, {})
            _ensure_tree_node(node)
        _ensure_tree_node(node)
        node["__files__"].append(filename)

    def _sort_tree(node: dict) -> None:
        if "__files__" in node:
            node["__files__"].sort()
        for key in sorted(k for k in node.keys() if k != "__files__"):
            _sort_tree(node[key])

    _sort_tree(tree)
    return tree


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


@router.get("")
def groups_home(
    request: Request,
    notice: str | None = None,
    error: str | None = None,
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

    return templates.TemplateResponse(
        "groups.html",
        {
            "request": request,
            "user": user,
            "memberships": memberships,
            "pending_invites": pending_invites,
            "notice": notice,
            "error": error,
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
    if getattr(user, "messaging_disabled", False):
        add_audit_log(
            db,
            user=user,
            event_type="message.send_blocked_restricted",
            details="Direct message send blocked (messaging disabled).",
            request=request,
        )
        db.commit()
        return RedirectResponse(
            url=f"/ui/groups?error={quote_plus('Direct messaging has been disabled on your account.')}",
            status_code=303,
        )
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
    if getattr(recipient, "is_disabled", False):
        raise HTTPException(status_code=400, detail="Recipient account is disabled")

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


@router.post("/messages/report")
def report_message(
    request: Request,
    message_id: str = Form(...),
    reason: str = Form("other"),
    details: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _must_user(db, request)

    try:
        mid = uuid.UUID(message_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Message not found")

    message = (
        db.query(DirectMessage)
        .options(joinedload(DirectMessage.sender), joinedload(DirectMessage.recipient))
        .filter(DirectMessage.id == mid)
        .first()
    )
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    if user.id not in {message.sender_id, message.recipient_id}:
        raise HTTPException(status_code=403, detail="Forbidden")

    if message.sender_id == user.id:
        raise HTTPException(status_code=400, detail="Cannot report your own message")

    normalized_reason = (reason or "").strip().lower()
    if normalized_reason not in DM_REPORT_REASONS:
        normalized_reason = "other"

    note = (details or "").strip()
    if len(note) > 2000:
        raise HTTPException(status_code=400, detail="Details too long")

    thread_uuid = message.thread_id or message.id
    report = DirectMessageReport(
        message_id=message.id,
        thread_id=thread_uuid,
        reporter_id=user.id,
        reported_user_id=message.sender_id,
        reason=normalized_reason,
        details=encrypt_message(note) if note else None,
        status="open",
    )
    db.add(report)
    add_event(
        db,
        user,
        action="report",
        message=f"Reported a direct message from '{message.sender.username}' (reason: {normalized_reason}).",
        level="WARN",
    )
    add_audit_log(
        db,
        user=user,
        event_type="message.reported",
        details=f"Reported direct message {message.id} from '{message.sender.username}' (reason: {normalized_reason}).",
        request=request,
    )

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return RedirectResponse(
            url=f"/ui/groups?thread={thread_uuid}&notice={quote_plus('You already reported that message.')}",
            status_code=303,
        )

    return RedirectResponse(
        url=f"/ui/groups?thread={thread_uuid}&notice={quote_plus('Report submitted. An administrator will review it.')}",
        status_code=303,
    )


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
    notice: str | None = None,
    error: str | None = None,
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

    file_records = files_query.all()

    root = _group_root(group).resolve()
    file_rows: list[dict] = []
    for record in file_records:
        try:
            rel = Path(record.file_path).resolve().relative_to(root)
            rel_path = str(rel)
        except ValueError:
            rel_path = record.file_name
        file_rows.append(
            {
                "record": record,
                "rel_path": rel_path,
                "id": str(record.id),
                "display_name": record.file_name,
                "can_edit": _can_edit_group_file(user, membership, record),
            }
        )

    folder_rows = []
    for dirpath, dirnames, _ in os.walk(root):
        rel = Path(dirpath).resolve().relative_to(root)
        rel_path = "" if str(rel) == "." else str(rel)
        depth = 0 if rel_path == "" else len(Path(rel_path).parts)
        folder_rows.append({"path": rel_path, "depth": depth})
        dirnames.sort()
    folder_rows.sort(key=lambda item: (item["depth"], item["path"]))

    folder_tree: dict[str, dict] = {}
    for folder in folder_rows:
        if not folder["path"]:
            continue
        node = folder_tree
        for part in Path(folder["path"]).parts:
            node = node.setdefault(part, {})

    vault_tree = _build_group_vault_tree(root, file_records)

    return templates.TemplateResponse(
        "group_detail.html",
        {
            "request": request,
            "user": user,
            "group": group,
            "members": members,
            "pending_invites": pending_invites,
            "files": file_rows,
            "folders": folder_rows,
            "folder_tree": folder_tree,
            "vault_tree": vault_tree,
            "is_owner": normalized_role == ROLE_OWNER,
            "membership_role": normalized_role,
            "can_invite": can_invite,
            "can_manage_members": can_manage_members,
            "can_upload": can_upload,
            "member_role_options": MANAGE_MEMBER_ROLES,
            "file_q": normalized_file_q,
            "file_sort": normalized_file_sort,
            "notice": notice or request.query_params.get("notice"),
            "error": error or request.query_params.get("error"),
        },
    )


@router.post("/{group_id}/upload")
def upload_group_file(
    group_id: str,
    request: Request,
    folder: str = Form(""),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    user = _must_user(db, request)
    group, _ = _must_group_role(db, user, group_id, ROLE_MEMBER)
    _group_root(group)
    ensure_group_key(db, group)
    dek = get_group_dek(db, group)

    safe_name = Path(file.filename).name
    dest_dir = _safe_group_join(group, folder)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / safe_name
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
        message=f"Uploaded file '{safe_name}' to group '{group.name}' -> '{folder or '/'}'.",
        level="SUCCESS",
    )
    db.commit()
    return RedirectResponse(url=f"/ui/groups/{group.id}", status_code=303)


@router.post("/{group_id}/folder")
def create_group_folder(
    group_id: str,
    request: Request,
    folder: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _must_user(db, request)
    group, membership = _must_group_role(db, user, group_id, ROLE_VIEWER)

    normalized_role = _normalize_role(membership.role)
    if not _role_at_least(normalized_role, ROLE_MEMBER):
        return _group_detail_redirect(group, "Your role is read-only for creating folders.", error=True)

    folder_path = (folder or "").strip()
    if not folder_path:
        return _group_detail_redirect(group, "Folder path is required.", error=True)

    dest_dir = _safe_group_join(group, folder_path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    add_event(db, user, action="group", message=f"Created group folder '{folder_path}' in '{group.name}'.", level="SUCCESS")
    db.commit()
    return _group_detail_redirect(group, f"Folder created: /{folder_path}", error=False)


@router.post("/{group_id}/move")
def move_group_file(
    group_id: str,
    request: Request,
    file_id: str = Form(...),
    new_folder: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _must_user(db, request)
    group, membership = _must_group_role(db, user, group_id, ROLE_VIEWER)

    normalized_role = _normalize_role(membership.role)
    if not _role_at_least(normalized_role, ROLE_MEMBER):
        return _group_detail_redirect(group, "Your role is read-only for moving files.", error=True)

    record = _must_group_file(db, group, file_id)
    if not _can_edit_group_file(user, membership, record):
        return _group_detail_redirect(group, "You do not have permission to move that file.", error=True)

    dest_dir = _safe_group_join(group, new_folder)
    dest_dir.mkdir(parents=True, exist_ok=True)

    current_path = _safe_group_path(group, record.file_path)
    if not current_path.exists():
        return _group_detail_redirect(group, "File missing on disk.", error=True)

    dest = dest_dir / current_path.name
    try:
        if dest.resolve() == current_path.resolve():
            return _group_detail_redirect(group, "File is already in that folder.", error=False)
    except FileNotFoundError:
        # Current file missing should have been caught above; fall through.
        pass

    if dest.exists():
        target_display = f"/{new_folder.strip().lstrip('/')}" if (new_folder or "").strip() else "/"
        return _group_detail_redirect(
            group,
            f"A file named '{record.file_name}' already exists in {target_display}.",
            error=True,
        )

    current_path.replace(dest)
    record.file_path = str(dest)
    add_event(
        db,
        user,
        action="group",
        message=f"Moved group file '{record.file_name}' -> '{new_folder or '/'}' in '{group.name}'.",
        level="SUCCESS",
    )
    db.commit()
    return _group_detail_redirect(group, f"Moved: {record.file_name}", error=False)


@router.post("/{group_id}/rename")
def rename_group_file(
    group_id: str,
    request: Request,
    file_id: str = Form(...),
    new_name: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _must_user(db, request)
    group, membership = _must_group_role(db, user, group_id, ROLE_VIEWER)

    normalized_role = _normalize_role(membership.role)
    if not _role_at_least(normalized_role, ROLE_MEMBER):
        return _group_detail_redirect(group, "Your role is read-only for renaming files.", error=True)

    record = _must_group_file(db, group, file_id)
    if not _can_edit_group_file(user, membership, record):
        return _group_detail_redirect(group, "You do not have permission to rename that file.", error=True)

    safe_name = Path(new_name).name.strip()
    if not safe_name:
        return _group_detail_redirect(group, "Invalid file name.", error=True)

    current_path = _safe_group_path(group, record.file_path)
    if not current_path.exists():
        return _group_detail_redirect(group, "File missing on disk.", error=True)

    dest = current_path.with_name(safe_name)
    if dest.exists():
        return _group_detail_redirect(group, f"A file named '{safe_name}' already exists here.", error=True)

    old_name = record.file_name
    current_path.replace(dest)
    record.file_name = safe_name
    record.file_path = str(dest)
    add_event(
        db,
        user,
        action="group",
        message=f"Renamed group file '{old_name}' -> '{safe_name}' in '{group.name}'.",
        level="SUCCESS",
    )
    db.commit()
    return _group_detail_redirect(group, f"Renamed: {old_name} -> {safe_name}", error=False)


@router.post("/{group_id}/delete")
def delete_group_file(
    group_id: str,
    request: Request,
    file_id: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _must_user(db, request)
    group, membership = _must_group_role(db, user, group_id, ROLE_VIEWER)

    normalized_role = _normalize_role(membership.role)
    if not _role_at_least(normalized_role, ROLE_MEMBER):
        return _group_detail_redirect(group, "Your role is read-only for deleting files.", error=True)

    record = _must_group_file(db, group, file_id)
    if not _can_edit_group_file(user, membership, record):
        return _group_detail_redirect(group, "You do not have permission to delete that file.", error=True)

    path = _safe_group_path(group, record.file_path)
    try:
        path.unlink()
    except FileNotFoundError:
        pass

    add_event(
        db,
        user,
        action="group",
        message=f"Deleted group file '{record.file_name}' from '{group.name}'.",
        level="WARN",
    )
    db.delete(record)
    db.commit()
    return _group_detail_redirect(group, f"Deleted: {record.file_name}", error=False)


@router.get("/{group_id}/preview/{file_id}")
def preview_group_file(group_id: str, file_id: str, request: Request, db: Session = Depends(get_db)):
    user = _must_user(db, request)
    group, _ = _must_group_role(db, user, group_id, ROLE_VIEWER)
    record = _must_group_file(db, group, file_id)
    path = _safe_group_path(group, record.file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="File missing on disk")

    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": f'inline; filename="{record.file_name}"',
    }

    media_type = record.mime_type or (mimetypes.guess_type(record.file_name)[0] or "application/octet-stream")
    if not record.is_encrypted:
        return FileResponse(path=path, filename=record.file_name, media_type=media_type, headers=headers)
    if not record.enc_nonce or not record.enc_tag:
        raise HTTPException(status_code=500, detail="Encrypted file metadata is incomplete")

    add_event(db, user, action="decrypt", message=f"Decrypting group file '{record.file_name}' for preview...")
    db.commit()
    dek = get_group_dek(db, group)
    return StreamingResponse(
        decrypt_file_iter(dek, path, record.enc_nonce, record.enc_tag),
        media_type=media_type,
        headers=headers,
    )


@router.get("/{group_id}/preview-frame/{file_id}")
def preview_group_file_frame(group_id: str, file_id: str, request: Request, db: Session = Depends(get_db)):
    user = _must_user(db, request)
    group, _ = _must_group_role(db, user, group_id, ROLE_VIEWER)
    record = _must_group_file(db, group, file_id)
    path = _safe_group_path(group, record.file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="File missing on disk")

    mime_type = (record.mime_type or mimetypes.guess_type(record.file_name)[0] or "application/octet-stream").lower()
    ext = Path(record.file_name or "").suffix.lower()
    theme = (request.query_params.get("theme") or "").strip().lower()
    if theme not in {"light", "dark"}:
        theme = "light"

    return templates.TemplateResponse(
        "preview_frame.html",
        {
            "request": request,
            "title": f"Preview {record.file_name}",
            "raw_url": f"/ui/groups/{group_id}/preview/{file_id}?v={int(datetime.utcnow().timestamp())}",
            "file_name": record.file_name,
            "mime_type": mime_type,
            "file_ext": ext,
            "theme": theme,
        },
    )


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
