from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
import mimetypes

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi import File, UploadFile
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.db import get_db
from app.models.core import DirectMessage, Group, GroupFileRecord, GroupInvite, GroupMembership, Session as SessionModel, User
from app.services.activity import add_event
from app.services.crypto import decrypt_file_iter, encrypt_file_to_path
from app.services.group_keystore import ensure_group_key, get_group_dek
from app.services.message_crypto import decrypt_message, encrypt_message

router = APIRouter(prefix="/ui/groups", tags=["groups"])
templates = Jinja2Templates(directory="templates")


def _get_session(db: Session, session_id: str | None) -> SessionModel | None:
    if not session_id:
        return None
    try:
        parsed = uuid.UUID(session_id)
    except ValueError:
        return None
    return (
        db.query(SessionModel)
        .filter(
            SessionModel.id == parsed,
            SessionModel.is_active.is_(True),
            SessionModel.expires_at > datetime.utcnow(),
        )
        .first()
    )


def _get_current_user(db: Session, request: Request) -> User | None:
    session = _get_session(db, request.cookies.get("pfv_session"))
    if not session:
        return None
    return db.query(User).filter(User.id == session.user_id).first()


def _must_user(db: Session, request: Request) -> User:
    user = _get_current_user(db, request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def _is_group_member(db: Session, group_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    return (
        db.query(GroupMembership.id)
        .filter(GroupMembership.group_id == group_id, GroupMembership.user_id == user_id)
        .first()
        is not None
    )


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


def _must_group_member(db: Session, user: User, group_id: str) -> Group:
    try:
        gid = uuid.UUID(group_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Group not found")
    group = db.query(Group).filter(Group.id == gid).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if not _is_group_member(db, group.id, user.id):
        raise HTTPException(status_code=403, detail="Not a member of this group")
    return group


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


@router.get("")
def groups_home(request: Request, db: Session = Depends(get_db)):
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

    recent_messages = (
        db.query(DirectMessage)
        .options(joinedload(DirectMessage.sender), joinedload(DirectMessage.recipient))
        .filter(or_(DirectMessage.sender_id == user.id, DirectMessage.recipient_id == user.id))
        .order_by(DirectMessage.created_at.desc())
        .limit(50)
        .all()
    )
    message_rows = [
        {
            "sender_username": row.sender.username,
            "recipient_username": row.recipient.username,
            "body": decrypt_message(row.body),
            "created_at": row.created_at,
        }
        for row in recent_messages
    ]

    return templates.TemplateResponse(
        "groups.html",
        {
            "request": request,
            "user": user,
            "memberships": memberships,
            "pending_invites": pending_invites,
            "recent_messages": message_rows,
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

    owner_membership = GroupMembership(group_id=group.id, user_id=user.id, role="owner")
    db.add(owner_membership)
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
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    try:
        gid = uuid.UUID(group_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Group not found")

    group = db.query(Group).filter(Group.id == gid).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if group.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Only the group owner can invite users")

    target_username = username.strip()
    invitee = db.query(User).filter(User.username == target_username).first()
    if not invitee:
        raise HTTPException(status_code=404, detail="User not found")
    if invitee.id == user.id:
        raise HTTPException(status_code=400, detail="You are already in this group")

    if _is_group_member(db, group.id, invitee.id):
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
    add_event(db, user, action="group", message=f"Invited '{invitee.username}' to '{group.name}'.")
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

    if not _is_group_member(db, invite.group_id, user.id):
        db.add(GroupMembership(group_id=invite.group_id, user_id=user.id, role="member"))
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


@router.post("/messages/send")
def send_message(
    request: Request,
    username: str = Form(...),
    message: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _must_user(db, request)
    target_username = username.strip()
    body = message.strip()
    if not target_username:
        raise HTTPException(status_code=400, detail="Recipient username is required")
    if not body:
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    if len(body) > 4000:
        raise HTTPException(status_code=400, detail="Message too long")

    recipient = db.query(User).filter(User.username == target_username).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    if recipient.id == user.id:
        raise HTTPException(status_code=400, detail="Cannot message yourself")

    dm = DirectMessage(sender_id=user.id, recipient_id=recipient.id, body=encrypt_message(body))
    db.add(dm)
    add_event(db, user, action="message", message=f"Sent message to '{recipient.username}'.", level="SUCCESS")
    db.commit()

    return RedirectResponse(url="/ui/groups", status_code=303)


@router.get("/{group_id}")
def group_detail(group_id: str, request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(db, request)
    if not user:
        return RedirectResponse(url="/ui/login", status_code=303)

    group = _must_group_member(db, user, group_id)
    _group_root(group)
    ensure_group_key(db, group)

    members = (
        db.query(GroupMembership)
        .options(joinedload(GroupMembership.user))
        .filter(GroupMembership.group_id == group.id)
        .order_by(GroupMembership.joined_at.asc())
        .all()
    )
    pending_invites = (
        db.query(GroupInvite)
        .options(joinedload(GroupInvite.invitee), joinedload(GroupInvite.inviter))
        .filter(
            GroupInvite.group_id == group.id,
            GroupInvite.status == "pending",
            or_(GroupInvite.inviter_id == user.id, Group.owner_id == user.id),
        )
        .join(Group, Group.id == GroupInvite.group_id)
        .all()
    )
    files = (
        db.query(GroupFileRecord)
        .filter(GroupFileRecord.group_id == group.id)
        .order_by(GroupFileRecord.uploaded_at.desc())
        .all()
    )

    return templates.TemplateResponse(
        "group_detail.html",
        {
            "request": request,
            "user": user,
            "group": group,
            "members": members,
            "pending_invites": pending_invites,
            "files": files,
            "is_owner": group.owner_id == user.id,
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
    group = _must_group_member(db, user, group_id)
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
    group = _must_group_member(db, user, group_id)
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
