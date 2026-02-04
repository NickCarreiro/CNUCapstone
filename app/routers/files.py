import os
import mimetypes
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models.core import FileRecord, User
from app.services.authn import get_current_user
from app.services.crypto import encrypt_file_to_path
from app.services.keystore import ensure_user_key, get_user_dek
from app.services.activity import add_event

router = APIRouter(prefix="/files", tags=["files"])


@router.post("/upload")
def upload_file(
    user: User = Depends(get_current_user),
    file: UploadFile = File(...),
    folder: str = Form(""),
    db: Session = Depends(get_db),
):
    ensure_user_key(db, user)
    dek = get_user_dek(db, user)

    add_event(
        db,
        user,
        action="encrypt",
        message=f"Encrypting API upload '{os.path.basename(file.filename)}' -> '{folder or '/'}' (AES-256-GCM)...",
    )
    db.commit()

    user_dir = Path(settings.staging_path) / str(user.id)
    user_dir.mkdir(parents=True, exist_ok=True)

    safe_folder = (folder or "").strip().lstrip("/").replace("\\", "/")
    dest_dir = (user_dir / safe_folder).resolve()
    if not dest_dir.is_relative_to(user_dir.resolve()):
        dest_dir = user_dir
    dest_dir.mkdir(parents=True, exist_ok=True)

    safe_name = os.path.basename(file.filename)
    dest = dest_dir / safe_name
    nonce_b64, tag_b64, plain_size = encrypt_file_to_path(dek, file.file, dest)
    mime_type, _ = mimetypes.guess_type(safe_name)

    record = FileRecord(
        user_id=user.id,
        file_name=safe_name,
        file_path=str(dest),
        original_path=None,
        file_size=plain_size,
        is_trashed=False,
        trashed_at=None,
        is_encrypted=True,
        enc_nonce=nonce_b64,
        enc_tag=tag_b64,
        mime_type=mime_type,
    )
    db.add(record)
    add_event(
        db,
        user,
        action="upload",
        message=f"API upload complete: '{safe_name}' ({plain_size} bytes).",
        level="SUCCESS",
    )
    db.commit()
    db.refresh(record)

    return {"file_id": str(record.id), "file_name": record.file_name}
