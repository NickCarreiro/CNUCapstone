import os

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models.core import FileRecord, User

router = APIRouter(prefix="/files", tags=["files"])


@router.post("/upload")
def upload_file(user_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # TODO: enforce session validation and per-user authorization
    # TODO: write to staging_path and apply chattr +i at the OS layer

    safe_name = os.path.basename(file.filename)
    staged_path = f"{settings.staging_path}/{safe_name}"
    contents = file.file.read()
    with open(staged_path, "wb") as f:
        f.write(contents)

    record = FileRecord(
        user_id=user.id,
        file_name=safe_name,
        file_path=staged_path,
        file_size=len(contents),
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return {"file_id": str(record.id), "file_name": record.file_name}
