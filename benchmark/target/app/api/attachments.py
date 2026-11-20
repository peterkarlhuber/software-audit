from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import current_user
from ..config import ATTACHMENT_DIR
from ..db import Message, User, get_session

router = APIRouter()


@router.get("/attachments/{message_id}/{name:path}")
def download(message_id: int, name: str, user: User = Depends(current_user), session: Session = Depends(get_session)):
    msg = session.scalar(select(Message).where(Message.id == message_id, Message.owner_id == user.id))
    if msg is None:
        raise HTTPException(status_code=404)
    path = ATTACHMENT_DIR / str(msg.owner_id) / name
    if not path.exists():
        raise HTTPException(status_code=404)
    return FileResponse(path)
