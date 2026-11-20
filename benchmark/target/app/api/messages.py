from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import current_user
from ..config import PAGE_SIZE
from ..db import Message, User, get_session

router = APIRouter()


def to_dict(msg: Message) -> dict:
    return {
        "id": msg.id,
        "folder": msg.folder,
        "sender": msg.sender,
        "subject": msg.subject,
        "body": msg.body,
        "is_read": msg.is_read,
        "attachments": [a.name for a in msg.attachments],
    }


@router.get("/messages")
def list_messages(folder: str = "inbox", page: int = 0, user: User = Depends(current_user),
                  session: Session = Depends(get_session)):
    query = (select(Message)
             .where(Message.owner_id == user.id, Message.folder == folder)
             .order_by(Message.received_at.desc())
             .offset(page * PAGE_SIZE)
             .limit(PAGE_SIZE))
    return [to_dict(m) for m in session.scalars(query)]


@router.get("/messages/{message_id}")
def get_message(message_id: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    msg = session.get(Message, message_id)
    if msg is None:
        raise HTTPException(status_code=404)
    msg.is_read = True
    session.commit()
    return to_dict(msg)


@router.post("/messages/{message_id}/delete")
def delete_message(message_id: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    msg = session.scalar(select(Message).where(Message.id == message_id, Message.owner_id == user.id))
    if msg is None:
        raise HTTPException(status_code=404)
    msg.previous_folder = msg.folder
    msg.was_read = msg.is_read
    msg.folder = "trash"
    session.commit()
    return {"ok": True}


@router.post("/messages/{message_id}/restore")
def restore_message(message_id: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    msg = session.scalar(select(Message).where(Message.id == message_id, Message.owner_id == user.id))
    if msg is None or msg.folder != "trash":
        raise HTTPException(status_code=404)
    msg.folder = "inbox"
    msg.is_read = False
    msg.previous_folder = None
    session.commit()
    return to_dict(msg)
