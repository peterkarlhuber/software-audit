from fastapi import APIRouter, Depends
from sqlalchemy import delete
from sqlalchemy.orm import Session

from ..auth import current_user
from ..db import Attachment, Message, User, get_session

router = APIRouter()


@router.delete("/account")
def delete_account(user: User = Depends(current_user), session: Session = Depends(get_session)):
    message_ids = [m.id for m in session.query(Message.id).filter(Message.owner_id == user.id)]
    session.execute(delete(Attachment).where(Attachment.message_id.in_(message_ids)))
    session.execute(delete(Message).where(Message.owner_id == user.id))
    session.delete(user)
    session.commit()
    return {"deleted": True}
