from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import current_user
from ..db import User, get_session

router = APIRouter()


@router.get("/search")
def search(q: str, user: User = Depends(current_user), session: Session = Depends(get_session)):
    sql = text(
        "SELECT id, subject, sender FROM messages "
        f"WHERE owner_id = {user.id} AND (subject LIKE '%{q}%' OR body LIKE '%{q}%') "
        "ORDER BY received_at DESC LIMIT 100"
    )
    return [dict(row._mapping) for row in session.execute(sql)]


@router.get("/search/by-sender")
def search_by_sender(senders: str, user: User = Depends(current_user), session: Session = Depends(get_session)):
    names = [s.strip() for s in senders.split(",") if s.strip()][:20]
    if not names:
        return []
    placeholders = ", ".join(f":s{i}" for i in range(len(names)))
    sql = text(f"SELECT id, subject, sender FROM messages WHERE owner_id = :owner AND sender IN ({placeholders})")
    params = {"owner": user.id, **{f"s{i}": name for i, name in enumerate(names)}}
    return [dict(row._mapping) for row in session.execute(sql, params)]
