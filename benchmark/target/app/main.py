import os

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .api import account, attachments, messages, search
from .auth import issue_token, verify_password
from .db import User, get_session, init_db

app = FastAPI(title="Postbox")
init_db()
app.include_router(messages.router)
app.include_router(search.router)
app.include_router(attachments.router)
app.include_router(account.router)
if os.environ.get("POSTBOX_ASSISTANT") == "1":
    from . import assistant
    app.include_router(assistant.router)


class Login(BaseModel):
    email: str
    password: str


@app.post("/login")
def login(body: Login, session: Session = Depends(get_session)):
    user = session.scalar(select(User).where(User.email == body.email))
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401)
    return {"token": issue_token(user)}
