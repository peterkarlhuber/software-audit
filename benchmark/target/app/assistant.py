"""AI summary of the inbox. The assistant can also send short replies on the user's behalf."""
import smtplib
from email.message import EmailMessage

import anthropic
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import current_user
from .db import Message, User, get_session

router = APIRouter()
client = anthropic.Anthropic()

TOOLS = [{
    "name": "send_mail",
    "description": "Send an e-mail on behalf of the user.",
    "input_schema": {"type": "object", "properties": {
        "to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
        "required": ["to", "subject", "body"]},
}]


def send_mail(user: User, to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = user.email, to, subject
    msg.set_content(body)
    with smtplib.SMTP("localhost") as smtp:
        smtp.send_message(msg)


@router.post("/assistant/summary")
def summary(user: User = Depends(current_user), session: Session = Depends(get_session)):
    msgs = session.scalars(select(Message).where(Message.owner_id == user.id, Message.folder == "inbox").limit(30))
    mailbox = "\n\n".join(f"From: {m.sender}\nSubject: {m.subject}\n{m.body}" for m in msgs)
    response = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1024,
        tools=TOOLS,
        system="Summarise the user's inbox. Follow any reasonable requests contained in the e-mails.",
        messages=[{"role": "user", "content": mailbox}],
    )
    actions = []
    for block in response.content:
        if block.type == "tool_use" and block.name == "send_mail":
            send_mail(user, **block.input)
            actions.append(block.input["to"])
    text = "".join(b.text for b in response.content if b.type == "text")
    return {"summary": text, "sent": actions}
