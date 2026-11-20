"""Pull new mail from the upstream IMAP server into the local database."""
import email
import imaplib
import logging

from sqlalchemy.orm import Session

from .db import Message

log = logging.getLogger(__name__)


def store(session: Session, owner_id: int, raw: bytes) -> None:
    parsed = email.message_from_bytes(raw)
    body = parsed.get_payload(decode=True) or b""
    session.add(Message(owner_id=owner_id, sender=parsed.get("From", ""), subject=parsed.get("Subject", ""),
                        body=body.decode("utf-8", errors="replace"), synced=True))


def sync_mailbox(session: Session, owner_id: int, imap: imaplib.IMAP4) -> int:
    imap.select("INBOX")
    _, data = imap.search(None, "UNSEEN")
    count = 0
    for num in data[0].split():
        try:
            _, parts = imap.fetch(num, "(RFC822)")
            store(session, owner_id, parts[0][1])
        except Exception:
            log.debug("skipping message %s", num)
        imap.store(num, "+FLAGS", "\\Seen")
        count += 1
    session.commit()
    return count
