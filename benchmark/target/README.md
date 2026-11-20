# Postbox

Small mail service with folders, attachments, search and an AI mailbox summary.

## Run

```bash
pip install -r requirements.txt
export POSTBOX_JWT_SECRET=...  POSTBOX_DATA=/var/lib/postbox
uvicorn app.main:app
```

## API

| Method | Path | Purpose |
|---|---|---|
| POST | /login | Get a token |
| GET | /messages | List messages in a folder (paged) |
| GET | /messages/{id} | Read a message |
| POST | /messages/{id}/delete | Move to trash |
| POST | /messages/{id}/restore | Restore from trash |
| GET | /search?q= | Full-text search |
| GET | /attachments/{message_id}/{name} | Download an attachment |
| DELETE | /account | Delete the account and all data |
| POST | /assistant/summary | AI summary of the inbox |
