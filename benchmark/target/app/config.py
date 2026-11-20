import os
from pathlib import Path

JWT_SECRET = os.environ.get("POSTBOX_JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 3600
DATA_DIR = Path(os.environ.get("POSTBOX_DATA", "./data"))
ATTACHMENT_DIR = DATA_DIR / "attachments"
DATABASE_URL = os.environ.get("POSTBOX_DB", f"sqlite:///{DATA_DIR / 'postbox.db'}")
ADMIN_TOKEN = os.environ.get("POSTBOX_ADMIN_TOKEN", "")
PAGE_SIZE = 50
