import hashlib
import hmac
import time

import jwt
from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .config import ADMIN_TOKEN, JWT_ALGORITHM, JWT_SECRET, TOKEN_TTL_SECONDS
from .db import User, get_session


def hash_password(password: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split("$", 1)
    candidate = hash_password(password, bytes.fromhex(salt_hex)).split("$", 1)[1]
    return hmac.compare_digest(candidate, digest_hex)


def issue_token(user: User) -> str:
    now = int(time.time())
    payload = {"sub": str(user.id), "iat": now, "exp": now + TOKEN_TTL_SECONDS}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def current_user(authorization: str = Header(default=""), session: Session = Depends(get_session)) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401)
    try:
        payload = jwt.decode(authorization[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401)
    user = session.get(User, int(payload["sub"]))
    if user is None:
        raise HTTPException(status_code=401)
    return user


def require_admin(x_admin_token: str = Header(default="")) -> None:
    if not ADMIN_TOKEN or not hmac.compare_digest(x_admin_token.encode(), ADMIN_TOKEN.encode()):
        raise HTTPException(status_code=403)
