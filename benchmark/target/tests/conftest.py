import os
import tempfile

os.environ.setdefault("POSTBOX_DATA", tempfile.mkdtemp())
os.environ.setdefault("POSTBOX_JWT_SECRET", "test-secret-for-unit-tests-only")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.auth import hash_password, issue_token  # noqa: E402
from app.db import Message, SessionLocal, User  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def make_user():
    def _make(email):
        with SessionLocal() as s:
            u = User(email=email, password_hash=hash_password("pw", os.urandom(16)))
            s.add(u)
            s.commit()
            return u
    return _make


@pytest.fixture()
def auth():
    return lambda user: {"Authorization": f"Bearer {issue_token(user)}"}


@pytest.fixture()
def make_message():
    def _make(owner, folder="inbox", **kw):
        with SessionLocal() as s:
            m = Message(owner_id=owner.id, folder=folder, sender=kw.get("sender", "a@example.com"),
                        subject=kw.get("subject", "Hello"), body=kw.get("body", "Hi"), is_read=kw.get("is_read", False))
            s.add(m)
            s.commit()
            return m
    return _make
