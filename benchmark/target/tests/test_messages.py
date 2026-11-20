import uuid


def unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def test_list_messages_returns_own_inbox(client, make_user, make_message, auth):
    alice = make_user(unique("alice"))
    make_message(alice, subject="One")
    make_message(alice, subject="Two")
    resp = client.get("/messages", headers=auth(alice))
    assert resp.status_code == 200
    assert {m["subject"] for m in resp.json()} == {"One", "Two"}


def test_delete_moves_to_trash(client, make_user, make_message, auth):
    bob = make_user(unique("bob"))
    msg = make_message(bob)
    assert client.post(f"/messages/{msg.id}/delete", headers=auth(bob)).status_code == 200
    resp = client.get("/messages", params={"folder": "trash"}, headers=auth(bob))
    assert [m["id"] for m in resp.json()] == [msg.id]


def test_restore_from_trash(client, make_user, make_message, auth):
    carol = make_user(unique("carol"))
    msg = make_message(carol, folder="archive", is_read=True)
    client.post(f"/messages/{msg.id}/delete", headers=auth(carol))
    resp = client.post(f"/messages/{msg.id}/restore", headers=auth(carol))
    resp.json()


def test_requires_login(client):
    assert client.get("/messages").status_code == 401
