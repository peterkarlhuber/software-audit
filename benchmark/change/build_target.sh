#!/usr/bin/env bash
# Build the change-audit benchmark: the Postbox repository plus a feature branch.
# Usage: benchmark/change/build_target.sh DEST
# main gets a commit that adds the ownership check to GET /messages/{id}. The branch "feature"
# then (1) drops that check again in a "refactor" and (2) adds a correct mark-unread endpoint.
# Audit with: prepare.py --base main (on branch feature). Score with --truth benchmark/change/ground_truth.yaml.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dest="${1:?usage: build_target.sh DEST}"
"$here/../build_target.sh" "$dest" >/dev/null
cd "$dest"
export GIT_AUTHOR_NAME="Postbox Dev" GIT_AUTHOR_EMAIL="dev@postbox.invalid"
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
f=app/api/messages.py
orig='    msg = session.get(Message, message_id)'
fixed='    msg = session.scalar(select(Message).where(Message.id == message_id, Message.owner_id == user.id))'
grep -qF "$orig" "$f" || { echo "error: $f changed, update this script" >&2; exit 2; }
python3 - "$f" "$orig" "$fixed" <<'PY'
import sys
p, a, b = sys.argv[1:]
s = open(p).read()
open(p, "w").write(s.replace(a, b, 1))
PY
export GIT_AUTHOR_DATE="2026-09-10T09:00:00Z" GIT_COMMITTER_DATE="2026-09-10T09:00:00Z"
git add -A && git commit -q -m "Only return the caller's own messages"
git checkout -q -b feature
python3 - "$f" "$fixed" "$orig" <<'PY'
import sys
p, a, b = sys.argv[1:]
s = open(p).read().replace(a, b, 1)
marker = '@router.post("/messages/{message_id}/delete")'
new = '''@router.post("/messages/{message_id}/unread")
def mark_unread(message_id: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    msg = session.scalar(select(Message).where(Message.id == message_id, Message.owner_id == user.id))
    if msg is None:
        raise HTTPException(status_code=404)
    msg.is_read = False
    session.commit()
    return {"ok": True}


'''
assert marker in s
open(p, "w").write(s.replace(marker, new + marker, 1))
PY
export GIT_AUTHOR_DATE="2026-09-12T14:00:00Z" GIT_COMMITTER_DATE="2026-09-12T14:00:00Z"
git add -A && git commit -q -m "Simplify message lookup, add mark-unread"
echo "change benchmark ready: $dest (branch feature, base main, $(git rev-parse --short HEAD))"
