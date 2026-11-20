#!/usr/bin/env bash
# Build the benchmark repository (with a short Git history) in a new folder.
# Usage: benchmark/build_target.sh DEST
# The ground truth (ground_truth.yaml) is NOT copied; the audit must not see it.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dest="${1:?usage: build_target.sh DEST}"
[ -e "$dest" ] && { echo "error: $dest already exists" >&2; exit 2; }
mkdir -p "$dest"
cp -R "$here/target/." "$dest/"
cd "$dest"
export GIT_AUTHOR_NAME="Postbox Dev" GIT_AUTHOR_EMAIL="dev@postbox.invalid"
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GIT_AUTHOR_DATE="2026-09-01T10:00:00Z" GIT_COMMITTER_DATE="2026-09-01T10:00:00Z"
git init -q -b main
# First commit: settings with a hard-coded signing key.
mv app/config.py /tmp/postbox-config.$$
sed 's|^JWT_SECRET = .*|JWT_SECRET = "Zx8vQ2mN7pL4rT9wK3sB6yH1dF5gJ0cA"|' /tmp/postbox-config.$$ > app/config.py
git add -A && git commit -q -m "Initial version"
# Second commit: read the key from the environment.
mv /tmp/postbox-config.$$ app/config.py
export GIT_AUTHOR_DATE="2026-09-03T15:30:00Z" GIT_COMMITTER_DATE="2026-09-03T15:30:00Z"
git add -A && git commit -q -m "Read settings from environment"
echo "benchmark repo ready: $dest ($(git rev-parse --short HEAD))"
