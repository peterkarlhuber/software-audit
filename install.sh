#!/usr/bin/env bash
# Install the software-audit skill for Claude Code (user level: ~/.claude/skills/software-audit).
# An existing skill of the same name (e.g. the older v2.5) is moved to a backup folder first.
set -euo pipefail
src="$(cd "$(dirname "$0")" && pwd)/skill/software-audit"
dest="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}/software-audit"
mkdir -p "$(dirname "$dest")"
if [ -e "$dest" ]; then
  backup="$dest.backup-$(date +%Y%m%d-%H%M%S)"
  mv "$dest" "$backup"
  echo "existing skill moved to $backup"
fi
cp -R "$src" "$dest"
echo "installed: $dest"
python3 -c "import yaml" 2>/dev/null || echo "note: PyYAML missing -> pip install pyyaml"
for t in gitleaks semgrep osv-scanner syft hadolint ruff bwrap; do
  command -v "$t" >/dev/null || echo "optional tool not found: $t"
done
