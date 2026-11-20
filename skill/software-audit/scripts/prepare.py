#!/usr/bin/env python3
"""Step 1: pin the commit, build the file inventory, detect facts, select checklist items.

Usage:
  prepare.py [--repo PATH] [--allow-exec | --allow-exec-unsandboxed] [--extra-checklist FILE.yaml ...]
             [--exclude PATH ...] [--fact NAME=yes|no ...] [--allow-dirty] [--base REF]

--base REF audits only the change from the merge base of REF to HEAD (a pull request or branch).

Creates <repo>/.audit/<run_id>/ with run.json, inventory.json, facts.json, items.json
and prints the run folder path.
"""
import argparse
import datetime as dt
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (CHECKLIST_DIR, git, load_checklists, load_yaml, repo_root,  # noqa: E402
                    sandbox_available, sha256_file, write_json, die)

SKILL_VERSION = "0.3.4"

CLASS_RULES = [
    ("vendored", re.compile(r"(^|/)(vendor|third_party|node_modules)/")),
    ("generated", re.compile(r"(\.min\.(js|css)$|(^|/)dist/|(^|/)build/|_pb2\.py$|\.generated\.)")),
    ("test", re.compile(r"(^|/)(tests?|__tests__|spec)/|(_test|\.test|\.spec)\.[a-z]+$|(^|/)test_[^/]+\.py$")),
    ("ci", re.compile(r"(^|/)(\.github/workflows|\.gitlab-ci\.yml|\.circleci|Jenkinsfile)")),
    ("container", re.compile(r"(^|/)(Dockerfile[^/]*|docker-compose[^/]*\.ya?ml|compose\.ya?ml)$")),
    ("dependency-manifest", re.compile(r"(^|/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|setup\.py|Pipfile|go\.mod|Cargo\.toml|pom\.xml|build\.gradle)$")),
    ("lockfile", re.compile(r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|uv\.lock|Pipfile\.lock|go\.sum|Cargo\.lock)$")),
    ("docs", re.compile(r"\.(md|rst|txt|adoc)$")),
    ("config", re.compile(r"\.(ya?ml|toml|ini|cfg|conf|json|env\.example)$|(^|/)\.[a-z]+rc$")),
    ("source", re.compile(r"\.(py|js|jsx|ts|tsx|mjs|cjs|go|rs|java|kt|rb|php|cs|swift|c|h|cpp|hpp|sql|sh|vue|svelte|html|css)$")),
]
AREA_TO_PASS = {"functionality": "functionality", "operations": "functionality",
                "security": "security", "governance": "governance"}
OUT_OF_SCOPE = {"vendored", "generated", "binary"}

# fact -> list of (file glob regex, content regex). A fact is true if any signal matches.
FACT_SIGNALS = {
    "has_api": [(r"\.py$", r"@(app|router|bp|blueprint)\.(get|post|put|patch|delete|route)\(|APIRouter\(|FastAPI\(|Flask\(|urlpatterns"),
                (r"\.[cm]?[jt]sx?$", r"\b(app|router)\.(get|post|put|patch|delete)\(|express\(\)|fastify\(|@(Get|Post|Controller)\(")],
    "has_ui": [(r"\.(html|jsx|tsx|vue|svelte)$", r".")],
    "has_db": [(r"\.py$", r"sqlalchemy|sqlite3|psycopg|pymongo|django\.db|peewee|tortoise"),
               (r"\.[cm]?[jt]sx?$", r"prisma|typeorm|sequelize|knex|mongoose|better-sqlite3|sqlite3?\b|node:sqlite|pg\b|drizzle-orm|dexie"),
               (r"(^|/)migrations?/", r".")],
    "has_tests": [(r"(^|/)(tests?|__tests__)/|(_test|\.test|\.spec)\.[a-z]+$|(^|/)test_[^/]+\.py$", r".")],
    "has_ai_features": [(r"\.py$|\.[cm]?[jt]sx?$", r"\b(openai|anthropic|langchain|llama_index|ollama|google\.generativeai|@anthropic-ai|mistralai|litellm|transformers)\b"),
                        # agent skills, subagents and commands are AI features too
                        (r"(^|/)(SKILL\.md|AGENTS\.md)$|(^|/)\.claude/(agents|skills|commands)/", r".")],
    "processes_personal_data": [(r"\.(py|sql|prisma)$|\.[cm]?[jt]sx?$", r"\b(email|e_mail|password|phone|address|birth|first_?name|last_?name|ip_address|user_?id)\b")],
    "has_docker": [(r"(^|/)Dockerfile", r".")],
    "has_ci": [(r"(^|/)(\.github/workflows/|\.gitlab-ci\.yml|\.circleci/)", r".")],
}


def changed_lines(root, base_commit):
    """Files changed between base_commit and HEAD with their changed line ranges (new side).

    Returns ({path: ["12-20", ...]}, [deleted paths]). A pure deletion inside a file is recorded
    as the line where it happened, so a removed check still counts as part of the change.
    An empty range list means "changed, no line information" (binary file, pure rename)."""
    files, deleted = {}, []
    status = git(root, "-c", "core.quotePath=false", "diff", "--name-status", "-z", "-M",
                 "--no-ext-diff", base_commit, "HEAD").split("\0")
    i = 0
    while i < len(status) and status[i]:
        code = status[i]
        if code.startswith(("R", "C")):
            new = status[i + 2]
            i += 3
        else:
            new = status[i + 1]
            i += 2
        if code.startswith("D"):
            deleted.append(new)
        else:
            files[new] = []
    cur = None
    patch = git(root, "-c", "core.quotePath=false", "diff", "--unified=0", "--no-color", "--no-ext-diff",
                "-M", base_commit, "HEAD")
    for line in patch.splitlines():
        if line.startswith("+++ "):
            path = line[4:]
            cur = path[2:] if path.startswith("b/") else None
        elif line.startswith("@@") and cur in files:
            m = re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", line)
            if m:
                start, n = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
                files[cur].append(f"{max(start, 1)}-{start + n - 1}" if n else f"{max(start, 1)}-{max(start, 1)}")
    return files, deleted


def classify(path, data):
    if b"\x00" in data[:8192]:
        return "binary"
    for cls, rx in CLASS_RULES:
        if rx.search(path):
            return cls
    return "other"


def build_inventory(root, exclude=()):
    files = [f for f in git(root, "ls-files", "-z").split("\0") if f]
    inv = []
    for rel in files:
        if any(rel == e or rel.startswith(e + "/") for e in exclude):
            inv.append({"path": rel, "class": "excluded", "in_scope": False,
                        "exclude_reason": "excluded by the user (--exclude)"})
            continue
        p = root / rel
        if p.is_symlink():
            inv.append({"path": rel, "class": "symlink", "in_scope": False, "exclude_reason": "symlink"})
            continue
        if not p.is_file():
            inv.append({"path": rel, "class": "missing", "in_scope": False, "exclude_reason": "in git index but not in working tree"})
            continue
        data = p.read_bytes()
        cls = classify(rel, data)
        entry = {"path": rel, "bytes": len(data), "sha256": sha256_file(p), "class": cls,
                 "lines": None if cls == "binary" else data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1),
                 "in_scope": cls not in OUT_OF_SCOPE}
        if not entry["in_scope"]:
            entry["exclude_reason"] = cls
        inv.append(entry)
    return inv


def detect_facts(root, inv):
    facts = {}
    for fact, signals in FACT_SIGNALS.items():
        hits = []
        for f in inv:
            if not f.get("in_scope") or f["class"] == "binary":
                continue
            for path_rx, content_rx in signals:
                if not re.search(path_rx, f["path"]):
                    continue
                if content_rx == r".":
                    hits.append(f["path"])
                    break
                try:
                    text = (root / f["path"]).read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                m = re.search(content_rx, text, re.IGNORECASE if fact == "processes_personal_data" else 0)
                if m:
                    line = text.count("\n", 0, m.start()) + 1
                    hits.append(f"{f['path']}:{line}")
                    break
            if len(hits) >= 5:
                break
        facts[fact] = {"value": bool(hits), "signals": hits, "source": "detected"}
    facts["always"] = {"value": True, "signals": [], "source": "fixed"}
    return facts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--allow-exec", action="store_true", help="allow running tests/builds (needs bubblewrap)")
    g.add_argument("--allow-exec-unsandboxed", action="store_true",
                   help="allow running tests/builds without bubblewrap (own trusted repos only)")
    ap.add_argument("--extra-checklist", action="append", default=[],
                    help="additional checklist file (absolute path or name in checklists/)")
    ap.add_argument("--allow-dirty", action="store_true",
                    help="audit even if tracked files have uncommitted changes (the report then says the "
                         "audited state is NOT the recorded commit)")
    ap.add_argument("--exclude", action="append", default=[], metavar="PATH",
                    help="leave a repo-relative folder or file out of the audit, e.g. a test fixture or "
                         "a deliberately vulnerable demo app; listed in the report")
    ap.add_argument("--fact", action="append", default=[], metavar="NAME=yes|no",
                    help="override a detected fact, e.g. --fact processes_personal_data=yes")
    ap.add_argument("--base", metavar="REF",
                    help="audit only the change from the merge base of REF to HEAD, e.g. --base origin/main "
                         "for a pull request")
    a = ap.parse_args()

    root = repo_root(a.repo)
    commit = git(root, "rev-parse", "HEAD").strip()
    dirty = git(root, "status", "--porcelain", "--untracked-files=no").strip()
    if dirty and not a.allow_dirty:
        die("the working tree has uncommitted changes to tracked files, so the audit would not match the "
            "commit. Commit or stash them, or run again with --allow-dirty.\n" + dirty[:2000])
    skip = []
    for e in a.exclude:
        e = e.strip().rstrip("/")
        while e.startswith("./"):
            e = e[2:]
        if not e or e.startswith("/") or ".." in Path(e).parts:
            die(f"bad --exclude {e!r}: give a path relative to the repository root")
        skip.append(e)
    inv = build_inventory(root, skip)
    change = None
    if a.base:
        mb = git(root, "merge-base", a.base, "HEAD", check=False).strip()
        if not mb:
            die(f"cannot find a merge base of {a.base!r} and HEAD. Fetch the base branch first "
                f"(e.g. git fetch origin main; in a shallow clone git fetch --unshallow).")
        files, deleted = changed_lines(root, mb)
        by_path = {f["path"]: f for f in inv}
        files = {p: r for p, r in files.items() if by_path.get(p, {}).get("in_scope")}
        if not files and not deleted:
            die(f"no in-scope file changed between {a.base} ({mb[:12]}) and HEAD; nothing to audit")
        for p in files:
            by_path[p]["changed"] = True
        change = {"base": a.base, "base_commit": mb, "files": files, "deleted": deleted,
                  "commits": len(git(root, "rev-list", f"{mb}..HEAD").split())}
    unmatched = [e for e in skip if not any(f["class"] == "excluded" and (f["path"] == e or f["path"].startswith(e + "/"))
                                            for f in inv)]
    if unmatched:
        die(f"--exclude matches no tracked file: {', '.join(unmatched)}")
    now = dt.datetime.now(dt.timezone.utc)
    run_id = now.strftime("%Y%m%d-%H%M%S") + "-" + commit[:7]
    run_dir, n = root / ".audit" / run_id, 1
    while run_dir.exists():
        n += 1
        run_dir = root / ".audit" / f"{run_id}-{n}"
    run_id = run_dir.name
    run_dir.mkdir(parents=True)

    # Keep audit output out of git status of the audited repo.
    exclude = Path(git(root, "rev-parse", "--git-path", "info/exclude").strip())
    if not exclude.is_absolute():
        exclude = root / exclude
    exclude.parent.mkdir(parents=True, exist_ok=True)
    if ".audit/" not in (exclude.read_text() if exclude.exists() else ""):
        with open(exclude, "a") as f:
            f.write("\n.audit/\n")

    exec_mode = "none"
    if a.allow_exec:
        exec_mode = "sandboxed"
    elif a.allow_exec_unsandboxed:
        exec_mode = "unsandboxed"

    facts = detect_facts(root, inv)
    for ov in a.fact:
        name, _, val = ov.partition("=")
        if name not in facts or val not in ("yes", "no"):
            die(f"bad --fact {ov}; known facts: {', '.join(facts)}")
        facts[name] = {"value": val == "yes", "signals": facts[name]["signals"], "source": "override"}

    extra = []
    for e in a.extra_checklist:
        p = Path(e)
        if not p.is_absolute():
            p = CHECKLIST_DIR / e
        if not p.exists():
            die(f"checklist {e} not found")
        extra.append(p)
    items = load_checklists()
    for p in extra:
        for it in load_yaml(p):
            it["_file"] = p.name
            items.append(it)

    applicable, not_applicable = [], []
    for it in items:
        cond = it.get("applies_if", "always")
        fact = facts.get(cond)
        if fact is None:
            die(f"{it['id']}: unknown applies_if '{cond}'")
        it["pass"] = AREA_TO_PASS.get(it.get("area"), "functionality")
        if fact["value"]:
            applicable.append(it)
        else:
            not_applicable.append({"id": it["id"], "title": it["title"], "area": it["area"],
                                   "reason": f"applies_if '{cond}' is false (no signals found)"})

    run = {
        "run_id": run_id, "skill_version": SKILL_VERSION, "repo": str(root), "repo_name": root.name,
        "commit": commit, "dirty": bool(dirty), "dirty_files": dirty.splitlines()[:50],
        "started_at": now.isoformat(timespec="seconds"), "exec_mode": exec_mode,
        "sandbox_available": sandbox_available(),
        "extra_checklists": [str(p) for p in extra],
        "exclude": skip,
        "change": change,
    }
    write_json(run_dir / "run.json", run)
    write_json(run_dir / "inventory.json", inv)
    write_json(run_dir / "facts.json", facts)
    write_json(run_dir / "items.json", {"applicable": applicable, "not_applicable": not_applicable})

    in_scope = sum(1 for f in inv if f.get("in_scope"))
    print(f"run folder: {run_dir}")
    print(f"commit {commit[:12]}{' (working tree has uncommitted changes)' if dirty else ''}")
    print(f"files: {len(inv)} total, {in_scope} in scope"
          + (f" (excluded by --exclude: {', '.join(skip)})" if skip else ""))
    if change:
        print(f"change audit: {len(change['files'])} changed files, {len(change['deleted'])} deleted, "
              f"{change['commits']} commits since {a.base} ({change['base_commit'][:12]})")
    print("facts: " + ", ".join(f"{k}={'yes' if v['value'] else 'no'}" for k, v in facts.items() if k != "always"))
    by_pass = {}
    for it in applicable:
        by_pass[it["pass"]] = by_pass.get(it["pass"], 0) + 1
    print(f"checklist items: {len(applicable)} applicable ({by_pass}), {len(not_applicable)} not applicable")
    print(f"repo code execution: {exec_mode}; bubblewrap {'available' if run['sandbox_available'] else 'not installed'}")


if __name__ == "__main__":
    main()
