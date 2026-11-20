"""Shared helpers for the audit scripts. Python 3.9+, standard library plus PyYAML."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
CHECKLIST_DIR = SKILL_DIR / "checklists"
PASSES = {
    "functionality": ["functionality.yaml", "operations.yaml"],
    "security": ["security.yaml"],
    "governance": ["governance.yaml"],
}
SEVERITIES = ["critical", "high", "medium", "low"]
RESULTS = ["PASS", "FAIL", "UNKNOWN", "N/A"]

# Environment variables that are kept when repo code runs. Everything else
# (tokens, cloud credentials, SSH agent) is dropped.
SAFE_ENV = {"PATH", "LANG", "LC_ALL", "TERM", "TZ"}


def die(msg, code=2):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        die("PyYAML is required: pip install pyyaml")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def read_json(path, default=None):
    p = Path(path)
    if not p.exists():
        return default
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def write_json(path, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def git(repo, *args, check=True):
    """Run git with hooks, filters and external helpers neutralised."""
    cmd = ["git", "-C", str(repo),
           "-c", "core.hooksPath=/dev/null",
           "-c", "core.fsmonitor=false",
           "-c", "diff.external=",
           "-c", "core.pager=cat",
           *args]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        die(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


def repo_root(path="."):
    out = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        die(f"{path} is not inside a git repository")
    return Path(out.stdout.strip())


def load_checklists(names=None):
    items = []
    files = names or [f for fs in PASSES.values() for f in fs]
    for name in files:
        for item in load_yaml(CHECKLIST_DIR / name):
            item["_file"] = name
            items.append(item)
    return items


def pass_of(item_file):
    for p, files in PASSES.items():
        if item_file in files:
            return p
    return "extra"


def run_dir_from_arg(arg):
    p = Path(arg).resolve()
    if not (p / "run.json").exists():
        die(f"{p} is not an audit run folder (run.json missing)")
    return p


def sandbox_available():
    return shutil.which("bwrap") is not None


def sandboxed_cmd(argv, workdir, network=False):
    """Wrap argv with bubblewrap: read-only system, writable copy of the repo,
    empty home, no network by default."""
    bw = ["bwrap", "--die-with-parent", "--unshare-all", "--new-session",
          "--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc",
          "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
          "--tmpfs", "/home", "--setenv", "HOME", "/home/audit",
          "--bind", str(workdir), "/work", "--chdir", "/work"]
    for d in ("/bin", "/lib", "/lib64", "/lib32", "/opt", "/usr/local"):
        if os.path.exists(d) and not os.path.islink(d):
            bw += ["--ro-bind", d, d]
        elif os.path.islink(d):
            bw += ["--symlink", os.readlink(d), d]
    if network:
        bw += ["--share-net"]
    return bw + ["--"] + list(argv)


def run_repo_code(argv, repo, run, timeout=900, extra_files=None, extra_env=None, collect=None):
    """Run repo code (tests, builds) in a throwaway copy of the repo.

    Uses bubblewrap when available. Without it, runs only if the run was
    started with --allow-exec-unsandboxed (for the user's own trusted repos),
    and always with a stripped environment.
    extra_files: {relative dest: source path} copied into the copy before running.
    extra_env: additional environment variables. collect: relative paths of JSON
    files to read back from the copy after the run (returned under "collected").
    Returns dict(status, exit_code, output, sandbox, collected).
    """
    mode = run.get("exec_mode", "none")
    if mode == "none":
        return {"status": "skipped", "reason": "execution of repo code not allowed for this run (use --allow-exec)",
                "exit_code": None, "output": "", "sandbox": None}
    use_bwrap = sandbox_available()
    if not use_bwrap and mode != "unsandboxed":
        return {"status": "skipped", "reason": "bubblewrap not installed; repo code is not executed without a sandbox "
                "(start the run with --allow-exec-unsandboxed only for your own trusted repos)",
                "exit_code": None, "output": "", "sandbox": None}
    tmp = Path(tempfile.mkdtemp(prefix="audit-exec-"))
    work = tmp / "work"
    shutil.copytree(repo, work, symlinks=True, ignore=shutil.ignore_patterns(".audit"))
    for rel, src in (extra_files or {}).items():
        dest = work / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
    env = {k: v for k, v in os.environ.items() if k in SAFE_ENV}
    env.update(extra_env or {})
    env["HOME"] = str(tmp / "home")
    os.makedirs(env["HOME"], exist_ok=True)
    cmd = sandboxed_cmd(argv, work) if use_bwrap else list(argv)
    try:
        r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout + "\n" + r.stderr)[-200000:]
        res = {"status": "ran", "exit_code": r.returncode, "output": out, "collected": {}}
        for rel in collect or []:
            p = work / rel
            if p.is_file():
                try:
                    res["collected"][rel] = json.loads(p.read_text(encoding="utf-8"))
                except ValueError:
                    pass
    except subprocess.TimeoutExpired:
        res = {"status": "timeout", "exit_code": None, "output": f"timeout after {timeout}s"}
    except FileNotFoundError as e:
        res = {"status": "error", "exit_code": None, "output": str(e)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    res["sandbox"] = "bubblewrap" if use_bwrap else "none (stripped environment, temp copy)"
    return res
