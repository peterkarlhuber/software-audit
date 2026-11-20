#!/usr/bin/env python3
"""Step 1b (optional): install the repository's dependencies into a workspace copy, so that
tests and confirmation tests can run.

Usage:
  install_deps.py RUN_DIR

Installing needs network access, so it runs only if the run was started with
prepare.py --allow-install (or --allow-install-scripts), on top of --allow-exec. The repository
itself is never changed: its tracked files are copied to RUN/workspace and dependencies are
installed there, inside the bubblewrap sandbox with network access (ordinary user, empty home,
only proxy/CA settings in the environment, no credentials). Afterwards run_tools.py and
run_test.py run repo code from that workspace.

Package install scripts are third-party code. By default they do not run:
  - npm/pnpm/yarn with --ignore-scripts (native modules are then not built)
  - pip with --only-binary :all: (no sdist or git builds) and without installing the project
    itself (tests run with `python -m pytest` from the project folder, which imports it)
With --allow-install-scripts they run, still inside the sandbox.

Per package root (a folder with a lockfile or Python project file, outside excluded paths):
  - package-lock.json      -> npm ci            (large binary downloads such as Electron skipped)
  - pnpm-lock.yaml         -> pnpm install --frozen-lockfile (if pnpm is installed)
  - yarn.lock              -> yarn install --frozen-lockfile (if yarn is installed)
  - pyproject/setup.py/requirements*.txt -> one shared venv RUN/workspace/.audit-venv with pytest,
    the dev/test requirements, the lock file, requirements.txt (and, with scripts, the project)
Results go to RUN/deps.json; failures are recorded, not fatal.
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (NETWORK_ENV, SAFE_ENV, git, read_json, run_dir_from_arg,  # noqa: E402
                    sandbox_available, sandboxed_cmd, write_json)

TIMEOUT = 1200
SKIP_DOWNLOADS = {
    "ELECTRON_SKIP_BINARY_DOWNLOAD": "1",
    "PUPPETEER_SKIP_DOWNLOAD": "1",
    "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
    "CYPRESS_INSTALL_BINARY": "0",
    "npm_config_audit": "false",
    "npm_config_fund": "false",
    "npm_config_update_notifier": "false",
}
PY_REQUIREMENTS = ["requirements-dev-lock.txt", "requirements-dev.txt", "requirements-test.txt",
                   "requirements_dev.txt", "requirements-lock.txt", "requirements.txt"]
VENV = ".audit-venv"


def package_roots(inv, exclude):
    """Folders (repo-relative, '' = root) with a lockfile or Python project file."""
    js, py = {}, set()
    for f in inv:
        if not f.get("in_scope") and f.get("class") != "lockfile":
            continue
        p = f["path"]
        if any(p == e or p.startswith(e + "/") for e in exclude) or "node_modules/" in p:
            continue
        d, name = (p.rsplit("/", 1) if "/" in p else ("", p))
        if name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
            js.setdefault(d, name)
        elif name in ("pyproject.toml", "setup.py") or re.fullmatch(r"requirements[^/]*\.txt", name):
            py.add(d)
    # npm workspaces: a lockfile in a parent covers its children
    return dict(sorted(js.items())), sorted(py)


def copy_tracked(repo, dest):
    files = [f for f in git(repo, "ls-files", "-z").split("\0") if f]
    for rel in files:
        src = repo / rel
        if not (src.is_file() or src.is_symlink()):
            continue
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        if src.is_symlink():
            os.symlink(os.readlink(src), out)
        else:
            shutil.copy2(src, out)
    # git metadata is not copied; tools that need a repository see a plain folder
    dest.mkdir(parents=True, exist_ok=True)


def requirement_entries(text):
    """Requirement entries of a requirements file, continuation lines joined; options,
    includes and editable/path entries are left out."""
    entries, cur = [], ""
    for line in text.splitlines():
        line = line.split(" #", 1)[0].rstrip() if not line.lstrip().startswith("#") else ""
        if line.endswith("\\"):
            cur += line[:-1] + " "
            continue
        cur += line
        e = cur.strip()
        cur = ""
        if e and not e.startswith(("-", ".", "/")):
            entries.append(e)
    return entries


def install_one_by_one(ws, sandboxed, venv_py, base, d, req, no_deps):
    try:
        entries = requirement_entries((base / req).read_text(errors="ignore"))
    except OSError:
        return None
    tmp = ws / ".audit-req"
    tmp.mkdir(exist_ok=True)
    root_ref = "/work" if sandboxed else str(ws)
    missing = []
    for i, e in enumerate(entries):
        (tmp / f"{i}.txt").write_text(e + "\n")
        hashed = "--hash" in e
        argv = [venv_py, "-m", "pip", "install", "-q", "--only-binary", ":all:", "-r", f"{root_ref}/.audit-req/{i}.txt"] \
            + (["--no-deps"] if no_deps or hashed else [])
        code, _ = run_in(ws, sandboxed, argv, d)
        if code != 0:
            missing.append(e.split()[0])
    shutil.rmtree(tmp, ignore_errors=True)
    return missing


def has_workspaces(pkg):
    try:
        return '"workspaces"' in pkg.read_text(errors="ignore")
    except OSError:
        return False


def run_in(ws, sandboxed, argv, subdir="", env_extra=None):
    env = {k: v for k, v in os.environ.items() if k in SAFE_ENV or k in NETWORK_ENV}
    home = ws.parent / "workspace-home"
    home.mkdir(exist_ok=True)
    env["HOME"] = str(home)
    env.update(SKIP_DOWNLOADS)
    env.update(env_extra or {})
    ca_files = sorted({v for k, v in env.items() if k in NETWORK_ENV and os.path.isfile(v)})
    cmd = sandboxed_cmd(argv, ws, network=True, subdir=subdir, ro_files=ca_files) if sandboxed else argv
    cwd = ws / subdir if subdir else ws
    try:
        r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=TIMEOUT)
        return r.returncode, (r.stdout + "\n" + r.stderr)[-4000:]
    except subprocess.TimeoutExpired:
        return None, f"timeout after {TIMEOUT}s"
    except FileNotFoundError as e:
        return None, str(e)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    rd = run_dir_from_arg(sys.argv[1])
    run = read_json(rd / "run.json")
    mode = run.get("exec_mode", "none")
    if mode == "none":
        print("skipped: repo code execution is not allowed for this run (prepare.py --allow-exec)")
        write_json(rd / "deps.json", {"status": "skipped", "reason": "exec_mode none", "steps": []})
        return
    sandboxed = sandbox_available()
    if not sandboxed and mode != "unsandboxed":
        print("skipped: bubblewrap is not installed")
        write_json(rd / "deps.json", {"status": "skipped", "reason": "bubblewrap not installed", "steps": []})
        return
    install = run.get("install_mode", "none")
    if install == "none":
        print("skipped: installing dependencies needs network access and was not allowed for this run "
              "(prepare.py --allow-install, or --allow-install-scripts to also run package install scripts)")
        write_json(rd / "deps.json", {"status": "skipped", "reason": "install_mode none", "steps": []})
        return
    scripts = install == "scripts"
    repo = Path(run["repo"])
    inv = read_json(rd / "inventory.json")
    js, py = package_roots(inv, run.get("exclude", []))
    if not js and not py:
        print("nothing to install: no lockfile or Python project file found")
        write_json(rd / "deps.json", {"status": "not_applicable", "steps": []})
        return

    ws = rd / "workspace"
    if ws.exists():
        shutil.rmtree(ws)
    # Only tracked files are copied: untracked local files (.env, credentials) never reach
    # the network-enabled sandbox.
    copy_tracked(repo, ws)
    root_ref = "/work" if sandboxed else str(ws)
    steps = []

    installed = []  # JS roots installed so far; a parent with "workspaces" covers its children
    for d, lock in js.items():
        parent = next((c for c in installed if c == "" or d.startswith(c + "/")), None)
        if parent is not None and has_workspaces(ws / parent / "package.json"):
            steps.append({"root": d, "tool": "-", "status": "ok",
                          "note": f"covered by the workspace install in '{parent or '.'}'"})
            continue
        tool = {"package-lock.json": "npm", "pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn"}[lock]
        if not shutil.which(tool):
            steps.append({"root": d or ".", "tool": tool, "status": "missing", "note": f"{tool} not installed"})
            continue
        argv = {"npm": ["npm", "ci"], "pnpm": ["pnpm", "install", "--frozen-lockfile"],
                "yarn": ["yarn", "install", "--frozen-lockfile"]}[tool] + ([] if scripts else ["--ignore-scripts"])
        code, out = run_in(ws, sandboxed, argv, d)
        steps.append({"root": d or ".", "tool": tool, "command": argv,
                      "status": "ok" if code == 0 else "failed", "exit_code": code, "output_tail": out[-1500:]})
        if code == 0:
            installed.append(d)

    if py:
        venv_py = f"{root_ref}/{VENV}/bin/python"
        code, out = run_in(ws, sandboxed, [sys.executable if not sandboxed else shutil.which("python3") or "python3",
                                           "-m", "venv", f"{root_ref}/{VENV}"])
        ok = code == 0
        steps.append({"root": ".", "tool": "venv", "status": "ok" if ok else "failed", "exit_code": code,
                      "output_tail": out[-800:]})
        if ok:
            pip_bin = [] if scripts else ["--only-binary", ":all:"]
            code, out = run_in(ws, sandboxed, [venv_py, "-m", "pip", "install", "-q", "pytest"] + pip_bin)
            steps.append({"root": ".", "tool": "pip", "command": ["pip", "install", "pytest"],
                          "status": "ok" if code == 0 else "failed", "exit_code": code, "output_tail": out[-800:]})
            for d in py:
                base = ws / d if d else ws
                # test/dev requirements, the runtime lock, then the plain requirements file; after a
                # lock only the missing pins (e.g. git sources) are added, without re-resolving
                reqs = [r for r in PY_REQUIREMENTS if (base / r).is_file()]
                locked = False
                for req in reqs:
                    no_deps = locked and req == "requirements.txt"
                    argv = [venv_py, "-m", "pip", "install", "-q", "-r", req] + (["--no-deps"] if no_deps else []) + pip_bin
                    code, out = run_in(ws, sandboxed, argv, d)
                    step = {"root": d or ".", "tool": "pip", "command": argv[1:], "status": "ok" if code == 0 else "failed",
                            "exit_code": code, "output_tail": out[-1500:]}
                    if code != 0 and not scripts:
                        # without builds one sdist-only package fails the whole file: install the
                        # entries one by one and record which ones could not be installed
                        missing = install_one_by_one(ws, sandboxed, venv_py, base, d, req, no_deps)
                        step.update(status="partial" if missing is not None else "failed",
                                    fallback="one by one, binary wheels only",
                                    not_installed=missing if missing is not None else None)
                    steps.append(step)
                    locked = locked or (step["status"] != "failed" and "lock" in req)
                req = bool(reqs)
                if scripts and ((base / "pyproject.toml").is_file() or (base / "setup.py").is_file()):
                    # with a (locked) requirements file the dependencies are already installed;
                    # resolving them again from the project file can fail for pinned git sources
                    argv = [venv_py, "-m", "pip", "install", "-q", "-e", "."] + (["--no-deps"] if req else [])
                    code, out = run_in(ws, sandboxed, argv, d)
                    steps.append({"root": d or ".", "tool": "pip", "command": argv[1:], "status": "ok" if code == 0 else "failed",
                                  "exit_code": code, "output_tail": out[-1500:]})

    failed = [s for s in steps if s["status"] not in ("ok",)]
    status = "ok" if not failed else ("partial" if len(failed) < len(steps) else "failed")
    write_json(rd / "deps.json", {"status": status, "sandbox": "bubblewrap (network on)" if sandboxed else "none",
                                  "install_scripts": scripts,
                                  "workspace": str(ws), "venv": VENV if py else None, "steps": steps})
    run["workspace"] = str(ws)
    run["workspace_venv"] = VENV if py and (ws / VENV).is_dir() else None
    write_json(rd / "run.json", run)
    print(f"workspace: {ws}")
    for s in steps:
        print(f"{s['root']:<20} {s['tool']:<6} {s['status']}" + (f" (exit {s.get('exit_code')})" if s["status"] != "ok" else ""))
    print(f"dependencies: {status}")


if __name__ == "__main__":
    main()
