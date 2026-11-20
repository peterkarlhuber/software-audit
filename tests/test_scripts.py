"""Self-tests for the audit scripts. Run: python3 -m pytest -q tests/"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "skill" / "software-audit" / "scripts"


def sh(*args, cwd=None):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


@pytest.fixture()
def run(tmp_path):
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "api.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "\n"
        "@app.get('/items/{item_id}')\n"
        "def get_item(item_id: int):\n"
        "    return db.lookup(item_id)\n")
    (repo / "README.md").write_text("# Demo\n")
    sh("git", "init", "-q", "-b", "main", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init", cwd=repo)
    sh(sys.executable, str(SCRIPTS / "prepare.py"), "--repo", str(repo))
    rd = next((repo / ".audit").iterdir())
    return repo, rd


def write_pass(rd, items, findings=(), triage=()):
    (rd / "passes").mkdir(exist_ok=True)
    (rd / "passes" / "security.json").write_text(json.dumps(
        {"pass": "security", "items": items, "findings": list(findings), "tool_triage": list(triage)}))


def check(rd):
    sh(sys.executable, str(SCRIPTS / "check_run.py"), str(rd), "--no-transcripts")
    res = json.loads((rd / "results.json").read_text())
    return {i["id"]: i for i in res["items"]}, {f["id"]: f for f in res["findings"]}, res


GOOD_QUOTE = {"file": "app/api.py", "lines": "4-6", "quote": "@app.get('/items/{item_id}')\ndef get_item(item_id: int):"}


def test_prepare_detects_api_and_excludes_audit_folder(run):
    repo, rd = run
    facts = json.loads((rd / "facts.json").read_text())
    assert facts["has_api"]["value"] is True
    status = subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True).stdout
    assert ".audit" not in status


def test_missing_items_become_unknown(run):
    _, rd = run
    write_pass(rd, [])
    items, _, _ = check(rd)
    assert items["SEC-AUTHZ-01"]["result"] == "UNKNOWN"
    assert all(i["result"] in ("UNKNOWN", "N/A") for i in items.values())


def test_pass_without_completeness_is_rejected(run):
    _, rd = run
    write_pass(rd, [{"id": "SEC-AUTHN-01", "result": "PASS", "examined": ["app/api.py"], "completeness": "",
                     "evidence": [GOOD_QUOTE]}])
    items, _, _ = check(rd)
    assert items["SEC-AUTHN-01"]["result"] == "UNKNOWN"
    assert "completeness" in items["SEC-AUTHN-01"]["reason"]


def test_pass_with_invented_quote_is_rejected(run):
    _, rd = run
    write_pass(rd, [{"id": "SEC-AUTHN-01", "result": "PASS", "examined": ["app/api.py"],
                     "completeness": "Listed every route in app/api.py with grep for '@app.' and checked each one.",
                     "evidence": [{"file": "app/api.py", "lines": "4", "quote": "require_login(current_user)"}]}])
    items, _, _ = check(rd)
    assert items["SEC-AUTHN-01"]["result"] == "UNKNOWN"
    assert "quote not found" in items["SEC-AUTHN-01"]["reason"]


def test_supported_pass_is_kept(run):
    _, rd = run
    write_pass(rd, [{"id": "SEC-AUTHN-01", "result": "PASS", "examined": ["app/api.py"],
                     "completeness": "Listed every route in app/api.py with grep for '@app.' and checked each one.",
                     "evidence": [GOOD_QUOTE]}])
    items, _, _ = check(rd)
    assert items["SEC-AUTHN-01"]["result"] == "PASS"


def test_tool_item_cannot_pass_without_tool(run):
    _, rd = run
    write_pass(rd, [{"id": "SEC-SECRETS-01", "result": "PASS", "examined": ["app/api.py"],
                     "completeness": "Reviewed the whole repository by hand for anything that looks like a key.",
                     "evidence": [GOOD_QUOTE]}])
    items, _, _ = check(rd)  # run_tools.py was not run
    assert items["SEC-SECRETS-01"]["result"] == "UNKNOWN"
    assert "did not run" in items["SEC-SECRETS-01"]["reason"]


def test_critical_finding_without_test_is_unconfirmed(run):
    _, rd = run
    finding = {"id": "F-SEC-001", "checklist_id": "SEC-AUTHZ-01", "title": "No ownership check", "severity": "critical",
               **GOOD_QUOTE, "impact": "Any user reads any item.", "recommendation": "Check the owner."}
    write_pass(rd, [{"id": "SEC-AUTHZ-01", "result": "FAIL", "finding_ids": ["F-SEC-001"], "evidence": [GOOD_QUOTE]}],
               [finding])
    items, findings, _ = check(rd)
    assert items["SEC-AUTHZ-01"]["result"] == "FAIL"
    assert findings["F-SEC-001"]["status"] == "unconfirmed"


def test_reproduced_test_confirms_finding(run):
    _, rd = run
    finding = {"id": "F-SEC-001", "checklist_id": "SEC-AUTHZ-01", "title": "No ownership check", "severity": "high",
               **GOOD_QUOTE, "impact": "Any user reads any item.", "recommendation": "Check the owner."}
    write_pass(rd, [{"id": "SEC-AUTHZ-01", "result": "FAIL", "finding_ids": ["F-SEC-001"]}], [finding])
    (rd / "tests").mkdir()
    (rd / "tests" / "F-SEC-001.json").write_text(json.dumps({"outcome": "reproduced"}))
    _, findings, _ = check(rd)
    assert findings["F-SEC-001"]["status"] == "confirmed"


def test_fail_with_only_invalid_finding_becomes_unknown(run):
    _, rd = run
    finding = {"id": "F-SEC-002", "checklist_id": "SEC-INJ-01", "title": "SQL injection", "severity": "medium",
               "file": "app/api.py", "lines": "2", "quote": "cursor.execute(f'SELECT * FROM t WHERE id={x}')",
               "impact": "Injection.", "recommendation": "Use parameters."}
    write_pass(rd, [{"id": "SEC-INJ-01", "result": "FAIL", "finding_ids": ["F-SEC-002"]}], [finding])
    items, findings, _ = check(rd)
    assert findings["F-SEC-002"]["status"] == "invalid_evidence"
    assert items["SEC-INJ-01"]["result"] == "UNKNOWN"


def test_report_contains_legal_disclaimer(run):
    _, rd = run
    write_pass(rd, [])
    check(rd)
    report = (rd / "report.md").read_text()
    assert "does not establish legal compliance" in report


def run_test(rd, fid, files, target="app/calc.py:2-3", cmd=None):
    args = [sys.executable, str(SCRIPTS / "run_test.py"), str(rd), fid, "--target", target]
    for f in files:
        args += ["--file", str(f)]
    sh(*args, "--", *(cmd or ["python3", "-m", "pytest", "-q", f"audit_tests/{Path(files[0]).name}"]))
    return json.loads((rd / "tests" / f"{fid}.json").read_text())


def test_run_test_requires_permission(run):
    _, rd = run
    d = rd / "tests" / "F-SEC-001"
    d.mkdir(parents=True)
    (d / "test_x.py").write_text("def test_x():\n    assert len('ab') == 3, 'AUDIT_CONFIRM:F-SEC-001'\n")
    assert run_test(rd, "F-SEC-001", [d / "test_x.py"])["outcome"] == "not_run"  # prepared without --allow-exec


@pytest.mark.parametrize("body, reason", [
    ("assert False, 'AUDIT_CONFIRM:F-SEC-001'", "constant condition"),
    ("raise AssertionError('AUDIT_CONFIRM:F-SEC-001')", "raised directly"),
    ("import pytest; pytest.fail('AUDIT_CONFIRM:F-SEC-001')", "pytest.fail"),
    ("x = 'AUDIT_CONFIRM:F-SEC-001'", "no assert statement"),
])
def test_run_test_rejects_trivial_tests(run, body, reason):
    _, rd = run
    d = rd / "tests" / "F-SEC-001"
    d.mkdir(parents=True)
    (d / "test_x.py").write_text(f"def test_x():\n    {body}\n")
    out = run_test(rd, "F-SEC-001", [d / "test_x.py"])
    assert out["outcome"] == "rejected" and reason in out["reason"]


@pytest.fixture()
def exec_run(tmp_path):
    repo = tmp_path / "calc"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "__init__.py").write_text("")
    (repo / "app" / "calc.py").write_text(
        "def add(a, b):\n"
        "    # defect: off by one\n"
        "    return a + b + 1\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "def unrelated():\n"
        "    return 2\n")
    sh("git", "init", "-q", "-b", "main", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init", cwd=repo)
    sh(sys.executable, str(SCRIPTS / "prepare.py"), "--repo", str(repo), "--allow-exec")
    rd = next((repo / ".audit").iterdir())
    d = rd / "tests" / "F-FUN-001"
    d.mkdir(parents=True)
    return rd, d


needs_bwrap = pytest.mark.skipif(subprocess.run(["which", "bwrap"], capture_output=True).returncode != 0,
                                 reason="bubblewrap not installed")


@needs_bwrap
def test_run_test_reproduced_only_with_real_assertion_on_cited_lines(exec_run):
    rd, d = exec_run
    (d / "test_ok.py").write_text(
        "from app.calc import add\n"
        "def test_add():\n"
        "    assert add(1, 2) == 3, 'AUDIT_CONFIRM:F-FUN-001 add is off by one'\n")
    out = run_test(rd, "F-FUN-001", [d / "test_ok.py"])
    assert out["outcome"] == "reproduced", out
    assert 3 in out["target_lines_executed"]


@needs_bwrap
def test_run_test_cited_lines_not_executed_is_inconclusive(exec_run):
    rd, d = exec_run
    (d / "test_other.py").write_text(
        "from app.calc import unrelated\n"
        "def test_other():\n"
        "    assert unrelated() == 3, 'AUDIT_CONFIRM:F-FUN-001'\n")
    out = run_test(rd, "F-FUN-001", [d / "test_other.py"])
    assert out["outcome"] == "inconclusive" and "never executed" in out["reason"]


@needs_bwrap
def test_run_test_marker_failing_outside_assertion_is_inconclusive(exec_run):
    rd, d = exec_run
    (d / "test_crash.py").write_text(
        "import pytest\n"
        "from app.calc import add\n"
        "@pytest.fixture\n"
        "def broken():\n"
        "    raise RuntimeError('setup failed')\n"
        "def test_add(broken):\n"
        "    assert add(1, 2) == 3, 'AUDIT_CONFIRM:F-FUN-001'\n")
    out = run_test(rd, "F-FUN-001", [d / "test_crash.py"])
    assert out["outcome"] == "inconclusive" and "setup" in out["reason"]


@needs_bwrap
def test_run_test_passing_test_is_not_reproduced(exec_run):
    rd, d = exec_run
    (d / "test_pass.py").write_text(
        "from app.calc import add\n"
        "def test_add():\n"
        "    assert add(1, 2) == 4, 'AUDIT_CONFIRM:F-FUN-001'\n")
    assert run_test(rd, "F-FUN-001", [d / "test_pass.py"])["outcome"] == "not_reproduced"


def test_prepare_aborts_on_uncommitted_changes(run):
    repo, _ = run
    (repo / "README.md").write_text("# Changed\n")
    r = subprocess.run([sys.executable, str(SCRIPTS / "prepare.py"), "--repo", str(repo)], capture_output=True, text=True)
    assert r.returncode != 0 and "--allow-dirty" in (r.stdout + r.stderr)
    sh(sys.executable, str(SCRIPTS / "prepare.py"), "--repo", str(repo), "--allow-dirty")
    rd = sorted((repo / ".audit").iterdir())[-1]
    assert json.loads((rd / "run.json").read_text())["dirty"] is True


# ---------------------------------------------------------------- v0.3.2

sys.path.insert(0, str(SCRIPTS))
import check_run  # noqa: E402


def test_run_test_rejects_constant_comparison(run):
    _, rd = run
    d = rd / "tests" / "F-SEC-001"
    d.mkdir(parents=True)
    (d / "test_x.py").write_text("def test_x():\n    assert 1 == 2, 'AUDIT_CONFIRM:F-SEC-001'\n")
    out = run_test(rd, "F-SEC-001", [d / "test_x.py"])
    assert out["outcome"] == "rejected" and "constant" in out["reason"]
    from run_test import trivial_python  # noqa: E402
    assert "constant" in trivial_python("def test_x():\n    assert 1 == 2, 'M'\n", "M")
    assert "constant" in trivial_python("def test_x():\n    assert not (3 > 1), 'M'\n", "M")
    assert trivial_python("def test_x():\n    assert add(1, 2) == 3, 'M'\n", "M") is None


def write_transcript(path, commands):
    lines = [json.dumps({"message": {"content": [{"type": "tool_use", "name": n, "input": i}]}}) for n, i in commands]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def test_coverage_follows_cd_loops_globs_and_dotfiles(run, tmp_path):
    repo, rd = run
    inv = json.loads((rd / "inventory.json").read_text())
    inv += [{"path": "app/util.py", "class": "source", "in_scope": True},
            {"path": "app/other.py", "class": "source", "in_scope": True},
            {"path": ".env.example", "class": "config", "in_scope": True},
            {"path": "README.md", "class": "docs", "in_scope": True}]
    r = check_run.Repo(repo, inv)
    t = tmp_path / "log.jsonl"
    write_transcript(t, [
        ("Bash", {"command": f"cd {repo}/app && for f in api.py util.py; do echo \"== $f\"; cat -n $f; done"}),
        ("Bash", {"command": f"cd {repo}; cat ./.env.example"}),
        ("Bash", {"command": "head -50 app/*.py | grep x"}),
        ("Bash", {"command": "ls README.md"}),
    ])
    opened, _ = check_run.opened_files([t], r)
    assert {"app/api.py", "app/util.py", ".env.example", "app/other.py"} <= opened
    assert "README.md" not in opened


def test_examined_folder_requires_every_file_opened(run, tmp_path):
    repo, rd = run
    t = tmp_path / "log.jsonl"
    write_transcript(t, [("Read", {"file_path": str(repo / "README.md")})])
    write_pass(rd, [{"id": "SEC-AUTHN-01", "result": "PASS", "examined": ["app"],
                     "completeness": "Listed every route in app/ with grep for '@app.' and checked each one.",
                     "evidence": [GOOD_QUOTE]}])
    sh(sys.executable, str(SCRIPTS / "check_run.py"), str(rd), "--transcripts", str(t))
    items = {i["id"]: i for i in json.loads((rd / "results.json").read_text())["items"]}
    assert items["SEC-AUTHN-01"]["result"] == "UNKNOWN"
    assert "app/api.py" in items["SEC-AUTHN-01"]["reason"]


def test_transcripts_found_when_session_started_in_parent_folder(run, tmp_path):
    repo, rd = run
    import datetime as dt
    base = tmp_path / "projects"
    write_transcript(base / "-somewhere-else" / "s1" / "subagents" / "agent-1.jsonl",
                     [("Read", {"file_path": str(repo / "app" / "api.py")})])
    write_transcript(base / "-unrelated" / "s2.jsonl", [("Read", {"file_path": "/elsewhere/x.py"})])
    found = check_run.find_transcripts(repo, dt.datetime.now(dt.timezone.utc), None, base=base)
    assert [f.name for f in found] == ["agent-1.jsonl"]


def test_missing_session_log_is_listed_as_problem(run, monkeypatch, tmp_path):
    _, rd = run
    write_pass(rd, [])
    env = {**__import__("os").environ, "HOME": str(tmp_path)}
    subprocess.run([sys.executable, str(SCRIPTS / "check_run.py"), str(rd)], env=env, check=True, capture_output=True)
    res = json.loads((rd / "results.json").read_text())
    assert any("coverage not measured" in p for p in res["problems"])


def test_tool_backed_finding_is_tool_reported_not_confirmed(run):
    _, rd = run
    (rd / "tools").mkdir()
    (rd / "tools" / "sast.json").write_text(json.dumps({"group": "sast", "status": "findings"}))
    (rd / "tools" / "sast.findings.json").write_text(json.dumps(
        [{"tool_id": "T-sast-001", "tool": "semgrep", "file": "app/api.py", "line": 4, "severity": "high"}]))
    finding = {"id": "F-SEC-001", "checklist_id": "SEC-AUTHZ-01", "title": "No ownership check", "severity": "high",
               **GOOD_QUOTE, "impact": "Any user reads any item.", "recommendation": "Check the owner.",
               "tool_ids": ["T-sast-001"]}
    write_pass(rd, [{"id": "SEC-AUTHZ-01", "result": "FAIL", "finding_ids": ["F-SEC-001"]}], [finding],
               [{"tool_id": "T-sast-001", "verdict": "real", "reason": "same defect"}])
    items, findings, _ = check(rd)
    assert findings["F-SEC-001"]["status"] == "tool_reported"
    assert items["SEC-AUTHZ-01"]["result"] == "FAIL"


def test_prepare_exclude_drops_paths_from_scope_facts_and_evidence(tmp_path):
    repo = tmp_path / "repo"
    (repo / "demo").mkdir(parents=True)
    (repo / "demo" / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\nimport sqlite3\n")
    (repo / "tool.py").write_text("print('hello world from the tool')\n")
    sh("git", "init", "-q", "-b", "main", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init", cwd=repo)
    bad = subprocess.run([sys.executable, str(SCRIPTS / "prepare.py"), "--repo", str(repo), "--exclude", "nope"],
                         capture_output=True, text=True)
    assert bad.returncode != 0 and "matches no tracked file" in bad.stdout + bad.stderr
    sh(sys.executable, str(SCRIPTS / "prepare.py"), "--repo", str(repo), "--exclude", "demo/")
    rd = next((repo / ".audit").iterdir())
    assert json.loads((rd / "run.json").read_text())["exclude"] == ["demo"]
    inv = {f["path"]: f for f in json.loads((rd / "inventory.json").read_text())}
    assert inv["demo/app.py"]["in_scope"] is False
    facts = json.loads((rd / "facts.json").read_text())
    assert facts["has_api"]["value"] is False and facts["has_db"]["value"] is False
    finding = {"id": "F-SEC-001", "checklist_id": "SEC-SAST-01", "title": "x", "severity": "low",
               "file": "demo/app.py", "lines": "2", "quote": "app = FastAPI()", "impact": "x", "recommendation": "x"}
    write_pass(rd, [], [finding])
    _, findings, res = check(rd)
    assert findings["F-SEC-001"]["status"] == "invalid_evidence"
    assert "Excluded by the user" in (rd / "report.md").read_text()


def test_skill_files_count_as_ai_feature_and_ci_item_always_applies(run):
    repo, _ = run
    (repo / "skill").mkdir()
    (repo / "skill" / "SKILL.md").write_text("# a skill\n")
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "skill", cwd=repo)
    out = sh(sys.executable, str(SCRIPTS / "prepare.py"), "--repo", str(repo))
    rd = Path(out.split("run folder: ")[1].splitlines()[0])
    assert json.loads((rd / "facts.json").read_text())["has_ai_features"]["value"] is True
    ids = {i["id"] for i in json.loads((rd / "items.json").read_text())["applicable"]}
    assert {"OPS-CI-01", "SEC-EXEC-01", "SEC-AI-01"} <= ids


def fake_tool(tmp_path, name, script):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    (b / name).write_text("#!/bin/sh\n" + script + "\n")
    (b / name).chmod(0o755)
    return b


def test_hadolint_failure_is_an_error_not_clean(tmp_path):
    import run_tools  # noqa: E402
    root = tmp_path / "r"
    root.mkdir()
    (root / "Dockerfile").write_text("FROM x\n")
    td = tmp_path / "run" / "tools"
    td.mkdir(parents=True)
    b = fake_tool(tmp_path, "hadolint", "echo 'parse error' >&2; exit 1")
    import os
    old = os.environ["PATH"]
    os.environ["PATH"] = f"{b}:{old}"
    try:
        out = run_tools.container(root, td, [{"path": "Dockerfile", "in_scope": True}])
    finally:
        os.environ["PATH"] = old
    assert out["status"] == "error" and "parse error" in out["note"]


def test_tool_findings_in_excluded_paths_are_dropped(tmp_path):
    import run_tools  # noqa: E402
    td = tmp_path / "tools"
    td.mkdir()
    run_tools.EXCLUDE[:] = ["demo"]
    try:
        out = run_tools.record(td, "sast", status="ran", findings=[{"file": "demo/a.py"}, {"file": "./src/b.py"},
                                                                      {"file": "demo2/c.py"}])
    finally:
        run_tools.EXCLUDE[:] = []
    assert out["finding_count"] == 2 and out["excluded_findings"] == 1


# ---------------------------------------------------------------- change audit (prepare.py --base)

def git_commit(repo, msg):
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", msg, cwd=repo)


@pytest.fixture()
def change_run(tmp_path):
    """Repo with a base commit on main and a feature branch that edits api.py, adds new.py, deletes old.py."""
    repo = tmp_path / "feature-repo"
    (repo / "app").mkdir(parents=True)
    api = [f"x{i} = {i}" for i in range(1, 21)]
    (repo / "app" / "api.py").write_text("\n".join(api) + "\n")
    (repo / "app" / "old.py").write_text("print('old')\n")
    (repo / "README.md").write_text("# Demo\n")
    sh("git", "init", "-q", "-b", "main", cwd=repo)
    git_commit(repo, "base")
    sh("git", "checkout", "-q", "-b", "feature", cwd=repo)
    api[9] = "x10 = eval(input())  # changed line"
    del api[16]  # remove line 17
    (repo / "app" / "api.py").write_text("\n".join(api) + "\n")
    (repo / "app" / "new.py").write_text("import os\nos.system(input())\n")
    (repo / "app" / "old.py").unlink()
    git_commit(repo, "feature")
    sh(sys.executable, str(SCRIPTS / "prepare.py"), "--repo", str(repo), "--base", "main")
    rd = next((repo / ".audit").iterdir())
    return repo, rd


def test_prepare_base_records_changed_lines(change_run):
    _, rd = change_run
    run = json.loads((rd / "run.json").read_text())
    ch = run["change"]
    assert ch["base"] == "main" and ch["commits"] == 1
    assert ch["files"] == {"app/api.py": ["10-10", "16-16"], "app/new.py": ["1-2"]}
    assert ch["deleted"] == ["app/old.py"]
    inv = {f["path"]: f for f in json.loads((rd / "inventory.json").read_text())}
    assert inv["app/api.py"].get("changed") and not inv["README.md"].get("changed")


def test_prepare_base_without_changes_or_unknown_ref_stops(run):
    repo, _ = run
    r = subprocess.run([sys.executable, str(SCRIPTS / "prepare.py"), "--repo", str(repo), "--base", "HEAD"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "nothing to audit" in r.stderr
    r = subprocess.run([sys.executable, str(SCRIPTS / "prepare.py"), "--repo", str(repo), "--base", "nope"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "merge base" in r.stderr


def test_in_change_uses_line_ranges_with_margin():
    from common import in_change
    ch = {"files": {"a.py": ["10-12"], "bin.png": []}}
    assert in_change(None, "anything.py", 5)
    assert in_change(ch, "a.py", 14) and in_change(ch, "./a.py", "1-7") and in_change(ch, "a.py", None)
    assert not in_change(ch, "a.py", 16) and not in_change(ch, "a.py", "1-6")
    assert not in_change(ch, "b.py", 10)
    assert in_change(ch, "bin.png", 99)


def test_change_audit_drops_tool_findings_outside_change(tmp_path):
    import run_tools  # noqa: E402
    td = tmp_path / "tools"
    td.mkdir()
    run_tools.CHANGE.update({"files": {"app/api.py": ["10-10"]}})
    try:
        out = run_tools.record(td, "sast", status="ran", findings=[
            {"file": "app/api.py", "line": 10}, {"file": "app/api.py", "line": 1}, {"file": "README.md", "line": 1}])
    finally:
        run_tools.CHANGE.clear()
    assert out["finding_count"] == 1 and out["outside_change_findings"] == 2


def test_change_audit_marks_findings_outside_change_and_reports_scope(change_run):
    _, rd = change_run
    (rd / "tools").mkdir(exist_ok=True)
    (rd / "tools" / "sast.json").write_text(json.dumps({"group": "sast", "status": "findings"}))
    (rd / "tools" / "sast.findings.json").write_text(json.dumps([
        {"tool_id": "T-sast-001", "file": "app/api.py", "line": 10},
        {"tool_id": "T-sast-002", "file": "app/api.py", "line": 1}]))  # outside: no triage needed
    inside = {"id": "F-SEC-001", "checklist_id": "SEC-INJ-01", "title": "eval of user input", "severity": "medium",
              "file": "app/api.py", "lines": "10", "quote": "x10 = eval(input())", "impact": "i", "recommendation": "r",
              "tool_ids": ["T-sast-001"]}
    outside = {**inside, "id": "F-SEC-002", "lines": "2", "quote": "x2 = 2  ...", "title": "old code"}
    outside["quote"] = "x1 = 1\nx2 = 2\nx3 = 3\nx4 = 4"
    write_pass(rd, [{"id": "SEC-INJ-01", "result": "FAIL", "finding_ids": ["F-SEC-001", "F-SEC-002"]}],
               findings=[inside, outside],
               triage=[{"tool_id": "T-sast-001", "verdict": "real", "reason": "eval of input"}])
    items, findings, res = check(rd)
    assert findings["F-SEC-001"]["in_change"] is True
    assert findings["F-SEC-002"]["in_change"] is False
    assert any("outside the changed lines" in n for n in findings["F-SEC-002"]["check_notes"])
    assert res["untriaged_tool_findings"] == [] and res["tool_findings_outside_change"] == ["T-sast-002"]
    assert res["coverage"]["code_files"] == 2  # only the changed files api.py and new.py
    report = (rd / "report.md").read_text()
    assert "Change audit" in report and "outside the change" in report


def test_summarize_combines_runs(run, change_run, tmp_path):
    rds = []
    for _, rd in (run, change_run):
        write_pass(rd, [])
        check(rd)
        rds.append(str(rd))
    out = tmp_path / "overview.md"
    sh(sys.executable, str(SCRIPTS / "summarize.py"), *rds, "--out", str(out))
    text = out.read_text()
    assert "| [repo](" in text and "| [feature-repo](" in text
    assert "| full |" in text and "change since `main`" in text
    assert "does not establish legal compliance" in text


# ---------------------------------------------------------------- v0.3.4 (first real run: Levuvo Mail)

def test_lowered_severity_still_needs_a_test(run):
    _, rd = run
    write_pass(rd, [{"id": "SEC-AUTHN-01", "result": "FAIL", "finding_ids": ["F-SEC-001"]}],
               [{"id": "F-SEC-001", "checklist_id": "SEC-AUTHN-01", "title": "Route without login", "severity": "low",
                 **GOOD_QUOTE, "impact": "Lowered: dev only.", "recommendation": "Add auth.", "tool_ids": []}])
    items, findings, _ = check(rd)
    f = findings["F-SEC-001"]
    assert f["status"] == "unconfirmed" and f["needs_test"] is True
    assert f["severity_default"] == "critical"
    assert any("lowered by the agent from critical to low" in n for n in f["check_notes"])
    queue = json.loads((rd / "confirm_queue.json").read_text())
    assert [q["id"] for q in queue] == ["F-SEC-001"]
    assert "checklist default: critical" in (rd / "report.md").read_text()


def test_medium_default_finding_is_not_queued(run):
    _, rd = run
    write_pass(rd, [], [{"id": "F-SEC-002", "checklist_id": "SEC-RATE-01", "title": "No rate limit", "severity": "medium",
                         **GOOD_QUOTE, "impact": "i", "recommendation": "r", "tool_ids": []}])
    _, findings, _ = check(rd)
    items_doc = json.loads((rd / "items.json").read_text())
    default = {i["id"]: i.get("severity_if_fail") for i in items_doc["applicable"]}.get("SEC-RATE-01")
    if default in ("critical", "high"):
        pytest.skip("checklist default changed")
    assert findings["F-SEC-002"]["status"] == "evidenced" and not findings["F-SEC-002"]["needs_test"]
    assert json.loads((rd / "confirm_queue.json").read_text()) == []


def test_rejected_pass_for_unopened_files_is_a_problem(run, tmp_path):
    repo, rd = run
    t = tmp_path / "log.jsonl"
    write_transcript(t, [("Grep", {"pattern": "get", "path": str(repo / "app")})])
    write_pass(rd, [{"id": "SEC-AUTHN-01", "result": "PASS", "examined": ["app/api.py"],
                     "completeness": "Listed every route in app/ with grep for '@app.' and checked each one.",
                     "evidence": [GOOD_QUOTE]}])
    sh(sys.executable, str(SCRIPTS / "check_run.py"), str(rd), "--transcripts", str(t))
    res = json.loads((rd / "results.json").read_text())
    assert any(p.startswith("SEC-AUTHN-01: PASS not accepted because examined files were never opened")
               for p in res["problems"])


def make_repo(tmp_path, files):
    repo = tmp_path / "mono"
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    sh("git", "init", "-q", "-b", "main", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A", cwd=repo)
    sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init", cwd=repo)
    return repo


def test_prepare_detects_db_in_mjs(tmp_path):
    repo = make_repo(tmp_path, {"src/index.mjs": "const Database = require('better-sqlite3-multiple-ciphers');\n"})
    sh(sys.executable, str(SCRIPTS / "prepare.py"), "--repo", str(repo))
    rd = next((repo / ".audit").iterdir())
    assert json.loads((rd / "facts.json").read_text())["has_db"]["value"] is True


def test_test_roots_in_a_monorepo(tmp_path):
    import run_tools
    repo = make_repo(tmp_path, {
        "package.json": json.dumps({"scripts": {"test": "node --test"}}),
        "apps/web/package.json": json.dumps({"scripts": {"test": "vitest"}}),
        "apps/ai/pyproject.toml": "[project]\nname='x'\n",
        "apps/ai/tests/test_a.py": "def test_a():\n    assert 1\n",
        "tools/test_b.py": "def test_b():\n    assert 1\n",
    })
    inv = [{"path": p, "in_scope": True} for p in
           ("package.json", "apps/web/package.json", "apps/ai/pyproject.toml", "apps/ai/tests/test_a.py", "tools/test_b.py")]
    py, js = run_tools.test_roots(repo, inv)
    assert py == ["", "apps/ai"]
    assert js == [""]  # apps/web is covered by the root test script


def test_install_deps_copies_only_tracked_files_and_finds_roots(tmp_path):
    import install_deps
    repo = make_repo(tmp_path, {"package-lock.json": "{}", "package.json": "{}", "apps/ai/requirements.txt": "",
                                "apps/ai/pyproject.toml": ""})
    (repo / ".env").write_text("SECRET=1\n")  # untracked
    (repo / "node_modules" / "x").mkdir(parents=True)
    ws = tmp_path / "ws"
    install_deps.copy_tracked(repo, ws)
    assert (ws / "package.json").exists() and (ws / "apps/ai/pyproject.toml").exists()
    assert not (ws / ".env").exists() and not (ws / "node_modules").exists()
    inv = [{"path": p, "in_scope": True, "class": "x"} for p in
           ("package-lock.json", "package.json", "apps/ai/requirements.txt", "apps/ai/pyproject.toml")]
    js, py = install_deps.package_roots(inv, [])
    assert js == {"": "package-lock.json"} and py == ["apps/ai"]


def test_install_deps_skipped_without_exec(run):
    _, rd = run
    out = sh(sys.executable, str(SCRIPTS / "install_deps.py"), str(rd))
    assert "skipped" in out
    assert json.loads((rd / "deps.json").read_text())["status"] == "skipped"
    assert "workspace" not in json.loads((rd / "run.json").read_text())


@pytest.mark.parametrize("mode", ["unsandboxed", "sandboxed"])
def test_run_repo_code_uses_workspace_subdir_and_work_placeholder(tmp_path, mode):
    import common
    if mode == "sandboxed" and not common.sandbox_available():
        pytest.skip("bubblewrap not installed")
    repo, ws = tmp_path / "repo", tmp_path / "ws"
    (repo / "sub").mkdir(parents=True)
    (ws / "sub").mkdir(parents=True)
    (ws / "sub" / "marker.txt").write_text("from workspace")
    run = {"exec_mode": mode, "workspace": str(ws)}
    r = common.run_repo_code([sys.executable, "-c", "import os,sys; print(open('marker.txt').read(), sys.argv[1])",
                              "{work}/x"], repo, run, subdir="sub")
    assert r["exit_code"] == 0, r["output"]
    assert "from workspace" in r["output"] and "{work}" not in r["output"]
    if mode == "sandboxed":
        assert "/work/x" in r["output"]
