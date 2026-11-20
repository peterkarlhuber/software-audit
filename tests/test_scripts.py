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


def test_run_test_requires_permission(run):
    _, rd = run
    d = rd / "tests" / "F-SEC-001"
    d.mkdir(parents=True)
    (d / "test_x.py").write_text("def test_x():\n    assert False, 'AUDIT_CONFIRM:F-SEC-001'\n")
    sh(sys.executable, str(SCRIPTS / "run_test.py"), str(rd), "F-SEC-001", "--file", str(d / "test_x.py"),
       "--", sys.executable, "-m", "pytest", "-q", "audit_tests/test_x.py")
    out = json.loads((rd / "tests" / "F-SEC-001.json").read_text())
    assert out["outcome"] == "not_run"  # prepare.py ran without --allow-exec


@pytest.mark.skipif(subprocess.run(["which", "bwrap"], capture_output=True).returncode != 0, reason="bubblewrap not installed")
def test_run_test_in_sandbox_reproduces_and_needs_marker(run):
    repo, _ = run
    sh(sys.executable, str(SCRIPTS / "prepare.py"), "--repo", str(repo), "--allow-exec")
    rd = sorted((repo / ".audit").iterdir())[-1]
    d = rd / "tests" / "F-SEC-001"
    d.mkdir(parents=True)
    (d / "test_ok.py").write_text("def test_x():\n    assert 1 == 2, 'AUDIT_CONFIRM:F-SEC-001 defect present'\n")
    (d / "test_crash.py").write_text("import not_a_module\n")
    for name, expected in (("test_ok.py", "reproduced"), ("test_crash.py", "inconclusive")):
        sh(sys.executable, str(SCRIPTS / "run_test.py"), str(rd), "F-SEC-001", "--file", str(d / name),
           "--", "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", f"audit_tests/{name}")
        assert json.loads((rd / "tests" / "F-SEC-001.json").read_text())["outcome"] == expected
