#!/usr/bin/env python3
"""Step 4: run a test that demonstrates a finding, in a sandboxed throwaway copy of the repo.

Usage:
  run_test.py RUN_DIR FINDING_ID --target FILE:LINES \
      --file RUN_DIR/tests/<FINDING_ID>/test_x.py[:DEST] [--file ...] -- COMMAND...

  --target  the finding's location, e.g. app/api/messages.py:35-42
  --file    test file written by the agent (must be inside RUN_DIR/tests/<FINDING_ID>/),
            copied into the repo copy at DEST (default: audit_tests/<file name>)
  COMMAND   how to run it inside the repo copy, e.g. python3 -m pytest -q tests/test_audit_x.py

A finding counts as reproduced only if ALL of these hold:
  1. the test fails (exit code != 0);
  2. the failing assertion carries the marker AUDIT_CONFIRM:<FINDING_ID>;
  3. the marker assertion is not trivial (no `assert False`, constant condition,
     `pytest.fail(...)` or `raise` with the marker);
  4. for pytest: the failure is an AssertionError in the test body (not setup,
     import or fixture errors), and the cited lines (+-2) were actually executed.
     Importing the file is not enough: module-level lines count only inside the cited range.
     For other test runners, 4 cannot be checked; the outcome is then
     reproduced_unverified, which does not confirm the finding.

Outcome written to RUN_DIR/tests/<FINDING_ID>.json:
  reproduced             all checks passed            -> finding "confirmed"
  reproduced_unverified  1-3 passed, 4 not checkable  -> finding stays "unconfirmed"
  not_reproduced         the test passed              -> finding "not reproduced"
  inconclusive           any other failure; see "reason"
  rejected               the test itself is not acceptable (trivial assertion)
  not_run                execution not allowed or no sandbox
"""
import ast
import datetime as dt
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import die, read_json, run_dir_from_arg, run_repo_code, sha256_file, write_json  # noqa: E402

PLUGIN = Path(__file__).resolve().parent / "audit_pytest_plugin.py"
TRACE = ".audit_trace.json"
LINE_TOLERANCE = 2


def trivial_python(src, marker):
    """Return a reason if the marker assertion in Python source is trivial, else None.
    Also returns a reason if the marker is not used in any assert statement."""
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return f"test file does not parse: {e}"
    found = False
    for node in ast.walk(tree):
        text = ast.get_source_segment(src, node) or ""
        if marker not in text:
            continue
        if isinstance(node, ast.Assert):
            found = True
            if isinstance(node.test, ast.Constant) or (
                    isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not)
                    and isinstance(node.test.operand, ast.Constant)):
                return "the marker assertion has a constant condition (e.g. assert False)"
        elif isinstance(node, ast.Raise):
            return "the marker is raised directly instead of being asserted"
        elif isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", "")) == "fail":
            return "the marker is passed to pytest.fail() instead of an assertion"
    return None if found else "no assert statement carries the marker"


def trivial_other(src, marker):
    for line in src.splitlines():
        if marker in line and re.search(r"(assert\s*\(?\s*(false|False|0)\b|expect\(\s*false\s*\)|throw\s|fail\()", line):
            return "the marker assertion has a constant condition or is thrown directly"
    return None if marker in src else "no assertion carries the marker"


def main():
    argv = sys.argv[1:]
    if "--" not in argv or len(argv) < 4:
        print(__doc__)
        sys.exit(2)
    sep = argv.index("--")
    head, cmd = argv[:sep], argv[sep + 1:]
    rd = run_dir_from_arg(head[0])
    fid = head[1]
    files, target = {}, None
    i = 2
    while i < len(head):
        if i + 1 >= len(head):
            die(f"missing value after {head[i]}")
        opt, val = head[i], head[i + 1]
        if opt == "--target":
            path, _, lines = val.rpartition(":")
            m = re.fullmatch(r"(\d+)(?:-(\d+))?", lines)
            if not path or not m:
                die("--target must look like path/to/file.py:12-20")
            target = (path, int(m.group(1)), int(m.group(2) or m.group(1)))
        elif opt == "--file":
            src, _, dest = val.partition(":")
            src = Path(src).resolve()
            allowed = (rd / "tests" / fid).resolve()
            if allowed not in src.parents:
                die(f"test files must be inside {allowed}")
            if not src.is_file():
                die(f"{src} not found")
            dest = dest or f"audit_tests/{src.name}"
            if dest.startswith("/") or ".." in Path(dest).parts:
                die("DEST must be a relative path inside the repo")
            files[dest] = src
        else:
            die(f"unexpected argument {opt}")
        i += 2
    if not files or not target or not cmd:
        die("--target, at least one --file and a COMMAND are required")

    marker = f"AUDIT_CONFIRM:{fid}"
    run = read_json(rd / "run.json")
    record = {"finding_id": fid, "target": f"{target[0]}:{target[1]}-{target[2]}", "command": cmd,
              "files": {d: {"source": str(s.relative_to(rd)), "sha256": sha256_file(s)} for d, s in files.items()},
              "ran_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}

    def finish(outcome, reason, **extra):
        record.update(outcome=outcome, reason=reason, **extra)
        write_json(rd / "tests" / f"{fid}.json", record)
        print(f"{fid}: {outcome}" + (f" ({reason})" if reason else ""))
        sys.exit(0)

    # Static check of the test source before running anything.
    for dest, src in files.items():
        text = src.read_text(encoding="utf-8", errors="replace")
        if marker in text:
            why = trivial_python(text, marker) if src.suffix == ".py" else trivial_other(text, marker)
            if why:
                finish("rejected", why)
    if not any(marker in s.read_text(encoding="utf-8", errors="replace") for s in files.values()):
        finish("rejected", f"no test file contains the marker {marker}")

    is_pytest = any("pytest" in c for c in cmd)
    env, collect = {}, []
    if is_pytest:
        files = {**files, "audit_pytest_plugin.py": PLUGIN}
        cmd = cmd + ["-p", "audit_pytest_plugin", "-p", "no:cacheprovider"]
        env = {"AUDIT_TARGET_FILE": target[0], "AUDIT_TRACE_OUT": TRACE, "PYTHONPATH": "."}
        collect = [TRACE]
    res = run_repo_code(cmd, Path(run["repo"]), run, timeout=600, extra_files=files, extra_env=env, collect=collect)
    log = rd / "tests" / f"{fid}.log"
    log.write_text(res.get("output", ""), encoding="utf-8")
    record.update(exit_code=res.get("exit_code"), sandbox=res.get("sandbox"), log=str(log.relative_to(rd)),
                  marker_found=marker in res.get("output", ""))

    if res["status"] == "skipped":
        finish("not_run", res.get("reason", ""))
    if res["status"] != "ran":
        finish("inconclusive", f"test run {res['status']}")
    if res["exit_code"] == 0:
        finish("not_reproduced", "the test passed")
    if not is_pytest:
        if marker in res["output"]:
            finish("reproduced_unverified", "failed with the marker; executed code path cannot be checked for this test runner")
        finish("inconclusive", "the test failed without the marker (crash, import or setup error?)")

    trace = res.get("collected", {}).get(TRACE)
    if trace is None:
        finish("inconclusive", "no trace from the pytest plugin (did pytest start?)")
    fails = trace["failures"]
    relevant = [f for f in fails if f["when"] == "call" and f["type"] == "AssertionError" and marker in f["message"]]
    other = [f for f in fails if f not in relevant]
    # Lines inside functions count with a tolerance. Module-level lines (run on import, e.g. a
    # `def` line) count only inside the cited range, so importing the file is not enough.
    hit = sorted({l for l in trace["hits"] if target[1] - LINE_TOLERANCE <= l <= target[2] + LINE_TOLERANCE}
                 | {l for l in trace.get("module_hits", []) if target[1] <= l <= target[2]})
    record.update(failures=fails[:20], target_lines_executed=hit)
    if not relevant:
        kinds = ", ".join(f"{f['type']} in {f['when']}" for f in fails[:5]) or "none recorded"
        finish("inconclusive", f"no AssertionError with the marker in the test body (failures: {kinds})")
    if not hit:
        finish("inconclusive", f"the cited lines {target[1]}-{target[2]} of {target[0]} were never executed by the test")
    finish("reproduced", "", other_failures=len(other))


if __name__ == "__main__":
    main()
