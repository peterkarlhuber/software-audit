#!/usr/bin/env python3
"""Step 4: run a test that demonstrates a finding, in a sandboxed throwaway copy of the repo.

Usage:
  run_test.py RUN_DIR FINDING_ID --file RUN_DIR/tests/F-003/test_f003.py[:DEST] -- COMMAND...

  --file   test file written by the agent (must be inside RUN_DIR/tests/<FINDING_ID>/).
           It is copied into the repo copy at DEST (default: audit_tests/<file name>).
           May be given more than once.
  COMMAND  how to run it inside the repo copy, e.g. python3 -m pytest -q audit_tests/test_f003.py

The test must fail BECAUSE of the defect, and the failing assertion must print the
marker  AUDIT_CONFIRM:<FINDING_ID>  (e.g. assert x, "AUDIT_CONFIRM:F-003 ...").
A failure without the marker (import error, syntax error, crash) does not count.

Outcome written to RUN_DIR/tests/<FINDING_ID>.json:
  reproduced      exit code != 0 and marker in output  -> finding becomes "confirmed"
  not_reproduced  exit code == 0                       -> finding becomes "not reproduced"
  inconclusive    failed without the marker, timeout, or error
  not_run         execution of repo code not allowed or no sandbox
"""
import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import die, read_json, run_dir_from_arg, run_repo_code, sha256_file, write_json  # noqa: E402


def main():
    argv = sys.argv[1:]
    if "--" not in argv or len(argv) < 4:
        print(__doc__)
        sys.exit(2)
    sep = argv.index("--")
    head, cmd = argv[:sep], argv[sep + 1:]
    rd = run_dir_from_arg(head[0])
    fid = head[1]
    files = {}
    i = 2
    while i < len(head):
        if head[i] != "--file" or i + 1 >= len(head):
            die(f"unexpected argument {head[i]}")
        spec = head[i + 1]
        src, _, dest = spec.partition(":")
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
        i += 2
    if not files:
        die("at least one --file is required")
    if not cmd:
        die("COMMAND is missing")

    run = read_json(rd / "run.json")
    res = run_repo_code(cmd, Path(run["repo"]), run, timeout=600, extra_files=files)
    marker = f"AUDIT_CONFIRM:{fid}"
    if res["status"] == "skipped":
        outcome = "not_run"
    elif res["status"] != "ran":
        outcome = "inconclusive"
    elif res["exit_code"] == 0:
        outcome = "not_reproduced"
    elif marker in res["output"]:
        outcome = "reproduced"
    else:
        outcome = "inconclusive"

    log = rd / "tests" / f"{fid}.log"
    log.write_text(res.get("output", ""), encoding="utf-8")
    write_json(rd / "tests" / f"{fid}.json", {
        "finding_id": fid, "outcome": outcome, "command": cmd,
        "files": {d: {"source": str(s.relative_to(rd)), "sha256": sha256_file(s)} for d, s in files.items()},
        "exit_code": res.get("exit_code"), "sandbox": res.get("sandbox"), "reason": res.get("reason", ""),
        "marker_found": marker in res.get("output", ""), "log": str(log.relative_to(rd)),
        "ran_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    })
    print(f"{fid}: {outcome}" + (f" ({res.get('reason')})" if res.get("reason") else f" (exit {res.get('exit_code')})"))


if __name__ == "__main__":
    main()
