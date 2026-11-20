#!/usr/bin/env python3
"""Combine the results of several audit runs (one per repository) into one overview.

Usage:
  summarize.py RUN_DIR [RUN_DIR ...] --out FILE.md

Each RUN_DIR must contain results.json from check_run.py. The overview lists every run with
its result counts and findings, then all critical and high findings across the runs. It adds
nothing of its own: every number comes from a results.json.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import RESULTS, SEVERITIES, die, read_json  # noqa: E402
from check_run import DISCLAIMER, md  # noqa: E402


def load(run_dir):
    p = Path(run_dir).resolve()
    res = read_json(p / "results.json")
    if res is None:
        die(f"{p}: no results.json; run check_run.py for this run first")
    return p, res


def render(runs):
    L = ["# Audit overview", "", f"{len(runs)} repositories. Each row links to the full report of that run.", "",
         f"> **Scope note.** {DISCLAIMER}", "",
         "| Repository | Commit | Scope | PASS | FAIL | UNKNOWN | N/A | critical | high | medium | low | confirmed | Problems |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    top = []
    for p, o in runs:
        run = o["run"]
        tot = {k: sum(a.get(k, 0) for a in o["summary"].values()) for k in RESULTS}
        valid = [f for f in o["findings"] if f.get("status") != "invalid_evidence"]
        sev = {s: sum(1 for f in valid if f["severity"] == s) for s in SEVERITIES}
        ch = run.get("change")
        scope = f"change since `{ch['base']}` ({len(ch['files'])} files)" if ch else "full"
        if run.get("dirty"):
            scope += ", dirty tree"
        L.append(f"| [{md(run['repo_name'])}]({p / 'report.md'}) | `{run['commit'][:12]}` | {scope} | "
                 + " | ".join(str(tot[k]) for k in RESULTS) + " | "
                 + " | ".join(str(sev[s]) for s in SEVERITIES)
                 + f" | {sum(1 for f in valid if f.get('status') == 'confirmed')} | {len(o.get('problems', []))} |")
        top += [(run["repo_name"], f) for f in valid if f["severity"] in ("critical", "high")]
    L.append("")
    L.append("## Critical and high findings")
    L.append("")
    if not top:
        L.append("None reported. This does not mean the software is free of defects; see the reports.")
    for repo, f in sorted(top, key=lambda x: (SEVERITIES.index(x[1]["severity"]), x[0], x[1].get("id", ""))):
        L.append(f"- **{f['severity']}** ({f['status']}) {md(repo)}: {md(f.get('title'))} – "
                 f"`{f.get('file')}:{f.get('lines')}`" + ("" if f.get("in_change", True) else " (outside the change)"))
    L.append("")
    unk = [(p, o) for p, o in runs if o.get("problems") or not o.get("coverage", {}).get("measured")]
    if unk:
        L.append("## Caveats")
        L.append("")
        for p, o in unk:
            notes = []
            if not o.get("coverage", {}).get("measured"):
                notes.append("coverage not measured")
            if o.get("problems"):
                notes.append(f"{len(o['problems'])} problems in the audit output")
            L.append(f"- {md(o['run']['repo_name'])}: " + "; ".join(notes))
        L.append("")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dirs", nargs="+")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    runs = [load(r) for r in a.run_dirs]
    names = [o["run"]["repo_name"] for _, o in runs]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        print(f"note: more than one run for {', '.join(dup)}; all are listed", file=sys.stderr)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(runs), encoding="utf-8")
    print(f"overview of {len(runs)} runs: {out}")


if __name__ == "__main__":
    main()
