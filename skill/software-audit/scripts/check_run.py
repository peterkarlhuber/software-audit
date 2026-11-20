#!/usr/bin/env python3
"""Step 5 + 6: check the agent's output mechanically, then write results.json and report.md.

Usage:
  check_run.py RUN_DIR [--transcripts PATH | --no-transcripts]

Reads items.json, tools/, tests/ and passes/*.json (written by the agent) and enforces:
  - every applicable checklist item has a result; missing -> UNKNOWN
  - PASS needs: examined files, a completeness statement, valid evidence, a clean tool
    result for tool items, and (if the session log is available) the examined files
    must actually have been opened. Otherwise PASS -> UNKNOWN.
  - FAIL needs at least one finding with valid evidence, otherwise -> UNKNOWN
  - every quote must exist in the cited file near the cited lines
  - critical/high findings are "confirmed" only by a reproduced test (run_test.py) or a
    triaged tool finding; otherwise "unconfirmed"
  - every tool finding must be triaged
The agent never sets a finding's status; this script does.
"""
import argparse
import datetime as dt
import json
import re
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import RESULTS, SEVERITIES, read_json, run_dir_from_arg, write_json  # noqa: E402

DISCLAIMER = (
    "This audit checks technical controls and collects evidence. It does not establish legal "
    "compliance with the GDPR, the EU AI Act, the Cyber Resilience Act or any other regulation. "
    "Whether a regulation applies, and whether it is met, must be decided by a responsible person "
    "and, where needed, legal counsel. A missing finding never means the software is free of defects."
)
MIN_QUOTE_CHARS = 12
MIN_COMPLETENESS = 30
READ_CMDS = {"cat", "head", "tail", "sed", "less", "more", "nl", "awk", "bat", "view"}


def norm(s):
    return re.sub(r"\s+", " ", s).strip()


class Repo:
    def __init__(self, root, inv):
        self.root = root
        self.inv = {f["path"]: f for f in inv}
        self._cache = {}

    def lines(self, path):
        if path not in self._cache:
            p = self.root / path
            try:
                self._cache[path] = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._cache[path] = None
        return self._cache[path]

    def known(self, path):
        return path in self.inv or any(k.startswith(path.rstrip("/") + "/") for k in self.inv)


def parse_lines(spec):
    m = re.fullmatch(r"(\d+)(?:-(\d+))?", str(spec or "").strip())
    if not m:
        return None
    a = int(m.group(1))
    b = int(m.group(2) or a)
    return (min(a, b), max(a, b))


def check_quote(repo, file, lines, quote):
    """Return (ok, reason, corrected_lines)."""
    if not file:
        return False, "no file given", None
    if file not in repo.inv:
        return False, f"file {file} is not in the inventory", None
    content = repo.lines(file)
    if content is None:
        return False, f"file {file} cannot be read", None
    parts = [norm(l) for l in (quote or "").splitlines() if norm(l) and norm(l) != "..."]
    if sum(len(p) for p in parts) < MIN_QUOTE_CHARS:
        return False, f"quote shorter than {MIN_QUOTE_CHARS} characters", None
    rng = parse_lines(lines)

    def find(start, end):
        region = [norm(l) for l in content[max(0, start - 1):end]]
        pos = 0
        first = None
        for part in parts:
            hit = None
            for i in range(pos, len(region)):
                if part in region[i]:
                    hit = i
                    break
            if hit is None:
                return None
            first = hit if first is None else first
            pos = hit + 1
        return (start + first, start + pos - 1)

    if rng:
        got = find(max(1, rng[0] - 3), rng[1] + 3)
        if got:
            return True, "", None
    got = find(1, len(content))
    if got:
        return True, "quote found at other lines; lines corrected", f"{got[0]}-{got[1]}" if got[1] > got[0] else str(got[0])
    return False, "quote not found in file", None


def check_evidence(repo, rd, ev):
    if ev.get("artifact"):
        p = (rd / ev["artifact"]).resolve()
        if rd.resolve() not in p.parents or not p.exists():
            return False, f"artifact {ev['artifact']} not found in run folder"
        return True, ""
    ok, reason, corrected = check_quote(repo, ev.get("file"), ev.get("lines"), ev.get("quote"))
    if corrected:
        ev["lines_original"], ev["lines"] = ev.get("lines"), corrected
    return ok, reason


def schema_errors(doc):
    """Validate a pass file against schemas/pass-output.schema.json if jsonschema is installed."""
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        return []
    schema = read_json(Path(__file__).resolve().parent.parent / "schemas" / "pass-output.schema.json")
    errs = sorted(Draft202012Validator(schema).iter_errors(doc), key=lambda e: list(e.path))
    return [f"schema: {'/'.join(map(str, e.path)) or '(root)'}: {e.message[:200]}" for e in errs[:20]]


# ---------------------------------------------------------------- transcripts

def find_transcripts(repo_root, started, explicit):
    if explicit:
        p = Path(explicit).expanduser()
        return sorted(p.rglob("*.jsonl")) if p.is_dir() else [p]
    base = Path.home() / ".claude" / "projects"
    slug = re.sub(r"[^A-Za-z0-9]", "-", str(repo_root))
    cands = [d for d in base.glob("*") if d.is_dir() and d.name == slug] if base.exists() else []
    t0 = started.timestamp() - 60
    return sorted(f for d in cands for f in d.rglob("*.jsonl") if f.stat().st_mtime >= t0)


def walk_tool_uses(obj):
    if isinstance(obj, dict):
        if obj.get("type") == "tool_use" and "name" in obj:
            yield obj["name"], obj.get("input") or {}
        for v in obj.values():
            yield from walk_tool_uses(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_tool_uses(v)


def opened_files(transcripts, repo):
    opened, touched = set(), set()
    root = str(repo.root)

    def rel(p):
        p = str(p)
        if p.startswith(root + "/"):
            p = p[len(root) + 1:]
        p = p.lstrip("./") if p.startswith("./") else p
        return p

    for t in transcripts:
        try:
            fh = open(t, encoding="utf-8", errors="ignore")
        except OSError:
            continue
        with fh:
            for line in fh:
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                for name, inp in walk_tool_uses(obj):
                    if name in ("Read", "View", "read_file"):
                        r = rel(inp.get("file_path") or inp.get("path") or "")
                        if r in repo.inv:
                            opened.add(r)
                    elif name in ("Grep", "Glob"):
                        r = rel(inp.get("path") or "")
                        if r:
                            touched.add(r)
                    elif name == "Bash":
                        try:
                            toks = shlex.split(inp.get("command", ""))
                        except ValueError:
                            continue
                        reading = False
                        for tok in toks:
                            if tok in ("|", "&&", ";", "||"):
                                reading = False
                                continue
                            if Path(tok).name in READ_CMDS:
                                reading = True
                                continue
                            if reading:
                                r = rel(tok)
                                if r in repo.inv:
                                    opened.add(r)
    return opened, touched


# ---------------------------------------------------------------- main checks

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--transcripts", help="session log file or folder (default: auto-detect Claude Code logs)")
    g.add_argument("--no-transcripts", action="store_true")
    a = ap.parse_args()

    rd = run_dir_from_arg(a.run_dir)
    run = read_json(rd / "run.json")
    repo = Repo(Path(run["repo"]), read_json(rd / "inventory.json"))
    items_doc = read_json(rd / "items.json")
    applicable = {it["id"]: it for it in items_doc["applicable"]}
    tools = {p.stem: read_json(p) for p in (rd / "tools").glob("*.json")
             if not p.name.endswith((".findings.json", ".raw.json", ".cdx.json", ".licences.json", ".ruff.json"))} \
        if (rd / "tools").exists() else {}
    tool_findings = {}
    for p in (rd / "tools").glob("*.findings.json") if (rd / "tools").exists() else []:
        for f in read_json(p, []):
            tool_findings[f["tool_id"]] = f

    problems = []  # problems with the agent's output, shown in the report
    results, findings, triage = {}, {}, {}
    pass_files = sorted((rd / "passes").glob("*.json")) if (rd / "passes").exists() else []
    if not pass_files:
        problems.append("No pass output found in passes/. All items are UNKNOWN.")
    for pf in pass_files:
        try:
            doc = read_json(pf)
        except ValueError as e:
            problems.append(f"{pf.name}: invalid JSON ({e})")
            continue
        problems.extend(f"{pf.name}: {m}" for m in schema_errors(doc))
        for r in doc.get("items", []):
            if r.get("id") in results:
                problems.append(f"{r.get('id')}: more than one result; the last one is used")
            results[r.get("id")] = r
        for f in doc.get("findings", []):
            if f.get("id") in findings:
                problems.append(f"finding {f.get('id')} defined twice; the last one is used")
            findings[f.get("id")] = f
        for t in doc.get("tool_triage", []):
            triage[t.get("tool_id")] = t

    # coverage
    started = dt.datetime.fromisoformat(run["started_at"])
    transcripts = [] if a.no_transcripts else find_transcripts(repo.root, started, a.transcripts)
    coverage_measured = bool(transcripts)
    opened, touched = opened_files(transcripts, repo) if transcripts else (set(), set())

    # ---- findings
    for fid, f in findings.items():
        notes = []
        if f.get("severity") not in SEVERITIES:
            notes.append(f"invalid severity {f.get('severity')!r}")
            f["severity"] = "medium"
        evid_ok = False
        if f.get("artifact"):
            evid_ok, why = check_evidence(repo, rd, {"artifact": f["artifact"]})
        else:
            ev = {"file": f.get("file"), "lines": f.get("lines"), "quote": f.get("quote")}
            evid_ok, why = check_evidence(repo, rd, ev)
            if ev.get("lines_original"):
                f["lines_original"], f["lines"] = ev["lines_original"], ev["lines"]
                notes.append(f"lines corrected from {ev['lines_original']} to {ev['lines']}")
        if not evid_ok:
            notes.append(f"evidence check failed: {why}")
        if coverage_measured and f.get("file") and f["file"] not in opened:
            notes.append("cited file was not opened according to the session log")
            evid_ok = False
        tool_ok = [t for t in f.get("tool_ids", []) if t in tool_findings and triage.get(t, {}).get("verdict") == "real"]
        test = read_json(rd / "tests" / f"{fid}.json")
        if not evid_ok and not tool_ok:
            status = "invalid_evidence"
        elif f["severity"] in ("critical", "high"):
            if test and test.get("outcome") == "reproduced":
                status = "confirmed"
                notes.append("reproduced by test")
            elif tool_ok:
                status = "confirmed"
                notes.append(f"reported by tool ({', '.join(tool_ok)})")
            elif test and test.get("outcome") == "not_reproduced":
                status = "not_reproduced"
                notes.append("test passed: defect not reproduced")
            else:
                status = "unconfirmed"
                notes.append("no reproducing test" + (f" (test {test.get('outcome')}: {test.get('reason') or 'see log'})" if test else ""))
        else:
            status = "evidenced"
        f["status"] = status
        f["check_notes"] = notes
        if f.get("checklist_id") not in applicable:
            problems.append(f"finding {fid} refers to unknown or not applicable item {f.get('checklist_id')}")

    # ---- tool triage
    untriaged = [tid for tid in tool_findings if tid not in triage]
    bad_triage = [tid for tid, t in triage.items() if t.get("verdict") not in ("real", "false_positive") or len(t.get("reason", "")) < 5]
    for tid in bad_triage:
        problems.append(f"tool finding {tid}: triage needs verdict real|false_positive and a reason")

    # ---- items
    final = []
    for iid, it in applicable.items():
        r = dict(results.get(iid) or {})
        down = []
        res = r.get("result")
        if not r:
            res, reason = "UNKNOWN", "no result from the agent"
        elif res not in RESULTS:
            res, reason = "UNKNOWN", f"invalid result {res!r}"
        else:
            reason = r.get("reason", "")
        evidence = r.get("evidence", []) or []
        ev_bad = []
        for ev in evidence:
            ok, why = check_evidence(repo, rd, ev)
            ev["valid"] = ok
            if not ok:
                ev_bad.append(why)
        tool = it.get("tool")
        tstat = tools.get(tool, {}).get("status") if tool else None
        tool_ids_for_item = [tid for tid, tf in tool_findings.items() if tid.startswith(f"T-{tool}-")] if tool else []

        if res == "PASS":
            examined = r.get("examined") or []
            if not examined:
                down.append("no examined files listed")
            unknown_paths = [e for e in examined if not (repo.known(e) or (rd / e).exists())]
            if unknown_paths:
                down.append(f"examined paths not in inventory: {', '.join(unknown_paths[:5])}")
            if len(r.get("completeness", "")) < MIN_COMPLETENESS:
                down.append("no statement on how completeness was ensured")
            if not evidence:
                down.append("no evidence")
            if ev_bad:
                down.append("invalid evidence: " + "; ".join(ev_bad[:3]))
            if tool:
                if tstat not in ("ok", "findings"):
                    down.append(f"required tool group '{tool}' did not run ({tstat or 'no record'})")
                else:
                    open_ = [t for t in tool_ids_for_item if triage.get(t, {}).get("verdict") != "false_positive"]
                    if open_:
                        down.append(f"{len(open_)} tool findings not triaged as false positive")
            if coverage_measured:
                not_opened = [e for e in examined if e in repo.inv and e not in opened]
                if not_opened:
                    down.append(f"examined files never opened: {', '.join(not_opened[:5])}")
            if down:
                res = "UNKNOWN"
                reason = "PASS not accepted: " + "; ".join(down)
        elif res == "FAIL":
            fids = [x for x in r.get("finding_ids", []) if x in findings]
            good = [x for x in fids if findings[x]["status"] not in ("invalid_evidence", "not_reproduced")]
            if not good:
                res = "UNKNOWN"
                reason = "FAIL not accepted: no finding with valid evidence" + (f" ({', '.join(r.get('finding_ids', []))})" if r.get("finding_ids") else "")
        elif res == "N/A":
            if len(reason) < 10:
                res, reason = "UNKNOWN", "N/A without a reason"
        elif res == "UNKNOWN" and not reason:
            reason = "no reason given"
        if tool and tstat not in ("ok", "findings") and res == "N/A":
            pass
        final.append({"id": iid, "title": it["title"], "area": it["area"], "pass": it["pass"],
                      "severity_if_fail": it.get("severity_if_fail"), "result": res,
                      "agent_result": r.get("result"), "reason": reason,
                      "examined": r.get("examined", []), "completeness": r.get("completeness", ""),
                      "evidence": evidence, "finding_ids": r.get("finding_ids", [])})
    for na in items_doc["not_applicable"]:
        final.append({**na, "result": "N/A", "agent_result": None, "examined": [], "evidence": [], "finding_ids": []})
    extra = sorted(set(results) - set(applicable))
    for x in extra:
        problems.append(f"result for unknown or not applicable item {x} ignored")

    # ---- coverage summary
    in_scope = [p for p, f in repo.inv.items() if f.get("in_scope") and f.get("class") not in ("binary", "symlink", "missing")]
    code_like = [p for p in in_scope if repo.inv[p]["class"] in ("source", "test", "config", "container", "ci", "dependency-manifest")]
    coverage = {"measured": coverage_measured, "transcripts": [str(t) for t in transcripts][:20],
                "in_scope_files": len(in_scope), "opened": len(opened & set(in_scope)),
                "code_files": len(code_like), "code_opened": len(opened & set(code_like)),
                "not_opened_code_files": sorted(set(code_like) - opened)[:200] if coverage_measured else []}

    summary = {}
    for it in final:
        summary.setdefault(it["area"], {k: 0 for k in RESULTS})[it["result"]] += 1
    out = {
        "run": run, "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "disclaimer": DISCLAIMER, "summary": summary, "items": final,
        "findings": sorted(findings.values(), key=lambda f: (SEVERITIES.index(f["severity"]), f.get("id", ""))),
        "tools": tools, "tool_findings": list(tool_findings.values()), "tool_triage": triage,
        "untriaged_tool_findings": untriaged, "coverage": coverage, "problems": problems,
    }
    write_json(rd / "results.json", out)
    (rd / "report.md").write_text(render(out), encoding="utf-8")

    tot = {k: sum(v[k] for v in summary.values()) for k in RESULTS}
    print(f"items: {tot}")
    print(f"findings: {len(findings)} ({sum(1 for f in findings.values() if f['status'] == 'confirmed')} confirmed)")
    print(f"untriaged tool findings: {len(untriaged)}; problems: {len(problems)}")
    print(f"coverage: {'measured' if coverage_measured else 'not measured'}"
          + (f", {coverage['code_opened']}/{coverage['code_files']} code files opened" if coverage_measured else ""))
    print(f"report: {rd / 'report.md'}")


# ---------------------------------------------------------------- report

def md(s):
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def render(o):
    run, L = o["run"], []
    L.append(f"# Audit report: {run['repo_name']}")
    L.append("")
    L.append(f"Commit `{run['commit']}`{' (uncommitted changes present)' if run['dirty'] else ''} · run `{run['run_id']}` · "
             f"skill {run['skill_version']} · checked {o['checked_at']}")
    L.append("")
    L.append(f"> **Scope note.** {o['disclaimer']}")
    L.append("")
    L.append("## 1. Summary")
    L.append("")
    L.append("| Area | PASS | FAIL | UNKNOWN | N/A |")
    L.append("|---|---|---|---|---|")
    for area in ("functionality", "operations", "security", "governance"):
        if area in o["summary"]:
            s = o["summary"][area]
            L.append(f"| {area} | {s['PASS']} | {s['FAIL']} | {s['UNKNOWN']} | {s['N/A']} |")
    for area, s in o["summary"].items():
        if area not in ("functionality", "operations", "security", "governance"):
            L.append(f"| {area} | {s['PASS']} | {s['FAIL']} | {s['UNKNOWN']} | {s['N/A']} |")
    L.append("")
    top = [f for f in o["findings"] if f["severity"] in ("critical", "high") and f["status"] != "invalid_evidence"]
    if top:
        L.append("**Top risks**")
        L.append("")
        for f in top[:10]:
            L.append(f"- **{f['severity']}** ({f['status']}): {md(f.get('title'))} – `{f.get('file')}:{f.get('lines')}`")
        L.append("")
    cov = o["coverage"]
    if cov["measured"]:
        L.append(f"Coverage: {cov['code_opened']} of {cov['code_files']} code files were opened by the agent (from the session log).")
    else:
        L.append("Coverage: **not measured** (no session log found). Examined files are as stated by the agent.")
    L.append("")
    L.append("## 2. Findings")
    L.append("")
    L.append("Status: `confirmed` = reproduced by a test or reported by a tool · `evidenced` = shown by a verified code quote · "
             "`unconfirmed` = critical/high without a reproducing test · `not_reproduced` = test passed · "
             "`invalid_evidence` = quote or file could not be verified")
    L.append("")
    if not o["findings"]:
        L.append("No findings were reported. This does not mean the software is free of defects; see section 4.")
    for f in o["findings"]:
        L.append(f"### {f.get('id')} · {md(f.get('title'))}")
        L.append("")
        L.append(f"- Severity: **{f['severity']}** · Status: **{f['status']}** · Checklist: {f.get('checklist_id')}")
        if f.get("file"):
            L.append(f"- Location: `{f['file']}:{f.get('lines')}`")
        if f.get("quote"):
            L.append("")
            L.append("```")
            L.append(f["quote"].rstrip())
            L.append("```")
            L.append("")
        L.append(f"- Impact: {md(f.get('impact'))}")
        L.append(f"- Recommendation: {md(f.get('recommendation'))}")
        if f.get("check_notes"):
            L.append(f"- Check notes: {md('; '.join(f['check_notes']))}")
        L.append("")
    L.append("## 3. Checklist")
    L.append("")
    L.append("| ID | Item | Result | Evidence / reason |")
    L.append("|---|---|---|---|")
    order = {"FAIL": 0, "UNKNOWN": 1, "PASS": 2, "N/A": 3}
    for it in sorted(o["items"], key=lambda x: (x["area"], order[x["result"]], x["id"])):
        ev = ", ".join(f"`{e['file']}:{e.get('lines')}`" if e.get("file") else f"`{e.get('artifact')}`"
                       for e in it.get("evidence", []) if e.get("valid", True))
        detail = it.get("reason") or ""
        if it["result"] == "FAIL":
            detail = "findings: " + ", ".join(it["finding_ids"])
        elif it["result"] == "PASS":
            detail = ev
        L.append(f"| {it['id']} | {md(it['title'])} | **{it['result']}** | {md(detail)} |")
    L.append("")
    L.append("## 4. Not checked")
    L.append("")
    unk = [it for it in o["items"] if it["result"] == "UNKNOWN"]
    L.append(f"**{len(unk)} checklist items are UNKNOWN** (listed in section 3 with reasons).")
    L.append("")
    L.append("| Tool group | Status | Note |")
    L.append("|---|---|---|")
    for g, t in sorted(o["tools"].items()):
        L.append(f"| {g} | {t.get('status')} | {md(t.get('note', ''))[:200]} |")
    L.append("")
    if o["untriaged_tool_findings"]:
        L.append(f"**{len(o['untriaged_tool_findings'])} tool findings were not triaged:** "
                 + ", ".join(o["untriaged_tool_findings"][:30]) + (" …" if len(o["untriaged_tool_findings"]) > 30 else ""))
        L.append("")
    if cov["measured"] and cov["not_opened_code_files"]:
        L.append(f"**Code files never opened ({len(cov['not_opened_code_files'])}):** "
                 + ", ".join(f"`{p}`" for p in cov["not_opened_code_files"][:40]) + (" …" if len(cov["not_opened_code_files"]) > 40 else ""))
        L.append("")
    if run.get("exec_mode") == "none":
        L.append("Repo code (tests, builds) was not executed in this run, so critical and high findings cannot be confirmed by a test.")
        L.append("")
    if o["problems"]:
        L.append("**Problems in the audit output:**")
        L.append("")
        for p in o["problems"]:
            L.append(f"- {md(p)}")
        L.append("")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
