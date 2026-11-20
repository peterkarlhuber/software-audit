#!/usr/bin/env python3
"""Step 2: run the standard tools that fit the repository and store their raw output.

Usage:
  run_tools.py RUN_DIR

Tool groups (checklist items refer to them with `tool:`):
  secrets    Gitleaks (working tree + Git history)
  sast       Semgrep: bundled offline rules (rules/semgrep) + $AUDIT_SEMGREP_CONFIG
             (default p/default from the registry, skipped if unreachable; "none" = bundled only)
  deps       OSV-Scanner online -> OSV offline database -> pip-audit -> Trivy
  sbom       Syft (CycloneDX) + licence summary
  lint       Ruff (Python), tsc --noEmit (TypeScript)
  container  Hadolint (+ Trivy config if installed)
  tests      Pytest / npm test, only if repo code execution is allowed for the run

Static tools read the repo but do not execute repo code. Tests do, and run via
common.run_repo_code (bubblewrap sandbox, throwaway copy, stripped environment).

For each group, writes tools/<group>.json (status, command, exit code, version)
and tools/<group>.findings.json (normalised findings with IDs T-<group>-NNN that
the agent must triage).
"""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import read_json, run_dir_from_arg, run_repo_code, write_json  # noqa: E402

COPYLEFT = re.compile(r"\b(A?GPL|LGPL|SSPL|EUPL|OSL|CC-BY-SA|MPL)", re.I)


def version(tool):
    for flag in ("--version", "version"):
        try:
            r = subprocess.run([tool, flag], capture_output=True, text=True, timeout=30)
            out = (r.stdout or r.stderr).strip().splitlines()
            if r.returncode == 0 and out:
                return out[0][:120]
        except (OSError, subprocess.TimeoutExpired):
            pass
    return None


def run(cmd, cwd, timeout=1800):
    # Drop credentials, and drop GIT_CONFIG_* as a whole (removing only some of them breaks git).
    env = {k: v for k, v in os.environ.items()
           if not re.search(r"TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL", k, re.I) and not k.startswith("GIT_CONFIG")}
    env["SEMGREP_SEND_METRICS"] = "off"
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return None, "", f"timeout after {timeout}s"
    except OSError as e:
        return None, "", str(e)


def has(inv, rx):
    return [f["path"] for f in inv if f.get("in_scope") and re.search(rx, f["path"])]


EXCLUDE = []  # repo-relative path prefixes excluded with prepare.py --exclude


def excluded(path):
    p = str(path or "")
    while p.startswith("./"):
        p = p[2:]
    return any(p == e or p.startswith(e + "/") for e in EXCLUDE)


def record(tools_dir, group, **kw):
    findings = kw.pop("findings", None)
    data = {"group": group, **kw}
    if findings is not None:
        dropped = [f for f in findings if excluded(f.get("file"))]
        if dropped:
            findings = [f for f in findings if not excluded(f.get("file"))]
            data["excluded_findings"] = len(dropped)
        for i, f in enumerate(findings, 1):
            f["tool_id"] = f"T-{group}-{i:03d}"
        data["finding_count"] = len(findings)
        write_json(tools_dir / f"{group}.findings.json", findings)
        if data.get("status") == "ran":
            data["status"] = "findings" if findings else "ok"
    write_json(tools_dir / f"{group}.json", data)
    return data


def save_raw(tools_dir, name, text):
    p = tools_dir / name
    p.write_text(text or "", encoding="utf-8")
    return str(p.relative_to(tools_dir.parent))


def missing(tools_dir, group, tools, why=None):
    return record(tools_dir, group, status="missing", tool="/".join(tools),
                  note=why or f"{' and '.join(tools)} not installed")


def secrets(root, tools_dir, inv):
    if not shutil.which("gitleaks"):
        return missing(tools_dir, "secrets", ["gitleaks"])
    out = tools_dir / "secrets.raw.json"
    cmd = ["gitleaks", "detect", "--source", str(root), "--report-format", "json",
           "--report-path", str(out), "--redact", "--no-banner", "--exit-code", "0"]
    code, so, se = run(cmd, root)
    if code != 0 or not out.exists() or "failed to scan" in se or " ERR " in re.sub(r"\x1b\[[0-9;]*m", " ", se):
        return record(tools_dir, "secrets", status="error", tool="gitleaks", command=cmd, exit_code=code,
                      version=version("gitleaks"), note=(se or so)[-2000:])
    raw = json.loads(out.read_text() or "[]")
    fnd = [{"tool": "gitleaks", "rule": x.get("RuleID"), "file": x.get("File"), "line": x.get("StartLine"),
            "message": x.get("Description"), "commit": (x.get("Commit") or "")[:12], "severity": "high"} for x in raw]
    return record(tools_dir, "secrets", status="ran", tool="gitleaks", command=cmd, exit_code=code,
                  version=version("gitleaks"), output_file=str(out.relative_to(tools_dir.parent)), findings=fnd)


BUNDLED_RULES = Path(__file__).resolve().parent.parent / "rules" / "semgrep"


def sast(root, tools_dir, inv):
    """Semgrep with the bundled offline rules plus, if reachable, an extra config
    ($AUDIT_SEMGREP_CONFIG, default the registry ruleset p/default).
    Set AUDIT_SEMGREP_CONFIG=none to use the bundled rules only."""
    if not shutil.which("semgrep"):
        return missing(tools_dir, "sast", ["semgrep"])
    extra = os.environ.get("AUDIT_SEMGREP_CONFIG", "p/default")
    base = ["semgrep", "scan", "--json", "--metrics=off", "--disable-version-check", "--config", str(BUNDLED_RULES)]
    note = ""
    attempts = [base + ["--config", extra, str(root)]] if extra and extra != "none" else []
    attempts.append(base + [str(root)])
    for cmd in attempts:
        code, so, se = run(cmd, root)
        if code in (0, 1) and so.strip().startswith("{"):
            break
        note = f"config {extra} unavailable ({(se.strip().splitlines() or ['?'])[-1][:200]}); bundled rules only"
    else:
        return record(tools_dir, "sast", status="error", tool="semgrep", command=cmd, exit_code=code,
                      version=version("semgrep"), note=(se.strip().splitlines() or [so[-500:]])[-1][-500:])
    rel = save_raw(tools_dir, "sast.raw.json", so)
    raw = json.loads(so)
    fnd = []
    for x in raw.get("results", []):
        path = x.get("path", "")
        try:
            path = str(Path(path).resolve().relative_to(root))
        except ValueError:
            pass
        fnd.append({"tool": "semgrep", "rule": x.get("check_id", "").split(".")[-1], "file": path,
                    "line": x.get("start", {}).get("line"), "message": x.get("extra", {}).get("message", "")[:500],
                    "severity": {"ERROR": "high", "WARNING": "medium"}.get(x.get("extra", {}).get("severity"), "low")})
    rule_errors = [e.get("message", "")[:200] for e in raw.get("errors", []) if e.get("level") != "warn"]
    if rule_errors:
        note = (note + "; " if note else "") + f"{len(rule_errors)} semgrep errors: {rule_errors[0]}"
    return record(tools_dir, "sast", status="ran", tool="semgrep", command=cmd, exit_code=code,
                  rulesets=[cmd[i + 1] for i, c in enumerate(cmd) if c == "--config"], version=version("semgrep"),
                  output_file=rel, findings=fnd, note=note, scanned_files=len(raw.get("paths", {}).get("scanned", [])))


def _osv_findings(raw, root, tool):
    fnd = []
    for res in raw.get("results", []):
        src = res.get("source", {}).get("path", "")
        try:
            src = str(Path(src).resolve().relative_to(root))
        except ValueError:
            pass
        for pkg in res.get("packages", []):
            sev = {}
            for g in pkg.get("groups", []):
                for i in g.get("ids", []):
                    sev[i] = g.get("max_severity")
            for v in pkg.get("vulnerabilities", []):
                fnd.append({"tool": tool, "rule": v.get("id"), "file": src, "line": None,
                            "package": f"{pkg['package'].get('name')}@{pkg['package'].get('version')}",
                            "message": (v.get("summary") or "")[:300], "cvss": sev.get(v.get("id")),
                            "severity": cvss_to_sev(sev.get(v.get("id")))})
    return fnd


def deps(root, tools_dir, inv):
    """Known vulnerabilities in dependencies. Tries, in order:
    OSV-Scanner online, OSV-Scanner with its offline database (downloaded or cached),
    pip-audit (PyPI advisory data, Python requirements files), Trivy."""
    tried = []
    if shutil.which("osv-scanner"):
        variants = [("osv-scanner (online)", ["osv-scanner", "--format", "json", "-r", str(root)]),
                    ("osv-scanner (offline database)", ["osv-scanner", "--format", "json", "--experimental-offline",
                                                        "--experimental-download-offline-databases", "-r", str(root)]),
                    ("osv-scanner (cached offline database)", ["osv-scanner", "--format", "json",
                                                               "--experimental-offline", "-r", str(root)])]
        for label, cmd in variants:
            code, so, se = run(cmd, root)
            if code in (0, 1) and so.strip().startswith("{") and "query failed" not in se:
                rel = save_raw(tools_dir, "deps.raw.json", so)
                return record(tools_dir, "deps", status="ran", tool=label, command=cmd, exit_code=code,
                              version=version("osv-scanner"), output_file=rel,
                              findings=_osv_findings(json.loads(so), root, "osv-scanner"),
                              note="; ".join(tried))
            tried.append(f"{label} failed: {' '.join((se or so).strip().splitlines()[-1:])[-200:]}")
    reqs = has(inv, r"(^|/)requirements[^/]*\.txt$")
    if reqs and shutil.which("pip-audit"):
        fnd, cmds, ok = [], [], True
        for r in reqs:
            cmd = ["pip-audit", "-r", str(root / r), "--no-deps", "--disable-pip", "--format", "json",
                   "--vulnerability-service", "pypi", "--progress-spinner", "off"]
            code, so, se = run(cmd, root)
            cmds.append(cmd)
            if not so.strip().startswith("{"):
                ok = False
                tried.append(f"pip-audit failed on {r}: {(se.strip().splitlines() or ['?'])[-1][:200]}")
                break
            save_raw(tools_dir, f"deps.pip-audit.{Path(r).name}.json", so)
            for d in json.loads(so).get("dependencies", []):
                for v in d.get("vulns", []):
                    fnd.append({"tool": "pip-audit", "rule": v.get("id"), "file": r, "line": None,
                                "package": f"{d.get('name')}@{d.get('version')}", "aliases": v.get("aliases", []),
                                "message": (v.get("description") or "")[:300], "severity": "unknown",
                                "fix_versions": v.get("fix_versions", [])})
        if ok:
            npm_note = "; package.json not covered by pip-audit" if has(inv, r"(^|/)package\.json$") else ""
            return record(tools_dir, "deps", status="ran", tool="pip-audit", command=cmds, version=version("pip-audit"),
                          findings=fnd, note="; ".join(tried) + npm_note)
    if shutil.which("trivy"):
        for label, cmd in (("trivy", ["trivy", "fs", "--scanners", "vuln", "--format", "json", "--quiet", str(root)]),
                           ("trivy (offline)", ["trivy", "fs", "--scanners", "vuln", "--format", "json", "--quiet",
                                                "--offline-scan", "--skip-db-update", str(root)])):
            code, so, se = run(cmd, root)
            if code == 0 and so.strip().startswith("{"):
                rel = save_raw(tools_dir, "deps.raw.json", so)
                fnd = [{"tool": "trivy", "rule": v.get("VulnerabilityID"), "file": r.get("Target"), "line": None,
                        "package": f"{v.get('PkgName')}@{v.get('InstalledVersion')}", "message": (v.get("Title") or "")[:300],
                        "severity": (v.get("Severity") or "unknown").lower()}
                       for r in json.loads(so).get("Results", []) for v in (r.get("Vulnerabilities") or [])]
                return record(tools_dir, "deps", status="ran", tool=label, command=cmd, exit_code=code,
                              version=version("trivy"), output_file=rel, findings=fnd, note="; ".join(tried))
            tried.append(f"{label} failed: {(se.strip().splitlines() or ['?'])[-1][:200]}")
    if not tried:
        return missing(tools_dir, "deps", ["osv-scanner", "pip-audit", "trivy"])
    return record(tools_dir, "deps", status="error", tool="osv-scanner/pip-audit/trivy", note="; ".join(tried))


def cvss_to_sev(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


def sbom(root, tools_dir, inv):
    if not shutil.which("syft"):
        return missing(tools_dir, "sbom", ["syft"])
    out = tools_dir / "sbom.cdx.json"
    cmd = ["syft", f"dir:{root}", "-o", f"cyclonedx-json={out}", "-q"]
    for e in EXCLUDE:
        cmd += ["--exclude", f"./{e}/**"]
    code, so, se = run(cmd, root)
    if code != 0 or not out.exists():
        return record(tools_dir, "sbom", status="error", tool="syft", command=cmd, exit_code=code, note=(se or so)[-2000:])
    doc = json.loads(out.read_text())
    licences, fnd = {}, []
    for c in doc.get("components", []):
        names = []
        for l in c.get("licenses", []) or []:
            lic = l.get("license", {})
            names.append(lic.get("id") or lic.get("name") or l.get("expression") or "unknown")
        names = names or ["unknown"]
        for n in names:
            licences.setdefault(n, []).append(f"{c.get('name')}@{c.get('version')}")
            if COPYLEFT.search(n) or n == "unknown":
                fnd.append({"tool": "syft", "rule": "licence-review", "file": "", "line": None,
                            "package": f"{c.get('name')}@{c.get('version')}", "message": f"licence {n} needs review",
                            "severity": "low"})
    write_json(tools_dir / "sbom.licences.json", licences)
    return record(tools_dir, "sbom", status="ran", tool="syft", command=cmd, exit_code=code, version=version("syft"),
                  output_file=str(out.relative_to(tools_dir.parent)), components=len(doc.get("components", [])),
                  findings=fnd)


def lint(root, tools_dir, inv):
    py, ts = has(inv, r"\.py$"), has(inv, r"\.tsx?$")
    if not py and not ts:
        return record(tools_dir, "lint", status="not_applicable", tool="-", note="no Python or TypeScript files")
    fnd, cmds, notes, ran = [], [], [], False
    if py:
        if shutil.which("ruff"):
            cmd = ["ruff", "check", "--output-format", "json", "--no-cache", "--exit-zero", str(root)]
            code, so, se = run(cmd, root)
            cmds.append(cmd)
            if so.strip().startswith("["):
                ran = True
                save_raw(tools_dir, "lint.ruff.json", so)
                for x in json.loads(so):
                    fnd.append({"tool": "ruff", "rule": x.get("code"), "file": str(Path(x["filename"]).resolve().relative_to(root)),
                                "line": x.get("location", {}).get("row"), "message": x.get("message"), "severity": "low"})
            else:
                notes.append("ruff failed: " + (se or so)[-500:])
        else:
            notes.append("ruff not installed")
    if ts and has(inv, r"(^|/)tsconfig\.json$"):
        if shutil.which("tsc"):
            cmd = ["tsc", "--noEmit", "--pretty", "false", "-p", str(root)]
            code, so, se = run(cmd, root)
            cmds.append(cmd)
            ran = True
            save_raw(tools_dir, "lint.tsc.txt", so + se)
            errs = list(re.finditer(r"^(.+?)\((\d+),\d+\): error (TS\d+): (.+)$", so, re.M))
            for m in errs:
                fnd.append({"tool": "tsc", "rule": m.group(3), "file": m.group(1), "line": int(m.group(2)),
                            "message": m.group(4), "severity": "low"})
            if code != 0 and not errs:
                # tsc exits non-zero on type errors; without parsable errors it did not check anything
                return record(tools_dir, "lint", status="error", tool="ruff/tsc", command=cmds, exit_code=code,
                              note="tsc failed: " + (se or so).strip()[-500:])
        else:
            notes.append("tsc not installed")
    if not ran:
        return record(tools_dir, "lint", status="missing", tool="ruff/tsc", command=cmds, note="; ".join(notes))
    return record(tools_dir, "lint", status="ran", tool="ruff/tsc", command=cmds, note="; ".join(notes), findings=fnd)


def container(root, tools_dir, inv):
    dockerfiles = [p for p in has(inv, r"(^|/)Dockerfile[^/]*$")]
    if not dockerfiles:
        return record(tools_dir, "container", status="not_applicable", tool="-", note="no Dockerfile")
    if not shutil.which("hadolint"):
        return missing(tools_dir, "container", ["hadolint"])
    fnd, cmds = [], []
    for d in dockerfiles:
        cmd = ["hadolint", "--format", "json", "--no-fail", str(root / d)]
        code, so, se = run(cmd, root)
        cmds.append(cmd)
        try:
            out = json.loads(so)
        except ValueError:
            out = None
        if code != 0 or not isinstance(out, list):
            return record(tools_dir, "container", status="error", tool="hadolint", command=cmds, exit_code=code,
                          version=version("hadolint"), note=f"hadolint failed on {d}: " + (se or so).strip()[-500:])
        for x in out:
            fnd.append({"tool": "hadolint", "rule": x.get("code"), "file": d, "line": x.get("line"),
                        "message": x.get("message"), "severity": {"error": "medium", "warning": "low"}.get(x.get("level"), "low")})
    return record(tools_dir, "container", status="ran", tool="hadolint", command=cmds, version=version("hadolint"),
                  findings=fnd)


def tests(root, tools_dir, inv, run_meta):
    py_tests = has(inv, r"(^|/)(tests?/.*\.py|test_[^/]+\.py|[^/]+_test\.py)$")
    pkg = root / "package.json"
    js_test = False
    if pkg.exists():
        try:
            js_test = bool(json.loads(pkg.read_text()).get("scripts", {}).get("test"))
        except ValueError:
            pass
    if not py_tests and not js_test:
        return record(tools_dir, "tests", status="not_applicable", tool="-", note="no test suite found")
    results = []
    if py_tests:
        results.append(("pytest", ["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
                        + [f"--ignore={e}" for e in EXCLUDE]))
    if js_test:
        results.append(("npm test", ["npm", "test", "--silent"]))
    outs, status, codes = [], "ok", []
    for name, cmd in results:
        r = run_repo_code(cmd, root, run_meta)
        if r["status"] == "skipped":
            return record(tools_dir, "tests", status="skipped", tool=name, command=cmd, note=r["reason"])
        save_raw(tools_dir, f"tests.{name.split()[0]}.log", r["output"])
        codes.append(r["exit_code"])
        outs.append({"runner": name, "command": cmd, "status": r["status"], "exit_code": r["exit_code"],
                     "sandbox": r["sandbox"], "summary": summarise(r["output"])})
        if r["status"] != "ran":
            status = "error"
        elif r["exit_code"] != 0 and status != "error":
            status = "failed"
    data = record(tools_dir, "tests", status="ran" if status in ("ok", "failed") else "error", tool="/".join(n for n, _ in results),
                  runs=outs, exit_code=max((c for c in codes if c is not None), default=None))
    data["status"] = "ok" if status == "ok" else ("findings" if status == "failed" else "error")
    write_json(tools_dir / "tests.json", data)
    return data


def summarise(out):
    lines = [l for l in out.strip().splitlines() if re.search(r"passed|failed|error|Tests?:", l, re.I)]
    return lines[-1][:300] if lines else out.strip().splitlines()[-1][:300] if out.strip() else ""


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    rd = run_dir_from_arg(sys.argv[1])
    run_meta = read_json(rd / "run.json")
    root = Path(run_meta["repo"])
    inv = read_json(rd / "inventory.json")
    EXCLUDE[:] = run_meta.get("exclude", [])
    tools_dir = rd / "tools"
    tools_dir.mkdir(exist_ok=True)
    summary = []
    for fn in (secrets, sast, deps, sbom, lint, container):
        summary.append(fn(root, tools_dir, inv))
    summary.append(tests(root, tools_dir, inv, run_meta))
    for s in summary:
        extra = f", {s['finding_count']} findings" if "finding_count" in s else ""
        print(f"{s['group']:<10} {s['status']:<15} {s.get('tool', '')}{extra}{' – ' + s['note'][:120] if s.get('note') else ''}")


if __name__ == "__main__":
    main()
