#!/usr/bin/env python3
"""Step 2: run the standard tools that fit the repository and store their raw output.

Usage:
  run_tools.py RUN_DIR

Tool groups (checklist items refer to them with `tool:`):
  secrets    Gitleaks (working tree + Git history)
  sast       Semgrep (config from $AUDIT_SEMGREP_CONFIG, default p/default)
  deps       OSV-Scanner, else Trivy
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


def record(tools_dir, group, **kw):
    findings = kw.pop("findings", None)
    data = {"group": group, **kw}
    if findings is not None:
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


def sast(root, tools_dir, inv):
    if not shutil.which("semgrep"):
        return missing(tools_dir, "sast", ["semgrep"])
    config = os.environ.get("AUDIT_SEMGREP_CONFIG", "p/default")
    cmd = ["semgrep", "scan", "--config", config, "--json", "--metrics=off", "--disable-version-check", str(root)]
    code, so, se = run(cmd, root)
    if code not in (0, 1) or not so.strip().startswith("{"):
        return record(tools_dir, "sast", status="error", tool="semgrep", command=cmd, exit_code=code,
                      version=version("semgrep"), note=(se.strip().splitlines() or [so[-500:]])[-1][-500:]
                      + " (the default config p/default is downloaded from semgrep.dev; set AUDIT_SEMGREP_CONFIG to a local rules folder to run offline)")
    rel = save_raw(tools_dir, "sast.raw.json", so)
    raw = json.loads(so)
    fnd = []
    for x in raw.get("results", []):
        path = x.get("path", "")
        try:
            path = str(Path(path).resolve().relative_to(root))
        except ValueError:
            pass
        fnd.append({"tool": "semgrep", "rule": x.get("check_id"), "file": path, "line": x.get("start", {}).get("line"),
                    "message": x.get("extra", {}).get("message", "")[:500],
                    "severity": {"ERROR": "high", "WARNING": "medium"}.get(x.get("extra", {}).get("severity"), "low")})
    return record(tools_dir, "sast", status="ran", tool="semgrep", command=cmd, exit_code=code, config=config,
                  version=version("semgrep"), output_file=rel, findings=fnd,
                  scanned_files=len(raw.get("paths", {}).get("scanned", [])))


def deps(root, tools_dir, inv):
    if shutil.which("osv-scanner"):
        for cmd in (["osv-scanner", "scan", "source", "--format", "json", "-r", str(root)],
                    ["osv-scanner", "--format", "json", "-r", str(root)]):
            code, so, se = run(cmd, root)
            if so.strip().startswith("{"):
                rel = save_raw(tools_dir, "deps.raw.json", so)
                raw = json.loads(so)
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
                            fnd.append({"tool": "osv-scanner", "rule": v.get("id"), "file": src, "line": None,
                                        "package": f"{pkg['package'].get('name')}@{pkg['package'].get('version')}",
                                        "message": (v.get("summary") or "")[:300], "cvss": sev.get(v.get("id")),
                                        "severity": cvss_to_sev(sev.get(v.get("id")))})
                return record(tools_dir, "deps", status="ran", tool="osv-scanner", command=cmd, exit_code=code,
                              version=version("osv-scanner"), output_file=rel, findings=fnd)
        if not shutil.which("trivy"):
            return record(tools_dir, "deps", status="error", tool="osv-scanner", command=cmd, exit_code=code,
                          note=" ".join((se or so).strip().splitlines()[-2:])[-600:])
    if shutil.which("trivy"):
        cmd = ["trivy", "fs", "--scanners", "vuln", "--format", "json", "--quiet", str(root)]
        code, so, se = run(cmd, root)
        if code != 0 or not so.strip().startswith("{"):
            return record(tools_dir, "deps", status="error", tool="trivy", command=cmd, exit_code=code, note=(se or so)[-2000:])
        rel = save_raw(tools_dir, "deps.raw.json", so)
        fnd = [{"tool": "trivy", "rule": v.get("VulnerabilityID"), "file": r.get("Target"), "line": None,
                "package": f"{v.get('PkgName')}@{v.get('InstalledVersion')}", "message": (v.get("Title") or "")[:300],
                "severity": (v.get("Severity") or "unknown").lower()}
               for r in json.loads(so).get("Results", []) for v in (r.get("Vulnerabilities") or [])]
        return record(tools_dir, "deps", status="ran", tool="trivy", command=cmd, exit_code=code,
                      version=version("trivy"), output_file=rel, findings=fnd)
    return missing(tools_dir, "deps", ["osv-scanner", "trivy"])


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
            for m in re.finditer(r"^(.+?)\((\d+),\d+\): error (TS\d+): (.+)$", so, re.M):
                fnd.append({"tool": "tsc", "rule": m.group(3), "file": m.group(1), "line": int(m.group(2)),
                            "message": m.group(4), "severity": "low"})
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
        for x in json.loads(so or "[]"):
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
        results.append(("pytest", ["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider"]))
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
