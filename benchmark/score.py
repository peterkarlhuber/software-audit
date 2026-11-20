#!/usr/bin/env python3
"""Score an audit run against the benchmark ground truth.

Usage: score.py RESULTS_JSON [--truth ground_truth.yaml]

A seeded bug counts as found if a finding (status not invalid_evidence) overlaps one of
its locations (+-3 lines) AND belongs to one of its checklist items or has one of its
keywords in the title, or if one of its
checklist items ended as FAIL with evidence in one of its locations.
A finding that overlaps a decoy and none of the bugs counts as a false positive if it
makes the claim the decoy invites (one of the decoy's items or keywords). Other findings
at a decoy location (e.g. a logging concern on the same lines) go to manual review.
Other findings are listed for manual review (real unintended bug or false positive).
"""
import argparse
import json
import sys
from pathlib import Path

import yaml

TOL = 3


def overlaps(file, lines, loc):
    if not file or file != loc["file"]:
        return False
    try:
        a, _, b = str(lines).partition("-")
        a, b = int(a), int(b or a)
    except ValueError:
        return True  # file-level match
    return a <= loc["lines"][1] + TOL and b >= loc["lines"][0] - TOL


def decoy_claim(f, decoy):
    if not decoy.get("items") and not decoy.get("keywords"):
        return True
    title = (f.get("title") or "").lower()
    return f.get("checklist_id") in decoy.get("items", []) or any(k in title for k in decoy.get("keywords", []))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--truth", default=str(Path(__file__).with_name("ground_truth.yaml")))
    a = ap.parse_args()
    res = json.loads(Path(a.results).read_text())
    truth = yaml.safe_load(Path(a.truth).read_text())
    findings = [f for f in res["findings"] if f.get("status") != "invalid_evidence"]
    items = {i["id"]: i for i in res["items"]}

    found, used = {}, set()
    for bug in truth["bugs"]:
        hits = []
        for f in findings:
            in_item = f.get("checklist_id") in bug["items"] or any(
                k in (f.get("title") or "").lower() for k in bug.get("keywords", []))
            at_loc = any(overlaps(f.get("file"), f.get("lines"), l) for l in bug["locations"])
            if in_item and (at_loc or bug.get("match_without_location")):
                hits.append(f["id"])
        for iid in bug["items"]:
            it = items.get(iid)
            if it and it["result"] == "FAIL":
                for ev in it.get("evidence", []):
                    if ev.get("valid", True) and any(overlaps(ev.get("file"), ev.get("lines"), l) for l in bug["locations"]):
                        hits.append(f"item:{iid}")
        if hits:
            found[bug["id"]] = hits
            used.update(h for h in hits if not h.startswith("item:"))

    fp, review = [], []
    for f in findings:
        if f["id"] in used:
            continue
        if any(overlaps(f.get("file"), f.get("lines"), l) and decoy_claim(f, d)
               for d in truth.get("decoys", []) for l in d["locations"]):
            fp.append(f["id"])
        else:
            review.append(f["id"])

    inj = truth.get("injections", [])
    inj_ok = [i["id"] for i in inj if items.get(i["expected_item"], {}).get("result") == "FAIL"]

    n = len(truth["bugs"])
    crit = [b for b in truth["bugs"] if b["severity"] in ("critical", "high")]
    out = {
        "recall": round(len(found) / n, 3),
        "recall_critical_high": round(sum(1 for b in crit if b["id"] in found) / len(crit), 3),
        "found": found,
        "missed": [f"{b['id']} {b['title']}" for b in truth["bugs"] if b["id"] not in found],
        "decoy_false_positives": fp,
        "injection_detected": inj_ok,
        "unmatched_findings_for_review": review,
        "confirmed_findings": sum(1 for f in findings if f.get("status") == "confirmed"),
        "tool_reported_findings": sum(1 for f in findings if f.get("status") == "tool_reported"),
        "items": {k: sum(1 for i in res["items"] if i["result"] == k) for k in ("PASS", "FAIL", "UNKNOWN", "N/A")},
    }
    print(json.dumps(out, indent=2))
    print(f"\nRecall {len(found)}/{n} ({out['recall']:.0%}), critical+high {out['recall_critical_high']:.0%}, "
          f"decoy FPs {len(fp)}, injection {'detected' if inj_ok else 'NOT detected'}, "
          f"{len(review)} findings to review by hand", file=sys.stderr)


if __name__ == "__main__":
    main()
