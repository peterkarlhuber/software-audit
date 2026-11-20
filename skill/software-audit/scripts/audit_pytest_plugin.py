"""Pytest plugin used by run_test.py to check that a confirming test is real.

It records
  - which lines of the cited file were executed (all threads), split into lines
    run inside functions and lines run at module level (import time), and
  - every failure: phase (setup/call/teardown), exception type and message.
run_test.py loads it with `-p audit_pytest_plugin` and reads the JSON written to
$AUDIT_TRACE_OUT at the end of the session.
"""
import json
import os
import sys
import threading

_TARGET = os.environ.get("AUDIT_TARGET_FILE", "")
_OUT = os.environ.get("AUDIT_TRACE_OUT", "")
_hits = set()
_module_hits = set()
_failures = []


def _local(frame, event, arg):
    if event == "line":
        (_module_hits if frame.f_code.co_name == "<module>" else _hits).add(frame.f_lineno)
    return _local


def _global(frame, event, arg):
    if _TARGET and frame.f_code.co_filename.endswith(_TARGET):
        return _local
    return None


def pytest_configure(config):
    if _TARGET:
        sys.settrace(_global)
        threading.settrace(_global)


def pytest_runtest_makereport(item, call):
    if call.excinfo is not None and not call.excinfo.errisinstance(KeyboardInterrupt):
        _failures.append({
            "nodeid": item.nodeid,
            "when": call.when,
            "type": call.excinfo.type.__name__,
            "message": str(call.excinfo.value)[:2000],
        })


def pytest_sessionfinish(session, exitstatus):
    sys.settrace(None)
    threading.settrace(None)
    if _OUT:
        with open(_OUT, "w", encoding="utf-8") as f:
            json.dump({"target": _TARGET, "hits": sorted(_hits), "module_hits": sorted(_module_hits),
                   "failures": _failures}, f)
