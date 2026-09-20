# Copyright 2026 Alibaba Group Holding Ltd.
# Licensed under the Apache License, Version 2.0.
"""Observe the unchanged execd-init suite; keep its outcome separate from diagnostics."""

from __future__ import annotations

import http.client
import json
import os
import re
from pathlib import Path
import subprocess
import time
import traceback
from urllib.parse import urlsplit

import pytest

STRESS = "test_sustained_fork_heavy_mix_keeps_process_table_bounded"
STATE: dict = {"observed": False, "errors": [], "original_reports": []}

# One observer process in the container; identify it instead of counting it as workload.
CENSUS = r'''
import json, os, pathlib, time
root = pathlib.Path('/proc')
now = time.monotonic()
uptime = float((root / 'uptime').read_text().split()[0])
hz = os.sysconf('SC_CLK_TCK')
rows, unavailable = [], []
for entry in sorted(root.iterdir(), key=lambda p: p.name):
    if not entry.name.isdigit():
        continue
    try:
        stat = (entry / 'stat').read_text()
        fields = stat[stat.rfind(')') + 2:].split()
        start = int(fields[19])
        rows.append(dict(pid=int(entry.name), ppid=int(fields[1]),
                         state=fields[0], comm=(entry / 'comm').read_text().strip(),
                         argv=(entry / 'cmdline').read_bytes().decode(errors='replace').split('\0')[:-1],
                         start_ticks=start, age_seconds=uptime-start/hz))
    except (FileNotFoundError, ProcessLookupError, PermissionError) as exc:
        unavailable.append(dict(pid=int(entry.name), error=type(exc).__name__))
print(json.dumps(dict(observer_pid=os.getpid(), monotonic=now,
                     processes=rows, unavailable=unavailable)))
'''


def docker(*args: str) -> str:
    return subprocess.run(
        ["docker", *args], check=True, capture_output=True, text=True, timeout=30
    ).stdout.strip()


def census(container: str) -> dict:
    started = time.monotonic()
    result = json.loads(docker("exec", container, "python3", "-c", CENSUS))
    result["host_started"] = started
    result["host_finished"] = time.monotonic()
    return result


def workload_rows(snapshot: dict) -> list[dict]:
    return [p for p in snapshot["processes"] if p["pid"] != snapshot["observer_pid"]]


def validate_census(snapshot: dict) -> None:
    rows = snapshot["processes"]
    if not any(p["pid"] == snapshot["observer_pid"] for p in rows):
        raise AssertionError("census did not observe its own process")
    if not any(p["pid"] == 1 and p["comm"] == "execd" for p in rows):
        raise AssertionError("census did not establish execd as PID 1")
    if any(p["error"] not in {"FileNotFoundError", "ProcessLookupError"}
           for p in snapshot["unavailable"]):
        raise AssertionError("census could not read a process; evidence is incomplete")


def evaluate_drain(immediate: dict, drained: dict, original_baseline=None) -> dict:
    """Track PID plus start time so PID reuse cannot look like a surviving sleeper."""
    validate_census(immediate)
    validate_census(drained)
    live = workload_rows(immediate)
    after = workload_rows(drained)
    sleepers = {
        (p["pid"], p["start_ticks"])
        for p in live
        if len(p["argv"]) == 2 and Path(p["argv"][0]).name == "sleep" and p["argv"][1] == "10"
    }
    survivors = [p for p in after if (p["pid"], p["start_ticks"]) in sleepers]
    zombies = [p for p in after if p["state"] == "Z"]
    return {
        "immediate_workload_count": len(live),
        "post_expiry_workload_count": len(after),
        "immediate_ten_second_sleepers": len(sleepers),
        "surviving_original_sleepers": survivors,
        "post_expiry_zombies": zombies,
        "tracked_sleepers_and_zombies_passed": not survivors and not zombies,
        "post_expiry_other_live_processes": [p for p in after if p["state"] != "Z"],
        "original_baseline_count": original_baseline,
        "full_baseline_accounting": "unestablished: original count includes different probe processes",
    }


def parse_events(body: bytes) -> list[dict]:
    # Execd currently sends JSON followed by a blank line (without a data: prefix).
    text = body.decode("utf-8").replace("\r\n", "\n")
    if not text.endswith("\n\n"):
        raise AssertionError("SSE body is missing its final blank-line delimiter")
    events = []
    for frame in text.split("\n\n"):
        if not frame:
            continue
        if frame.startswith("data:"):
            frame = frame[5:].lstrip()
        value = json.loads(frame)
        if not isinstance(value, dict):
            raise AssertionError("SSE frame is not a JSON object")
        events.append(value)
    return events


def check_events(events: list[dict], failure: bool) -> None:
    expected = "error" if failure else "execution_complete"
    terminal = [e for e in events if e.get("type") in {"execution_complete", "error"}]
    if len(terminal) != 1 or terminal[0].get("type") != expected:
        raise AssertionError(f"unexpected terminal events: {terminal}")
    terminal_index = events.index(terminal[0])
    if any(e.get("type") != "ping" for e in events[terminal_index+1:]):
        raise AssertionError("non-ping events arrived after terminal event")
    for kind, marker in (("stdout", "radar-out"), ("stderr", "radar-err")):
        values = [e.get("text") for e in events if e.get("type") == kind]
        if values != [marker]:
            raise AssertionError(f"unexpected {kind} output: {values}")
    if failure and str(terminal[0].get("error", {}).get("evalue")) != "7":
        raise AssertionError("nonzero command did not report exit code 7")
    if failure and terminal[0].get("error", {}).get("ename") != "CommandExecError":
        raise AssertionError("nonzero command did not report CommandExecError")


def read_framed_response(response: http.client.HTTPResponse) -> tuple[bytes, list[float]]:
    if response.version != 11 or not response.chunked:
        raise AssertionError("expected an HTTP/1.1 chunked response")
    if response.status != 200:
        raise AssertionError(f"unexpected HTTP status {response.status}")
    if response.getheader("Content-Type", "").split(";", 1)[0] != "text/event-stream":
        raise AssertionError("expected text/event-stream")
    # Consume raw body framing: stdlib's decoder tolerates missing trailer endings
    # and discards chunk separators without verifying CRLF. This bounded probe
    # verifies both explicitly; it does not replace the production HTTP client.
    stream = response.fp
    if stream is None:
        raise AssertionError("HTTP response body stream is unavailable")
    body, pending, terminals = bytearray(), bytearray(), []
    deadline = time.monotonic() + 10

    def line() -> bytes:
        value = stream.readline(8193)
        if not value:
            raise http.client.IncompleteRead(b"")
        if len(value) > 8192 or not value.endswith(b"\r\n"):
            raise AssertionError("invalid or oversized chunk framing line")
        if time.monotonic() > deadline:
            raise AssertionError("SSE diagnostic exceeded its time bound")
        return value

    while True:
        size_text = line()[:-2].split(b";", 1)[0]
        if not re.fullmatch(rb"[0-9a-fA-F]+", size_text):
            raise http.client.IncompleteRead(b"")
        size = int(size_text, 16)
        if size == 0:
            trailer_bytes = 0
            while True:
                trailer = line()
                trailer_bytes += len(trailer)
                if trailer_bytes > 8192:
                    raise AssertionError("oversized HTTP trailers")
                if trailer == b"\r\n":
                    break
                if b":" not in trailer[:-2]:
                    raise AssertionError("malformed HTTP trailer")
            break
        if len(body) + size > 65536:
            raise AssertionError("SSE diagnostic exceeded its byte bound")
        chunk = stream.read(size)
        if len(chunk) != size:
            raise http.client.IncompleteRead(chunk, size-len(chunk))
        if stream.read(2) != b"\r\n":
            raise AssertionError("HTTP chunk is missing its CRLF separator")
        body.extend(chunk)
        pending.extend(chunk)
        while delimiter := re.search(rb"\r?\n\r?\n", pending):
            events = parse_events(bytes(pending[:delimiter.end()]))
            terminals.extend(time.monotonic() for e in events
                             if e.get("type") in {"execution_complete", "error"})
            del pending[:delimiter.end()]
    return bytes(body), terminals


def probe_sse(sandbox, failure: bool) -> dict:
    endpoint = sandbox.get_endpoint(44772)
    url = urlsplit(f"{sandbox.connection_config.protocol}://{endpoint.endpoint}")
    if url.scheme != "http":
        raise AssertionError("diagnostic bridge setup expected HTTP")
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
    command = "printf 'radar-out\\n'; printf 'radar-err\\n' >&2"
    if failure:
        command += "; exit 7"
    headers = endpoint.build_request_headers(sandbox.connection_config)
    headers["Content-Type"] = "application/json"
    start = time.monotonic()
    try:
        connection.request("POST", url.path.rstrip("/") + "/command",
                           json.dumps({"command": command, "background": False}), headers)
        response = connection.getresponse()
        headers_at = time.monotonic()
        body, terminals = read_framed_response(response)
        ended = time.monotonic()
        events = parse_events(body)
        check_events(events, failure)
        return {"case": "exit-7" if failure else "success", "status": response.status,
                "http_version": response.version, "chunked": response.chunked,
                "headers_seconds": headers_at-start, "complete_read_seconds": ended-start,
                "terminal_received_seconds": [t-start for t in terminals],
                "terminal_to_end_seconds": ended-terminals[0],
                "events": events, "clean_framing": True}
    finally:
        connection.close()


def prepare_observation(sandbox, state: dict) -> None:
    container_ids = docker("ps", "-aq", "--filter", f"label=opensandbox.io/id={sandbox.id}").splitlines()
    if len(container_ids) != 1:
        raise AssertionError(f"expected one sandbox container, got {len(container_ids)}")
    container = container_ids[0]
    image_id = docker("inspect", "--format", "{{.Image}}", container)
    expected_id = docker("image", "inspect", "--format", "{{.Id}}",
                         os.environ["OPENSANDBOX_SANDBOX_DEFAULT_IMAGE"])
    if image_id != expected_id:
        raise AssertionError(f"sandbox image mismatch: {image_id} != {expected_id}")
    state["container"] = container
    state["image_id"] = image_id


def observe(sandbox, state: dict) -> None:
    container = state["container"]
    state["immediate"] = census(container)
    state["capture_after_outcome_seconds"] = state["immediate"]["host_started"] - state["outcome_monotonic"]
    state["wait_started"] = time.monotonic()
    time.sleep(12)
    state["wait_elapsed"] = time.monotonic() - state["wait_started"]
    state["post_expiry"] = census(container)
    state["drain"] = evaluate_drain(state["immediate"], state["post_expiry"],
                                    state.get("original_locals", {}).get("baseline"))
    state["sse"] = []
    for failure in (False, True):
        state["sse"].append(probe_sse(sandbox, failure))
    if not state["drain"]["tracked_sleepers_and_zombies_passed"]:
        raise AssertionError("original sleepers survived expiry or post-expiry zombies remained")
    if state["wait_elapsed"] < 12:
        raise AssertionError("post-expiry wait did not meet the twelve-second allowance")


def pytest_collection_finish(session):
    STATE["collected"] = [item.nodeid for item in session.items]
    if len(session.items) != 11 or any("test_execd_init_e2e.py::" not in item.nodeid for item in session.items):
        STATE["errors"].append("expected the unchanged eleven-test execd-init suite")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    if item.name == STRESS:
        try:
            # Docker metadata only, before the unchanged test takes its baseline.
            prepare_observation(item.funcargs["sandbox"], STATE)
        except Exception as exc:
            STATE["errors"].append(f"preparation {type(exc).__name__}: {exc}")
    yield
    if item.name == STRESS:
        STATE["original_call_ended"] = time.monotonic()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when != "call":
        return
    STATE["original_reports"].append({"nodeid": report.nodeid, "outcome": report.outcome})
    if item.name != STRESS:
        return
    STATE["observed"] = True
    STATE["outcome_monotonic"] = STATE["original_call_ended"]
    STATE["original_stress_outcome"] = report.outcome
    if report.outcome not in {"passed", "failed"}:
        STATE["errors"].append(f"stress test was {report.outcome}; workload execution unestablished")
        return
    STATE["original_failure"] = str(report.longrepr) if report.failed else None
    STATE["original_locals"] = {}
    if call.excinfo is not None:
        for entry in call.excinfo.traceback:
            if entry.name == STRESS:
                STATE["original_locals"] = {
                    k: v for k, v in entry.frame.f_locals.items()
                    if k in {"baseline", "total", "round_n", "zombies"} and isinstance(v, int)
                }
    try:
        observe(item.funcargs["sandbox"], STATE)
    except Exception as exc:
        STATE["errors"].append(f"{type(exc).__name__}: {exc}")
        STATE["observer_traceback"] = traceback.format_exc()
    # Never overwrite report.outcome, report.longrepr or the original exception.


def finish_state(state: dict, original_exit: int) -> int:
    state["original_pytest_exit_code"] = int(original_exit)
    if not state["observed"]:
        state["errors"].append("stress observer never ran")
    if len(state["original_reports"]) != 11:
        state["errors"].append("not all eleven original test calls completed")
    if any(r.get("outcome") == "skipped" for r in state["original_reports"]):
        state["errors"].append("original test call skipped; full suite was not executed")
    state["diagnostic_scope"] = "image identity, post-expiry tracked sleepers/zombies, and SSE probes; full process baseline accounting remains unestablished"
    state["diagnostic_passed"] = state["observed"] and not state["errors"]
    state["final_exit_code"] = int(original_exit) or (0 if state["diagnostic_passed"] else 1)
    return state["final_exit_code"]


def pytest_sessionfinish(session, exitstatus):
    session.exitstatus = finish_state(STATE, exitstatus)
    STATE["source_sha"] = os.environ["RADAR_SOURCE_SHA"]
    path = Path(os.environ["RADAR_DIAGNOSTICS_DIR"])
    path.mkdir(parents=True, exist_ok=True)
    (path / "diagnostics.json").write_text(json.dumps(STATE, indent=2) + "\n", encoding="utf-8")
