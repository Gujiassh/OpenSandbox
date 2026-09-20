# Copyright 2026 The OpenSandbox Authors
# Licensed under the Apache License, Version 2.0.
"""Observe original count results without changing the workload or its outcome."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

STRESS = "test_sustained_fork_heavy_mix_keeps_process_table_bounded"
STATE: dict = {"counts": [], "errors": [], "original_reports": []}


def process_row(entry: Path, uptime: float, hz: int) -> dict:
    started = time.monotonic()
    stat = (entry / "stat").read_text()
    fields = stat[stat.rfind(")") + 2 :].split()
    start = int(fields[19])
    argv = (entry / "cmdline").read_bytes().decode(errors="replace").split("\0")
    after = (entry / "stat").read_text()
    if int(after[after.rfind(")") + 2 :].split()[19]) != start:
        raise RuntimeError(f"PID {entry.name} changed identity during census")
    return {
        "pid": int(entry.name),
        "ppid": int(fields[1]),
        "state": fields[0],
        "comm": stat[stat.find("(") + 1 : stat.rfind(")")],
        "argv": argv[:-1] if argv[-1] == "" else argv,
        "start_ticks": start,
        "age_seconds": uptime - start / hz,
        "read_started": started,
        "read_finished": time.monotonic(),
    }


def read_proc(root: Path) -> dict:
    started = time.monotonic()
    uptime = float((root / "uptime").read_text().split()[0])
    hz = os.sysconf("SC_CLK_TCK")
    rows, unavailable = [], []
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        if not entry.name.isdigit():
            continue
        try:
            rows.append(process_row(entry, uptime, hz))
        except (FileNotFoundError, ProcessLookupError, PermissionError) as exc:
            unavailable.append({"pid": int(entry.name), "error": type(exc).__name__})
    return {
        "started": started,
        "finished": time.monotonic(),
        "processes": rows,
        "unavailable": unavailable,
    }


def checked_command(*args: str) -> str:
    return subprocess.run(
        args, check=True, capture_output=True, text=True, timeout=30
    ).stdout.strip()


def validate_snapshot(snapshot: dict) -> None:
    if not any(p["pid"] == 1 and p["comm"] == "execd" for p in snapshot["processes"]):
        raise AssertionError("census did not establish container execd PID 1")
    if any(
        p["error"] not in {"FileNotFoundError", "ProcessLookupError"}
        for p in snapshot["unavailable"]
    ):
        raise AssertionError("unreadable process makes census incomplete")


def census(state: dict) -> dict:
    started = time.monotonic()
    snapshot = json.loads(
        checked_command(
            "sudo",
            "-n",
            sys.executable,
            str(Path(__file__).resolve()),
            "--proc-root",
            state["proc_root"],
        )
    )
    snapshot["host_started"] = started
    snapshot["host_finished"] = time.monotonic()
    validate_snapshot(snapshot)
    init = next(p for p in snapshot["processes"] if p["pid"] == 1)
    if init["start_ticks"] != state["init_start_ticks"]:
        raise AssertionError("container PID 1 identity changed")
    return snapshot


def prepare(sandbox, state: dict) -> None:
    ids = checked_command(
        "docker", "ps", "-aq", "--filter", f"label=opensandbox.io/id={sandbox.id}"
    ).splitlines()
    if len(ids) != 1:
        raise AssertionError(f"expected one sandbox container, got {len(ids)}")
    container = json.loads(checked_command("docker", "inspect", ids[0]))[0]
    expected = checked_command(
        "docker",
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        os.environ["OPENSANDBOX_SANDBOX_DEFAULT_IMAGE"],
    )
    if container["Image"] != expected:
        raise AssertionError("sandbox does not use the pinned interpreter image")
    root = f"/proc/{int(container['State']['Pid'])}/root/proc"
    snapshot = json.loads(
        checked_command(
            "sudo",
            "-n",
            sys.executable,
            str(Path(__file__).resolve()),
            "--proc-root",
            root,
        )
    )
    validate_snapshot(snapshot)
    state.update(
        container=ids[0],
        image_id=expected,
        proc_root=root,
        init_start_ticks=next(
            p["start_ticks"] for p in snapshot["processes"] if p["pid"] == 1
        ),
    )
    state["preflight"] = snapshot


def identity(row: dict) -> tuple[int, int]:
    return row["pid"], row["start_ticks"]


def evaluate_drain(baseline: dict, final: dict, drained: dict) -> dict:
    for snapshot in (baseline, final, drained):
        validate_snapshot(snapshot)
    before = {identity(p) for p in baseline["processes"]}
    sleepers = [
        p
        for p in final["processes"]
        if len(p["argv"]) == 2
        and Path(p["argv"][0]).name == "sleep"
        and p["argv"][1] == "10"
        and p["state"] != "Z"
        and p["ppid"] == 1
        and 0 <= p["age_seconds"] <= 10
    ]
    sleeper_ids = {identity(p) for p in sleepers}
    return {
        "final_live_ten_second_sleepers": sleepers,
        "surviving_original_sleepers": [
            p for p in drained["processes"] if identity(p) in sleeper_ids
        ],
        "post_expiry_zombies": [p for p in drained["processes"] if p["state"] == "Z"],
        "post_expiry_new_identities": [
            p for p in drained["processes"] if identity(p) not in before
        ],
        "boundary_census_complete": not any(
            s["unavailable"] for s in (baseline, final, drained)
        ),
        "count_membership": "non-atomic: original shell/ls/wc and disappearing processes remain unaccounted",
    }


def wrapped_count(original, state: dict):
    def observe_count(sandbox):
        caller = sys._getframe(1).f_locals
        record = {
            "request_started": time.monotonic(),
            "original_locals": {
                k: v
                for k, v in caller.items()
                if k in {"baseline", "round_n", "zombies"} and isinstance(v, int)
            },
        }
        value = original(sandbox)
        record.update(value=value, returned=time.monotonic())
        state["counts"].append(record)
        try:
            record["census"] = census(state)
            record["census_after_return_seconds"] = (
                record["census"]["host_started"] - record["returned"]
            )
        except Exception as exc:  # noqa: BLE001 - Retain native results when diagnostics fail.
            state["errors"].append(f"count census {type(exc).__name__}: {exc}")
        return value

    return observe_count


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    original = None
    if item.name == STRESS:
        try:
            prepare(item.funcargs["sandbox"], STATE)
            original = item.module._process_count
            item.module._process_count = wrapped_count(original, STATE)
        except Exception as exc:  # noqa: BLE001 - Retain native results when diagnostics fail.
            STATE["errors"].append(f"preflight {type(exc).__name__}: {exc}")
    try:
        yield
    finally:
        if original is not None:
            item.module._process_count = original


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when != "call":
        return
    STATE["original_reports"].append(
        {"nodeid": report.nodeid, "outcome": report.outcome}
    )
    if item.name != STRESS:
        return
    STATE["original_stress_outcome"] = report.outcome
    STATE["original_failure"] = str(report.longrepr) if report.failed else None
    try:
        if len(STATE["counts"]) != 2 or any("census" not in c for c in STATE["counts"]):
            raise AssertionError("expected two observed original count calls")
        started = time.monotonic()
        time.sleep(12)
        STATE["drain_wait_seconds"] = time.monotonic() - started
        if STATE["drain_wait_seconds"] < 12:
            raise AssertionError(
                "post-expiry observation needs twelve no-workload seconds"
            )
        STATE["post_expiry"] = census(STATE)
        STATE["drain"] = evaluate_drain(
            STATE["counts"][0]["census"],
            STATE["counts"][1]["census"],
            STATE["post_expiry"],
        )
        if any(
            STATE["drain"][key]
            for key in (
                "surviving_original_sleepers",
                "post_expiry_zombies",
                "post_expiry_new_identities",
            )
        ):
            raise AssertionError(
                "post-expiry workload has surviving or new process identities"
            )
    except Exception as exc:  # noqa: BLE001 - Retain native results when diagnostics fail.
        STATE["errors"].append(f"drain {type(exc).__name__}: {exc}")


def finish_state(state: dict, original_exit: int, expected_tests: int) -> int:
    state["original_pytest_exit_code"] = int(original_exit)
    if len(state["original_reports"]) != expected_tests:
        state["errors"].append("not all expected native test calls completed")
    if any(r["outcome"] == "skipped" for r in state["original_reports"]):
        state["errors"].append("native test skipped")
    if state.get("original_stress_outcome") not in {"passed", "failed"}:
        state["errors"].append("stress workload outcome missing")
    state["diagnostic_scope"] = (
        "original count scalars, non-atomic boundary census and post-expiry identity comparison"
    )
    state["diagnostic_passed"] = not state["errors"]
    state["final_exit_code"] = int(original_exit) or (
        0 if state["diagnostic_passed"] else 1
    )
    return state["final_exit_code"]


def pytest_sessionfinish(session, exitstatus):
    session.exitstatus = finish_state(
        STATE, exitstatus, int(os.environ["RADAR_EXPECTED_TESTS"])
    )
    STATE["source_sha"] = os.environ["RADAR_SOURCE_SHA"]
    path = Path(os.environ["RADAR_DIAGNOSTICS_DIR"])
    path.mkdir(parents=True, exist_ok=True)
    (path / "diagnostics.json").write_text(
        json.dumps(STATE, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--proc-root":
        raise SystemExit(
            "usage: execd_init_observer.py --proc-root /proc/HOST_PID/root/proc"
        )
    print(json.dumps(read_proc(Path(sys.argv[2]))))
