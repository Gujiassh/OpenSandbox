# Copyright 2026 The OpenSandbox Authors
# Licensed under the Apache License, Version 2.0.

"""Native negative controls for the corrected execd-init accounting oracle."""

import json
import shlex
import time

import pytest

from tests import test_execd_init_e2e as e2e


@pytest.fixture
def sandbox():
    instance = e2e._create_sandbox(tag="execd-accounting-negative")
    try:
        yield instance
    finally:
        e2e._destroy(instance)


def _state(sandbox, pid):
    output = e2e._run_command(
        sandbox,
        f'IFS= read -r stat < "/proc/{pid}/stat" || exit 1; '
        "stat=${stat##*) }; set -- $stat; state=$1; parent=$2; "
        'shift 19 || exit 1; printf "%s:%s:%s" "$1" "$state" "$parent"',
    )
    start, state, parent = output.strip().split(":")
    return int(start), state, int(parent)


def test_owned_process_outliving_deadline_is_rejected(sandbox, monkeypatch):
    original_run = e2e._run_command

    def overlong_run(instance, command):
        assert command.startswith("sleep 10 &")
        return original_run(instance, command.replace("sleep 10 &", "sleep 30 &", 1))

    with monkeypatch.context() as patch:
        patch.setattr(e2e, "_run_command", overlong_run)
        pid, start, deadline = e2e._start_long_sleeper(sandbox)
    observed_start, state, _ = _state(sandbox, pid)
    assert observed_start == start and state != "Z"
    with pytest.raises(AssertionError, match="outlived its deadline") as rejected:
        e2e._wait_for_long_sleepers(sandbox, [(pid, start, deadline)])
    assert time.monotonic() >= deadline
    assert _state(sandbox, pid)[0] == start
    print(
        "NATIVE_ACCOUNTING_NEGATIVE "
        + json.dumps(
            {
                "case": "owned-overlong",
                "pid": pid,
                "start_ticks": start,
                "error": str(rejected.value),
            }
        )
    )


def test_owned_zombie_is_rejected(sandbox):
    path = "/tmp/execd-accounting-zombie.json"
    program = "\n".join(
        [
            "import json, os, time",
            "from pathlib import Path",
            "child = os.fork()",
            "if child == 0: os._exit(0)",
            'fields = Path(f"/proc/{child}/stat").read_text().rsplit(") ", 1)[1].split()',
            f"Path({path!r}).write_text(json.dumps({{'pid': child, 'start': int(fields[19]), 'parent': os.getpid()}}))",
            "time.sleep(30)",
        ]
    )
    e2e._run_command(
        sandbox,
        f"python3 -c {shlex.quote(program)} >/tmp/execd-accounting-zombie.log 2>&1 &",
    )
    deadline = time.monotonic() + 5
    record = None
    while time.monotonic() < deadline:
        output = e2e._run_command(sandbox, f"if [ -f {path} ]; then cat {path}; fi")
        if output.strip():
            record = json.loads(output)
            break
        time.sleep(0.1)
    assert record is not None, "controlled parent did not publish its child identity"
    pid, start, parent = record["pid"], record["start"], record["parent"]
    while time.monotonic() < deadline:
        actual_start, state, actual_parent = _state(sandbox, pid)
        assert actual_start == start and actual_parent == parent and parent > 1
        if state == "Z":
            break
        time.sleep(0.1)
    assert _state(sandbox, pid) == (start, "Z", parent)
    with pytest.raises(AssertionError, match="became a zombie") as rejected:
        e2e._wait_for_long_sleepers(sandbox, [(pid, start, time.monotonic() + 12)])
    print(
        "NATIVE_ACCOUNTING_NEGATIVE "
        + json.dumps(
            {
                "case": "owned-zombie",
                "pid": pid,
                "start_ticks": start,
                "ppid": parent,
                "error": str(rejected.value),
            }
        )
    )


def test_unowned_persistent_processes_exceed_original_bound(sandbox, monkeypatch):
    original_count = e2e._process_count
    counts = []
    extras = []

    def count_then_seed(instance):
        count = original_count(instance)
        counts.append(count)
        if len(counts) == 1:
            output = e2e._run_command(
                instance,
                'i=0; while [ "$i" -lt 15 ]; do sleep 90 & '
                'printf "%s " "$!"; i=$((i+1)); done',
            )
            extras.extend(int(pid) for pid in output.split())
            assert len(set(extras)) == 15
        return count

    with monkeypatch.context() as patch:
        patch.setattr(e2e, "_process_count", count_then_seed)
        with pytest.raises(
            AssertionError, match="process table grew over sustained churn"
        ) as rejected:
            e2e.TestExecdInitE2E().test_sustained_fork_heavy_mix_keeps_process_table_bounded(
                sandbox
            )
    assert len(counts) == 2 and counts[1] > counts[0] + 12
    states = [_state(sandbox, pid) for pid in extras]
    assert all(state != "Z" and parent == 1 for _, state, parent in states)
    print(
        "NATIVE_ACCOUNTING_NEGATIVE "
        + json.dumps(
            {
                "case": "unowned-persistent",
                "injected": 15,
                "pids": extras,
                "baseline": counts[0],
                "final": counts[1],
                "allowance": 12,
                "error": str(rejected.value),
            }
        )
    )
