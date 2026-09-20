# Copyright 2026 Alibaba Group Holding Ltd.
# Licensed under the Apache License, Version 2.0.
"""Local tests of diagnostic mechanics; these do not emulate native E2E acceptance."""

import http.client
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import execd_init_observer as observer


class Socket:
    def __init__(self, wire):
        self.wire = wire

    def makefile(self, *args):
        return io.BufferedReader(io.BytesIO(self.wire))


def response(body, terminated=True):
    chunks = f"{len(body):x}\r\n".encode() + body + b"\r\n"
    if terminated:
        chunks += b"0\r\n\r\n"
    wire = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
            b"Content-Type: text/event-stream\r\n\r\n" + chunks)
    result = http.client.HTTPResponse(Socket(wire))
    result.begin()
    return result


def events(failure=False):
    return [{"type": "stdout", "text": "radar-out"},
            {"type": "stderr", "text": "radar-err"},
            {"type": "error", "error": {"ename": "CommandExecError", "evalue": "7"}} if failure
            else {"type": "execution_complete"}]


def row(pid, argv, state="S", start=100):
    return dict(pid=pid, ppid=1, argv=argv, state=state, start_ticks=start,
                comm=Path(argv[0]).name if argv else "exited", age_seconds=1)


def snapshot(*extra):
    return {"observer_pid": 99, "unavailable": [], "processes": [
        row(1, ["execd"]), row(99, ["python3"]), *extra]}


class DiagnosticTests(unittest.TestCase):
    def test_clean_chunk_framing_and_success(self):
        body = b"".join(json.dumps(e).encode() + b"\n\n" for e in events())
        raw, terminal_times = observer.read_framed_response(response(body))
        self.assertEqual(len(terminal_times), 1)
        parsed = observer.parse_events(raw)
        observer.check_events(parsed, False)

    def test_missing_zero_chunk_fails(self):
        with self.assertRaises(http.client.IncompleteRead):
            observer.read_framed_response(response(b'{"type":"execution_complete"}\n\n', False))

    def test_zero_chunk_requires_final_trailer_blank_line(self):
        body = b"".join(json.dumps(e).encode() + b"\n\n" for e in events())
        wire = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                b"Content-Type: text/event-stream\r\n\r\n"
                + f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n")
        value = http.client.HTTPResponse(Socket(wire))
        value.begin()
        with self.assertRaises(http.client.IncompleteRead):
            observer.read_framed_response(value)

    def test_data_chunk_requires_crlf_separator(self):
        body = b"".join(json.dumps(e).encode() + b"\n\n" for e in events())
        wire = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                b"Content-Type: text/event-stream\r\n\r\n"
                + f"{len(body):x}\r\n".encode() + body + b"XX0\r\n\r\n")
        value = http.client.HTTPResponse(Socket(wire))
        value.begin()
        with self.assertRaisesRegex(AssertionError, "CRLF separator"):
            observer.read_framed_response(value)

    def test_non_chunked_fails(self):
        r = response(b"\n\n")
        r.chunked = False
        with self.assertRaises(AssertionError):
            observer.read_framed_response(r)

    def test_complete_error_and_exit_code(self):
        observer.check_events(events(True), True)
        wrong = events(True)
        wrong[-1]["error"]["evalue"] = "8"
        with self.assertRaises(AssertionError):
            observer.check_events(wrong, True)

    def test_output_and_terminal_not_dropped_or_duplicated(self):
        for bad in (events()[1:], events() + events()[-1:], events() + [{"type": "stdout", "text": "late"}]):
            with self.assertRaises(AssertionError):
                observer.check_events(bad, False)

    def test_trailing_keepalive_ping_is_allowed(self):
        observer.check_events(events() + [{"type": "ping"}], False)

    def test_malformed_event_or_unterminated_frame_fails(self):
        for bad in (b"broken\n\n", b'{"type":"stdout"}\n'):
            with self.assertRaises((AssertionError, ValueError)):
                observer.parse_events(bad)

    def test_accounted_sleepers_disappear(self):
        result = observer.evaluate_drain(snapshot(row(42, ["sleep", "10"])), snapshot())
        self.assertTrue(result["tracked_sleepers_and_zombies_passed"])
        self.assertEqual(result["immediate_ten_second_sleepers"], 1)
        self.assertEqual(result["post_expiry_workload_count"], 1)

    def test_survivors_zombies_and_pid_reuse(self):
        before = snapshot(row(42, ["sleep", "10"]))
        self.assertFalse(observer.evaluate_drain(before, before)["tracked_sleepers_and_zombies_passed"])
        self.assertFalse(observer.evaluate_drain(before, snapshot(row(50, [], "Z")))["tracked_sleepers_and_zombies_passed"])
        reused = snapshot(row(42, ["sh"], start=200))
        self.assertTrue(observer.evaluate_drain(before, reused)["tracked_sleepers_and_zombies_passed"])

    def test_empty_or_incomplete_census_fails(self):
        invalid = [dict(observer_pid=99, processes=[], unavailable=[]),
                   {**snapshot(), "unavailable": [{"pid": 42, "error": "PermissionError"}]}]
        for value in invalid:
            with self.assertRaises(AssertionError):
                observer.evaluate_drain(snapshot(), value)

    def test_split_frame_across_chunks_and_malformed_chunk(self):
        body = b"".join(json.dumps(e).encode() + b"\n\n" for e in events())
        chunks = b"".join(f"{len(piece):x}\r\n".encode() + piece + b"\r\n"
                          for piece in (body[:7], body[7:])) + b"0\r\n\r\n"
        header = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                  b"Content-Type: text/event-stream\r\n\r\n")
        value = http.client.HTTPResponse(Socket(header + chunks))
        value.begin()
        got, terminals = observer.read_framed_response(value)
        self.assertEqual(got, body)
        self.assertEqual(len(terminals), 1)
        broken = http.client.HTTPResponse(Socket(header + b"not-hex\r\n"))
        broken.begin()
        with self.assertRaises(http.client.IncompleteRead):
            observer.read_framed_response(broken)

    def test_finish_cannot_mask_original_failure(self):
        state = dict(observed=True, errors=[], original_reports=[{}]*11)
        self.assertEqual(observer.finish_state(state, 1), 1)
        self.assertTrue(state["diagnostic_passed"])
        self.assertEqual(state["original_pytest_exit_code"], 1)

    def test_missing_observer_or_calls_fails_green_suite(self):
        for seen, calls in ((False, 11), (True, 10)):
            state = dict(observed=seen, errors=[], original_reports=[{}]*calls)
            self.assertEqual(observer.finish_state(state, 0), 1)

    def test_image_mismatch_fails_before_workload_observation(self):
        class Sandbox:
            id = "local-test"
        with patch.object(observer, "docker", side_effect=["container", "wrong", "wanted"]), \
             patch.dict(os.environ, {"OPENSANDBOX_SANDBOX_DEFAULT_IMAGE": "image"}):
            with self.assertRaisesRegex(AssertionError, "image mismatch"):
                observer.prepare_observation(Sandbox(), {})

    def test_skipped_call_cannot_pass_diagnostic(self):
        state = dict(observed=True, errors=[], original_reports=[{"outcome": "passed"}]*10 + [{"outcome": "skipped"}])
        self.assertEqual(observer.finish_state(state, 0), 1)

    def test_observer_exception_fails_without_changing_original_junit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "conftest.py").write_text("""import pytest
import execd_init_observer as observer
@pytest.fixture
def sandbox(): return object()
def observe(sandbox,state): raise RuntimeError('diagnostic unavailable')
observer.observe=observe
observer.prepare_observation=lambda sandbox,state: None
""", encoding="utf-8")
            source = "\n".join(f"def test_control_{i}(): pass" for i in range(10))
            source += f"\ndef {observer.STRESS}(sandbox): pass\n"
            (root / "test_execd_init_e2e.py").write_text(source, encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(Path(observer.__file__).parent),
                   "PYTEST_PLUGINS": "execd_init_observer", "RADAR_DIAGNOSTICS_DIR": directory,
                   "RADAR_SOURCE_SHA": "local-mechanics-test"}
            run = subprocess.run([sys.executable, "-m", "pytest", "-q", "--junitxml=original.xml"],
                                 cwd=root, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
            data = json.loads((root / "diagnostics.json").read_text())
            self.assertEqual(data["original_pytest_exit_code"], 0)
            self.assertEqual(data["original_stress_outcome"], "passed")
            self.assertFalse(data["diagnostic_passed"])
            self.assertIn("RuntimeError: diagnostic unavailable", data["errors"])
            self.assertIn('failures="0"', (root / "original.xml").read_text())

    def test_real_pytest_hook_preserves_failure_and_runs_before_teardown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "conftest.py").write_text('''import pytest
import execd_init_observer as observer
@pytest.fixture
def sandbox():
    class Sandbox: active=True
    value=Sandbox()
    yield value
    value.active=False
def observe(sandbox,state):
    assert sandbox.active
    state['mock_observed_before_teardown']=True
observer.observe=observe
observer.prepare_observation=lambda sandbox,state: None
''', encoding="utf-8")
            source = "\n".join(f"def test_control_{i}(): pass" for i in range(10))
            source += f"\ndef {observer.STRESS}(sandbox):\n    baseline=5\n    total=18\n    round_n=134\n    assert total <= baseline + 12\n"
            (root / "test_execd_init_e2e.py").write_text(source, encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(Path(observer.__file__).parent),
                   "PYTEST_PLUGINS": "execd_init_observer", "RADAR_DIAGNOSTICS_DIR": directory,
                   "RADAR_SOURCE_SHA": "local-mechanics-test"}
            run = subprocess.run([sys.executable, "-m", "pytest", "-q", "--junitxml=original.xml"],
                                 cwd=root, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
            data = json.loads((root / "diagnostics.json").read_text())
            self.assertEqual(data["original_stress_outcome"], "failed")
            self.assertEqual(data["original_locals"], {"baseline": 5, "total": 18, "round_n": 134})
            self.assertTrue(data["mock_observed_before_teardown"])
            self.assertEqual(len(data["original_reports"]), 11)
            self.assertIn('failures="1"', (root / "original.xml").read_text())


if __name__ == "__main__":
    unittest.main()
