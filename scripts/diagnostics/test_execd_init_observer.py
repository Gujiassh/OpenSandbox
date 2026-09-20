# Copyright 2026 The OpenSandbox Authors
# Licensed under the Apache License, Version 2.0.

import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "observer", HERE / "execd_init_observer.py"
)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


def row(pid=1, start=10, state="S", argv=None, ppid=0, comm="execd"):
    return {
        "pid": pid,
        "start_ticks": start,
        "state": state,
        "ppid": ppid,
        "comm": comm,
        "argv": argv or [comm],
        "age_seconds": 2.0,
    }


def snapshot(*rows, unavailable=None):
    return {"processes": list(rows), "unavailable": unavailable or []}


def state():
    return {"counts": [], "errors": [], "original_reports": []}


class ObserverTests(unittest.TestCase):
    def test_wrapper_preserves_integer_and_calls_original_once(self):
        calls = []
        data = state()

        def original(sandbox):
            calls.append(sandbox)
            return 18

        with patch.object(
            observer,
            "census",
            return_value={**snapshot(row()), "host_started": observer.time.monotonic()},
        ):
            self.assertEqual(observer.wrapped_count(original, data)("sandbox"), 18)
        self.assertEqual(calls, ["sandbox"])
        self.assertEqual(data["errors"], [])
        self.assertEqual(data["counts"][0]["value"], 18)
        self.assertLessEqual(
            data["counts"][0]["request_started"], data["counts"][0]["returned"]
        )

    def test_census_runs_only_after_original_count(self):
        order = []

        def original(_):
            order.append("original")
            return 5

        def census(_):
            order.append("census")
            return {"host_started": observer.time.monotonic()}

        with patch.object(observer, "census", side_effect=census):
            self.assertEqual(observer.wrapped_count(original, state())(None), 5)
        self.assertEqual(order, ["original", "census"])

    def test_census_failure_preserves_original_integer(self):
        data = state()
        with patch.object(observer, "census", side_effect=PermissionError("denied")):
            self.assertEqual(observer.wrapped_count(lambda _: 18, data)(None), 18)
        self.assertIn("PermissionError", data["errors"][0])

    def test_original_exception_not_swallowed_or_retried(self):
        error = ValueError("original count")

        def original(_):
            raise error

        with (
            patch.object(observer, "census") as census,
            self.assertRaises(ValueError) as result,
        ):
            observer.wrapped_count(original, state())(None)
        self.assertIs(result.exception, error)
        census.assert_not_called()

    def test_helper_restored_after_failed_call(self):
        def original(_):
            return 5

        module = types.SimpleNamespace(_process_count=original)
        item = types.SimpleNamespace(
            name=observer.STRESS, module=module, funcargs={"sandbox": object()}
        )
        with (
            patch.object(observer, "prepare"),
            patch.object(observer, "STATE", state()),
        ):
            hook = observer.pytest_runtest_call(item)
            next(hook)
            self.assertIsNot(module._process_count, original)
            with self.assertRaises(RuntimeError):
                hook.throw(RuntimeError("native failure"))
        self.assertIs(module._process_count, original)

    def test_all_post_expiry_identities_are_accounted(self):
        init, entry = row(), row(2, 11, comm="tail", ppid=1)
        sleeper = row(10, 20, argv=["sleep", "10"], ppid=1, comm="sleep")
        result = observer.evaluate_drain(
            snapshot(init, entry), snapshot(init, entry, sleeper), snapshot(init, entry)
        )
        self.assertEqual(result["final_live_ten_second_sleepers"], [sleeper])
        self.assertFalse(result["surviving_original_sleepers"])
        self.assertFalse(result["post_expiry_new_identities"])
        self.assertTrue(result["boundary_census_complete"])

    def test_surviving_sleeper_and_zombie_are_retained(self):
        sleeper = row(10, 20, argv=["sleep", "10"], ppid=1)
        zombie = row(11, 21, state="Z", ppid=1)
        result = observer.evaluate_drain(
            snapshot(row()), snapshot(row(), sleeper), snapshot(row(), sleeper, zombie)
        )
        self.assertEqual(result["surviving_original_sleepers"], [sleeper])
        self.assertEqual(result["post_expiry_zombies"], [zombie])
        self.assertEqual(result["post_expiry_new_identities"], [sleeper, zombie])

    def test_reused_pid_is_a_new_identity_not_a_surviving_sleeper(self):
        sleeper = row(10, 20, argv=["sleep", "10"], ppid=1)
        replacement = row(10, 99, comm="unknown")
        result = observer.evaluate_drain(
            snapshot(row()), snapshot(row(), sleeper), snapshot(row(), replacement)
        )
        self.assertFalse(result["surviving_original_sleepers"])
        self.assertEqual(result["post_expiry_new_identities"], [replacement])

    def test_unreadable_and_missing_init_reject_evidence(self):
        with self.assertRaises(AssertionError):
            observer.validate_snapshot(
                snapshot(row(), unavailable=[{"pid": 2, "error": "PermissionError"}])
            )
        with self.assertRaises(AssertionError):
            observer.validate_snapshot(snapshot(row(2)))

    def test_disappearing_process_is_not_silently_complete(self):
        partial = snapshot(
            row(), unavailable=[{"pid": 2, "error": "FileNotFoundError"}]
        )
        result = observer.evaluate_drain(partial, snapshot(row()), snapshot(row()))
        self.assertFalse(result["boundary_census_complete"])
        self.assertIn("non-atomic", result["count_membership"])

    def test_pid_identity_change_during_read_rejects_row(self):
        values = iter(
            ["2 (sleep) S 1 " + "0 " * 17 + "20", "2 (sleep) S 1 " + "0 " * 17 + "21"]
        )
        with (
            patch.object(Path, "read_text", side_effect=lambda: next(values)),
            patch.object(Path, "read_bytes", return_value=b"sleep\x0010\x00"),
            self.assertRaises(RuntimeError),
        ):
            observer.process_row(Path("2"), 100, 100)

    def test_original_failure_exit_remains_failed(self):
        data = state()
        data.update(
            original_stress_outcome="failed", original_reports=[{"outcome": "failed"}]
        )
        self.assertEqual(observer.finish_state(data, 1, 1), 1)
        self.assertEqual(data["original_pytest_exit_code"], 1)
        self.assertTrue(data["diagnostic_passed"])

    def test_diagnostic_failure_cannot_hide_behind_native_pass(self):
        data = state()
        data.update(
            original_stress_outcome="passed", original_reports=[{"outcome": "passed"}]
        )
        data["errors"].append("unreadable")
        self.assertEqual(observer.finish_state(data, 0, 1), 1)
        self.assertEqual(data["original_pytest_exit_code"], 0)

    def test_missing_skipped_or_wrong_test_count_cannot_pass(self):
        for reports in ([], [{"outcome": "skipped"}]):
            data = state()
            data["original_reports"] = reports
            self.assertEqual(observer.finish_state(data, 0, 1), 1)

    def test_actual_pytest_keeps_original_failure_and_writes_distinct_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.joinpath("conftest.py").write_text(
                "import execd_init_observer as o\n"
                "def pytest_configure():\n"
                " o.prepare=lambda *args: None\n"
                " o.census=lambda *args: {'processes':[{'pid':1,'start_ticks':1,'comm':'execd','state':'S','argv':['execd']}], 'unavailable':[], 'host_started':o.time.monotonic()}\n"
                " o.time.sleep=lambda n: None\n",
                encoding="utf-8",
            )
            root.joinpath("test_native.py").write_text(
                "import pytest\n"
                "@pytest.fixture\ndef sandbox(): return object()\n"
                "values=iter([5,18])\ndef _process_count(sandbox): return next(values)\n"
                f"def {observer.STRESS}(sandbox):\n"
                " baseline=_process_count(sandbox)\n total=_process_count(sandbox)\n"
                " assert total <= baseline+12, 'original bounded table failure'\n",
                encoding="utf-8",
            )
            import os

            env = {
                **os.environ,
                "PYTHONPATH": str(HERE),
                "PYTEST_PLUGINS": "execd_init_observer",
                "RADAR_SOURCE_SHA": "test-source",
                "RADAR_EXPECTED_TESTS": "1",
                "RADAR_DIAGNOSTICS_DIR": str(root / "evidence"),
            }
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", str(root)],
                cwd=root,
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("original bounded table failure", result.stdout)
            data = json.loads((root / "evidence/diagnostics.json").read_text())
            self.assertEqual([c["value"] for c in data["counts"]], [5, 18])
            self.assertEqual(data["original_pytest_exit_code"], 1)
            self.assertEqual(data["original_stress_outcome"], "failed")
            self.assertIn("twelve no-workload", data["errors"][0])


if __name__ == "__main__":
    unittest.main()
