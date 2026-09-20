#!/usr/bin/env bash
# Copyright 2026 The OpenSandbox Authors
# Licensed under the Apache License, Version 2.0.
set -euo pipefail

: "${RADAR_DIAGNOSTICS_DIR:?}"
: "${RADAR_HARNESS_DIR:?}"
: "${RADAR_SOURCE_SHA:?}"
: "${OPENSANDBOX_SANDBOX_DEFAULT_IMAGE:?}"
source_root=$(pwd)
evidence=$RADAR_DIAGNOSTICS_DIR
mkdir -p "$evidence"
server_pid=
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Match the native entry script's builds, SDK generation and bridge server.
docker build -f components/execd/Dockerfile -t opensandbox/execd:local .
docker pull "$OPENSANDBOX_SANDBOX_DEFAULT_IMAGE"
mkdir -p /tmp/opensandbox-e2e/logs
export OPENSANDBOX_INSECURE_SERVER=YES
for project in server tests/python sdks/sandbox/python sdks/code-interpreter/python; do
  cp "$project/uv.lock" "$evidence/${project//\//-}-before.lock"
done
(cd server && uv sync --frozen)
(cd sdks/sandbox/python && uv sync --frozen && uv run --no-sync python scripts/generate_api.py)
tar --exclude='__pycache__' --exclude='*.pyc' -czf "$evidence/generated-sdk-api.tar.gz"   -C sdks/sandbox/python/src/opensandbox api
find sdks/sandbox/python/src/opensandbox/api -type f ! -name '*.pyc' -print0   | sort -z | xargs -0 sha256sum > "$evidence/generated-sdk-api.sha256"
(cd tests/python && uv sync --frozen --all-extras)
for project in server tests/python sdks/sandbox/python sdks/code-interpreter/python; do
  cp "$project/uv.lock" "$evidence/${project//\//-}-after.lock"
  cmp "$evidence/${project//\//-}-before.lock" "$evidence/${project//\//-}-after.lock"
done
for project in server tests/python; do
  uv pip freeze --python "$project/.venv/bin/python" > "$evidence/${project//\//-}-dependencies.txt"
  "$project/.venv/bin/python" --version >> "$evidence/runtime-versions.txt"
done
(cd server && exec .venv/bin/python -m opensandbox_server.main) > "$evidence/server.log" 2>&1 &
server_pid=$!
sleep 10
kill -0 "$server_pid"

status=0
set +e
tests/python/.venv/bin/python -m unittest discover -s "$RADAR_HARNESS_DIR/scripts/diagnostics" -p test_execd_init_observer.py -v   > "$evidence/harness-unit.log" 2>&1
harness_status=$?
set -e
printf '%s\n' "$harness_status" > "$evidence/harness-unit-exit-code.txt"
if [ "$harness_status" -ne 0 ]; then status=1; fi
run_suite() {
  local name=$1 expected=$2 selected=$3 plugin=$4
  local destination="$evidence/$name"
  mkdir -p "$destination"
  set +e
  (
    cd tests/python
    export RADAR_DIAGNOSTICS_DIR="$destination" RADAR_EXPECTED_TESTS="$expected"
    export PYTHONPATH="$source_root/tests/python:$RADAR_HARNESS_DIR/scripts/diagnostics${PYTHONPATH:+:$PYTHONPATH}"
    export PYTEST_PLUGINS="$plugin"
    .venv/bin/python -m pytest -c pyproject.toml "$selected" -v --junitxml="$destination/junit.xml"
  ) 2>&1 | tee "$destination/pytest.log"
  local codes=("${PIPESTATUS[@]}")
  set -e
  printf '%s\n' "${codes[0]}" > "$destination/exit-code.txt"
  if [ "${codes[0]}" -ne 0 ] || [ "${codes[1]}" -ne 0 ]; then status=1; fi
  if ! tests/python/.venv/bin/python - "$destination/junit.xml" "$expected" <<'PYXML'
import sys
import xml.etree.ElementTree as ET
cases = ET.parse(sys.argv[1]).findall(".//testcase")
expected = int(sys.argv[2])
assert len(cases) == expected, (len(cases), expected)
assert not any(case.find("skipped") is not None for case in cases), "native test skipped"
print(f"Recorded {len(cases)} native test cases without skips")
PYXML
  then status=1; fi
  if [ -n "$plugin" ] && [ ! -s "$destination/diagnostics.json" ]; then status=1; fi
}

run_suite init-full 11 tests/test_execd_init_e2e.py execd_init_observer
for repeat in 2 3; do
  run_suite "init-stress-$repeat" 1 \
    tests/test_execd_init_e2e.py::TestExecdInitE2E::test_sustained_fork_heavy_mix_keeps_process_table_bounded \
    execd_init_observer
done
# This existing transport matrix explicitly uses the 1s environment override.
run_suite command-stream 12 tests/test_command_stream_e2e.py ""
if [ -f tests/python/tests/test_execd_init_accounting.py ]; then
  run_suite accounting-unit 21 tests/test_execd_init_accounting.py ""
  run_suite accounting-native-negative 3 \
    "$RADAR_HARNESS_DIR/scripts/diagnostics/test_execd_accounting_native.py" ""
fi
printf '%s\n' "$status" > "$evidence/native-exit-code.txt"
git status --short > "$evidence/source-status.txt"
git diff -- tests/python/tests components/execd scripts/python-execd-init-e2e.sh \
  > "$evidence/tested-source.diff"
git diff -- sdks/sandbox/python/src/opensandbox/api > "$evidence/generated-sdk.diff"
docker image ls --digests > "$evidence/docker-images.txt"
exit "$status"
