#!/bin/bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$ROOT_DIR/scripts/code-interpreter-env.sh"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/opt/python/versions/cpython-3.12/bin"
mkdir -p "$TMPDIR/shims"
ENV_FILE="$TMPDIR/extra.env"
: > "$ENV_FILE"

cat > "$TMPDIR/opt/python/versions/cpython-3.12/bin/python3" <<'SH'
#!/bin/sh
if [ "$1" = "--version" ]; then
  echo 'Python 3.12.9'
  exit 0
fi
if [ "$1" = "-m" ] && [ "$2" = "pip" ]; then
  shift 2
  printf 'pip via python3 -m pip %s\n' "$*"
  exit 0
fi
printf 'python3 %s\n' "$*"
SH
chmod +x "$TMPDIR/opt/python/versions/cpython-3.12/bin/python3"

export EXECD_ENVS="$ENV_FILE"
export PYTHON_SHIMS_DIR="$TMPDIR/shims"
export PATH="/usr/bin:/bin"

find() {
  if [ "$1" = "/opt/python/versions" ]; then
    shift
    command find "$TMPDIR/opt/python/versions" "$@"
  else
    command find "$@"
  fi
}

source "$SCRIPT" python 3.12 >/dev/null

command -v python | grep -F "$TMPDIR/shims/python" >/dev/null
command -v pip | grep -F "$TMPDIR/shims/pip" >/dev/null
python --version | grep -F 'Python 3.12.9' >/dev/null
pip install demo-package | grep -F 'pip via python3 -m pip install demo-package' >/dev/null

grep -F "PATH=$TMPDIR/shims:$TMPDIR/opt/python/versions/cpython-3.12/bin:" "$ENV_FILE" >/dev/null
