#!/usr/bin/env bash
set -u

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${PROJECT_ROOT}/.venv"
PYTHON_BIN=""

for candidate in python3.13 python3.12 python3; do
  if command -v "${candidate}" >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v "${candidate}")"
    break
  fi
done

if [[ -z "${PYTHON_BIN}" ]]; then
  echo "Python 3.12 or newer is required." >&2
  exit 127
fi

if ! "${PYTHON_BIN}" -c 'import sys; raise SystemExit(sys.version_info < (3, 12))'; then
  echo "Python 3.12 or newer is required." >&2
  exit 2
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  "${PYTHON_BIN}" -m venv "${VENV_DIR}" || exit $?
fi

VENV_PYTHON="${VENV_DIR}/bin/python"
STAMP="${VENV_DIR}/.origin-audit-installed"
if [[ ! -f "${STAMP}" || "${PROJECT_ROOT}/pyproject.toml" -nt "${STAMP}" ]]; then
  "${VENV_PYTHON}" -m pip install --disable-pip-version-check -e "${PROJECT_ROOT}" || exit $?
  touch "${STAMP}" || exit $?
fi

"${VENV_PYTHON}" -m origin_audit "$@"
status=$?
exit "${status}"
