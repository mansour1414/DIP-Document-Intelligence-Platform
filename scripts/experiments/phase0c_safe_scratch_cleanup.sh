#!/usr/bin/env bash
# Remove only the fixed Phase 0C scratch leaf under GitHub's canonical runner temp.
set -euo pipefail

runner_temp="${1:-${RUNNER_TEMP:-}}"
expected_work_dir="${2:-${WORK_DIR:-}}"

if [[ -z "$runner_temp" || "$runner_temp" != /* || "$runner_temp" == */ ]]; then
  echo "Refusing scratch cleanup: RUNNER_TEMP is unset or not a normalized absolute path." >&2
  exit 1
fi
case "/$runner_temp/" in
  *"/../"*|*"/./"*)
    echo "Refusing scratch cleanup: RUNNER_TEMP contains a dot path component." >&2
    exit 1
    ;;
esac
if [[ "${runner_temp##*/}" != "_temp" || "${runner_temp%/*}" != */work ]]; then
  echo "Refusing scratch cleanup: RUNNER_TEMP is not the expected runner work/_temp directory." >&2
  exit 1
fi
if [[ ! -d "$runner_temp" || -L "$runner_temp" ]]; then
  echo "Refusing scratch cleanup: RUNNER_TEMP is missing or a symbolic link." >&2
  exit 1
fi
runner_temp_real="$(realpath -e -- "$runner_temp")"
if [[ "$runner_temp_real" != "$runner_temp" ]]; then
  echo "Refusing scratch cleanup: RUNNER_TEMP is not a canonical, non-symlink path." >&2
  exit 1
fi
scratch_dir="${runner_temp%/}/clamav-phase0c-work"
if [[ "$scratch_dir" != "$runner_temp/clamav-phase0c-work" || "$scratch_dir" == /clamav-phase0c-work ]]; then
  echo "Refusing scratch cleanup: derived scratch path is outside the validated runner temp directory." >&2
  exit 1
fi
if [[ -n "$expected_work_dir" && "$expected_work_dir" != "$scratch_dir" ]]; then
  echo "Refusing scratch cleanup: initialized WORK_DIR does not match the validated scratch path." >&2
  exit 1
fi
if [[ -L "$scratch_dir" ]]; then
  echo "Refusing scratch cleanup: scratch path is a symbolic link." >&2
  exit 1
fi
if [[ -e "$scratch_dir" ]]; then
  sudo rm -rf -- "$scratch_dir"
fi
if [[ -e "$scratch_dir" || -L "$scratch_dir" ]]; then
  echo "Scratch cleanup failed: fixed scratch leaf still exists." >&2
  exit 1
fi
printf '%s\n' 'PHASE0C_SCRATCH_CLEANUP_PASS'
