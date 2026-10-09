#!/bin/bash
set -euo pipefail

image="${1:-dip-clamav:arm64-stage5-custom}"
source_db="${SOURCE_DB_DIR:-/home/ubuntu/stage4/fixtures/db}"
fixture_root="${FIXTURE_ROOT:-/home/ubuntu/stage5/fixtures}"
evidence_file="${EVIDENCE_FILE:-/home/ubuntu/stage5/evidence/freshness-fixtures.log}"

fail_source() {
  echo "FRESHNESS_FIXTURE_SOURCE=REFUSE family=$1 reason=$2" >&2
  exit 1
}

select_source() {
  local family="$1" candidate header
  local matches=()
  for extension in cvd cld; do
    candidate="$source_db/$family.$extension"
    [[ -e "$candidate" ]] && matches+=("$candidate")
  done
  [[ "${#matches[@]}" -eq 1 ]] || \
    fail_source "$family" "expected-exactly-one-cvd-or-cld-found-${#matches[@]}"
  candidate="${matches[0]}"
  [[ -f "$candidate" && -s "$candidate" && -r "$candidate" ]] || \
    fail_source "$family" "source-not-readable-regular-nonempty"
  header=$(head -c 11 "$candidate" 2>/dev/null || true)
  [[ "$header" == "ClamAV-VDB:" ]] || fail_source "$family" "invalid-clamav-header"
  printf '%s\n' "$candidate"
}

main_source=$(select_source main)
daily_source=$(select_source daily)

[[ -n "$fixture_root" && "$fixture_root" != "/" ]] || \
  fail_source fixture-root "unsafe-path"
rm -rf -- "$fixture_root"
mkdir -p "$fixture_root" "$(dirname "$evidence_file")"
: >"$evidence_file"

cases=(complete missing-main missing-daily invalid-main invalid-daily zero-main stale-daily future-daily unreadable-daily)
# The freshness gate's contract is extension-independent: it validates the
# ClamAV-VDB header, readability, size, and daily mtime. Preserve the selected
# source bytes while exercising that same contract under each supported name.
representations=(cvd cld)
total_passes=0
total_failures=0

run_case() {
  local representation="$1" name="$2" expected="$3" output rc
  set +e
  output=$(docker run --rm --entrypoint /usr/local/bin/clamd-freshness-gate \
    -e CLAMAV_DB_DIR=/db -v "$fixture_root/$representation/$name:/db:ro" "$image" --check 2>&1)
  rc=$?
  set -e
  if { [[ "$expected" == pass && $rc -eq 0 ]]; } || { [[ "$expected" == fail && $rc -ne 0 ]]; }; then
    printf 'PASS|representation=%s|case=%s|expected=%s|rc=%s|%s\n' \
      "$representation" "$name" "$expected" "$rc" "$output" | tee -a "$evidence_file"
    representation_passes=$((representation_passes + 1))
  else
    printf 'FAIL|representation=%s|case=%s|expected=%s|rc=%s|%s\n' \
      "$representation" "$name" "$expected" "$rc" "$output" | tee -a "$evidence_file"
    representation_failures=$((representation_failures + 1))
  fi
}

for representation in "${representations[@]}"; do
  main_name="main.$representation"
  daily_name="daily.$representation"
  for name in "${cases[@]}"; do
    case_root="$fixture_root/$representation/$name"
    mkdir -p "$case_root"
    cp "$main_source" "$case_root/$main_name"
    cp "$daily_source" "$case_root/$daily_name"
  done

  rm "$fixture_root/$representation/missing-main/$main_name"
  rm "$fixture_root/$representation/missing-daily/$daily_name"
  printf 'not-a-clamav-db' >"$fixture_root/$representation/invalid-main/$main_name"
  printf 'not-a-clamav-db' >"$fixture_root/$representation/invalid-daily/$daily_name"
  : >"$fixture_root/$representation/zero-main/$main_name"
  touch -d '5 days ago' "$fixture_root/$representation/stale-daily/$daily_name"
  touch -d '3 days' "$fixture_root/$representation/future-daily/$daily_name"
  chmod 000 "$fixture_root/$representation/unreadable-daily/$daily_name"

  representation_passes=0
  representation_failures=0
  run_case "$representation" complete pass
  for name in "${cases[@]:1}"; do
    run_case "$representation" "$name" fail
  done
  printf 'TOTAL|representation=%s|pass=%s|fail=%s\n' \
    "$representation" "$representation_passes" "$representation_failures" | tee -a "$evidence_file"
  test "$representation_passes" -eq 9
  test "$representation_failures" -eq 0
  total_passes=$((total_passes + representation_passes))
  total_failures=$((total_failures + representation_failures))
done

printf 'TOTAL|representations=2|pass=%s|fail=%s\n' "$total_passes" "$total_failures" | tee -a "$evidence_file"
test "$total_passes" -eq 18
test "$total_failures" -eq 0
