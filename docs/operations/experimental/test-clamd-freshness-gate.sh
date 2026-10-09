#!/bin/bash
set -euo pipefail

image="${1:-dip-clamav:arm64-stage5-custom}"
source_db="${SOURCE_DB_DIR:-/home/ubuntu/stage4/fixtures/db}"
fixture_root="${FIXTURE_ROOT:-/home/ubuntu/stage5/fixtures}"
evidence_file="${EVIDENCE_FILE:-/home/ubuntu/stage5/evidence/freshness-fixtures.log}"

rm -rf "$fixture_root"
mkdir -p "$fixture_root"
cases=(complete missing-main missing-daily invalid-main invalid-daily zero-main stale-daily future-daily unreadable-daily)
for name in "${cases[@]}"; do
  mkdir -p "$fixture_root/$name"
  cp "$source_db/main.cvd" "$fixture_root/$name/main.cvd"
  cp "$source_db/daily.cvd" "$fixture_root/$name/daily.cvd"
done

rm "$fixture_root/missing-main/main.cvd"
rm "$fixture_root/missing-daily/daily.cvd"
printf 'not-a-clamav-db' >"$fixture_root/invalid-main/main.cvd"
printf 'not-a-clamav-db' >"$fixture_root/invalid-daily/daily.cvd"
: >"$fixture_root/zero-main/main.cvd"
touch -d '5 days ago' "$fixture_root/stale-daily/daily.cvd"
touch -d '3 days' "$fixture_root/future-daily/daily.cvd"
chmod 000 "$fixture_root/unreadable-daily/daily.cvd"

: >"$evidence_file"
passes=0
failures=0
run_case() {
  local name="$1" expected="$2" output rc
  set +e
  output=$(docker run --rm --entrypoint /usr/local/bin/clamd-freshness-gate \
    -e CLAMAV_DB_DIR=/db -v "$fixture_root/$name:/db:ro" "$image" --check 2>&1)
  rc=$?
  set -e
  if { [[ "$expected" == pass && $rc -eq 0 ]]; } || { [[ "$expected" == fail && $rc -ne 0 ]]; }; then
    printf 'PASS|%s|expected=%s|rc=%s|%s\n' "$name" "$expected" "$rc" "$output" | tee -a "$evidence_file"
    passes=$((passes + 1))
  else
    printf 'FAIL|%s|expected=%s|rc=%s|%s\n' "$name" "$expected" "$rc" "$output" | tee -a "$evidence_file"
    failures=$((failures + 1))
  fi
}

run_case complete pass
for name in "${cases[@]:1}"; do run_case "$name" fail; done
printf 'TOTAL|pass=%s|fail=%s\n' "$passes" "$failures" | tee -a "$evidence_file"
test "$failures" -eq 0
