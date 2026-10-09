#!/bin/bash
# ============================================================================
# ClamAV signature freshness gate — Stage 4 candidate.
#
# WHY THIS EXISTS
#   docs/operator-runbook.md:20 requires verifying signature freshness before
#   admitting traffic. A bare `clamd` entrypoint cannot do this: clamd loads
#   whatever database it finds and then serves zPING/PONG forever. A stale or
#   empty database therefore produces a "healthy" scanner that silently misses
#   every signature published since it went stale. That is a security control
#   that appears to work and does not.
#
#   This gate makes the failure explicit and fail-closed: it refuses to start
#   clamd at all when signatures are missing, unreadable, or too old, so DIP
#   receives SCANNER_UNAVAILABLE and job intake stays closed.
#
# MAX-AGE RATIONALE (read before changing CLAMAV_MAX_DB_AGE_HOURS)
#   clamav-daily.cvd is published Monday, Tuesday, Wednesday, Friday and Saturday.
#   It is NOT published on Thursday or Sunday. The largest natural gap between
#   published daily signatures is therefore 2 days (Wed->Fri, Sat->Mon).
#   The default below is 72h, which leaves one full day of margin for exactly one
#   missed or failed freshclam update before the gate trips. Setting this to 24h
#   or 48h would fail-closed every Thursday and Sunday — an outage created by the
#   control itself. main.cvd is updated far less often and is deliberately not
#   used as the freshness signal.
#
# USAGE
#   clamd-freshness-gate --check    verify only; exit 0 = usable, exit 1 = refuse
#   clamd-freshness-gate --exec     verify, then exec "$@" (entrypoint mode)
# ============================================================================
set -uo pipefail

DBDIR="${CLAMAV_DB_DIR:-/var/lib/clamav}"
MAX_AGE_HOURS="${CLAMAV_MAX_DB_AGE_HOURS:-72}"

fail() {
  echo "FRESHNESS_GATE=REFUSE reason=$1" >&2
  [[ -n "${2:-}" ]] && echo "  detail: $2" >&2
  exit 1
}

[[ -d "$DBDIR" ]] || fail "db-dir-missing" "$DBDIR does not exist or is not a directory"

# The database files clamd must be able to load a meaningful rule set from.
# main.* is the base database; daily.* carries the frequently-updated rules and
# is the freshness signal because it moves most often. Both families are
# mandatory: accepting a fresh daily.* without main.* would pass freshness while
# silently omitting the base signatures.
REQUIRED=()
declare -A BUILD_EPOCH=()
declare -A BUILD_TIME=()
for base in daily main; do
  found=""
  for ext in cvd cld; do
    [[ -e "$DBDIR/$base.$ext" ]] && { found="$base.$ext"; break; }
  done
  [[ -n "$found" ]] || fail "signature-database-family-missing" \
    "required $base.cvd/.cld is missing from $DBDIR"
  REQUIRED+=("$found")
done

# Every discovered file must be non-empty and actually readable by this user.
# A zero-length or root-only main.cvd is a classic failed-freshclam artifact.
for f in "${REQUIRED[@]}"; do
  p="$DBDIR/$f"
  [[ -s "$p" ]] || fail "signature-database-empty" "$p is zero-length (a failed freshclam run leaves this behind)"
  [[ -r "$p" ]] || fail "signature-database-unreadable" "$p is not readable by uid $(id -u); check volume ownership"
  header=$(head -c 512 "$p" 2>/dev/null || true)
  IFS=: read -r magic build_time _ <<<"$header"
  [[ "$magic" == "ClamAV-VDB" && -n "$build_time" ]] || \
    fail "signature-database-invalid" "$p does not contain a valid ClamAV CVD/CLD header"
  build_epoch=$(date -u -d "$build_time" +%s 2>/dev/null) || \
    fail "signature-database-invalid-build-time" \
      "$p has an unparseable database build time: $build_time"
  BUILD_EPOCH["$f"]="$build_epoch"
  BUILD_TIME["$f"]="$build_time"
done

# Freshness is determined by daily.*, not by the newest arbitrary file. Check
# both the signed database header's build time and the filesystem mtime. A copy
# or restore can refresh mtime without refreshing signatures; accepting that
# would turn an old database into an apparently fresh one.
daily_name="${REQUIRED[0]}"
daily_mtime=$(stat -c %Y "$DBDIR/$daily_name" 2>/dev/null) || \
  fail "signature-database-unstat-able" "cannot stat $DBDIR/$daily_name"
daily_build_epoch="${BUILD_EPOCH[$daily_name]}"
daily_build_time="${BUILD_TIME[$daily_name]}"
now_epoch=$(date +%s)
mtime_age_hours=$(( ( now_epoch - daily_mtime ) / 3600 ))
signature_age_hours=$(( ( now_epoch - daily_build_epoch ) / 3600 ))

# A future timestamp means a skewed clock or a bad restore; treat it as
# untrusted rather than as infinitely fresh.
if (( daily_build_epoch > now_epoch + 300 )); then
  fail "signature-database-build-time-in-future" \
    "$daily_name build time $daily_build_time is ahead of the system clock"
fi
if (( daily_mtime > now_epoch + 300 )); then
  fail "signature-database-timestamp-in-future" \
    "$daily_name has mtime $(date -d "@$daily_mtime" -u +%Y-%m-%dT%H:%M:%SZ), ahead of the system clock"
fi

if (( signature_age_hours > MAX_AGE_HOURS )); then
  fail "signature-database-signatures-stale" \
    "daily signature database ($daily_name) was built ${signature_age_hours}h ago, limit is ${MAX_AGE_HOURS}h"
fi
if (( mtime_age_hours > MAX_AGE_HOURS )); then
  fail "signature-database-stale" \
    "daily signature file ($daily_name) has an mtime ${mtime_age_hours}h old, limit is ${MAX_AGE_HOURS}h"
fi

echo "FRESHNESS_GATE=PASS freshness_file=$daily_name signature_age_hours=$signature_age_hours mtime_age_hours=$mtime_age_hours limit_hours=$MAX_AGE_HOURS files=${REQUIRED[*]}"

if [[ "${1:-}" == "--exec" ]]; then
  shift
  echo "FRESHNESS_GATE=EXEC $*"
  exec "$@"
fi
[[ "${1:-}" == "--check" ]] && exit 0
exit 0
