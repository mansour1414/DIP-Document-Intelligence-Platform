#!/bin/bash
# Experimental host-side admission guard for Stage 4 evidence runs.
# This does not modify DIP production Compose or clamd.ts. It prevents the
# evidence harness from treating a running-but-unhealthy scanner as eligible.
set -euo pipefail

container="${CLAMAV_CONTAINER_NAME:-clamav-stage4}"
health=$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}')
if [[ "$health" != "healthy" ]]; then
  echo "STAGE4_GATE=REFUSE reason=scanner-not-healthy container=$container health=$health" >&2
  exit 1
fi

echo "STAGE4_GATE=PASS container=$container health=$health"
exec "$@"
