#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  printf '%s\n' 'usage: structural-grayscale-stage3c-timeout-probe.sh <probe-root> [timeout|success|failure|unset]' >&2
  exit 64
fi

probe=$1
mode=${2:-timeout}
case "$probe" in
  ""|/|/tmp|/tmp/dip)
    printf '%s\n' 'unsafe Stage 3C probe root' >&2
    exit 64
    ;;
esac

cleanup_probe() {
  rm -rf "$probe"
}

terminate_probe() {
  cleanup_probe
  exit 143
}

trap cleanup_probe EXIT HUP INT
trap terminate_probe TERM
mkdir -p "$probe"
printf '%s\n' started >"$probe/marker"

case "$mode" in
  timeout)
    sleep 30
    ;;
  success)
    exit 0
    ;;
  failure)
    exit 23
    ;;
  unset)
    printf '%s\n' "$DIP_STAGE3C_INTENTIONALLY_UNSET" >/dev/null
    ;;
  *)
    printf '%s\n' 'invalid Stage 3C timeout-probe mode' >&2
    exit 64
    ;;
esac
