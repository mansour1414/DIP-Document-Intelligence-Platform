#!/bin/sh
set -eu

# Stage 3C review-only reproduction recipe. It builds a derivative from the
# actual production worker and never changes Dockerfile.worker.
repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
artifact_root="${RUNNER_TEMP:-/tmp}/dip-gray-stage3c-output"
wheelhouse="$repository_root/.stage3c-wheelhouse"
icc_fixture_root="$repository_root/.stage3c-fixtures"
container_name="dip-gray-stage3c-poc"
result="failed"

cleanup_host() {
  exit_code=$?
  docker rm --force "$container_name" >/dev/null 2>&1 || true
  rm -rf "$wheelhouse"
  rm -rf "$icc_fixture_root"
  mkdir -p "$artifact_root"
  printf '{"scope":"isolated-stage3c-ci-gate-only","result":"%s","exit_code":%s}\n' \
    "$result" "$exit_code" >"$artifact_root/ci-diagnostic.json"
  exit "$exit_code"
}
trap cleanup_host EXIT HUP INT TERM

rm -rf "$artifact_root" "$wheelhouse"
mkdir -p "$artifact_root/licensing" "$wheelhouse"
chmod 0777 "$artifact_root" "$artifact_root/licensing"

cd "$repository_root"
python3 -c 'import sys; assert sys.version_info[:2] == (3, 11), sys.version'
python3 -m pip download \
  --disable-pip-version-check \
  --only-binary=:all: \
  --dest "$wheelhouse" \
  --requirement scripts/experiments/structural-grayscale-stage3b.requirements.txt
python3 scripts/experiments/structural-grayscale-stage3b-wheel-audit.py \
  --wheel-dir "$wheelhouse" \
  --output "$artifact_root/licensing/wheel-audit.json"
cp "$artifact_root/licensing/wheel-manifest.json" "$wheelhouse/wheel-manifest.json"

test -s "$icc_fixture_root/CGATS001Compat-v2-micro.icc"
test -s "$icc_fixture_root/CGATS001Compat-v2-micro.LICENSE.txt"
test -s "$icc_fixture_root/CGATS001Compat-v2-micro.provenance.json"
cp "$icc_fixture_root/CGATS001Compat-v2-micro.provenance.json" \
  "$artifact_root/licensing/reviewed-cmyk-icc-fixture.json"
cp "$icc_fixture_root/CGATS001Compat-v2-micro.LICENSE.txt" \
  "$artifact_root/licensing/reviewed-cmyk-icc-fixture.LICENSE.txt"

test -s output/pdf/structural-grayscale-stage3a/arabic-logical-source.pdf
test -s output/pdf/structural-grayscale-stage3a/arabic-logical-expected.pdf
test "$(find output/pdf/structural-grayscale-stage3c-widgets -name '*.pdf' | wc -l)" -eq 8

docker build --file Dockerfile.worker --tag dip-document-worker:stage3b-base .
docker build --file scripts/experiments/Dockerfile.structural-grayscale-stage3b --tag dip-gray-stage3c:poc .
docker image inspect dip-document-worker:stage3b-base --format '{{json .RepoDigests}}' \
  >"$artifact_root/production-base-image-digests.json"
docker image inspect dip-document-worker:stage3b-base --format '{{json .Id}}' \
  >"$artifact_root/production-base-image-id.json"
docker image inspect dip-gray-stage3c:poc --format '{{json .Id}}' \
  >"$artifact_root/stage3c-image-id.json"

timeout --signal=TERM --kill-after=10s 420s docker run --rm \
  --name "$container_name" \
  --user 10001:10001 \
  --network none \
  --read-only \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --cpus 1 \
  --memory 768m \
  --memory-swap 768m \
  --pids-limit 128 \
  --ulimit cpu=300:300 \
  --ulimit nofile=1024:1024 \
  --ulimit nproc=128:128 \
  --stop-timeout 5 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
  --tmpfs /tmp/dip:rw,nosuid,nodev,noexec,size=256m,uid=10001,gid=10001,mode=0700 \
  --mount "type=bind,source=$artifact_root,target=/output" \
  --entrypoint /bin/sh \
  dip-gray-stage3c:poc -c '
    set -eu
    corpus=/tmp/dip/stage3c-corpus
    failure_root=/tmp/dip/stage3c-failure
    timeout_root=/tmp/dip/stage3c-timeout
    cleanup_runtime() {
      rm -rf "$corpus" "$failure_root" "$timeout_root"
    }
    trap cleanup_runtime EXIT HUP INT TERM

    /opt/dip-gray-stage3b/bin/python \
      scripts/experiments/structural-grayscale-stage3c-sandbox-probe.py \
      /output/sandbox-evidence.json

    export DIP_GRAYSCALE_CORPUS_ROOT="$corpus"
    export DIP_STAGE3A_FIXTURE_DIR=/stage3b/fixtures
    export DIP_STAGE3C_WIDGET_FIXTURE_DIR=/stage3b/widget-fixtures
    test -r "$DIP_STAGE3A_CMYK_ICC_PROFILE"
    test -r "$DIP_STAGE3A_PDFJS_MODULE"
    test "$(sha256sum "$DIP_STAGE3A_CMYK_ICC_PROFILE" | cut -d " " -f 1)" = \
      "73e1ba37d2bad5bab2a964f40a9eed96209666efc067c3322626214bbef234a0"
    node scripts/experiments/structural-grayscale-stage3a-browser.mjs probe-pdfjs \
      >/output/pdfjs-runtime.json
    timeout --signal=TERM --kill-after=5s 300s \
      /opt/dip-gray-stage3b/bin/python scripts/experiments/structural-grayscale-stage3c.py \
      --self-test --corpus-root "$corpus" --artifact-dir /output/metrics

    mkdir -p "$failure_root"
    head -c 128 "$corpus/structural-grayscale-stage3b/natural-jpeg-source.pdf" \
      >"$failure_root/malformed.pdf"
    set +e
    /opt/dip-gray-stage3b/bin/python scripts/experiments/structural-grayscale-stage3b.py \
      --transform-one "$failure_root/malformed.pdf" "$failure_root/unexpected-output.pdf" \
      >/dev/null 2>"$failure_root/diagnostic.txt"
    failure_code=$?
    set -e
    test "$failure_code" -ne 0
    test ! -e "$failure_root/unexpected-output.pdf"
    printf "%s\n" "{\"safe_rejection\":true,\"partial_output\":false,\"exit_code\":$failure_code}" \
      >/output/failure-cleanup.json
    rm -rf "$failure_root"

    set +e
    timeout --signal=TERM --kill-after=1s 2s /bin/sh \
      scripts/experiments/structural-grayscale-stage3c-timeout-probe.sh "$timeout_root"
    timeout_code=$?
    set -e
    test "$timeout_code" -eq 124 -o "$timeout_code" -eq 143
    test ! -e "$timeout_root"
    printf "%s\n" "{\"timeout_enforced\":true,\"cleanup_verified\":true,\"exit_code\":$timeout_code}" \
      >/output/timeout-cleanup.json

    cp /wheels/wheel-manifest.json /output/licensing/installed-wheel-manifest.json
    test ! -e /usr/bin/gs
    test ! -e /usr/local/bin/gs
    test -z "$(find /output -type f -name "*.pdf" -print -quit)"
    artifact_audit=$(/opt/dip-gray-stage3b/bin/python \
      scripts/experiments/verify-structural-grayscale-stage3c-artifacts.py /output)
    printf "%s\n" "$artifact_audit" >/output/artifact-audit.json
    printf "%s\n" "{\"all_required_gates_completed\":true}" \
      >/output/stage3c-complete.json
    cleanup_runtime
    test -z "$(find /tmp/dip -mindepth 1 -maxdepth 1 -print -quit)"
    trap - EXIT HUP INT TERM
  '

test -s "$artifact_root/stage3c-complete.json"
python3 scripts/experiments/verify-structural-grayscale-stage3c-artifacts.py "$artifact_root" \
  >/dev/null
result="passed"
