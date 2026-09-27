#!/bin/sh
set -eu

# Review-only reproduction recipe. It does not alter Dockerfile.worker.
docker build --file Dockerfile.worker --tag dip-document-worker:stage3b-base .
docker build --file scripts/experiments/Dockerfile.structural-grayscale-stage3b --tag dip-gray-stage3b:poc .

output_dir="${RUNNER_TEMP:-/tmp}/dip-gray-stage3b-output"
mkdir -p "$output_dir"
chmod 0777 "$output_dir"

docker run --rm \
  --name dip-gray-stage3b-poc \
  --user 10001:10001 \
  --network none \
  --read-only \
  --cpus 1 \
  --memory 768m \
  --memory-swap 768m \
  --pids-limit 128 \
  --stop-timeout 5 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
  --tmpfs /tmp/dip:rw,nosuid,nodev,noexec,size=256m,uid=10001,gid=10001,mode=0700 \
  --mount "type=bind,source=$output_dir,target=/output" \
  --entrypoint /bin/sh \
  dip-gray-stage3b:poc -c '
    set -eu
    test "$(id -u):$(id -g)" = "10001:10001"
    test ! -e /usr/bin/gs && test ! -e /usr/local/bin/gs
    awk '\''$2 == "/" && $4 ~ /(^|,)ro(,|$)/ { root=1 }
             $2 == "/tmp" && $4 ~ /size=65536k/ { tmp=1 }
             $2 == "/tmp/dip" && $4 ~ /size=262144k/ { dip=1 }
             END { exit !(root && tmp && dip) }'\'' /proc/mounts
    test ! -e /proc/net/route || ! awk '\''$2 == "00000000" { found=1 } END { exit !found }'\'' /proc/net/route
    test "$(cat /sys/fs/cgroup/memory.max)" = "805306368"
    test "$(cat /sys/fs/cgroup/pids.max)" = "128"
    test "$(awk '\''{print $1}'\'' /sys/fs/cgroup/cpu.max)" != "max"
    /opt/dip-gray-stage3b/bin/python - <<'\''PY'\''
import json, os, pathlib, resource, subprocess
assert os.getuid() == 10001 and os.getgid() == 10001
inventory = {}
for command in (
    ["/opt/dip-gray-stage3b/bin/python", "-m", "pip", "freeze", "--all"],
    ["/bin/sh", "-c", "ldd /opt/dip-gray-stage3b/lib/python3.11/site-packages/pikepdf/_core*.so"],
    ["/bin/sh", "-c", "ldd /opt/dip-gray-stage3b/lib/python3.11/site-packages/PIL/_imaging*.so"],
):
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    inventory[" ".join(command)] = completed.stdout
inventory["rlimits"] = {name: resource.getrlimit(value) for name, value in {
    "cpu": resource.RLIMIT_CPU,
    "address_space": resource.RLIMIT_AS,
    "processes": resource.RLIMIT_NPROC,
    "files": resource.RLIMIT_NOFILE,
}.items()}
inventory["cgroup"] = {
    name: pathlib.Path(path).read_text().strip()
    for name, path in {
        "cpu.max": "/sys/fs/cgroup/cpu.max",
        "memory.max": "/sys/fs/cgroup/memory.max",
        "pids.max": "/sys/fs/cgroup/pids.max",
    }.items()
}
pathlib.Path("/output/native-inventory.json").write_text(json.dumps(inventory, indent=2))
PY
    timeout --signal=TERM --kill-after=5s 180s \
      /opt/dip-gray-stage3b/bin/python scripts/experiments/structural-grayscale-stage3b.py \
      --self-test --output-dir /output
  '
