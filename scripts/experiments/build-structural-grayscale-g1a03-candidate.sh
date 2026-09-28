#!/usr/bin/env sh
set -eu

# Review-only builder. It never pushes and requires local Docker, Syft, and
# Grype. Run from the repository root after provisioning the exact wheelhouse.

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
wheelhouse=${G1A03_WHEELHOUSE:-"$root/.g1a03-wheelhouse"}
evidence=${G1A03_EVIDENCE_DIR:-"$root/output/g1a03-candidate"}
base_tag=dip-document-worker:g1a03-base
candidate_tag=dip-structural-grayscale:g1a03-candidate
: "${G1A03_NODE_IMAGE:?set G1A03_NODE_IMAGE to an approved node image repository@sha256 digest}"
case "$G1A03_NODE_IMAGE" in
  *@sha256:[0-9a-fA-F][0-9a-fA-F]*) ;;
  *) printf '%s\n' 'G1A03_NODE_IMAGE must be an immutable repository@sha256 reference' >&2; exit 2 ;;
esac

for command in docker syft grype python3 sha256sum; do
  command -v "$command" >/dev/null 2>&1 || {
    printf '%s\n' "required command missing: $command" >&2
    exit 2
  }
done
test -d "$wheelhouse" || { printf '%s\n' "wheelhouse missing: $wheelhouse" >&2; exit 2; }
test "$(find "$wheelhouse" -maxdepth 1 -name '*.whl' -type f | wc -l)" -eq 9 || {
  printf '%s\n' "expected exactly nine reviewed wheels" >&2
  exit 2
}

rm -rf "$evidence"
mkdir -p "$evidence/inventory"

python3 "$root/scripts/experiments/collect-structural-grayscale-g1a02-evidence.py" \
  --wheel-dir "$wheelhouse" --package-lock "$root/package-lock.json" \
  --output-dir "$evidence/prebuild"

docker build --build-arg "NODE_IMAGE=$G1A03_NODE_IMAGE" \
  --file "$root/Dockerfile.worker" --tag "$base_tag" "$root"
docker build --file "$root/scripts/experiments/Dockerfile.structural-grayscale-g1a03-candidate" \
  --tag "$candidate_tag" "$root"

docker image inspect "$candidate_tag" --format '{{json .Id}}' >"$evidence/local-image-id.json"
docker image inspect "$candidate_tag" --format '{{json .RepoDigests}}' >"$evidence/registry-repo-digests.json"
printf '%s\n' "$G1A03_NODE_IMAGE" >"$evidence/base-image-source.txt"
docker image inspect "$G1A03_NODE_IMAGE" --format '{{json .RepoDigests}}' >"$evidence/base-image-repo-digests.json"
grep -Fq "${G1A03_NODE_IMAGE#*@}" "$evidence/base-image-repo-digests.json" || {
  printf '%s\n' 'base image digest was not confirmed by Docker after pull/build' >&2
  exit 3
}
docker image save "$candidate_tag" | sha256sum >"$evidence/local-docker-archive.sha256"

docker run --rm --entrypoint sh "$candidate_tag" -c \
  "dpkg-query -W -f='\${Package}\t\${Version}\t\${Architecture}\n' | sort" \
  >"$evidence/inventory/debian-packages.tsv"
docker run --rm --entrypoint /opt/dip-gray-candidate/bin/python "$candidate_tag" \
  -m pip list --format=json >"$evidence/inventory/python-packages.json"
docker run --rm --entrypoint sh "$candidate_tag" -c \
  "find /opt/dip-gray-candidate -type f \( -name '*.so' -o -name '*.so.*' \) -print0 | sort -z | xargs -0 sha256sum" \
  >"$evidence/inventory/python-native-sha256.txt"
docker run --rm --entrypoint sh "$candidate_tag" -c \
  "find /usr/share/doc -type f -name copyright -print0 | sort -z | xargs -0 sha256sum" \
  >"$evidence/inventory/debian-notices-sha256.txt"
docker run --rm --entrypoint sh "$candidate_tag" -c \
  "tar -C / -czf - \$(find /usr/share/doc -type f -name copyright -printf '%P\n' | sed 's#^#usr/share/doc/#' | sort)" \
  >"$evidence/debian-notices.tar.gz"
docker run --rm --entrypoint node "$candidate_tag" -e \
  "const fs=require('fs'),p=require('path');function walk(d,o=[]){for(const n of fs.readdirSync(d)){const q=p.join(d,n);if(n.startsWith('.'))continue;const s=fs.statSync(q);if(s.isDirectory()){const f=p.join(q,'package.json');if(fs.existsSync(f)){const j=JSON.parse(fs.readFileSync(f));o.push({name:j.name,version:j.version,license:j.license||'NOASSERTION',path:q})}if(n!=='node_modules'||d==='/app')walk(q,o)}}return o}console.log(JSON.stringify(walk('/app/node_modules').sort((a,b)=>a.name.localeCompare(b.name)),null,2))" \
  >"$evidence/inventory/node-packages.json"

syft "$candidate_tag" -o spdx-json="$evidence/candidate-image.spdx.json"
syft "$candidate_tag" -o cyclonedx-json="$evidence/candidate-image.cdx.json"
grype "$candidate_tag" -o json >"$evidence/vulnerability-scan.grype.json"

python3 "$root/scripts/experiments/verify-structural-grayscale-g1a03b-evidence.py" \
  --expected "$root/docs/evidence/g1a02/g1a02-python-native-inventory.json" \
  --evidence "$evidence" --output "$evidence/reconciliation.json"

if grep -Eq '^\[\][[:space:]]*$' "$evidence/registry-repo-digests.json"; then
  printf '%s\n' 'registry digest NOT VERIFIED: local image has no RepoDigest' \
    >"$evidence/registry-digest-status.txt"
else
  printf '%s\n' 'registry digest present; requires independent registry verification before approval' \
    >"$evidence/registry-digest-status.txt"
fi

printf '%s\n' "Candidate evidence generated at $evidence"
printf '%s\n' 'No image was pushed by this script.'
