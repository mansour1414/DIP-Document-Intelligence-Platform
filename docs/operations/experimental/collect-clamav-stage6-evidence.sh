#!/usr/bin/env bash
set -euo pipefail

IMAGE="${IMAGE:-dip-clamav:arm64-stage5-custom}"
OUT="${OUT:-/home/ubuntu/stage6/evidence}"
EXTRACT_CONTAINER="clamav-stage6-extract"

mkdir -p "$OUT/licenses"
docker rm -f "$EXTRACT_CONTAINER" >/dev/null 2>&1 || true
cid="$(docker create --name "$EXTRACT_CONTAINER" --entrypoint /bin/true "$IMAGE")"
trap 'docker rm -f "$EXTRACT_CONTAINER" >/dev/null 2>&1 || true' EXIT
docker cp "$cid:/usr/share/doc/." "$OUT/licenses/"
docker rm "$EXTRACT_CONTAINER" >/dev/null
trap - EXIT

find "$OUT/licenses" -type f -name copyright -print0 \
  | sort -z \
  | tar --null -T - -czf "$OUT/custom-transitive-copyrights.tar.gz"

docker run --rm --entrypoint /bin/bash "$IMAGE" -lc '
  set -eu
  clamd_path="$(command -v clamd)"
  printf "clamd=%s\n" "$clamd_path"
  ldd "$clamd_path"
  printf "PACKAGE_OWNERS\n"
  {
    printf "%s\n" "$clamd_path"
    ldd "$clamd_path" | sed -n "s/.*=> \([^ ]*\).*/\1/p"
  } | while IFS= read -r file; do
    canonical="$(readlink -f "$file")"
    dpkg-query -S "$canonical" 2>/dev/null \
      || dpkg-query -S "$file" 2>/dev/null \
      || printf "unowned\t%s\n" "$file"
  done
' > "$OUT/clamd-runtime-linkage.txt"

find "$OUT/licenses" -type f -name copyright -printf '%P\n' \
  | sort > "$OUT/copyright-file-inventory.txt"

docker run --rm --entrypoint /bin/bash "$IMAGE" -lc '
  set -eu
  printf "package\tversion\tcopyright_status\tresolved_path\tsha256\tdeclared_license_fields\n"
  dpkg-query -W -f="\${binary:Package}\t\${Version}\n" | sort \
    | while IFS=$'"'"'\t'"'"' read -r binary_package version; do
        package="${binary_package%%:*}"
        source="/usr/share/doc/$package/copyright"
        if [ -r "$source" ]; then
          resolved="$(readlink -f "$source")"
          digest="$(sha256sum "$resolved" | cut -d " " -f 1)"
          licenses="$(sed -n "s/^License:[[:space:]]*//p" "$resolved" \
            | sort -u | paste -sd ";" -)"
          printf "%s\t%s\tpresent\t%s\t%s\t%s\n" \
            "$binary_package" "$version" "$resolved" "$digest" "$licenses"
        else
          printf "%s\t%s\tmissing\t%s\t-\t-\n" \
            "$binary_package" "$version" "$source"
        fi
      done
' > "$OUT/package-license-inventory.tsv"

sha256sum \
  "$OUT/custom-transitive-copyrights.tar.gz" \
  "$OUT/clamd-runtime-linkage.txt" \
  "$OUT/copyright-file-inventory.txt" \
  "$OUT/package-license-inventory.tsv"
