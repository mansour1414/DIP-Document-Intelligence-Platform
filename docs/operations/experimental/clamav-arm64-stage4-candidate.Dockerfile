# Stage 4 candidate image: ClamAV 1.5.4 for DIP on OCI ARM64.
#
# Isolated experiment only. This does NOT modify Dockerfile.worker, docker/docker-compose.yml,
# or any production file, and it is not published to any registry.
#
# Base image is pinned by OCI digest. The ClamAV packages are pinned by exact version.
# Every resolved package version is recorded inside the image at
# /usr/share/doc/dip-stage4/dpkg-manifest.txt so the build is auditable after the fact.
#
# Directive validation and sizing rationale:
#   docs/operations/experimental/clamav-arm64-stage4-candidate.conf
#   docs/operations/oci-arm64-stage4-clamav-security-licensing-evidence.md

FROM ubuntu:22.04@sha256:b8b6ee6aa931ecd9d0d952abc34dc0e5f7c6a30c6bb71b079fe399fde0329c02

ARG CLAMAV_VERSION=1.5.4+dfsg-0ubuntu0.22.04.1
ARG DEBIAN_FRONTEND=noninteractive

LABEL org.opencontainers.image.title="dip-clamav-arm64-internal-candidate" \
      org.opencontainers.image.description="ClamAV 1.5.4 ARM64 internal controlled candidate for DIP malware scanning" \
      org.opencontainers.image.version="${CLAMAV_VERSION}" \
      org.opencontainers.image.base.digest="sha256:b8b6ee6aa931ecd9d0d952abc34dc0e5f7c6a30c6bb71b079fe399fde0329c02" \
      org.opencontainers.image.vendor="DIP" \
      org.opencontainers.image.licenses="see-/usr/share/doc/*/copyright"

# clamav-daemon (clamd), clamav-freshclam (signature updates), clamav-base (libs/db).
# --no-install-recommends keeps the dependency surface minimal and auditable.
RUN apt-get update -qq \
 && apt-get upgrade -y -qq \
 && apt-get install -y -qq --no-install-recommends \
      "clamav-base=${CLAMAV_VERSION}" \
      "clamav-daemon=${CLAMAV_VERSION}" \
      "clamav-freshclam=${CLAMAV_VERSION}" \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY docs/operations/experimental/clamav-arm64-stage4-candidate.conf /etc/clamav/clamd.conf
COPY docs/operations/experimental/clamd-freshness-gate.sh /usr/local/bin/clamd-freshness-gate

# Fail closed on the scanner side: refuse to start clamd unless a readable,
# non-empty signature database of acceptable age is present. zPING proves the
# database LOADED, not that it is FRESH, so the freshness assertion is enforced
# here instead (docs/operator-runbook.md:20). Rationale for the 72h default is
# documented in the gate script: clamav-daily.cvd is not published Thursday or
# Sunday, so a shorter limit would fail-closed twice a week by design.
RUN set -eux; \
    mkdir -p /run/clamav /var/log/clamav /usr/share/doc/dip-stage4; \
    chown -R clamav:clamav /run/clamav /var/log/clamav /var/lib/clamav; \
    chmod 0755 /usr/local/bin/clamd-freshness-gate; \
    # Record the full resolved dependency set + versions for auditability.
    dpkg-query -W -f='${binary:Package}\t${Version}\n' | sort > /usr/share/doc/dip-stage4/dpkg-manifest.txt; \
    # Record the exact license/copyright text shipped with the ClamAV packages.
    for d in clamav-base clamav-daemon clamav-freshclam libclamunrar9 libclamunrar-common libclammspack7 clamav; do \
      if [ -f "/usr/share/doc/$d/copyright" ]; then \
        cp "/usr/share/doc/$d/copyright" "/usr/share/doc/dip-stage4/copyright-$d.txt"; \
      fi; \
    done; \
    # Record the compiled-in limits so the effective runtime config is auditable.
    { echo "clamd=$(clamd --version)"; echo "freshclam=$(freshclam --version)"; } \
      > /usr/share/doc/dip-stage4/tool-versions.txt; \
    test -s /usr/share/doc/dip-stage4/dpkg-manifest.txt

# non-root runtime
USER clamav

EXPOSE 3310

# Readiness + freshness, re-evaluated on every probe.
#
# zPING alone is not sufficient: a database that goes stale while clamd keeps
# listening would keep answering PONG and keep returning CLEAN. The gate is
# therefore re-run inside the healthcheck so staleness becomes a visible
# unhealthy state rather than a silent detection gap.
#
# LIMITATION (deliberately not overclaimed): this is an orchestration-level
# signal. src/lib/malware/clamd.ts connects to the socket and does not read
# container health, so a stale-but-listening clamd still answers CLEAN to DIP.
# Enforcement therefore depends on the deployment actually respecting the
# healthcheck (restart / pull from rotation) — tracked in the CR, not solved
# inside this image.
HEALTHCHECK --interval=60s --timeout=15s --start-period=120s --retries=3 \
  CMD /usr/local/bin/clamd-freshness-gate --check >/dev/null 2>&1 \
      && bash -c 'exec 3<>/dev/tcp/127.0.0.1/3310 && printf "zPING\0" >&3 && head -c 4 <&3 | grep -q PONG' || exit 1

# Fail closed: the freshness gate runs first and refuses to exec clamd when
# signatures are missing, empty, unreadable or stale.
ENTRYPOINT ["/usr/local/bin/clamd-freshness-gate", "--exec", "/usr/sbin/clamd", "--config-file=/etc/clamav/clamd.conf", "--foreground"]
