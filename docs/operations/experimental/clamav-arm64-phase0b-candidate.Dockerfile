# Phase 0B isolated experimental candidate: ClamAV 1.5.4 + upstream CLAM-3102 on OCI ARM64.
#
# ISOLATED EXPERIMENT ONLY — NOT FOR PRODUCTION, NOT PUBLISHED TO GHCR.
# Does NOT modify Dockerfile, Dockerfile.worker, docker/docker-compose.yml,
# clamav-arm64-stage4-candidate.conf, or any production code.
#
# Scope of modification (Part A only):
#   Rebuilds Ubuntu Jammy's DFSG-clean clamav source package (1.5.4+dfsg-0ubuntu0.22.04.1,
#   which strips non-free libclamunrar) with ONE officially merged Cisco Talos upstream
#   patch: PR #1832 / commit 9f84fb3404b9a66c782e33f3e2b0da5e3d32af76 (CLAM-3102: alert on
#   ZIP member truncation exceeding MaxFileSize).
#
#   Intentionally EXCLUDES unreviewed community ZIP64 PR #1845.
#   ZIP64 and unsupported-compression defense is evaluated separately in Part B
#   (docs/operations/experimental/clamav-phase0b-zip-preflight.mts).
#
# Licensing & GPLv2 obligations:
#   ClamAV is licensed GPL-2.0-only (with OpenSSL exception) plus separately licensed
#   bundled/transitive components (including statically linked Rust crates in libclamav_rust).
#   Because this image contains a modified GPLv2 binary (libclamav/unzip.c), any distribution
#   outside internal-only execution triggers GPLv2 Section 2(a) modification notices and
#   Section 3 Complete Corresponding Source obligations. The `corresponding-source` target
#   exposes the exact pinned source artifacts, patch, and packaging provenance.

# ============================================================================
# Stage 1: Builder (Ubuntu 22.04 ARM64, pinned by digest)
# ============================================================================
FROM ubuntu:22.04@sha256:b8b6ee6aa931ecd9d0d952abc34dc0e5f7c6a30c6bb71b079fe399fde0329c02 AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG CLAMAV_UPSTREAM_DEBIAN_VERSION=1.5.4+dfsg-0ubuntu0.22.04.1
ARG CLAMAV_PATCHED_DEBIAN_VERSION=1.5.4+dfsg-0ubuntu0.22.04.1+dipphase0b1
ARG ORIG_TAR_SHA256=b9c10b222d3302e6eed7496de5d01a766b68f023dbae2646866d96c25f13fd7c
ARG DEBIAN_TAR_SHA256=69e5adfdab189ab44b7ed04d1ad26c34183475ddabbedd9bd0b059da1b3578e9
ARG DSC_SHA256=d47b5139fcd190c7fc665db464380e32eecddb2e966c047ac668fefef43b0ac3
ARG CLAM3102_PATCH_SHA256=503040ebfc3a950ca3f5303c1591bb637e5d42ccb46cb3ca63fa94dab98cf013
ARG LAUNCHPAD_SOURCE_BASE=https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/clamav/1.5.4+dfsg-0ubuntu0.22.04.1

# Enable deb-src entries in /etc/apt/sources.list for signed APT source resolution
# and install minimal source-verification and Debian packaging tools first.
# Package Build-Depends are resolved directly from the SHA-256-verified extracted
# debian/control below so builds remain reproducible even if jammy-security later
# supersedes 1.5.4+dfsg-0ubuntu0.22.04.1 in the live APT index.
RUN set -eux; \
    sed -i 's/^# deb-src /deb-src /' /etc/apt/sources.list; \
    apt-get update -qq; \
    apt-get upgrade -y -qq; \
    apt-get install -y -qq --no-install-recommends \
      ca-certificates \
      curl \
      devscripts \
      dpkg-dev \
      quilt; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY docs/operations/experimental/patches/clamav-1.5.4-clam-3102.patch /build/clamav-1.5.4-clam-3102.patch

# Fetch Ubuntu's DFSG-clean source package, enforce exact SHA-256 verification
# on all three source artifacts and on the CLAM-3102 patch, install exact
# Build-Depends from the verified debian/control, confirm UnRAR exclusion,
# apply CLAM-3102 with zero fuzz, and build Debian binary packages.
RUN set -eux; \
    echo "${CLAM3102_PATCH_SHA256}  /build/clamav-1.5.4-clam-3102.patch" | sha256sum --check --strict; \
    mkdir -p /build/orig; \
    cd /build/orig; \
    apt-get update -qq; \
    if ! apt-get source --download-only "clamav=${CLAMAV_UPSTREAM_DEBIAN_VERSION}"; then \
      for f in \
        "clamav_1.5.4+dfsg.orig.tar.bz2" \
        "clamav_${CLAMAV_UPSTREAM_DEBIAN_VERSION}.debian.tar.xz" \
        "clamav_${CLAMAV_UPSTREAM_DEBIAN_VERSION}.dsc"; do \
        curl --fail --location --silent --show-error "${LAUNCHPAD_SOURCE_BASE}/${f}" --output "${f}"; \
      done; \
    fi; \
    printf '%s  %s\n' \
      "${ORIG_TAR_SHA256}" "clamav_1.5.4+dfsg.orig.tar.bz2" \
      "${DEBIAN_TAR_SHA256}" "clamav_${CLAMAV_UPSTREAM_DEBIAN_VERSION}.debian.tar.xz" \
      "${DSC_SHA256}" "clamav_${CLAMAV_UPSTREAM_DEBIAN_VERSION}.dsc" \
      > /build/ubuntu-source.sha256; \
    sha256sum --check --strict /build/ubuntu-source.sha256; \
    dpkg-source --no-check -x "clamav_${CLAMAV_UPSTREAM_DEBIAN_VERSION}.dsc" /build/src; \
    apt-get build-dep -y -qq --no-install-recommends /build/src; \
    rm -rf /var/lib/apt/lists/*; \
    # Fail-closed DFSG UnRAR exclusion check on extracted source tree
    test ! -d /build/src/libclamunrar; \
    # Fail-closed check: unreviewed PR #1845 must NOT be present
    ! grep -q 'cli_zip_parse_zip64_extra_field' /build/src/libclamav/unzip.c; \
    # Register CLAM-3102 as a quilt patch and apply with zero fuzz
    cp /build/clamav-1.5.4-clam-3102.patch /build/src/debian/patches/dip-phase0b-clam-3102.patch; \
    echo "dip-phase0b-clam-3102.patch" >> /build/src/debian/patches/series; \
    cd /build/src; \
    export QUILT_PATCHES=debian/patches; \
    export QUILT_PATCH_OPTS="--fuzz=0"; \
    quilt push -a; \
    # Verify exact 4 truncation-alert call sites exist in libclamav/unzip.c
    test "$(grep -c 'Heuristics.Limits.Exceeded.MaxFileSize' libclamav/unzip.c)" -eq 4; \
    grep -q 'Modified 2026-11-16 by DIP (Phase 0B isolated experiment)' libclamav/unzip.c; \
    # Record explicit GPLv2 Section 2(a) modification entry in debian/changelog
    DEBFULLNAME="DIP Phase 0B Isolated Experiment" \
    DEBEMAIL="security-experiment@dip.invalid" \
    dch --local "+dipphase0b" --distribution "jammy" --force-distribution \
      "Backport upstream Cisco ClamAV commit 9f84fb3404b9a66c782e33f3e2b0da5e3d32af76 (PR #1832 / CLAM-3102: alert on ZIP member truncation exceeding MaxFileSize). Isolated Phase 0B PoC only."; \
    dpkg-parsechangelog -S Version | grep -Fx "${CLAMAV_PATCHED_DEBIAN_VERSION}"; \
    # Preserve provenance & GPLv2 Corresponding Source metadata
    mkdir -p /build/provenance /build/corresponding-source; \
    cp /build/orig/clamav_1.5.4+dfsg.orig.tar.bz2 \
       "/build/orig/clamav_${CLAMAV_UPSTREAM_DEBIAN_VERSION}.debian.tar.xz" \
       "/build/orig/clamav_${CLAMAV_UPSTREAM_DEBIAN_VERSION}.dsc" \
       /build/ubuntu-source.sha256 \
       /build/clamav-1.5.4-clam-3102.patch \
       /build/corresponding-source/; \
    cp /build/ubuntu-source.sha256 /build/provenance/; \
    cp /build/clamav-1.5.4-clam-3102.patch /build/provenance/; \
    cp debian/changelog /build/provenance/debian-changelog.txt; \
    cp debian/patches/series /build/provenance/debian-patches-series.txt; \
    if [ -f COPYING.txt ]; then cp COPYING.txt /build/provenance/COPYING.txt; fi; \
    if [ -d COPYING ]; then cp -r COPYING /build/provenance/COPYING; fi; \
    if [ -f libclamav_rust/Cargo.lock ]; then cp libclamav_rust/Cargo.lock /build/provenance/libclamav_rust-Cargo.lock; fi; \
    if [ -f libclamav_rust/Cargo.toml ]; then cp libclamav_rust/Cargo.toml /build/provenance/libclamav_rust-Cargo.toml; fi; \
    # Build binary packages (nocheck avoids multi-hour QEMU Valgrind/CTest timeouts;
    # targeted CLAM-3102 and regression tests run live in the Phase 0B workflow)
    DEB_BUILD_OPTIONS="nocheck parallel=$(nproc)" dpkg-buildpackage -b -us -uc; \
    mkdir -p /build/out-debs; \
    for pkg in libclamav12 clamav-base clamav-daemon clamav-freshclam; do \
      cp /build/${pkg}_${CLAMAV_PATCHED_DEBIAN_VERSION}_*.deb /build/out-debs/; \
    done; \
    # Ensure no unrar package was produced
    ! ls /build/*unrar*.deb >/dev/null 2>&1; \
    sha256sum /build/out-debs/*.deb > /build/provenance/built-debs.sha256

# ============================================================================
# Stage 2 (Optional Export Target): GPLv2 Section 3 Corresponding Source Bundle
# ============================================================================
FROM scratch AS corresponding-source
COPY --from=builder /build/corresponding-source/ /corresponding-source/
COPY --from=builder /build/provenance/ /provenance/

# ============================================================================
# Stage 3 (Default): Hardened Non-Root ARM64 Runtime Image
# ============================================================================
FROM ubuntu:22.04@sha256:b8b6ee6aa931ecd9d0d952abc34dc0e5f7c6a30c6bb71b079fe399fde0329c02 AS runtime

ARG DEBIAN_FRONTEND=noninteractive
ARG CLAMAV_PATCHED_DEBIAN_VERSION=1.5.4+dfsg-0ubuntu0.22.04.1+dipphase0b1
ARG BASE_CONF_SHA256=75e2fc17058971c143580579d1d6027b5385c1724a3109e79390a272d95909a6
ARG FRESHNESS_GATE_SHA256=b1bff15489ece75f5baa20d6f244761492265ce52c072afdfde110461d9aade6

LABEL org.opencontainers.image.title="dip-clamav-arm64-phase0b-poc" \
      org.opencontainers.image.description="Isolated Phase 0B experimental ClamAV 1.5.4 + CLAM-3102 ARM64 candidate (NOT FOR PRODUCTION)" \
      org.opencontainers.image.version="${CLAMAV_PATCHED_DEBIAN_VERSION}" \
      org.opencontainers.image.base.digest="sha256:b8b6ee6aa931ecd9d0d952abc34dc0e5f7c6a30c6bb71b079fe399fde0329c02" \
      org.opencontainers.image.vendor="DIP" \
      org.opencontainers.image.licenses="GPL-2.0-only; see-/usr/share/doc/*/copyright-and-/usr/share/doc/dip-phase0b/" \
      io.dip.release-scope="phase0b-isolated-experimental-poc-not-for-production" \
      io.dip.patch.upstream-pr="https://github.com/Cisco-Talos/clamav/pull/1832" \
      io.dip.patch.upstream-commit="9f84fb3404b9a66c782e33f3e2b0da5e3d32af76" \
      io.dip.patch.zip64-pr1845-included="false" \
      io.dip.unrar-included="false"

COPY --from=builder /build/out-debs/ /tmp/dip-debs/
COPY --from=builder /build/provenance/ /usr/share/doc/dip-phase0b/

RUN set -eux; \
    apt-get update -qq; \
    apt-get upgrade -y -qq; \
    apt-get install -y -qq --no-install-recommends \
      ca-certificates \
      /tmp/dip-debs/*.deb; \
    rm -rf /tmp/dip-debs /var/lib/apt/lists/*; \
    # Fail-closed package version verification
    for pkg in libclamav12 clamav-base clamav-daemon clamav-freshclam; do \
      actual="$(dpkg-query -W -f='${Version}' "$pkg")"; \
      test "$actual" = "${CLAMAV_PATCHED_DEBIAN_VERSION}"; \
    done; \
    # Fail-closed UnRAR exclusion verification (packages, filesystem, and runtime linkage)
    ! dpkg-query -W '*unrar*' >/dev/null 2>&1; \
    ! ldd /usr/sbin/clamd | grep -qi unrar; \
    ! find /usr/lib /lib -iname '*clamunrar*' 2>/dev/null | grep -q .; \
    # Fail-closed build-tool absence verification in runtime image
    for tool in gcc g++ cmake cargo rustc dpkg-buildpackage quilt; do \
      ! command -v "$tool" >/dev/null 2>&1; \
    done

# Preserve the exact unmodified baseline Stage 4 configuration and freshness gate
COPY docs/operations/experimental/clamav-arm64-stage4-candidate.conf /etc/clamav/clamd.conf
COPY docs/operations/experimental/clamd-freshness-gate.sh /usr/local/bin/clamd-freshness-gate

RUN set -eux; \
    echo "${BASE_CONF_SHA256}  /etc/clamav/clamd.conf" | sha256sum --check --strict; \
    echo "${FRESHNESS_GATE_SHA256}  /usr/local/bin/clamd-freshness-gate" | sha256sum --check --strict; \
    mkdir -p /run/clamav /var/log/clamav /usr/share/doc/dip-phase0b; \
    chown -R clamav:clamav /run/clamav /var/log/clamav /var/lib/clamav; \
    chmod 0755 /usr/local/bin/clamd-freshness-gate; \
    dpkg-query -W -f='${binary:Package}\t${Version}\n' | sort > /usr/share/doc/dip-phase0b/dpkg-manifest.txt; \
    for d in clamav-base clamav-daemon clamav-freshclam libclamav12 libclammspack0 libclammspack7; do \
      if [ -f "/usr/share/doc/$d/copyright" ]; then \
        cp "/usr/share/doc/$d/copyright" "/usr/share/doc/dip-phase0b/copyright-$d.txt"; \
      fi; \
    done; \
    { echo "clamd=$(clamd --version)"; echo "freshclam=$(freshclam --version)"; } \
      > /usr/share/doc/dip-phase0b/tool-versions.txt; \
    test -s /usr/share/doc/dip-phase0b/dpkg-manifest.txt

USER clamav

EXPOSE 3310

HEALTHCHECK --interval=60s --timeout=15s --start-period=120s --retries=3 \
  CMD /usr/local/bin/clamd-freshness-gate --check >/dev/null 2>&1 \
      && bash -c 'exec 3<>/dev/tcp/127.0.0.1/3310 && printf "zPING\0" >&3 && head -c 4 <&3 | grep -q PONG' || exit 1

ENTRYPOINT ["/usr/local/bin/clamd-freshness-gate", "--exec", "/usr/sbin/clamd", "--config-file=/etc/clamav/clamd.conf", "--foreground"]
