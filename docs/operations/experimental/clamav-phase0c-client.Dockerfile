# Experimental-only Phase 0C Python client. Never used by DIP production services.
# Immutable Ubuntu base is shared with the existing isolated Phase 0B candidate.
FROM ubuntu:22.04@sha256:b8b6ee6aa931ecd9d0d952abc34dc0e5f7c6a30c6bb71b079fe399fde0329c02

ARG DEBIAN_FRONTEND=noninteractive

LABEL org.opencontainers.image.title="dip-phase0c-live-evidence-client" \
      org.opencontainers.image.description="Bounded experimental Phase 0C R1/R2 evidence client; not production" \
      org.opencontainers.image.licenses="PSF-2.0; Ubuntu package licenses recorded in /usr/share/doc/dip-phase0c-client/"

RUN set -eux; \
    apt-get update -qq; \
    apt-get install -y -qq --no-install-recommends python3-minimal; \
    command -v /usr/bin/timeout; \
    mkdir -p /opt/dip /usr/share/doc/dip-phase0c-client; \
    dpkg-query -W -f='${binary:Package}\t${Version}\n' | sort \
      > /usr/share/doc/dip-phase0c-client/dpkg-manifest.txt; \
    for path in /usr/share/doc/python3-minimal/copyright \
                /usr/share/doc/python3.10/copyright \
                /usr/share/doc/libpython3.10-minimal/copyright; do \
      if [ -f "$path" ]; then cp "$path" /usr/share/doc/dip-phase0c-client/; fi; \
    done; \
    rm -rf /var/lib/apt/lists/*; \
    chmod 0755 /opt/dip; \
    chmod 0644 /usr/share/doc/dip-phase0c-client/*

COPY scripts/experiments/phase0c_r1r2_poc.py /opt/dip/phase0c_r1r2_poc.py
COPY scripts/experiments/phase0c_r1r2_fixtures.py /opt/dip/phase0c_r1r2_fixtures.py
COPY scripts/experiments/phase0c_r1r2_live_evidence.py /opt/dip/phase0c_r1r2_live_evidence.py

WORKDIR /opt/dip
USER 10001:10001
ENTRYPOINT ["python3", "/opt/dip/phase0c_r1r2_live_evidence.py"]
