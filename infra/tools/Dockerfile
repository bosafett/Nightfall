# Worker + tools image (review §9, §13). Build from the repository root:
#   docker build -f infra/tools/Dockerfile -t nightfall-worker .
# Run with exactly these capabilities (egress-lock.sh uses NET_ADMIN and SETPCAP once at
# start, then drops them), e.g.
#   docker run --cap-drop ALL --cap-add NET_ADMIN --cap-add SETPCAP --cap-add SETUID \
#     --cap-add SETGID --read-only --tmpfs /tmp ... nightfall-worker
# Check readiness: docker run ... nightfall-worker nightfall-worker --check
# Images are pinned by digest; nothing is pulled at run time.

# Nuclei v3.11.1 (MIT), official image. Only the binary is copied.
FROM projectdiscovery/nuclei:v3.11.1@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb AS nuclei

# Lab tool pack 1 (docs/designs/2026-11-lab-tool-pack-1.md): only the templates listed in
# the reviewed manifest, from the pinned release, each checked against its SHA-256.
FROM python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1 AS pack1
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch v10.5.1 \
      https://github.com/projectdiscovery/nuclei-templates.git /src/nuclei-templates
COPY api/nightfall/tools/nuclei/pack1.json infra/tools/stage_nuclei_pack.py /src/
RUN python3 /src/stage_nuclei_pack.py /src/nuclei-templates /src/pack1.json /opt/nuclei-pack1

FROM python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1

RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin nfworker \
 && useradd --system --uid 10002 --home-dir /nonexistent --shell /usr/sbin/nologin nftool \
 && find / -xdev -type f -perm /6000 -exec chmod a-s {} +

COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=pack1 /opt/nuclei-pack1 /opt/nuclei-pack1
COPY api/requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r /app/requirements.lock
COPY api /app/api
RUN pip install --no-cache-dir --no-deps /app/api && rm -rf /app/api
COPY infra/tools/egress-lock.sh /usr/local/bin/egress-lock.sh
# A Windows checkout can turn the script's line endings into CRLF, which breaks the
# #!/bin/sh line ("no such file or directory"). Strip them so the build works either way.
RUN sed -i 's/\r$//' /usr/local/bin/egress-lock.sh && chmod 0755 /usr/local/bin/egress-lock.sh

ENV NIGHTFALL_NUCLEI_BIN=/usr/local/bin/nuclei \
    NIGHTFALL_TOOL_SANDBOX=uid \
    NIGHTFALL_TOOL_USER=nftool \
    NIGHTFALL_WORKER_USER=nfworker \
    NIGHTFALL_EGRESS_PORT=3128 \
    NIGHTFALL_EVIDENCE_DIR=/var/lib/nightfall/evidence \
    NIGHTFALL_LAB_PACK1_DIR=/opt/nuclei-pack1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["/usr/local/bin/egress-lock.sh"]
CMD ["nightfall-worker"]
