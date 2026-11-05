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

FROM python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1

RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin nfworker \
 && useradd --system --uid 10002 --home-dir /nonexistent --shell /usr/sbin/nologin nftool \
 && find / -xdev -type f -perm /6000 -exec chmod a-s {} +

COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY api/requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r /app/requirements.lock
COPY api /app/api
RUN pip install --no-cache-dir --no-deps /app/api && rm -rf /app/api
COPY infra/tools/egress-lock.sh /usr/local/bin/egress-lock.sh

ENV NIGHTFALL_NUCLEI_BIN=/usr/local/bin/nuclei \
    NIGHTFALL_TOOL_SANDBOX=uid \
    NIGHTFALL_TOOL_USER=nftool \
    NIGHTFALL_WORKER_USER=nfworker \
    NIGHTFALL_EGRESS_PORT=3128 \
    NIGHTFALL_EVIDENCE_DIR=/var/lib/nightfall/evidence \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["/usr/local/bin/egress-lock.sh"]
CMD ["nightfall-worker"]
