# EPIC E — sandboxed reader-svc.
#
# Built on the same Node image as the proxy but hardened:
#   - runs as non-root (UID 1001)
#   - minimal deps (only express + cors)
#   - no Mongo / proxy / engine imports — the Reader has no DB access by design
#
# Container-level hardening (read_only, cap_drop, no-new-privileges, egress
# isolation) is applied in docker-compose.yml — that's where the network policy
# actually prevents the reader from reaching Mongo/engine.
FROM node:20-alpine

# Non-root user.
RUN addgroup -S app && adduser -S app -G app -u 1001

WORKDIR /app

# Install deps for both the svc and the shared proxy/agents dir it imports.
COPY reader-svc/package.json reader-svc/package-lock.json* ./reader-svc/
COPY proxy/package.json proxy/package-lock.json* ./proxy/
RUN cd reader-svc && npm install --omit=dev && cd ../proxy && npm install --omit=dev

# Copy source: the svc itself + the shared proxy agents it imports.
COPY reader-svc/ ./reader-svc/
COPY proxy/agents/ ./proxy/agents/
COPY proxy/llm/ ./proxy/llm/

# tmpfs-only writable area (read_only FS is set in compose).
RUN mkdir -p /tmp && chown -R app:app /app /tmp
USER app

EXPOSE 8012
CMD ["node", "reader-svc/server.js"]
