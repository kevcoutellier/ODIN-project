# ── Odin by AgentLayers — Multi-stage Docker Build ──────────────────
# Stage 1: Build (full dev deps)
# Stage 2: Production (minimal runtime)
# ────────────────────────────────────────────────────────────────────

# ── Stage 1: Builder ───
FROM node:20-slim AS builder

RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /app

# Copy workspace config first (layer caching)
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.json ./

# Copy all package.json files (for dependency resolution)
COPY packages/core/package.json packages/core/
COPY packages/security/package.json packages/security/
COPY packages/trust/package.json packages/trust/
COPY packages/observability/package.json packages/observability/
COPY packages/cognition/package.json packages/cognition/
COPY packages/cli/package.json packages/cli/
COPY packages/dashboard/package.json packages/dashboard/

# Install dependencies (with native modules)
RUN pnpm install --frozen-lockfile

# Copy all source code
COPY packages/ packages/
COPY vitest.config.ts ./

# Build all packages
RUN pnpm build

# ── Stage 2: Production ───
FROM node:20-slim AS production

RUN corepack enable && corepack prepare pnpm@latest --activate

# Security: run as non-root
RUN groupadd -r odin && useradd -r -g odin -m odin

WORKDIR /app

# Copy workspace config
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.json ./
COPY packages/core/package.json packages/core/
COPY packages/security/package.json packages/security/
COPY packages/trust/package.json packages/trust/
COPY packages/observability/package.json packages/observability/
COPY packages/cognition/package.json packages/cognition/
COPY packages/cli/package.json packages/cli/
COPY packages/dashboard/package.json packages/dashboard/

# Install production dependencies only
RUN pnpm install --frozen-lockfile --prod

# Copy built artifacts from builder
COPY --from=builder /app/packages/core/dist packages/core/dist
COPY --from=builder /app/packages/security/dist packages/security/dist
COPY --from=builder /app/packages/trust/dist packages/trust/dist
COPY --from=builder /app/packages/observability/dist packages/observability/dist
COPY --from=builder /app/packages/cognition/dist packages/cognition/dist
COPY --from=builder /app/packages/cli/dist packages/cli/dist
COPY --from=builder /app/packages/dashboard/dist packages/dashboard/dist

# Create data directory for SQLite databases
RUN mkdir -p /app/data && chown -R odin:odin /app

# Configuration
COPY odin.yaml ./

# Switch to non-root user
USER odin

# Environment
ENV NODE_ENV=production
ENV ODIN_DATA_DIR=/app/data
ENV ODIN_DASHBOARD_PORT=3000

# Expose dashboard port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:3000/api/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

# Start Odin CLI (which launches dashboard + agent)
CMD ["node", "packages/cli/dist/index.js", "--dashboard"]
