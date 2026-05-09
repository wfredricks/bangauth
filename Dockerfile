# BangAuth — Multi-Stage Dockerfile
#
# Builds a minimal, production-ready image for running BangAuth as a standalone
# HTTP service. Uses multi-stage build to keep the final image small.

# ─── Stage 1: Build ──────────────────────────────────────────────────────────

FROM node:22-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies (including dev dependencies for build)
RUN npm ci

# Copy source files
COPY . .

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────

FROM node:22-alpine AS runtime

WORKDIR /app

# Install production dependencies only
COPY package.json package-lock.json* ./
RUN npm ci --production

# Copy source files and built artifacts from builder
COPY --from=builder /app/src ./src
COPY --from=builder /app/bangauth.yaml ./

# Create non-root user
RUN addgroup -g 1001 -S bangauth && \
    adduser -S -u 1001 -G bangauth bangauth && \
    chown -R bangauth:bangauth /app

USER bangauth

# Expose port (default 3000, configurable via BANGAUTH_PORT)
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1));"

# Start the server
CMD ["npx", "tsx", "src/server.ts"]
