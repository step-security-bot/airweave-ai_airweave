FROM node:22-slim@sha256:80fdb3f57c815e1b638d221f30a826823467c4a56c8f6a8d7aa091cd9b1675ea AS builder
WORKDIR /app/connect

# Copy connect app files
COPY connect/package.json connect/package-lock.json ./
RUN npm ci --ignore-scripts

# Copy connect source code
COPY connect/ .

# Copy frontend icons to expected relative path (vite.config.ts uses ../frontend/...)
COPY frontend/src/components/icons/apps/ /app/frontend/src/components/icons/apps/

# Build the application
# This produces .output/ directory with server and public assets
RUN NODE_OPTIONS="--max-old-space-size=4096" npm run build

# Runtime stage
FROM node:22-alpine@sha256:8094c002d08262dba12645a3b4a15cd6cd627d30bc782f53229a2ec13ee22a00
WORKDIR /app

# Install wget for healthcheck
RUN apk upgrade --no-cache && apk add --no-cache wget

# Copy built app from builder stage
COPY --from=builder /app/connect/.output /app/.output
COPY connect/docker-entrypoint.sh /usr/local/bin/

# Make entrypoint executable
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Default port for Connect widget
ENV PORT=8082

# Expose the port
EXPOSE 8082

# Use entrypoint script for runtime configuration
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
