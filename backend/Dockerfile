FROM node:22-alpine

WORKDIR /app

# Install dependencies first (layer caching)
# --omit=dev skips jest, nodemon, supertest
# better-sqlite3 needs native build tools but is only used for local dev
RUN apk add --no-cache python3 make g++

COPY backend/package*.json ./
RUN npm ci --omit=dev

# Copy backend application code
COPY backend/ .

# Copy static portal files (from repo root)
COPY index.html      /app/public/index.html
COPY success.html    /app/public/success.html
COPY status.html     /app/public/status.html
COPY error.html      /app/public/error.html
COPY admin.html      /app/public/admin.html
COPY login.html    /app/public/login.html
COPY assets/         /app/public/assets/
COPY config/config.js /app/public/config/config.js

# Expose port (Render sets $PORT dynamically at runtime)
ENV NODE_ENV=production

# Run as non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
USER nodejs

# Run migrations before starting the server
CMD ["sh", "-c", "node src/db/migrate.js && node src/server.js"]
