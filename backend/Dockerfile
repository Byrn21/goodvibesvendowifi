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

# --- Store location + contact details injection (build-time) ---
# The portal HTML ships with placeholders (__STORE_LOCATION__ in index.html and
# __FACEBOOK_PAGE_NAME__ / __FACEBOOK_URL__ / __CONTACT_NUMBER__ /
# __SUPPORT_EMAIL__ in the Contact Support modal and footers). Render passes the
# dashboard's environment variables to Docker builds as build arguments (see
# render.com/docs/docker), so every value below is available here. Unset values
# fall back safely — the modal hides the affected row and footer links become a
# harmless "#" — so a missing variable never breaks the page.
# The script is copied to /app (not /app/public) so it is never served as a
# static file; at /app it resolves the pages under /app/public.
COPY inject-secrets.js /app/inject-secrets.js
ARG STORE_LOCATION
ARG FACEBOOK_PAGE_NAME
ARG FACEBOOK_URL
ARG CONTACT_NUMBER
ARG SUPPORT_EMAIL
RUN node inject-secrets.js

# Expose port (Render sets $PORT dynamically at runtime)
ENV NODE_ENV=production

# Run as non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
USER nodejs

# Run migrations before starting the server
CMD ["sh", "-c", "node src/db/migrate.js && node src/server.js"]
