# ── Stage 1: Install dependencies ─────────────────────────────────────────────
FROM node:20-alpine AS deps

WORKDIR /app

COPY package.json package-lock.json ./
# Install all dependencies (dev deps needed for Next.js build).
RUN npm ci


# ── Stage 2: Build ────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy installed node_modules from deps stage.
COPY --from=deps /app/node_modules ./node_modules

COPY . .

ENV NEXT_TELEMETRY_DISABLED=1

# NEXT_PUBLIC_API_URL is baked in at build time. In production the Nginx
# reverse proxy handles /api/* routing so this can be left empty.
ARG NEXT_PUBLIC_API_URL=""
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

RUN npm run build


# ── Stage 3: Runtime ──────────────────────────────────────────────────────────
# The standalone output from `next build` includes only what is needed to run
# the server — no node_modules, no source files.
FROM node:20-alpine AS runtime

WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1

# Create non-root user.
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy the standalone server bundle.
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000 \
    HOSTNAME=0.0.0.0

CMD ["node", "server.js"]
