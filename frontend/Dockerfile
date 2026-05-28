# Stage 1: Install dependencies
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

# Stage 2: Build
FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build-time env vars (override at build or runtime)
ARG NEXT_PUBLIC_API_URL=https://www.example.com
ARG NEXT_PUBLIC_GA_MEASUREMENT_ID=
ARG NEXT_PUBLIC_CIAM_TENANT_NAME=argus
ARG NEXT_PUBLIC_CIAM_CLIENT_ID=<YOUR_CLIENT_ID>
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
ENV NEXT_PUBLIC_GA_MEASUREMENT_ID=${NEXT_PUBLIC_GA_MEASUREMENT_ID}
ENV NEXT_PUBLIC_CIAM_TENANT_NAME=${NEXT_PUBLIC_CIAM_TENANT_NAME}
ENV NEXT_PUBLIC_CIAM_CLIENT_ID=${NEXT_PUBLIC_CIAM_CLIENT_ID}

RUN npm run build

# Stage 3: Production runner (~150MB vs ~1GB without standalone)
FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy standalone server + static assets
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

USER nextjs
EXPOSE 3000

CMD ["node", "server.js"]
