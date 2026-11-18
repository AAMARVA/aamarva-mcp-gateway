FROM node:22-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY src/gateway ./src/gateway
COPY server.ts ./server.ts
COPY tsconfig.json ./
RUN npx esbuild src/gateway/index.ts --bundle --platform=node --format=esm --packages=external --outfile=dist-server/gateway.mjs

FROM node:22-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist-server/gateway.mjs ./dist-server/gateway.mjs
COPY examples ./examples

ENV NODE_ENV=production
ENV PORT=3000
ENV REQUIRE_TLS=true
ENV ENABLE_SANDBOX=false
ENV ENABLE_OPERATOR_CONSOLE=false
ENV AAMARVA_ONLINE_REVOCATION_CHECK=true

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/healthz || exit 1

CMD ["node", "dist-server/gateway.mjs"]
