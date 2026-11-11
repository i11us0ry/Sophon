FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json* pnpm-lock.yaml* pnpm-workspace.yaml* ./
RUN if [ -f pnpm-lock.yaml ]; then corepack enable && pnpm install --frozen-lockfile; else npm install; fi

COPY . .
RUN if [ -f pnpm-lock.yaml ]; then pnpm run build; else npm run build; fi

FROM nginx:stable-alpine
COPY --from=builder /app/dist /usr/share/nginx/html
