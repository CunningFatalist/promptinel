FROM node:22.14.0-bookworm-slim

ARG PNPM_VERSION=10.6.3

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@${PNPM_VERSION} --activate

ENTRYPOINT ["tail", "-f", "/dev/null"]
