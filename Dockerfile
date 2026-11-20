FROM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
ARG KEYSENTRY_BUILD_COMMIT=dev
ENV KEYSENTRY_BUILD_COMMIT=${KEYSENTRY_BUILD_COMMIT}
RUN npm run release:build
# Prepare the empty mount point before switching to the shell-free runtime.
RUN mkdir /watcher-state && chmod 0700 /watcher-state

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:cb606325b7ec4af55462cb0b424a53b452a5b4a894ffe841fcf1048d216fb9f8
ARG KEYSENTRY_BUILD_COMMIT=dev
LABEL org.opencontainers.image.source="https://github.com/grzegorzszmulik22/keysentry" \
      org.opencontainers.image.revision="${KEYSENTRY_BUILD_COMMIT}" \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
COPY --from=build /build/dist-release/out/keysentry.mjs /build/dist-release/out/release-manifest.json /app/
COPY --from=build /build/LICENSE /build/NOTICE /app/
COPY --from=build --chown=65532:65532 --chmod=0700 /watcher-state/ /data/
ENV KEYSENTRY_STATE_DIR=/data KEYSENTRY_VAULT=encrypted-file NODE_ENV=production
USER 65532
VOLUME /data
ENTRYPOINT ["/nodejs/bin/node", "/app/keysentry.mjs", "watch"]
