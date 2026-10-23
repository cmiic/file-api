# Stage 1: Build
FROM docker.io/library/golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS builder
WORKDIR /app

# Install dependencies needed for development AND execution
RUN apt update && apt install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY app/go.mod app/go.sum ./
RUN go mod download all
RUN mkdir -p /third-party-licenses/go /third-party-licenses/modules \
    && cp /usr/local/go/LICENSE /usr/local/go/PATENTS /third-party-licenses/go/ \
    && go list -m -f '{{if .Version}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}' all > /tmp/modules.txt \
    && while IFS='|' read -r module version directory; do \
        if test -z "$module"; then continue; fi; \
        if test -z "$directory"; then echo "Missing module directory: $module $version" >&2; exit 1; fi; \
        destination="$(printf '%s' "$module" | tr '/.' '__')-$version"; \
        licenses="$(find "$directory" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' -o -iname 'PATENTS*' \))"; \
        if test -z "$licenses"; then echo "Missing module license: $module $version" >&2; exit 1; fi; \
        mkdir -p "/third-party-licenses/modules/$destination"; \
        find "$directory" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' -o -iname 'PATENTS*' \) \
            -exec cp -t "/third-party-licenses/modules/$destination" {} +; \
    done < /tmp/modules.txt \
    && { go version; cut -d '|' -f 1,2 /tmp/modules.txt | tr '|' ' '; } > /third-party-licenses/NOTICE.txt
COPY app/ .

# Static build for production
# Set by the release workflow from the git tag (without its leading "v"); local
# and CI builds keep "dev". Declared just before the build step so a new
# version only rebuilds the binary, not the module and license layers.
ARG APP_VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${APP_VERSION}" -o file-api .

# Development: the builder plus Air for live reloading, which .devcontainer
# targets. Release and CI builds target the final stage and never build this
# one, so they download nothing for it. Air comes from the tools module, whose
# go.sum locks it and every dependency.
FROM builder AS dev
COPY tools/go.mod tools/go.sum /tools/
RUN go -C /tools install tool

# Stage 2: Production (This is what Podman uses)
FROM docker.io/library/debian:13.7-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
WORKDIR /app

ARG APP_VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/cmiic/file-api" \
    org.opencontainers.image.title="File Upload API" \
    org.opencontainers.image.version="${APP_VERSION}"

# Create non-root user
RUN groupadd -r fileapi && useradd -r -g fileapi fileapi

RUN apt update && apt install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/file-api .
COPY --from=builder /third-party-licenses /app/THIRD_PARTY_LICENSES
COPY LICENSE /app/LICENSE

# Create data directory with correct ownership
RUN mkdir -p /data/files && chown -R fileapi:fileapi /data/files

ENV STORAGE_PATH="/data/files"
ENV PORT=8080

# Run as non-root user
USER fileapi

EXPOSE 8080

CMD ["./file-api"]