# Stage 1: Build
FROM docker.io/library/golang:trixie AS builder
WORKDIR /app

COPY go.mod ./
RUN go mod download
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

COPY . .

# Static build for production
RUN CGO_ENABLED=0 go build -o pdf-sidecar .

# Stage 2: Production
FROM docker.io/library/debian:trixie-slim
WORKDIR /app

LABEL org.opencontainers.image.source="https://github.com/cmiic/file-api" \
    org.opencontainers.image.title="File API PDF Sidecar"

# Create non-root user
RUN groupadd -r pdfsidecar && useradd -r -g pdfsidecar pdfsidecar

RUN apt update && apt install -y \
    ca-certificates \
    curl \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/pdf-sidecar .
COPY --from=builder /third-party-licenses /app/THIRD_PARTY_LICENSES
COPY LICENSE /app/LICENSE

ENV PORT=8080

# Run as non-root user
USER pdfsidecar

EXPOSE 8080

CMD ["./pdf-sidecar"]
