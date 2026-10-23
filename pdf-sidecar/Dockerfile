# Stage 1: Build
FROM docker.io/library/golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS builder
WORKDIR /app

COPY go.mod ./
RUN go mod download
# Collect the license texts of the Go toolchain and every module. license_files
# names the files of one module directory that count as its license; any
# further arguments are handed to find, so the same selection both checks that
# a module has a license and copies it.
RUN license_files() { \
        dir="$1"; shift; \
        find "$dir" -maxdepth 1 -type f \
            \( -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' -o -iname 'PATENTS*' \) "$@"; \
    }; \
    mkdir -p /third-party-licenses/go /third-party-licenses/modules \
    && cp /usr/local/go/LICENSE /usr/local/go/PATENTS /third-party-licenses/go/ \
    && go list -m -f '{{if .Version}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}' all > /tmp/modules.txt \
    && while IFS='|' read -r module version directory; do \
        if test -z "$module"; then continue; fi; \
        if test -z "$directory"; then echo "Missing module directory: $module $version" >&2; exit 1; fi; \
        destination="$(printf '%s' "$module" | tr '/.' '__')-$version"; \
        if test -z "$(license_files "$directory")"; then \
            echo "Missing module license: $module $version" >&2; exit 1; \
        fi; \
        mkdir -p "/third-party-licenses/modules/$destination"; \
        license_files "$directory" -exec cp -t "/third-party-licenses/modules/$destination" {} +; \
    done < /tmp/modules.txt \
    && { go version; cut -d '|' -f 1,2 /tmp/modules.txt | tr '|' ' '; } > /third-party-licenses/NOTICE.txt

COPY . .

# Static build for production
# Set by the release workflow from the git tag (without its leading "v"); local
# and CI builds keep "dev". Declared just before the build step so a new
# version only rebuilds the binary, not the module and license layers.
ARG APP_VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${APP_VERSION}" -o pdf-sidecar .

# Stage 2: Production
FROM docker.io/library/debian:13.7-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
WORKDIR /app

ARG APP_VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/cmiic/file-api" \
    org.opencontainers.image.title="File API PDF Sidecar" \
    org.opencontainers.image.version="${APP_VERSION}"

# Create non-root user
RUN groupadd -r pdfsidecar && useradd -r -g pdfsidecar pdfsidecar

# Recommended packages are left out except poppler-data, the one Poppler
# needs: its CMaps render text in CJK and other predefined encodings that a
# PDF does not embed. The rest would be GnuPG tools, Kerberos, LDAP and SASL
# plugins and bash completion that nothing here uses.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    poppler-utils \
    poppler-data \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/pdf-sidecar .
COPY --from=builder /third-party-licenses /app/THIRD_PARTY_LICENSES
COPY LICENSE /app/LICENSE

ENV PORT=8080

# Run as non-root user
USER pdfsidecar

EXPOSE 8080

CMD ["./pdf-sidecar"]
