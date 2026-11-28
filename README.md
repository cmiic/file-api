# File Upload API

A high-performance file management API using Go and imgproxy for on-demand image processing.

## License

Copyright (c) 2026 Christoph Stadlbauer. File API and its PDF sidecar are licensed under the [MIT License](LICENSE). Both release images include the Go toolchain and module dependency license texts under `/app/THIRD_PARTY_LICENSES`. The PDF sidecar additionally retains Poppler and Debian package notices under `/usr/share/doc` and `/usr/share/common-licenses`. Each GitHub release attaches an SPDX SBOM of both images, generated from the published image digests, and states where Debian's Corresponding Source for every Debian package in them is available at those exact versions, linking the sidecar's Poppler source directly.

## Architecture

File API stores uploads, authorizes access with JWTs, and serves files. Two
rendering services sit alongside it and read their source files back from File
API, and two scanners screen every upload asynchronously.

```pre
                 ┌─▶ imgproxy (:8081) ──────▶ file-api (image resizing)
                 │
 client ────────▶├─▶ file-api (:8080) ──┬──▶ malware-scanner-api ──▶ clamav
                 │                      └──▶ media-screener-api
                 │
                 └─▶ pdf-sidecar (:8082) ───▶ file-api (PDF thumbnails)
```

- **file-api**: Go service handling uploads, JWT auth, and file serving
- **imgproxy**: On-demand image resizing
- **pdf-sidecar**: PDF thumbnail rendering (Poppler), pulls source files from file-api
- **[malware-scanner-api](https://github.com/cmiic/malware-scanner-api) → clamav**: asynchronous malware scanning of uploads
- **[media-screener-api](https://github.com/cmiic/media-screener-api)**: asynchronous media/content screening of uploads

All six services are designed to run on one host behind a reverse proxy that
terminates TLS and applies caching, rate limiting, and upload limits. Only File
API, imgproxy, and the PDF sidecar need to be reachable from that proxy, so
`compose.dev.yaml` publishes ports for those three and reaches ClamAV and the
two scanners over the Compose network only. Consult each scanner's own
documentation before changing that.

Production topology, TLS, digest pinning, host provisioning, upgrade and
rollback procedures, and the database integration plugin are maintained
separately and are not part of this repository.

## Development

Requires Docker (or Podman) with Compose. [compose.dev.yaml](compose.dev.yaml)
builds File API and the PDF sidecar from this checkout and pulls the remaining
services from published images. Every port is bound to loopback.

One-time setup. The NudeNet model is deliberately not redistributed in the
media screener image, so provision it with that repository's script, which
verifies its checksum:

```bash
mkdir -p tmp
/path/to/media-screener-api/scripts/provision-model.sh tmp/640m.onnx

printf 'JWT_SECRET=%s\nMEDIA_MODEL_FILE=./tmp/640m.onnx\n' \
  "$(openssl rand -hex 32)" > .env
```

Compose reads `.env` from this directory, so afterwards:

```bash
docker compose -f compose.dev.yaml up --build
```

Neither variable has a default. File API exits on startup when `JWT_SECRET` is
missing or shorter than 32 characters, and the same secret must be configured in
every application that issues File API tokens. `MEDIA_MODEL_FILE` is required
rather than defaulted because the Docker daemon silently creates a directory for
a missing bind source, which would otherwise mount an empty directory as the
model.

Host ports default to 8080 (File API), 8081 (imgproxy), and 8082 (PDF sidecar).
Set `FILE_API_PORT`, `IMGPROXY_PORT`, or `PDF_SIDECAR_PORT` when something else
already holds one. Every mapping's host side is pinned to `127.0.0.1`.

Verify the stack:

```bash
curl http://127.0.0.1:8080/health
docker compose -f compose.dev.yaml ps
docker compose -f compose.dev.yaml logs -f file-api
```

Stop it, optionally discarding the stored files:

```bash
docker compose -f compose.dev.yaml down
docker compose -f compose.dev.yaml down -v   # destructive
```

To iterate on the Go service alone, [.devcontainer](.devcontainer) builds the
`dev` stage and runs `air` for live reloading.

### Tests

```bash
(cd app && go vet ./... && go test ./...)
(cd pdf-sidecar && go vet ./...)
```

### Dependency image pinning

Every external image in `compose.dev.yaml` is a literal `tag@sha256:digest`
reference, so a checkout resolves to the exact bytes that were tested against it.
Dependabot monitors the repository root and proposes digest and in-track tag
updates.

## Configuration

File API reads its configuration from the environment. `JWT_SECRET` (or
`JWT_SECRET_FILE`) is required; everything else has a default.

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `JWT_SECRET` / `JWT_SECRET_FILE` | — | Token signing secret, minimum 32 characters |
| `PORT` | `8080` | Listen port |
| `BASE_PATH` | `/data/files` | Storage root |
| `MAX_UPLOAD_SIZE` | `209715200` | Upload limit in bytes |
| `MAX_FILENAME_LEN` | `60` | Maximum stored filename length |
| `DELETE_MAX_AGE` | empty (disabled) | Enables `DELETE /files/` for files younger than this Go duration, e.g. `24h`, or for any age with `unlimited` |
| `DELETE_MAX_AGE_PRIVATE` | `DELETE_MAX_AGE` | The same for private files, overriding `DELETE_MAX_AGE` for them |
| `MALWARE_SCANNER_URL` | empty (disabled) | Malware scanner base URL |
| `MEDIA_SCREENER_URL` | empty (disabled) | Media screener base URL |
| `SCAN_TIMEOUT_MS` | `30000` | Per-scanner HTTP timeout |
| `SCAN_META_PATH` | `/data/scan-meta` | Scan result metadata |
| `SCAN_QUEUE_PATH` | `/data/scan-queue` | Retry queue for failed scans |
| `SMTP_HOST` | empty (disabled) | Alert mail host |
| `SMTP_PORT` | `25` | Alert mail port |
| `SMTP_FROM` | `file-api@localhost` | Alert sender |
| `ALERT_EMAILS` | empty | Comma-separated alert recipients |

Moderation behavior, on-disk scan metadata, the retry queue, and the metadata
endpoint are documented in
[docs/moderation-integration.md](docs/moderation-integration.md).

## URL Patterns

| Use Case | URL |
| -------- | --- |
| Original file | `/files/2025/01/abc123.jpg` |
| Private file | `/files/cli/CLIENTCODE/2025/01/abc123.jpg` |
| Thumbnail (240px) | `/files-rs/rs:fit:240/plain/2025/01/abc123.jpg` |
| Large (1920px) | `/files-rs/rs:fit:1920/plain/2025/01/abc123.jpg` |
| Custom crop | `/files-rs/rs:fill:300:200/g:ce/plain/2025/01/abc123.jpg` |

The `/files-rs/` prefix is shared: requests for `.pdf` sources are routed to the
PDF sidecar and everything else to imgproxy. A reverse proxy in front of the
stack should constrain the accepted resize grammar rather than passing arbitrary
imgproxy options through.

The upload API is described in [docs/file-upload.yml](docs/file-upload.yml) and
rendered at <https://cmiic.github.io/file-api/>.

## Deleting files

The store is write-once by design: URLs are shared across applications and embedded in places such as newsletters that cannot be updated once sent. Deletion is therefore opt-in and narrow. It suits the accidental upload that is noticed shortly after it happens, and an application that uses File API as backing storage and keeps track of what it stored.

Set `DELETE_MAX_AGE` or `DELETE_MAX_AGE_PRIVATE` to register `DELETE /files/{path}` and `DELETE /files/cli/{CLI_CODE}/{path}`. Each takes a positive Go duration (`30m`, `24h`) or the keyword `unlimited`, which allows deletion at any age. Go durations have no unit for days or years. A value that does not parse, or is zero or negative, stops the service at startup rather than silently changing the window.

| `DELETE_MAX_AGE` | `DELETE_MAX_AGE_PRIVATE` | Public files | Private files |
| ---------------- | ------------------------ | ------------ | ------------- |
| unset | unset | off | off |
| `24h` | unset | younger than 24h | younger than 24h |
| unset | `unlimited` | off | any age |
| `24h` | `unlimited` | younger than 24h | any age |
| `unlimited` | unset | any age | any age |

Where deletion is off, the request answers `405`. On a deployment with a window for private files only, a public path answers `401` first when the request has no valid token, and `403` when the token lacks the `delete` scope.

A delete succeeds with `204` only when all of the following hold. Otherwise it answers `403` (missing scope, foreign client code, token bound to another file, or window elapsed), `404` (no such file), or `400` (invalid path).

- The token carries the `delete` scope. Upload tokens do not, so a leaked or over-broad upload token cannot remove anything.
- For a private path, the token's `cli_code` matches the path, as for upload.
- The token's `delete_path` claim is exactly the path of this file, as an upload returned it in `orig.name`. Mint a token per file, with a short `exp`, once your application has established that the caller may delete it. A session token shared across requests names no file and cannot delete anything.
- The file is within the window for its class. The age is the stored file's mtime, which is the time of the first upload: a deduplicated re-upload of identical content returns the existing path without touching the file. Under a finite window an old file cannot be removed even with a valid token, which bounds what a wrongly minted token can do to the archive.

The claims of a token that may delete one private file:

```json
{
  "scopes": ["delete"],
  "cli_code": "ACME",
  "delete_path": "cli/ACME/2026/11/report-b01cf64a61176d0be3cdf9c8e091ea4e96333d83.pdf",
  "exp": 1794000060
}
```

What deletion does not do:

- It does not purge caches. The reverse proxy and imgproxy cache public files with a long validity, and File API itself marks them cacheable for a year, so the bytes can stay reachable from a cache after a `204` until that validity runs out. Weigh that before setting `DELETE_MAX_AGE` to `unlimited`.
- It does not distinguish uploaders. Identical content uploaded under the same filename in the same month shares one path, within a client code or among public uploads, and a delete removes it for everyone holding that path. File API does not track who that is: an application that may reference a file more than once, or that shares a client code with another application, has to account for it.
- A finite window does not survive a restore that resets timestamps. Restore the storage volume with mtimes preserved (`rsync -a`, `cp -p`), or every restored file looks freshly uploaded and falls inside the window.

When moderation is enabled the scan metadata is kept and its status set to `deleted`, so a consumer polling `/meta/files/{path}` before persisting its own record sees that the file is gone. See [docs/moderation-integration.md](docs/moderation-integration.md).

## References

- [imgproxy Documentation](https://docs.imgproxy.net/)
