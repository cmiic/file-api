# File-API Moderation Integration

This document describes how file-api integrates with the Malware Scanner and Media Screener
for automated content moderation. Scanning is performed directly (no external gateway) as a
fail-fast layer before any future cloud-based moderation.

## Goals

- Public uploads trigger async malware + NSFW scanning immediately after storage.
- Private uploads are not scanned automatically (future: on-demand scanning by trusted clients).
- No database changes required; scan metadata is stored on disk.
- Admin notifications via email for detections.
- Malware: delete file, keep metadata.
- NSFW: flag file, keep both file and metadata for review.

## Architecture

```pre
┌─────────────┐     ┌─────────────┐
│  file-api   │────▶│  malware-   │
│  (Go)       │     │  scanner    │
│             │     │  :8081      │
│  async scan │     └─────────────┘
│  goroutine  │
│             │     ┌─────────────┐
│             │────▶│  media-     │
│             │     │  screener   │
│             │     │  :8080      │
└─────────────┘     └─────────────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐
│  SMTP       │     │  /data/     │
│  Gateway    │     │  scan-meta/ │
└─────────────┘     └─────────────┘
```

## Configuration

Environment variables for file-api:

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MALWARE_SCANNER_URL` | *(empty)* | URL of malware scanner (e.g., `http://malware-scanner:8081`) |
| `MEDIA_SCREENER_URL` | *(empty)* | URL of media screener (e.g., `http://media-screener:8080`) |
| `SCAN_TIMEOUT_MS` | `30000` | HTTP timeout for scanner calls |
| `SCAN_META_PATH` | `/data/scan-meta` | Directory for scan metadata files |
| `SCAN_QUEUE_PATH` | `/data/scan-queue` | Directory for retry queue |
| `SMTP_HOST` | *(empty)* | SMTP server for notifications |
| `SMTP_PORT` | `25` | SMTP port |
| `SMTP_FROM` | `file-api@localhost` | Sender address |
| `ALERT_EMAILS` | *(empty)* | Comma-separated admin emails |

If `MALWARE_SCANNER_URL` and `MEDIA_SCREENER_URL` are both empty, moderation is disabled.

## Upload Flow

1. **Upload completes** — file stored to disk with SHA1 deduplication.
2. **Response returned immediately** — no blocking on scan.
3. **Async goroutine triggered** (public files only):
   - Run malware scan via `/scan` endpoint.
   - If infected: delete file, save metadata, send email alert.
   - If clean: run NSFW scan via `/classify` endpoint.
   - If unsafe: save metadata with `flagged` status, send email alert.
   - If clean: save metadata with `clean` status.
4. **On scanner error**: queue for retry with exponential backoff (5 retries max).

## Scan Order

1. **Malware first** — faster (~20-100ms), security-critical, blocks dangerous content.
2. **NSFW second** — slower (~100-500ms), policy violation, flags for review.

If malware is detected, NSFW scan is skipped (file deleted anyway).

## On-Disk Metadata

Stored at `SCAN_META_PATH/{relative_path}.json`:

```json
{
  "status": "clean|flagged|malware|error",
  "requested_at": "2026-01-18T12:00:00Z",
  "completed_at": "2026-01-18T12:00:01Z",
  "malware": {
    "infected": false,
    "malware_name": null,
    "scan_time_ms": 45.2
  },
  "nsfw": {
    "unsafe": false,
    "confidence": 0.12,
    "detected_classes": []
  },
  "error": null
}
```

Written atomically (`.tmp` then rename).

## Metadata Endpoint

Read scan results for internal tools:

- **Endpoint**: `GET /meta/files/{relative_path}`
- **Auth**: JWT with `scan:read` scope
- **Response**: Metadata JSON or `404` if not found
- **Headers**: `Cache-Control: private, no-store`

## Email Notifications

Minimal alert format:

**Malware detected:**

```text
Subject: [file-api] Malware detected and removed

Malware detected in uploaded file.

File: 2026/1/document-abc123.pdf
Malware: Trojan.GenericKD.12345
Action: File deleted, metadata preserved
```

**NSFW detected:**

```text
Subject: [file-api] NSFW content detected

NSFW content detected in uploaded file.

File: 2026/1/image-abc123.jpg
Confidence: 0.87
Classes: FEMALE_BREAST_EXPOSED
Action: File flagged for review
```

## Retry Queue

Failed scans are queued at `SCAN_QUEUE_PATH/{filename}.json`:

```json
{
  "relative_path": "2026/1/file.jpg",
  "abs_path": "/data/files/2026/1/file.jpg",
  "client_code": "",
  "is_public": true,
  "queued_at": "2026-01-18T12:00:00Z",
  "retries": 0,
  "last_error": "connection refused"
}
```

Background processor runs every 5 minutes with exponential backoff:

- Retry 1: after 5 minutes
- Retry 2: after 10 minutes
- Retry 3: after 20 minutes
- Retry 4: after 40 minutes
- Retry 5: after 80 minutes (max, then give up)

## Future: Moderation Gateway

The current implementation uses direct scanner calls for simplicity. A future Moderation Gateway
could provide:

- Unified policy management across scanners and cloud providers (GCP Vision, OpenAI).
- Additional features: labels, text extraction, faces, crop hints.
- Callback-based async processing for large files.
- Centralized audit logging.

The metadata format is designed to be forward-compatible with gateway responses.
