# Security Policy

## Reporting a vulnerability

Please report security issues **privately** using GitHub's [private vulnerability reporting](https://github.com/cmiic/file-api/security/advisories/new). Do not open a public issue, pull request, or discussion for a suspected vulnerability.

If you cannot use GitHub advisories, email <c@miic.at>.

Please include the affected version or image digest, a description of the impact, and the smallest reproduction you can manage. You will get an acknowledgement, and a fix or an explanation of why the behavior is intended. This is a small project maintained by one person, so please allow reasonable time before disclosing publicly.

## Supported versions

Only the most recent release receives security fixes. Released images are immutable and identified by digest; upgrade rather than expecting a patched rebuild of an old tag.

## Deployment assumptions

The security of a deployment depends on assumptions this repository cannot enforce on its own. They are stated here so they can be checked rather than guessed:

- **File API is designed to sit behind a reverse proxy** that terminates TLS and applies caching, rate limiting, and request-body limits. Its own limits are defense in depth, not a replacement.
- **Moderation is optional and unauthenticated.** It is off unless `MALWARE_SCANNER_URL` or `MEDIA_SCREENER_URL` is set. When set, File API sends upload content to those endpoints over the internal network with no authentication and no TLS, so their reachability is part of File API's trust boundary: whatever can reach them can submit content to them, and whatever can impersonate them can influence a moderation verdict. Those services have their own security policies.
- **`JWT_SECRET` is required and fails closed.** The service refuses to start when it is missing or shorter than 32 characters. It is an HMAC secret shared with every application that issues tokens; treat it as a credential.
- **Uploads require a token with the `upload` scope**, and private file access checks the token's client code against the requested path.

## In scope

- Authentication or authorization bypass: serving a private file without a valid token, or across client codes
- Path traversal or filename handling that escapes the storage root
- Server-side request forgery in the fetch path, or bypass of its scheme and private-address restrictions
- Token forgery, replay, or scope escalation
- Bypass of the configured upload size limit leading to unbounded resource use

## Not a vulnerability

- **Denial of service through the deliberately public surface** — `GET`/`HEAD /files/` for non-private paths, and `/health` — or resource exhaustion when the documented reverse-proxy rate and body limits are absent. Public files are public by design; upload, resize, and metadata endpoints all require a token.
- **Missing TLS.** TLS termination is the reverse proxy's responsibility by design.
- Findings that require an already-compromised host, container runtime, or `JWT_SECRET`.
