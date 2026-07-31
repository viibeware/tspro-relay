# Changelog

All notable changes to TS Pro Relay are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-07-31

Security-focused release following an internal security review. Existing
installs upgrade in place: stored secrets are transparently re-encrypted
on first boot, and accounts still using the seeded default password are
forced to change it at next login.

### Security
- **No more `admin/admin` fallback.** `docker-compose.yml` now refuses to
  start without `RELAY_ADMIN_PASSWORD` (same pattern as
  `RELAY_SECRET_KEY`). If an account is ever seeded with — or still
  carries — the default password, the UI forces a password change at
  login before anything else can be done.
- **Dependency upgrades** clearing all known advisories (`pip-audit`
  clean): Flask ≥ 3.1.3 (PYSEC-2026-2151) and cryptography ≥ 48.0.1
  (PYSEC-2026-1284, PYSEC-2026-2141, PYSEC-2026-35, GHSA-537c-gmf6-5ccf).
  A GitHub Actions workflow now runs `pip-audit` on every push/PR and
  weekly.
- **Open-redirect fix** on the login `next` parameter
  (scheme-relative `//host` URLs were previously accepted).
- **Rate limiting**: login lockout after 5 failed attempts/minute per IP,
  and a per-IP ceiling on `/api/send` (`RELAY_SEND_PER_HOUR`, default 60,
  `0` disables) that also bounds API-key guessing. Throttling events
  appear in the Transaction Log as `rate_limited`.
- **Hardened key handling**: the relay refuses to boot without
  `RELAY_SECRET_KEY` (no more silent insecure fallback), warns when it is
  shorter than 32 chars, and derives the session + Fernet keys via HKDF
  instead of raw SHA-256. Secrets stored by earlier releases are
  re-encrypted automatically at startup.
- **Security response headers** on every response: a strict
  `Content-Security-Policy` (inline UI scripts moved to `static/app.js`;
  the Turnstile allowance is added only on the login page when enabled),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and
  `Referrer-Policy: no-referrer`. HSTS is documented for the
  TLS-terminating proxy.
- **`X-Forwarded-For` is no longer trusted unconditionally** — logged
  client IPs use the direct peer unless the request came from
  `RELAY_TRUSTED_PROXIES` (comma-separated IPs/CIDRs).
- **SMTP error hygiene**: API callers now get a generic
  `"SMTP delivery failed"`; upstream error detail (hostnames, banners) is
  kept to the internal log and a length-capped copy in the admin-only
  Transaction Log.
- **Container hardening**: the image runs as an unprivileged `relay`
  user (uid 1000); the test stack binds the relay UI to localhost only,
  requires an env-provided admin password, and pins Mailpit by digest.
- **Endpoint minimization**: `/healthz` now returns `{"ok": true}` only
  (configuration state moved behind the authenticated `/api/health`);
  oversized `/api/send` bodies are rejected from `Content-Length` before
  the payload is read, and attachments are size-checked before base64
  decoding.
- **Misc hardening**: 100-recipient cap per message, constant-time admin
  username comparison, Turnstile `hostname` verification, and a
  `settings_audit` table recording settings/credential changes and log
  clears (who / when / from where).

## [0.1.2] — 2026-07-04

### Changed
- **Project moved to the `hyprlab` organization.** The source repo is now
  [`hyprlab/tspro-relay`](https://github.com/hyprlab/tspro-relay) on GitHub
  and the published image is [`hyprlab/tspro-relay`](https://hub.docker.com/r/hyprlab/tspro-relay)
  on Docker Hub. All references to the former `viibeware` account have been
  updated. No code or behavior changes — pull `hyprlab/tspro-relay:latest`
  (or `:0.1.2`) and recreate the container.

## [0.1.1] — 2026-05-31

### Added
- **Authenticated health probe** (`GET /api/health`) — Bearer-authenticated,
  returns `{ok, configured, smtp_host_set, version}`. The Trusted Servants
  Pro portal calls it to validate the relay URL **and** the shared API key
  behind its "Test connection" status pill (Settings → Domain / Email),
  without sending a message. Unlike `/healthz` — which stays unauthenticated
  for liveness checks — this rejects a missing or incorrect key with `401`,
  and reports whether the relay's own upstream SMTP delivery is configured.

## [0.1.0] — 2026-05-30

Initial public release.

### Added
- **JSON send API** (`POST /api/send`) consumed by the Trusted Servants
  Pro portal: Bearer-authenticated, accepts plain-text + HTML bodies,
  Reply-To, and base64 attachments; delivers via the configured upstream
  SMTP server.
- **Admin web interface** with a session login:
  - **Transaction Log** — every send and unauthorized attempt, with
    status badges and total / sent / failed / unauthorized counters.
  - **Settings** — upstream SMTP server, one-click API key
    (reveal / copy / regenerate), allowed-sender allowlist, attachment
    size limit, send-test-email button, and admin credentials.
- **Cloudflare Turnstile** bot protection (optional) on the login page,
  configurable from Settings.
- **Encryption at rest** (Fernet) for the SMTP password and API key,
  keyed from `RELAY_SECRET_KEY`.
- `GET /healthz` unauthenticated liveness probe.
- SQLite storage on a `/data` volume with additive, race-safe startup
  migrations.
- Static-asset cache busting (`?v=<mtime>`) so UI changes appear on a
  normal refresh.
- Dockerfile (gunicorn) + `docker-compose.yml` for production and
  `docker-compose.test.yml` (with a Mailpit sink) for local end-to-end
  testing.
- Branded UI matched to Trusted Servants Pro (TS Pro logo, gold accent).

[0.2.0]: https://github.com/hyprlab/tspro-relay/releases/tag/v0.2.0
[0.1.2]: https://github.com/hyprlab/tspro-relay/releases/tag/v0.1.2
[0.1.1]: https://github.com/hyprlab/tspro-relay/releases/tag/v0.1.1
[0.1.0]: https://github.com/hyprlab/tspro-relay/releases/tag/v0.1.0
