# Changelog

All notable changes to TS Pro Relay are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to [Semantic Versioning](https://semver.org/).

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

[0.1.0]: https://github.com/viibeware/tspro-relay/releases/tag/v0.1.0
