# Changelog

All notable changes to TS Pro Relay are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to [Semantic Versioning](https://semver.org/).

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

[0.1.2]: https://github.com/hyprlab/tspro-relay/releases/tag/v0.1.2
[0.1.1]: https://github.com/hyprlab/tspro-relay/releases/tag/v0.1.1
[0.1.0]: https://github.com/hyprlab/tspro-relay/releases/tag/v0.1.0
