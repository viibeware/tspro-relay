# Release Notes

## v0.2.1 — 2026-07-31

Fixes Transaction Log client IPs showing the docker gateway (172.x)
instead of the real caller after upgrading to 0.2.0.

- **`X-Forwarded-For` is trusted as-is again by default**, matching
  0.1.x — no configuration needed behind a single reverse-proxy hop.
- `RELAY_TRUSTED_PROXIES` is now purely opt-in hardening: when set, the
  header is only honoured from those proxy IPs/CIDRs, making logged
  source IPs spoof-proof. Leave it unset for the default behavior.

Upgrading: `docker compose pull && docker compose up -d`. No other
changes since 0.2.0.

## v0.2.0 — 2026-07-31

A security-focused release following an internal security review of the
relay. Upgrading is drop-in for correctly-configured installs — stored
secrets are re-encrypted automatically on first boot — but note the two
**breaking requirements** below.

### Breaking / action required

- **`RELAY_ADMIN_PASSWORD` is now required.** The compose file refuses to
  start without it — there is no `admin/admin` fallback. Installs still
  using the seeded default password are forced to change it at next login
  before the rest of the UI unlocks.
- **`RELAY_SECRET_KEY` is now enforced at boot.** The relay exits instead
  of silently falling back to an insecure development key.

### Security highlights

- All dependency advisories cleared (Flask ≥ 3.1.3,
  cryptography ≥ 48.0.1); `pip-audit` now runs in CI.
- Login lockout (5 failures/minute per IP) and a per-IP `/api/send`
  rate ceiling (`RELAY_SEND_PER_HOUR`, default 60/hour).
- Open-redirect fix on the login `next` parameter.
- HKDF-based key derivation for sessions and at-rest encryption, with
  transparent migration of previously stored secrets.
- Strict security headers (CSP, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`) on every response.
- `X-Forwarded-For` honoured only from `RELAY_TRUSTED_PROXIES`.
- Generic SMTP errors to API callers; detail stays in the admin log.
- Container now runs as an unprivileged user; `/healthz` minimized to a
  bare liveness probe; 100-recipient cap per message; settings changes
  recorded in an audit table.

See `CHANGELOG.md` for the complete list.

## v0.1.2 — 2026-07-04

A maintenance release: the project has moved to the **`hyprlab`**
organization on both GitHub and Docker Hub.

### What's changed

- **New home.** Source is now
  [`hyprlab/tspro-relay`](https://github.com/hyprlab/tspro-relay) and the
  image is [`hyprlab/tspro-relay`](https://hub.docker.com/r/hyprlab/tspro-relay).
  Every reference to the former `viibeware` account has been updated.

There are **no code or behavior changes**. Upgrading is drop-in: pull
`hyprlab/tspro-relay:latest` (or `:0.1.2`) and recreate the container.
No settings or data changes.

## v0.1.1 — 2026-05-31

A small follow-up that makes the portal's relay **connection test**
trustworthy end-to-end.

### What's new

- **Authenticated health endpoint (`GET /api/health`).** Trusted Servants
  Pro's **Settings → Domain / Email** tab now shows a live **connection
  status pill** with a **Test connection** button for the API-relay
  transport. Backing it, the relay gained a Bearer-authenticated health
  probe that confirms both that the relay is reachable *and* that the API
  key matches — and reports whether the relay's own upstream SMTP delivery
  is configured — all without sending a test message. The existing public
  `/healthz` liveness probe is unchanged.

Upgrading is drop-in: pull `hyprlab/tspro-relay:latest` (or `:0.1.1`)
and recreate the container. No settings or data changes.

## v0.1.0 — 2026-05-30

First public release of **TS Pro Relay**, the outbound email relay for
[Trusted Servants Pro](https://hub.docker.com/r/hyprlab/trusted-servants-pro).

It exists so the portal can send mail on hosts that block outbound SMTP
ports (25/465/587) — like DigitalOcean. The app POSTs each message to the
relay over HTTPS; the relay, running somewhere with SMTP egress, delivers
it. SMTP credentials never leave the relay.

### Highlights

- **Self-service web UI** — sign in and configure the upstream SMTP
  server, manage the shared API key, and watch a live transaction log.
  No JSON or env-file editing required.
- **Transaction log** — see exactly what was sent, what failed, and any
  unauthorized attempts, with at-a-glance counters.
- **Secure by default** — Bearer-authenticated API, session login with
  CSRF protection, SMTP password + API key encrypted at rest, optional
  Cloudflare Turnstile on the login page, and a sender allowlist.
- **Drop-in Docker deploy** — `hyprlab/tspro-relay:latest`, one
  `docker-compose.yml` + `.env`, data persisted on a `/data` volume.

### Getting started

See the [README](README.md) for the full install. In short:

```bash
mkdir tspro-relay && cd tspro-relay
# create docker-compose.yml + .env (see README)
docker compose up -d
```

Then open `http://<host>:8026`, sign in, and finish setup on the
Settings page. Run it behind a TLS-terminating reverse proxy in
production.

### License

Released under the GNU Affero General Public License v3.0.
