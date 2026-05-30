# Release Notes

## v0.1.0 — 2026-05-30

First public release of **TS Pro Relay**, the outbound email relay for
[Trusted Servants Pro](https://hub.docker.com/r/viibeware/trusted-servants-pro).

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
- **Drop-in Docker deploy** — `viibeware/tspro-relay:latest`, one
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
