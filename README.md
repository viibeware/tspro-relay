# TS Pro Relay

[![Docker Hub](https://img.shields.io/badge/docker-hyprlab%2Ftspro--relay-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/hyprlab/tspro-relay)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

A small self-hosted **outbound email relay** for
[Trusted Servants Pro](https://hub.docker.com/r/hyprlab/trusted-servants-pro),
for running the portal on hosts that **block outbound SMTP ports**
(25/465/587) — most notably DigitalOcean droplets, but also many other
cloud providers.

Instead of the app connecting to an SMTP server directly, it POSTs each
message as JSON to this relay over **HTTPS** (behind a reverse proxy).
The relay runs somewhere with SMTP egress and performs the actual
delivery. SMTP credentials live only on the relay, never in the app's
database.

```
TSP app  ──HTTPS──▶  TS Pro Relay  ──SMTP:587/465──▶  mail server
(no SMTP egress)     (this repo)                      (Gmail, SES, …)
```

## Admin interface

The relay ships a **web interface with a login** so an operator can set
everything up without editing JSON or env files:

- **Transaction Log** — every send (and unauthorized attempt) with
  status, sender, recipients, subject, and any error. Counters for
  total / sent / failed / unauthorized.
- **Settings** — the upstream SMTP server, a one-click **API key**
  (reveal / copy / regenerate), an allowed-sender allowlist, attachment
  size limit, a **Send test email** button, optional **Cloudflare
  Turnstile** bot protection on the login page, and the **admin
  password**.

Configuration and the log are stored in a SQLite DB on the `./data`
volume. The SMTP password and API key are encrypted at rest with a key
derived from `RELAY_SECRET_KEY`.

## Install

The published image is on Docker Hub as
[`hyprlab/tspro-relay`](https://hub.docker.com/r/hyprlab/tspro-relay).
You don't need to clone this repo to run it — just a `docker-compose.yml`
and a `.env`.

### 1. Create a working directory

```bash
mkdir tspro-relay && cd tspro-relay
```

### 2. Create `docker-compose.yml`

```yaml
services:
  relay:
    image: hyprlab/tspro-relay:latest
    # The relay serves BOTH the admin UI and the JSON send API on one port.
    # In production put a TLS-terminating reverse proxy in front (see below)
    # and have the TSP app POST to the https:// URL.
    ports:
      - "0.0.0.0:8026:8000"
    environment:
      # Signs sessions AND derives the at-rest encryption key for the
      # stored SMTP password + API key. REQUIRED — set a long random value.
      #   python -c "import secrets; print(secrets.token_urlsafe(48))"
      - RELAY_SECRET_KEY=${RELAY_SECRET_KEY:?set RELAY_SECRET_KEY in .env}
      # First-boot admin login (ignored once the admin row exists).
      # REQUIRED — there is no admin/admin fallback.
      - RELAY_ADMIN_USER=${RELAY_ADMIN_USER:-admin}
      - RELAY_ADMIN_PASSWORD=${RELAY_ADMIN_PASSWORD:?set RELAY_ADMIN_PASSWORD in .env}
      - RELAY_LOG_LEVEL=${RELAY_LOG_LEVEL:-INFO}
      # Set to 1 ONLY for local HTTP testing without TLS.
      - RELAY_INSECURE_COOKIES=${RELAY_INSECURE_COOKIES:-}
      # Reverse proxies (IPs/CIDRs) whose X-Forwarded-For may be trusted
      # for logged client IPs. Leave blank to log the direct peer.
      - RELAY_TRUSTED_PROXIES=${RELAY_TRUSTED_PROXIES:-}
      # Per-IP ceiling on /api/send requests per hour (0 disables).
      - RELAY_SEND_PER_HOUR=${RELAY_SEND_PER_HOUR:-60}
    volumes:
      - ./data:/data        # relay.db (settings, admin, transaction log)
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=5).status==200 else 1)"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
```

### 3. Create `.env`

```bash
# Signs login sessions AND encrypts the stored SMTP password + API key.
# REQUIRED. Generate a strong value:
#   python -c "import secrets; print(secrets.token_urlsafe(48))"
RELAY_SECRET_KEY=replace-with-a-long-random-value

# First-boot admin login (change the password from the UI afterwards).
# REQUIRED — the container refuses to start without a password.
RELAY_ADMIN_USER=admin
RELAY_ADMIN_PASSWORD=change-me-on-first-login
```

### 4. Start it

```bash
docker compose up -d
```

The relay (UI + API) is now on **port 8026**. Open `http://<host>:8026`,
sign in, and on **Settings** fill in your SMTP server and copy the API
key.

> **Building from source instead?** Clone this repo and use
> `image:` → `build: .` in the compose file, then
> `docker compose up -d --build`.

## TLS in production

The login cookie and Bearer token must never cross plaintext. Put a
reverse proxy in front that terminates HTTPS and proxies to
`127.0.0.1:8026`.

**Caddy**
```
relay.example.com {
    reverse_proxy 127.0.0.1:8026
}
```

**nginx**
```
location / {
    proxy_pass http://127.0.0.1:8026;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

Then point the TSP app at `https://relay.example.com`.

Two proxy-related settings worth adding:

- **HSTS** — the relay does not emit `Strict-Transport-Security` itself
  (it never knows whether TLS is in play); set it at the proxy, e.g.
  nginx `add_header Strict-Transport-Security "max-age=31536000" always;`
  (Caddy sends sensible defaults with a `header` directive).
- **`RELAY_TRUSTED_PROXIES`** — set it to your proxy's address as seen by
  the relay (for the compose setup above, the docker bridge, e.g.
  `172.16.0.0/12`). Only then is `X-Forwarded-For` honoured for the
  client IPs shown in the Transaction Log; otherwise the header is
  ignored so clients can't spoof their logged address.

## Configure the TSP app

In the portal: **Settings → Domain / Email**

1. **Sending method** → *API relay (HTTPS)*
2. **Relay URL** → `https://relay.example.com`
3. **Relay API key** → the key from the relay's Settings page
4. **From email / From name** → your sender identity
5. **Save Email Settings**, then **Send Test**. The result also lands in
   the relay's Transaction Log.

## API (consumed by the TSP app)

### `POST /api/send`
Header: `Authorization: Bearer <api-key>` · Body: JSON

```json
{
  "from_email": "noreply@example.com",
  "from_name": "Trusted Servants Pro",
  "to": ["someone@example.org"],
  "subject": "Hello",
  "text": "Plain-text body",
  "html": "<p>Optional HTML body</p>",
  "reply_to": "replies@example.org",
  "reply_to_name": "Replies",
  "attachments": [
    {"filename": "doc.pdf", "mime_type": "application/pdf", "content_b64": "..."}
  ]
}
```

`200 {"ok": true}` on success; otherwise `{"ok": false, "error": "..."}`
with `401` (bad key), `403` (From not allowed), `413` (attachments or
request body too big), `429` (per-IP rate limit — see
`RELAY_SEND_PER_HOUR`), or `502` (SMTP failed — the response is generic;
delivery details appear only in the relay's Transaction Log). Messages
are capped at 100 recipients (`400`).

### `GET /healthz`
Unauthenticated liveness probe; returns `{"ok": true}` only.
Configuration state is available to authenticated callers via
`GET /api/health` (Bearer-authenticated).

## Environment variables

| Var | Required | Default | Notes |
|-----|----------|---------|-------|
| `RELAY_SECRET_KEY` | ✅ | — | Signs sessions + encrypts stored secrets (HKDF-derived keys). The relay **refuses to start** without it. Keep it stable — rotating it invalidates the stored SMTP password + API key. Use 32+ chars. |
| `RELAY_ADMIN_USER` | | `admin` | First-boot admin username. |
| `RELAY_ADMIN_PASSWORD` | ✅ | — | First-boot password (compose refuses to start without it). If it is ever seeded as `admin`, the UI forces a password change at first login. |
| `RELAY_TRUSTED_PROXIES` | | — | Comma-separated IPs/CIDRs of reverse proxies whose `X-Forwarded-For` is trusted for logged client IPs. Blank = log the direct peer. |
| `RELAY_SEND_PER_HOUR` | | `60` | Per-IP ceiling on `/api/send` requests per hour; `0` disables. Login is separately throttled (5 failures/minute per IP). |
| `RELAY_LOG_LEVEL` | | `INFO` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR`. |
| `RELAY_INSECURE_COOKIES` | | — | Set `1` only for local HTTP testing (no TLS). |
| `RELAY_DATA_DIR` | | `/data` | Where `relay.db` lives. |

Everything else (SMTP host/port/security/credentials, API key, allowed
senders, attachment limit, Turnstile keys) is managed from the
**Settings** page.

## Local end-to-end test

`docker-compose.test.yml` (in this repo) brings up the relay built from
source plus a **Mailpit** SMTP sink to verify delivery. Both the relay
UI and Mailpit's inbox are bound to localhost only, and the stack
requires `RELAY_SECRET_KEY` + `RELAY_ADMIN_PASSWORD` in the environment.
See the comments at the top of that file.

## Security notes

Built in:

- Sessions and at-rest encryption keys are HKDF-derived from
  `RELAY_SECRET_KEY`; the relay refuses to boot without one.
- Forced password change whenever the admin account carries the seeded
  default password.
- Login lockout (5 failures/minute per IP) and a per-IP `/api/send`
  ceiling (`RELAY_SEND_PER_HOUR`).
- Security response headers on every page (CSP, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`).
- 100-recipient cap per message; SMTP error details are kept out of API
  responses (they appear in the Transaction Log only).
- Settings/credential changes and log clears are recorded in a
  `settings_audit` table inside `relay.db` (who / when / from where).
- The container runs as an unprivileged user (uid 1000).

Operator checklist:

- Always run the UI + API behind TLS in production, and set **HSTS** at
  the reverse proxy (see *TLS in production*).
- **Populate the Allowed From list.** Blank accepts any sender — set it
  so a leaked key can't spoof arbitrary addresses.
- Keep `RELAY_SECRET_KEY` long (32+ chars), random, and stable.
- Set `RELAY_TRUSTED_PROXIES` so Transaction Log IPs are accurate and
  spoof-proof.
- The API key is a plain bearer token with no replay protection — TLS
  end-to-end between the TSP app and the relay is what protects it.
- Optionally enable **Cloudflare Turnstile** (Settings → Login bot
  protection) to challenge the sign-in page. The relay needs outbound
  HTTPS to `challenges.cloudflare.com` for verification, and verifies the
  token's `hostname` matches this relay.

## License

Released under the **GNU Affero General Public License v3.0** — see
[LICENSE](LICENSE). If you run a modified version as a network service,
the AGPL requires you to offer your users the corresponding source.
