# Fluxgate — HAProxy control panel

Single-node SNI proxy with per-server encrypted-stream accounting, quotas, shared bandwidth limits, HTTP/WebSocket proxying, and a browser dashboard.

## Deploy

Requires a Linux host with Docker Engine and Docker Compose, with TCP ports 443 and 9389 available.

1. Copy `.env.example` to `.env`. Set `PANEL_DOMAIN` to the primary domain. Generate **different** secrets for `PANEL_TOKEN` and `PANEL_MASTER_KEY`, for example with `openssl rand -base64 48`. Set `PANEL_SECRET_PATH` and `PANEL_TIMEZONE` (IANA name such as `Europe/Moscow`).
2. Point the primary domain and each exact or wildcard SNI name at the host. Wildcard routes need a matching wildcard DNS record.
3. Run `docker compose up -d --build`.
4. Open `https://<PANEL_DOMAIN>:9389/<PANEL_SECRET_PATH>/` and sign in with `PANEL_TOKEN`.

The public HTTPS listener is on TCP 443. The panel is on TCP 9389. All other ports are private to the Compose network namespace. The application generates self-signed certificates for the primary domain and each route. Clients must trust these certificates or deliberately accept the warning. For an unknown SNI, the primary-domain certificate is used, so hostname validation will normally fail before the fallback page is shown.

## How it works

HAProxy inspects the TLS ClientHello on 443 and selects a route by SNI. The Go gateway on a private port counts and shapes both directions of the encrypted TLS stream; its limits are shared across all connections to a route. The stream returns to HAProxy on private port 8443, where TLS ends. HAProxy then forwards HTTP/1.1 or WebSocket traffic to the configured HTTP or HTTPS upstream. The primary domain always shows the configured fallback HTML; unknown names also show it when clients accept the default certificate.

Per-route quotas can count client-to-server bytes, server-to-client bytes, or both. Accounting includes TLS records and handshake data, and excludes TCP/IP headers and retransmissions. A quota can overshoot slightly during concurrent writes or a process crash; counters are saved each second. New requests receive HTTP 429 after the HAProxy reload; active streams are closed at the quota boundary. A paused route returns 503. Daily periods begin at midnight in `PANEL_TIMEZONE`; monthly periods begin on the route creation day, using the last day of a shorter month.

The data volume contains the SQLite database, generated certificates, and HAProxy configuration. Back up this volume and the `.env` file together. Telegram settings are in the dashboard; the bot token is encrypted with `PANEL_MASTER_KEY` before storage. Changing the master key prevents decryption of the saved bot token and invalidates sessions.

## Development checks

Run `go test ./...` from the repository root and `npm ci && npm run build` from `web/`. With HAProxy installed locally, the Go process validates generated configurations via `haproxy -c` before replacing the active file. The HAProxy container validates again and reloads when the configuration changes.
