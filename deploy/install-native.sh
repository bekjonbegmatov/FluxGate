#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $(id -u) -ne 0 ]]; then echo 'Run as root' >&2; exit 1; fi
id fluxgate >/dev/null 2>&1 || useradd --system --home-dir /var/lib/fluxgate --shell /usr/sbin/nologin fluxgate
install -d -m 0750 -o fluxgate -g fluxgate /var/lib/fluxgate
install -d -m 0700 /etc/fluxgate
install -d -m 0755 /opt/fluxgate/web /usr/local/libexec
if [[ ! -e /etc/fluxgate/fluxgate.env ]]; then
  python3 - <<'PY'
from pathlib import Path
import secrets
p=Path('/etc/fluxgate/fluxgate.env')
p.write_text('PANEL_DATA=/var/lib/fluxgate\nPANEL_WEB=/opt/fluxgate/web\nPANEL_LISTEN=127.0.0.1:9389\nPANEL_SECRET_PATH=admin\nPANEL_DOMAIN=proxy.local.invalid\nPANEL_TIMEZONE=UTC\nPANEL_TOKEN='+secrets.token_hex(32)+'\nPANEL_MASTER_KEY='+secrets.token_hex(32)+'\n')
p.chmod(0o600)
PY
fi
go build -o /usr/local/bin/fluxgate-panel ./cmd/panel
npm --prefix web ci
npm --prefix web run build
cp -a web/dist/. /opt/fluxgate/web/
install -m 0755 haproxy/watch.sh /usr/local/libexec/fluxgate-watch
install -m 0644 deploy/fluxgate-panel.service /etc/systemd/system/fluxgate-panel.service
install -m 0644 deploy/fluxgate-haproxy.service /etc/systemd/system/fluxgate-haproxy.service
systemctl daemon-reload
systemctl enable --now fluxgate-panel.service fluxgate-haproxy.service
systemctl restart fluxgate-panel.service fluxgate-haproxy.service
