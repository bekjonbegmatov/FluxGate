#!/usr/bin/env bash
set -euo pipefail
config=${FLUXGATE_CONFIG:-/data/haproxy.cfg}
pidfile=${FLUXGATE_PID:-/data/haproxy.pid}
master_socket=${FLUXGATE_MASTER_SOCKET:-${pidfile%.pid}-master.sock}
child=''
stopping=0
stop() {
  stopping=1
  if [[ -n "$child" ]]; then kill -TERM "$child" 2>/dev/null || true; fi
}
trap stop TERM INT
while [[ $stopping == 0 && ! -s "$config" ]]; do sleep 1; done
[[ $stopping == 0 ]] || exit 0
haproxy -c -f "$config"
last=$(sha256sum "$config" | cut -d' ' -f1)
haproxy -W -db -f "$config" -p "$pidfile" -S "$master_socket,mode,600" &
child=$!
while [[ $stopping == 0 ]] && kill -0 "$child" 2>/dev/null; do
  sleep 1
  [[ $stopping == 0 ]] || break
  now=$(sha256sum "$config" | cut -d' ' -f1) || continue
  if [[ "$now" != "$last" ]] && haproxy -c -f "$config"; then
    # Re-exec the SAME master; it owns, drains and reaps every old worker.
    # Hash before validation so a concurrent atomic rename is retried next tick.
    kill -USR2 "$child"
    last=$now
  fi
done
status=0
wait "$child" || status=$?
[[ $stopping == 1 ]] && exit 0
# A clean but unexpected master exit must also restart the systemd service.
[[ $status != 0 ]] || status=1
exit "$status"
