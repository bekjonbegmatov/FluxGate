#!/usr/bin/env bash
set -euo pipefail
config=${FLUXGATE_CONFIG:-/data/haproxy.cfg}
pidfile=${FLUXGATE_PID:-/data/haproxy.pid}
master_socket=${FLUXGATE_MASTER_SOCKET:-${pidfile%.pid}-master.sock}
master_options="$master_socket,mode,600"
if [[ -n ${FLUXGATE_MASTER_GROUP:-} ]]; then master_options="$master_socket,mode,660,group,$FLUXGATE_MASTER_GROUP"; fi
reload_request=${config%.cfg}.reload-request
reload_ready=${config%.cfg}.reload-ready
restart_request=${config%.cfg}.restart-request
child=''
watchdog=''
watchdog_binary=${FLUXGATE_WATCHDOG:-/usr/local/bin/fluxgate-watchdog}
stopping=0
stop() {
  stopping=1
  if [[ -n "$child" ]]; then kill -TERM "$child" 2>/dev/null || true; fi
  if [[ -n "$watchdog" ]]; then kill -TERM "$watchdog" 2>/dev/null || true; fi
}
trap stop TERM INT
start_watchdog() {
  PANEL_DATA="$(dirname "$config")" PANEL_HAPROXY_MASTER_SOCKET="$master_socket" "$watchdog_binary" --watchdog &
  watchdog=$!
}
[[ -x "$watchdog_binary" ]] || { echo 'FluxGate quota watchdog binary missing' >&2; exit 1; }
start_watchdog
while [[ $stopping == 0 && ! -s "$config" ]]; do sleep 1; done
[[ $stopping == 0 ]] || exit 0
haproxy -c -f "$config"
last=$(sha256sum "$config" | cut -d' ' -f1)
haproxy -W -db -f "$config" -p "$pidfile" -S "$master_options" &
child=$!
while [[ $stopping == 0 ]] && kill -0 "$child" 2>/dev/null; do
  sleep 1
  [[ $stopping == 0 ]] || break
  if ! kill -0 "$watchdog" 2>/dev/null; then
    wait "$watchdog" || true
    echo 'Restarting quota watchdog' >&2
    start_watchdog
  fi
  if [[ -f "$restart_request" ]]; then
    # The panel writes this after draining and attempting its final commit.
    # Storage failures are logged by the panel and can lose unsaved deltas.
    # Restart the
    # HAProxy processes inside the same container/network namespace.
    rm -f "$restart_request"
    kill -TERM "$child" 2>/dev/null || true
    wait "$child" || true
    haproxy -c -f "$config"
    haproxy -W -db -f "$config" -p "$pidfile" -S "$master_options" &
    child=$!
    last=$(sha256sum "$config" | cut -d' ' -f1)
    continue
  fi
  now=$(sha256sum "$config" | cut -d' ' -f1) || continue
  if [[ "$now" != "$last" ]] && haproxy -c -f "$config"; then
    # Pin the current worker's Runtime API before it can drain and disappear.
    # No payload or request logs are written. The old config keeps serving if
    # the panel is unavailable; retry instead of losing direct byte counters.
    nonce="$now:$(date +%s):$$"
    printf '%s' "$nonce" > "$reload_request.tmp"
    mv "$reload_request.tmp" "$reload_request"
    ready=0
    for attempt in 1 2 3 4 5; do
      if [[ -f "$reload_ready" && $(<"$reload_ready") == "$nonce" ]]; then ready=1; break; fi
      sleep 1
      [[ $stopping == 0 ]] || break
    done
    [[ $stopping == 0 ]] || break
    if [[ $ready == 0 ]]; then echo 'Waiting for panel accounting before HAProxy reload' >&2; continue; fi
    # Re-exec the SAME master; it owns, drains and reaps every old worker.
    # Hash before validation so a concurrent atomic rename is retried next tick.
    kill -USR2 "$child"
    last=$now
  fi
done
status=0
wait "$child" || status=$?
kill -TERM "$watchdog" 2>/dev/null || true
wait "$watchdog" || true
[[ $stopping == 1 ]] && exit 0
# A clean but unexpected master exit must also restart the systemd service.
[[ $status != 0 ]] || status=1
exit "$status"
