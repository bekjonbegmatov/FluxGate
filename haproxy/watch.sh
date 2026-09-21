#!/usr/bin/env bash
set -euo pipefail
config=/data/haproxy.cfg
while [[ ! -s "$config" ]]; do sleep 1; done
haproxy -c -f "$config"
haproxy -W -db -f "$config" -p /data/haproxy.pid &
child=$!
last=$(sha256sum "$config" | cut -d' ' -f1)
while kill -0 "$child" 2>/dev/null; do
  sleep 1
  now=$(sha256sum "$config" | cut -d' ' -f1)
  if [[ "$now" != "$last" ]] && haproxy -c -f "$config"; then
    old=$(cat /data/haproxy.pid)
    haproxy -W -db -f "$config" -p /data/haproxy.pid -sf "$old" &
    child=$!
    last=$now
  fi
done
wait "$child"
