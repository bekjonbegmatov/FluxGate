#!/usr/bin/env bash
set -euo pipefail

# Downloadable entry point. All builds happen before the running stack changes.
install_dir=${FLUXGATE_DIR:-/opt/fluxgate}
ref=${FLUXGATE_REF:-main}
max_connections=''
if [[ $# == 2 && $1 == --max-connections && $2 =~ ^[0-9]+$ && ${#2} -le 6 ]]; then
  max_connections=$((10#$2))
  if (( max_connections < 1 || max_connections > 100000 )); then
    echo 'Connection limit must be between 1 and 100000.' >&2; exit 1
  fi
elif [[ $# != 0 ]]; then
  echo 'Usage: sudo bash update.sh [--max-connections 1..100000]' >&2; exit 1
fi
if [[ $(id -u) -ne 0 ]]; then echo 'Run with sudo bash.' >&2; exit 1; fi
for tool in git docker curl flock; do
  command -v "$tool" >/dev/null || { echo "Required command is missing: $tool" >&2; exit 1; }
done
if ! command -v python3 >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3
fi
if [[ ! -d "$install_dir/.git" || ! -f "$install_dir/.env" ]]; then
  echo "Docker installation not found at $install_dir. Set FLUXGATE_DIR to its checkout." >&2
  exit 1
fi
exec 9>/run/lock/fluxgate-update.lock
flock -n 9 || { echo 'Another FluxGate update is running.' >&2; exit 1; }
if ! git -C "$install_dir" diff --quiet || ! git -C "$install_dir" diff --cached --quiet; then
  echo 'The checkout has local changes. Preserve/commit them before updating.' >&2
  exit 1
fi
remote=$(git -C "$install_dir" remote get-url origin)
case "$remote" in
  https://github.com/bekjonbegmatov/FluxGate.git|git@github.com:bekjonbegmatov/FluxGate.git) ;;
  *) echo 'Unexpected origin; update stopped.' >&2; exit 1 ;;
esac
git -C "$install_dir" fetch origin "$ref"
revision=$(git -C "$install_dir" rev-parse FETCH_HEAD)
git -C "$install_dir" merge-base --is-ancestor HEAD "$revision" || {
  echo 'Update is not fast-forward; the running installation was left unchanged.' >&2; exit 1;
}
stage=$(mktemp -d /var/tmp/fluxgate-update.XXXXXXXX)
cleanup() { [[ $stage == /var/tmp/fluxgate-update.* ]] && rm -rf -- "$stage"; }
trap cleanup EXIT
git -C "$install_dir" archive "$revision" | tar -x -C "$stage"
if [[ ! -f "$stage/deploy/update-docker.sh" ]]; then
  echo 'The selected revision does not support safe updates.' >&2; exit 1
fi
FLUXGATE_DIR="$install_dir" FLUXGATE_REVISION="$revision" FLUXGATE_MAX_CONNECTIONS="$max_connections" bash "$stage/deploy/update-docker.sh"
