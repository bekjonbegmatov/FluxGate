#!/usr/bin/env bash
set -euo pipefail

# One-command installation for a fresh Ubuntu or Debian server.
repo_url='https://github.com/bekjonbegmatov/FluxGate.git'
install_dir=${FLUXGATE_DIR:-/opt/fluxgate}
domain=${FLUXGATE_DOMAIN:-cubeland.top}
secret_path=admin

if [[ $(id -u) -ne 0 ]]; then echo 'Run as root: curl ... | sudo bash' >&2; exit 1; fi
if [[ ! -f /etc/os-release ]]; then echo 'Unsupported operating system' >&2; exit 1; fi
. /etc/os-release
if [[ ${ID:-} != ubuntu && ${ID:-} != debian ]]; then echo 'Supported systems: Ubuntu and Debian' >&2; exit 1; fi
if [[ -z ${VERSION_CODENAME:-} ]]; then echo 'VERSION_CODENAME is missing' >&2; exit 1; fi
if [[ ! $domain =~ ^[A-Za-z0-9.-]+$ || $domain != *.* ]]; then echo 'Invalid FLUXGATE_DOMAIN' >&2; exit 1; fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git openssl
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  cat > /etc/apt/sources.list.d/docker.sources <<DOCKER_SOURCE
Types: deb
URIs: https://download.docker.com/linux/${ID}
Suites: ${VERSION_CODENAME}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
DOCKER_SOURCE
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
if [[ ! -d "$install_dir/.git" ]]; then
  if [[ -e "$install_dir" && -n $(ls -A "$install_dir") ]]; then echo "$install_dir exists and is not a Git checkout" >&2; exit 1; fi
  git clone --depth 1 "$repo_url" "$install_dir"
else
  current_remote=$(git -C "$install_dir" remote get-url origin)
  if [[ $current_remote != "$repo_url" ]]; then echo "Unexpected Git remote: $current_remote" >&2; exit 1; fi
  git -C "$install_dir" pull --ff-only
fi
cd "$install_dir"
if [[ -z $(swapon --noheadings --show=NAME) ]] && [[ $(df -BG --output=avail / | tail -n 1 | tr -dc '0-9') -ge 4 ]]; then
  if ! bash deploy/setup-swap.sh >/dev/null; then echo "Swap setup failed; continuing without it" >&2; fi
fi
if [[ ! -f .env ]]; then
  umask 077
  cat > .env.new <<SETTINGS
PANEL_DOMAIN=$domain
PANEL_SECRET_PATH=$secret_path
PANEL_TOKEN=$(openssl rand -hex 32)
PANEL_MASTER_KEY=$(openssl rand -hex 32)
PANEL_TIMEZONE=UTC
SETTINGS
  chmod 600 .env.new
  mv .env.new .env
fi
chmod 600 .env
secret_path=$(sed -n 's/^PANEL_SECRET_PATH=//p' .env | head -n 1)
if [[ -z $secret_path ]]; then secret_path=admin; fi
docker compose -p fluxgate up -d --build
ready=0
for ((attempt=0; attempt<90; attempt++)); do
  if [[ $(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:9389/${secret_path}/" 2>/dev/null || true) == 200 ]]; then ready=1; break; fi
  sleep 2
done
if [[ $ready != 1 ]]; then
  docker compose -p fluxgate ps
  echo 'Panel did not become ready; inspect: docker compose -p fluxgate logs' >&2
  exit 1
fi
public_ip=$(curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)
if [[ -z $public_ip ]]; then public_ip=$(hostname -I | awk '{print $1}'); fi
if [[ $public_ip == *:* ]]; then public_ip="[$public_ip]"; fi
token=$(sed -n 's/^PANEL_TOKEN=//p' .env | head -n 1)
printf '\nFluxGate is ready.\nURL: http://%s:9389/%s/\nToken: %s\nProject: %s\n' "$public_ip" "$secret_path" "$token" "$install_dir"
printf 'Ports: 443/TCP and 9389/TCP. If the URL is unreachable externally, allow these ports in your hosting provider firewall.\n'
