#!/usr/bin/env bash
set -euo pipefail
if [[ $(id -u) -ne 0 ]]; then echo 'Run as root' >&2; exit 1; fi
if [[ ! -e /swapfile ]]; then
  fallocate -l 2G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
fi
if ! swapon --show=NAME --noheadings | grep -qx '/swapfile'; then swapon /swapfile; fi
if ! grep -Eq '^/swapfile[[:space:]]' /etc/fstab; then printf '/swapfile none swap sw 0 0\n' >> /etc/fstab; fi
printf 'vm.swappiness = 10\n' > /etc/sysctl.d/99-fluxgate-swappiness.conf
sysctl -w vm.swappiness=10
free -h
