#!/usr/bin/env bash
set -euo pipefail
umask 077
# Compose shell variables take precedence over --env-file. This setting is
# deliberately managed in the file so rollback and subsequent starts agree.
unset PANEL_MAX_CONNECTIONS
source_dir=$(cd "$(dirname "$0")/.." && pwd)
install_dir=${FLUXGATE_DIR:?Run update.sh}
revision=${FLUXGATE_REVISION:?Run update.sh}
project=${FLUXGATE_PROJECT:-fluxgate}
backup_root=${FLUXGATE_BACKUP_DIR:-/var/backups/fluxgate}
stamp=$(date -u +%Y%m%dT%H%M%SZ)-$$
backup="$backup_root/$stamp"
install -d -m 0700 "$backup"
current=(docker compose -p "$project" --project-directory "$install_dir" --env-file "$install_dir/.env" -f "$install_dir/compose.yaml")
candidate=(docker compose -p "$project" --project-directory "$source_dir" --env-file "$backup/candidate.env" -f "$source_dir/compose.yaml")
helper="$source_dir/deploy/update-helper.py"
panel_id=$("${current[@]}" ps -q panel)
haproxy_id=$("${current[@]}" ps -q haproxy)
if [[ -z "$panel_id" || -z "$haproxy_id" ]]; then
  echo 'Both existing containers must be running before an update.' >&2; exit 1
fi
# Never silently discard a custom override (ports, mounts, resource limits).
for container_id in "$panel_id" "$haproxy_id"; do
  config_files=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$container_id")
  if [[ "$config_files" != "$install_dir/compose.yaml" ]]; then
    echo 'Custom or unknown Compose configuration detected. Use your original Compose files to update manually.' >&2
    exit 1
  fi
done
# Keep image tags so pruning dangling images cannot destroy the rollback.
for service in panel haproxy; do
  container_id=$("${current[@]}" ps -q "$service")
  image_id=$(docker inspect --format '{{.Image}}' "$container_id")
  docker image tag "$image_id" "fluxgate-rollback-$service:$stamp"
done
"${current[@]}" config --format json > "$backup/previous-compose.json"
python3 "$helper" rollback-config "$backup/previous-compose.json" "$backup/rollback.compose.json" "$stamp"
install -m 0600 "$install_dir/.env" "$backup/env"
python3 "$helper" configure-env "$backup/env" "$backup/candidate.env" "${FLUXGATE_MAX_CONNECTIONS:-}"
git -C "$install_dir" rev-parse HEAD > "$backup/previous-revision"
printf '%s\n' "$revision" > "$backup/new-revision"
echo 'Building new images while the existing installation serves traffic…'
"${candidate[@]}" build --pull
echo 'Creating and validating a live backup…'
docker inspect --format '{{json .Config.Env}}' "$panel_id" | python3 "$helper" backup "$backup/panel.zip"

activated=0
env_changed=0
rollback() {
  status=$?
  trap - EXIT INT TERM
  if [[ $env_changed == 1 ]]; then
    if ! { install -m 0600 "$backup/env" "$install_dir/.env.fluxgate-update" && mv -f "$install_dir/.env.fluxgate-update" "$install_dir/.env"; }; then
      # The resolved rollback Compose embeds the old environment, so still try
      # to recover the services even if the checkout disk is now full/read-only.
      echo "Could not restore .env. Restore it manually from $backup/env before the next update." >&2
    fi
  fi
  if [[ $activated == 1 ]]; then
    echo 'Update failed. Restoring the previous container images…' >&2
    if docker compose -p "$project" -f "$backup/rollback.compose.json" up -d --no-build --pull never --force-recreate; then
      old_panel=$(docker compose -p "$project" -f "$backup/rollback.compose.json" ps -q panel)
      if docker inspect --format '{{json .Config.Env}}' "$old_panel" | python3 "$helper" verify; then
        echo 'Previous version is running again. Data and secrets were preserved.' >&2
      else
        echo "Rollback containers started but did not pass checks. Backup: $backup" >&2
      fi
    else
      echo "Automatic rollback failed. Recovery configuration: $backup/rollback.compose.json" >&2
    fi
  fi
  [[ $status != 0 ]] || status=1
  exit "$status"
}
trap rollback EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
git -C "$install_dir" merge --ff-only "$revision"
env_changed=1
install -m 0600 "$backup/candidate.env" "$install_dir/.env.fluxgate-update"
mv -f "$install_dir/.env.fluxgate-update" "$install_dir/.env"
activated=1
echo 'Switching containers. Existing connections will need to reconnect.'
"${current[@]}" up -d --no-build --pull never --force-recreate --wait --wait-timeout 120
panel_id=$("${current[@]}" ps -q panel)
docker inspect --format '{{json .Config.Env}}' "$panel_id" | python3 "$helper" verify
activated=0
trap - EXIT INT TERM
printf '\nFluxGate updated successfully: %s\nBackup and rollback configuration: %s\n' "$revision" "$backup"
