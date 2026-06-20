#!/usr/bin/env bash
# This template script is to be copied and edited with actual values for running smartshield in AP mode
# it's used by the smartshield service unit to run smartshield inside a docker container on boot and on failure


set -euo pipefail

WIFI_IF="${WIFI_IF}"
ETH_IF="${ETH_IF}"
CWD="${CWD}"
OUTPUT_DIR="$CWD/output"
#CONFIG_DIR="$CWD/config"
CONTAINER_NAME="${CONTAINER_NAME:-smartshield}"
DOCKER_IMAGE="${DOCKER_IMAGE:-stratosphereips/smartshield:latest}"
LOG_FILE="${LOG_FILE}"

log() { printf "%b\n" "$(date -Iseconds) - $*" | tee -a "$LOG_FILE"; }

remove_existing_container() {
  # Removes existing smartshield container if found, because we'll be starting a new one with the same name
  if docker ps -a --format '{{.Names}}' | grep -xq "$CONTAINER_NAME"; then
    log "Container '$CONTAINER_NAME' already exists. Removing it."
    docker rm -f "$CONTAINER_NAME" || true
  fi
}

kill_ap_process() {
    PATTERN="create_ap.*\b$WIFI_IF\b.*\b$ETH_IF\b"
    log "Searching for AP processes matching: $PATTERN"

    pids=$(ps -ef | grep -E "$PATTERN" | grep -v grep | awk '{print $2}' || true)

    if [ -n "$pids" ]; then
        log "Found AP process(es): $pids"
        kill -TERM $pids
        if [ $? -eq 0 ]; then
            log "Successfully sent TERM to AP process(es)."
        else
            log "Failed to kill AP process(es)."
        fi
    else
        log "No AP processes found."
    fi
}


main() {
  # Removes existing smartshield containers, restarts smartshield docker, and monitors status
  # Stops the AP process on smartshield container exit to cut the user's internet to notice that something went wrong with smartshield
  # and his traffic is no longer being inspected.
  log "=== smartshield Runner Started ==="

  remove_existing_container
  docker_cmd=(
    docker run -d -it
    -v "$OUTPUT_DIR":/StratosphereLinuxIPS/output/
    # -v "$CONFIG_DIR":/StratosphereLinuxIPS/config/
    --name "$CONTAINER_NAME"
    --net=host
    --cpu-shares 800
    --memory 8g
    --memory-swap 8g
    --shm-size 512m
    --cap-add NET_ADMIN
    "$DOCKER_IMAGE"
    bash -c "tmux new -s smartshield './smartshield.py -ap $WIFI_IF,$ETH_IF'; tmux wait-for -S smartshield_done"
  )

  log "Starting smartshield container using command: ${docker_cmd[*]}"

  # Execute
  container_id=$("${docker_cmd[@]}")

  log "Container started: $container_id"


  # This loop blocks forever until the docker container dies.
  # qx matches exactly "smartshield" container
  while docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null | grep -qx "true" ; do
    sleep 10
    status=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")
    log "Container status: $status"
  done


  ### Docker exited. Termination Logic #### :D
  exit_code=$(docker inspect --format='{{.State.ExitCode}}' "$container_id" 2>/dev/null || echo 0)
  log "Exited with code $exit_code"


  # we want the user to notice that smartshield is no longer protecting their traffic, so we kill the AP process to cut internet access
  kill_ap_process

  netfilter-persistent save || true
  log "Runner finished."
}

main "$@"
