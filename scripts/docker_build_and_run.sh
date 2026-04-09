#!/usr/bin/env bash

IMAGE_NAME="agentrology-env:latest"
CONTAINER_NAME="agentrology-container"
PORT="8000"

SKIP_BUILD=false
ENABLE_WEB=false

GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
NC="\033[0m"

log() {
  echo -e "${GREEN}[+]${NC} $1"
}

warn() {
  echo -e "${YELLOW}[!]${NC} $1"
}

error() {
  echo -e "${RED}[x]${NC} $1" >&2
  exit 1
}

info() {
  echo -e "${BLUE}[*]${NC} $1"
}

usage() {
  cat <<EOF
Usage: $0 [options]

  Builds the Docker image and runs the container for Agentrology.

  By default, it builds the image and starts the container.
  You can skip the build step or enable the web interface
  using the options below.

Options:
  --skip-build
  --web
  -h, --help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
  --skip-build)
    SKIP_BUILD=true
    shift
    ;;
  --web)
    ENABLE_WEB=true
    shift
    ;;
  -h | --help | help | h)
    usage
    exit 0
    ;;
  *)
    error "Unknown option: $1"
    ;;
  esac
done

if [ "$SKIP_BUILD" = false ]; then
  log "Building Docker image..."
  docker build -t "$IMAGE_NAME" -f Dockerfile .
else
  warn "Skipping build"
fi

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  info "Stopping existing container..."
  docker stop "$CONTAINER_NAME" >/dev/null || true
  docker rm "$CONTAINER_NAME" >/dev/null || true
else
  warn "No existing container"
fi

DOCKER_ENV_ARGS=()

if [ "$ENABLE_WEB" = true ]; then
  info "ENABLE_WEB_INTERFACE=true"
  DOCKER_ENV_ARGS+=("-e" "ENABLE_WEB_INTERFACE=true")
fi

log "Starting container..."

docker run -it \
  --name "$CONTAINER_NAME" \
  -p "$PORT:$PORT" \
  "${DOCKER_ENV_ARGS[@]}" \
  "$IMAGE_NAME"
