#!/usr/bin/env bash

IMAGE_NAME="agentrology-env:latest"
CONTAINER_NAME="agentrology-container"
PORT="8000"
LOGGING_LEVEL=${LOGGING_LEVEL:-DEBUG}
SKIP_BUILD=false
ENABLE_WEB=false
BASH=false
BUILD_ONLY=false

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
  --bash
  --build-only
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
  --bash)
    BASH=true
    shift
    ;;
  --build-only)
    BUILD_ONLY=true
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

if [ "$BASH" = true ]; then
  info "Looking for running container to attach to..."
  if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    log "Attaching to running container..."
    docker exec -it "$CONTAINER_NAME" bash
    # find containers using the image name and attach to the first one found
    containers=$(docker ps --filter "ancestor=$IMAGE_NAME" --format '{{.Names}}')
    if [ -n "$containers" ]; then
      container=$(echo "$containers" | head -n 1)
      log "Attaching to container: $container"
      docker exec -it "$container" bash
    fi
    exit 0
  else
    error "No running container found to attach to."
    exit 1
  fi
fi

if [ "$SKIP_BUILD" = false ]; then
  log "Building Docker image..."
  docker build -t "$IMAGE_NAME" -f Dockerfile .
  EXIT_CODE=$?
  if [ $EXIT_CODE -ne 0 ]; then
    error "Docker build failed with exit code $EXIT_CODE"
  fi
else
  warn "Skipping build"
fi

if [ "$BUILD_ONLY" = true ]; then
  log "Build only mode enabled. Skipping container run."
  exit 0
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

DOCKER_ENV_ARGS+=("-e" "LOGGING_LEVEL=$LOGGING_LEVEL")

info "LOGGING_LEVEL=$LOGGING_LEVEL"

log "Starting container..."

docker run -it \
  --name "$CONTAINER_NAME" \
  -p "$PORT:$PORT" \
  "${DOCKER_ENV_ARGS[@]}" \
  "$IMAGE_NAME"
