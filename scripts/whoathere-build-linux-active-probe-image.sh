#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${WHOATHERE_LINUX_ACTIVE_PROBE_DOCKER_IMAGE:-whoathere/linux-active-probe:local}"
IMAGE_CONTEXT="$ROOT_DIR/whoathere/probe-images/linux-active-probe"

docker build --pull=false -t "$IMAGE_TAG" "$IMAGE_CONTEXT"
printf 'whoathere linux active probe image built image=%s\n' "$IMAGE_TAG"
