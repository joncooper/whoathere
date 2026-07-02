#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
IMAGE=${WHOATHERE_CORPUS_LAB_IMAGE:-whoathere-corpus-lab:local}
LAB_ROOT=${WHOATHERE_CORPUS_LAB_ROOT:-"$REPO_ROOT/.whoathere/corpus-lab"}
ENV_FILE=${WHOATHERE_CORPUS_LAB_ENV:-"$REPO_ROOT/.env"}

usage() {
  cat >&2 <<'EOF'
usage:
  scripts/whoathere-corpus-lab.sh build
  scripts/whoathere-corpus-lab.sh shell [cmd...]
  scripts/whoathere-corpus-lab.sh custody-shell [cmd...]
  scripts/whoathere-corpus-lab.sh validate-corpus [args...]
  scripts/whoathere-corpus-lab.sh validate-run-matrix [args...]
  scripts/whoathere-corpus-lab.sh malwarebazaar-validate-fixture [args...]
  scripts/whoathere-corpus-lab.sh malwarebazaar-query [args...]
  scripts/whoathere-corpus-lab.sh malwarebazaar-acquire [args...]
  scripts/whoathere-corpus-lab.sh malwarebazaar-acquire-fixture [args...]

The container is for corpus acquisition and custody work only. Do not execute malware in it.
EOF
  exit 64
}

ensure_lab_dirs() {
  mkdir -p \
    "$LAB_ROOT/quarantine" \
    "$LAB_ROOT/cases" \
    "$LAB_ROOT/evidence" \
    "$LAB_ROOT/workspaces" \
    "$LAB_ROOT/cache"
}

run_container() {
  network_args=$1
  shift
  ensure_lab_dirs
  if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
  fi
  env_args=""
  if [ -n "${MALWAREBAZAAR_AUTH_KEY:-}" ]; then
    env_args="-e MALWAREBAZAAR_AUTH_KEY"
  fi
  tty_args="-i"
  if [ -t 0 ] && [ -t 1 ]; then
    tty_args="-it"
  fi
  # shellcheck disable=SC2086
  docker run --rm $tty_args \
    --name whoathere-corpus-lab \
    --user "$(id -u):$(id -g)" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 256 \
    --memory 1g \
    --cpus 1 \
    --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m \
    $network_args \
    $env_args \
    -v "$REPO_ROOT:/workspace:ro" \
    -v "$LAB_ROOT/quarantine:/lab/quarantine" \
    -v "$LAB_ROOT/cases:/lab/cases" \
    -v "$LAB_ROOT/evidence:/lab/evidence" \
    -v "$LAB_ROOT/workspaces:/lab/workspaces" \
    -v "$LAB_ROOT/cache:/lab/cache" \
    -w /workspace \
    "$IMAGE" "$@"
}

if [ "$#" -lt 1 ]; then
  usage
fi

command=$1
shift

case "$command" in
  build)
    docker build -f "$REPO_ROOT/containers/malware-corpus-lab/Dockerfile" -t "$IMAGE" "$REPO_ROOT"
    ;;
  shell)
    if [ "$#" -eq 0 ]; then
      run_container "" /bin/sh
    else
      run_container "" "$@"
    fi
    ;;
  custody-shell)
    if [ "$#" -eq 0 ]; then
      run_container "--network none" /bin/sh
    else
      run_container "--network none" "$@"
    fi
    ;;
  validate-corpus|validate-run-matrix|malwarebazaar-validate-fixture)
    run_container "--network none" scripts/whoathere-actual-malware-evaluation.py "$command" "$@"
    ;;
  malwarebazaar-query|malwarebazaar-acquire|malwarebazaar-acquire-fixture)
    run_container "" scripts/whoathere-actual-malware-evaluation.py "$command" "$@"
    ;;
  *)
    usage
    ;;
esac
