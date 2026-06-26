#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
AGENT_SOURCE="$HELPER_ROOT/guest-agent/whoathere-guest-ready.c"
BUILD_DIR=${TMPDIR:-/tmp}/whoathere-guest-timeout.$$
HARNESS="$BUILD_DIR/guest-timeout-harness.c"
BINARY="$BUILD_DIR/guest-timeout-harness"

cleanup() {
  rm -rf "$BUILD_DIR"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$BUILD_DIR"

cat > "$HARNESS" <<EOF
#define main whoathere_guest_agent_main
#include "$AGENT_SOURCE"
#undef main

#include <assert.h>

int main(void) {
    char template[] = "/tmp/whoathere-timeout-fixture.XXXXXX";
    char *workspace = mkdtemp(template);
    assert(workspace != NULL);
    struct command_result result = run_shell_fixture(workspace, "sleep 10", 5);
    assert(result.timed_out == 1);
    assert(result.exit_code == 124);
    return 0;
}
EOF

cc -O2 -Wall -Wextra -target arm64-apple-macos13 -o "$BINARY" "$HARNESS"
"$BINARY"
echo "guest_agent_timeout_validation=ok"
