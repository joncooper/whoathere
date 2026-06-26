#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
AGENT_SOURCE="$HELPER_ROOT/guest-agent/whoathere-guest-ready.c"
BUILD_DIR=${TMPDIR:-/tmp}/whoathere-guest-project-payload.$$
HARNESS="$BUILD_DIR/guest-project-payload-harness.c"
BINARY="$BUILD_DIR/guest-project-payload-harness"

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

static void append_le16(unsigned char *buffer, size_t *offset, unsigned short value) {
    buffer[(*offset)++] = (unsigned char)(value & 0xff);
    buffer[(*offset)++] = (unsigned char)((value >> 8) & 0xff);
}

static void append_le32(unsigned char *buffer, size_t *offset, unsigned int value) {
    buffer[(*offset)++] = (unsigned char)(value & 0xff);
    buffer[(*offset)++] = (unsigned char)((value >> 8) & 0xff);
    buffer[(*offset)++] = (unsigned char)((value >> 16) & 0xff);
    buffer[(*offset)++] = (unsigned char)((value >> 24) & 0xff);
}

static void append_record(
    unsigned char *buffer,
    size_t *offset,
    const char *relative_path,
    const char *contents
) {
    size_t path_length = strlen(relative_path);
    size_t content_length = strlen(contents);
    assert(path_length < 65535);
    assert(content_length < 1024 * 1024);
    append_le16(buffer, offset, (unsigned short)path_length);
    append_le32(buffer, offset, (unsigned int)content_length);
    memcpy(buffer + *offset, relative_path, path_length);
    *offset += path_length;
    memcpy(buffer + *offset, contents, content_length);
    *offset += content_length;
}

static char *to_hex(const unsigned char *buffer, size_t length) {
    const char *hex = "0123456789abcdef";
    char *output = calloc(length * 2 + 1, 1);
    assert(output != NULL);
    for (size_t index = 0; index < length; index++) {
        output[index * 2] = hex[(buffer[index] >> 4) & 0x0f];
        output[index * 2 + 1] = hex[buffer[index] & 0x0f];
    }
    return output;
}

static char *project_payload_hex(const char *path, const char *body) {
    unsigned char buffer[4096];
    size_t offset = 0;
    memcpy(buffer + offset, "WTP1", 4);
    offset += 4;
    append_le32(buffer, &offset, 1);
    append_record(buffer, &offset, path, body);
    return to_hex(buffer, offset);
}

int main(void) {
    char template[] = "/tmp/whoathere-project-payload-fixture.XXXXXX";
    char *workspace = mkdtemp(template);
    assert(workspace != NULL);

    char *payload = project_payload_hex("pkg/__init__.py", "VALUE = 'clean'\\n");
    assert(materialize_project_payload(workspace, payload) == 0);
    free(payload);

    char expected_path[512];
    int length = snprintf(expected_path, sizeof(expected_path), "%s/pkg/__init__.py", workspace);
    assert(length > 0 && (size_t)length < sizeof(expected_path));
    assert(path_exists(expected_path));

    payload = project_payload_hex("../escape.py", "VALUE = 'escape'\\n");
    assert(materialize_project_payload(workspace, payload) == -1);
    free(payload);

    payload = project_payload_hex("bad;name.py", "VALUE = 'bad'\\n");
    assert(materialize_project_payload(workspace, payload) == -1);
    free(payload);

    return 0;
}
EOF

cc -O2 -Wall -Wextra -target arm64-apple-macos13 -o "$BINARY" "$HARNESS"
"$BINARY"
echo "guest_agent_project_payload_validation=ok"
