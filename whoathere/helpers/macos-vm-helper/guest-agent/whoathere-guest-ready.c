#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/vsock.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef AF_VSOCK
#error "AF_VSOCK is required for the WhoaThere guest readiness agent"
#endif

#define WHOATHERE_GUEST_READY_PORT 47078U
#define WHOATHERE_MAX_LINE 4096
#define WHOATHERE_MAX_JSON_LINE (10U * 1024U * 1024U)
#define WHOATHERE_MAX_CHALLENGE 128
#define WHOATHERE_MAX_FIELD 256
#define WHOATHERE_MAX_SYNC_BACK_FILES 256U
#define WHOATHERE_MAX_SYNC_BACK_FILE_BYTES (1024U * 1024U)
#define WHOATHERE_MAX_SYNC_BACK_TOTAL_BYTES (4U * 1024U * 1024U)
#define WHOATHERE_WORK_ROOT "/private/var/tmp/whoathere-detonation"
#define WHOATHERE_TOOL_PATH "/usr/local/whoathere/node/bin:/usr/local/whoathere/uv/bin:/usr/local/whoathere/python/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
#define WHOATHERE_PATH_PREFIX "PATH=${WHOATHERE_TELEMETRY_DIR:+$WHOATHERE_TELEMETRY_DIR/bin:}" WHOATHERE_TOOL_PATH "; export PATH; "
#define WHOATHERE_GUEST_PYTHON "/usr/local/whoathere/python/bin/python3"
#define WHOATHERE_PIP_WHEEL_DIR "/usr/local/whoathere/python-wheels"
#define WHOATHERE_PIP_PREFIX WHOATHERE_PATH_PREFIX "WHOATHERE_PYTHON=" WHOATHERE_GUEST_PYTHON "; if [ ! -x \"$WHOATHERE_PYTHON\" ]; then WHOATHERE_PYTHON=python3; fi; WHOATHERE_WHEEL_PATHS=\"\"; for WHOATHERE_WHEEL in " WHOATHERE_PIP_WHEEL_DIR "/*.whl; do if [ -f \"$WHOATHERE_WHEEL\" ]; then if [ -z \"$WHOATHERE_WHEEL_PATHS\" ]; then WHOATHERE_WHEEL_PATHS=\"$WHOATHERE_WHEEL\"; else WHOATHERE_WHEEL_PATHS=\"$WHOATHERE_WHEEL_PATHS:$WHOATHERE_WHEEL\"; fi; fi; done; if [ -n \"$WHOATHERE_WHEEL_PATHS\" ]; then export PYTHONPATH=\"$WHOATHERE_TELEMETRY_DIR:$WHOATHERE_WHEEL_PATHS\"; else export PYTHONPATH=\"$WHOATHERE_TELEMETRY_DIR\"; fi; "
#define WHOATHERE_TELEMETRY_FD 3

static char current_request_nonce[WHOATHERE_MAX_FIELD] = "";
static char current_project_workflow[WHOATHERE_MAX_FIELD] = "";
static int current_project_api_probe_enabled = 0;
static int current_execution_identity_isolated = 0;
static int current_runtime_network_telemetry_active = 0;
static unsigned int current_network_telemetry_events = 0;
static int current_process_group_cleanup_enforced = 0;

static int path_exists(const char *path);
static int safe_relative_path(const char *path);

static int read_line(int fd, char *buffer, size_t capacity) {
    size_t used = 0;
    while (used + 1 < capacity) {
        char byte = '\0';
        ssize_t count = read(fd, &byte, 1);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (count == 0) {
            break;
        }
        if (byte == '\n') {
            break;
        }
        buffer[used++] = byte;
    }
    buffer[used] = '\0';
    return used > 0 ? 0 : -1;
}

static int extract_json_string(const char *json, const char *key, char *output, size_t output_capacity) {
    char pattern[64];
    if (snprintf(pattern, sizeof(pattern), "\"%s\"", key) < 0) {
        return -1;
    }
    const char *cursor = strstr(json, pattern);
    if (cursor == NULL) {
        return -1;
    }
    cursor += strlen(pattern);
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }
    if (*cursor != ':') {
        return -1;
    }
    cursor++;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }
    if (*cursor != '"') {
        return -1;
    }
    cursor++;

    size_t used = 0;
    while (*cursor != '\0' && *cursor != '"') {
        if (*cursor == '\\') {
            return -1;
        }
        if (used + 1 >= output_capacity) {
            return -1;
        }
        output[used++] = *cursor++;
    }
    if (*cursor != '"') {
        return -1;
    }
    output[used] = '\0';
    return used > 0 ? 0 : -1;
}

static char *extract_json_string_alloc(const char *json, const char *key, size_t max_length) {
    char pattern[64];
    if (snprintf(pattern, sizeof(pattern), "\"%s\"", key) < 0) {
        return NULL;
    }
    const char *cursor = strstr(json, pattern);
    if (cursor == NULL) {
        return NULL;
    }
    cursor += strlen(pattern);
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }
    if (*cursor != ':') {
        return NULL;
    }
    cursor++;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }
    if (*cursor != '"') {
        return NULL;
    }
    cursor++;

    size_t used = 0;
    const char *start = cursor;
    while (*cursor != '\0' && *cursor != '"') {
        if (*cursor == '\\') {
            return NULL;
        }
        if (used >= max_length) {
            return NULL;
        }
        used++;
        cursor++;
    }
    if (*cursor != '"') {
        return NULL;
    }
    char *output = calloc(used + 1, 1);
    if (output == NULL) {
        return NULL;
    }
    memcpy(output, start, used);
    output[used] = '\0';
    return output;
}

static int write_all(int fd, const char *buffer, size_t length) {
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(fd, buffer + written, length - written);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (count == 0) {
            return -1;
        }
        written += (size_t)count;
    }
    return 0;
}

struct sync_archive {
    unsigned char *bytes;
    size_t length;
    size_t capacity;
    unsigned int file_count;
    size_t total_file_bytes;
};

static void sync_archive_free(struct sync_archive *archive) {
    if (archive->bytes != NULL) {
        free(archive->bytes);
    }
    archive->bytes = NULL;
    archive->length = 0;
    archive->capacity = 0;
    archive->file_count = 0;
    archive->total_file_bytes = 0;
}

static int sync_archive_reserve(struct sync_archive *archive, size_t additional) {
    if (additional > SIZE_MAX - archive->length) {
        return -1;
    }
    size_t required = archive->length + additional;
    if (required <= archive->capacity) {
        return 0;
    }
    size_t next_capacity = archive->capacity == 0 ? 4096U : archive->capacity;
    while (next_capacity < required) {
        if (next_capacity > SIZE_MAX / 2U) {
            return -1;
        }
        next_capacity *= 2U;
    }
    unsigned char *next = realloc(archive->bytes, next_capacity);
    if (next == NULL) {
        return -1;
    }
    archive->bytes = next;
    archive->capacity = next_capacity;
    return 0;
}

static int sync_archive_append(struct sync_archive *archive, const void *bytes, size_t length) {
    if (sync_archive_reserve(archive, length) != 0) {
        return -1;
    }
    memcpy(archive->bytes + archive->length, bytes, length);
    archive->length += length;
    return 0;
}

static int sync_archive_append_le16(struct sync_archive *archive, unsigned short value) {
    unsigned char bytes[2] = {
        (unsigned char)(value & 0xffU),
        (unsigned char)((value >> 8U) & 0xffU)
    };
    return sync_archive_append(archive, bytes, sizeof(bytes));
}

static int sync_archive_append_le32(struct sync_archive *archive, unsigned int value) {
    unsigned char bytes[4] = {
        (unsigned char)(value & 0xffU),
        (unsigned char)((value >> 8U) & 0xffU),
        (unsigned char)((value >> 16U) & 0xffU),
        (unsigned char)((value >> 24U) & 0xffU)
    };
    return sync_archive_append(archive, bytes, sizeof(bytes));
}

static int sync_archive_init(struct sync_archive *archive) {
    memset(archive, 0, sizeof(*archive));
    if (sync_archive_append(archive, "WTP1", 4) != 0) {
        return -1;
    }
    return sync_archive_append_le32(archive, 0);
}

static void sync_archive_finish(struct sync_archive *archive) {
    if (archive->length >= 8U) {
        archive->bytes[4] = (unsigned char)(archive->file_count & 0xffU);
        archive->bytes[5] = (unsigned char)((archive->file_count >> 8U) & 0xffU);
        archive->bytes[6] = (unsigned char)((archive->file_count >> 16U) & 0xffU);
        archive->bytes[7] = (unsigned char)((archive->file_count >> 24U) & 0xffU);
    }
}

static int sync_archive_append_file(
    struct sync_archive *archive,
    const char *filesystem_path,
    const char *sync_path
) {
    struct stat st;
    if (lstat(filesystem_path, &st) != 0) {
        return -1;
    }
    if (S_ISLNK(st.st_mode)) {
        return -2;
    }
    if (!S_ISREG(st.st_mode)) {
        return 0;
    }
    size_t path_length = strlen(sync_path);
    if (path_length == 0 || path_length > 65535U || !safe_relative_path(sync_path)) {
        return -1;
    }
    if (st.st_size < 0 || (size_t)st.st_size > WHOATHERE_MAX_SYNC_BACK_FILE_BYTES) {
        return -1;
    }
    if (archive->file_count >= WHOATHERE_MAX_SYNC_BACK_FILES) {
        return -1;
    }
    size_t content_length = (size_t)st.st_size;
    if (content_length > WHOATHERE_MAX_SYNC_BACK_TOTAL_BYTES - archive->total_file_bytes) {
        return -1;
    }
    FILE *file = fopen(filesystem_path, "rb");
    if (file == NULL) {
        return -1;
    }
    unsigned char *contents = malloc(content_length == 0 ? 1 : content_length);
    if (contents == NULL) {
        fclose(file);
        return -1;
    }
    size_t read_count = fread(contents, 1, content_length, file);
    int close_result = fclose(file);
    if (read_count != content_length || close_result != 0) {
        free(contents);
        return -1;
    }
    if (sync_archive_append_le16(archive, (unsigned short)path_length) != 0
        || sync_archive_append_le32(archive, (unsigned int)content_length) != 0
        || sync_archive_append(archive, sync_path, path_length) != 0
        || sync_archive_append(archive, contents, content_length) != 0) {
        free(contents);
        return -1;
    }
    free(contents);
    archive->file_count++;
    archive->total_file_bytes += content_length;
    return 0;
}

static int sync_archive_append_tree(
    struct sync_archive *archive,
    const char *filesystem_root,
    const char *sync_prefix
) {
    struct stat st;
    if (lstat(filesystem_root, &st) != 0) {
        if (errno == ENOENT) {
            return 0;
        }
        return -1;
    }
    if (S_ISLNK(st.st_mode)) {
        return -2;
    }
    if (S_ISREG(st.st_mode)) {
        return sync_archive_append_file(archive, filesystem_root, sync_prefix);
    }
    if (!S_ISDIR(st.st_mode)) {
        return 0;
    }
    DIR *dir = opendir(filesystem_root);
    if (dir == NULL) {
        return -1;
    }
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char child_filesystem_path[1024];
        char child_sync_path[1024];
        int fs_length = snprintf(
            child_filesystem_path,
            sizeof(child_filesystem_path),
            "%s/%s",
            filesystem_root,
            entry->d_name
        );
        int sync_length = snprintf(
            child_sync_path,
            sizeof(child_sync_path),
            "%s/%s",
            sync_prefix,
            entry->d_name
        );
        if (fs_length < 0 || (size_t)fs_length >= sizeof(child_filesystem_path)
            || sync_length < 0 || (size_t)sync_length >= sizeof(child_sync_path)) {
            closedir(dir);
            return -1;
        }
        int append_result = sync_archive_append_tree(archive, child_filesystem_path, child_sync_path);
        if (append_result != 0) {
            closedir(dir);
            return append_result;
        }
    }
    closedir(dir);
    return 0;
}

static char *hex_encode_bytes(const unsigned char *bytes, size_t length) {
    static const char hex[] = "0123456789abcdef";
    if (length > (SIZE_MAX - 1U) / 2U) {
        return NULL;
    }
    char *output = malloc(length * 2U + 1U);
    if (output == NULL) {
        return NULL;
    }
    for (size_t index = 0; index < length; index++) {
        output[index * 2U] = hex[(bytes[index] >> 4U) & 0x0fU];
        output[index * 2U + 1U] = hex[bytes[index] & 0x0fU];
    }
    output[length * 2U] = '\0';
    return output;
}

static int build_sync_output_archive(
    const char *workspace,
    const char *tool,
    char **archive_hex,
    unsigned int *file_count,
    unsigned int *total_bytes
) {
    struct sync_archive archive;
    if (sync_archive_init(&archive) != 0) {
        return -1;
    }
    int append_result = 0;
    if (strcmp(tool, "npm") == 0) {
        char lockfile[1024];
        char node_modules[1024];
        if (snprintf(lockfile, sizeof(lockfile), "%s/package-lock.json", workspace) < 0
            || snprintf(node_modules, sizeof(node_modules), "%s/node_modules", workspace) < 0) {
            sync_archive_free(&archive);
            return -1;
        }
        if (path_exists(lockfile)) {
            append_result = sync_archive_append_file(&archive, lockfile, "package-lock.json");
        }
        if (append_result == 0 && path_exists(node_modules)) {
            append_result = sync_archive_append_tree(&archive, node_modules, "node_modules");
        }
    } else if (strcmp(tool, "pip") == 0 || strcmp(tool, "uv") == 0) {
        char target[1024];
        if (snprintf(target, sizeof(target), "%s/target", workspace) < 0) {
            sync_archive_free(&archive);
            return -1;
        }
        append_result = sync_archive_append_tree(
            &archive,
            target,
            ".venv/lib/python3.11/site-packages"
        );
    } else {
        append_result = -1;
    }
    if (append_result != 0 || archive.file_count == 0) {
        sync_archive_free(&archive);
        return append_result == -2 ? -2 : -1;
    }
    sync_archive_finish(&archive);
    char *hex = hex_encode_bytes(archive.bytes, archive.length);
    if (hex == NULL) {
        sync_archive_free(&archive);
        return -1;
    }
    *archive_hex = hex;
    *file_count = archive.file_count;
    *total_bytes = (unsigned int)archive.total_file_bytes;
    sync_archive_free(&archive);
    return 0;
}

static unsigned int extract_json_uint(const char *json, const char *key, unsigned int fallback) {
    char pattern[64];
    if (snprintf(pattern, sizeof(pattern), "\"%s\"", key) < 0) {
        return fallback;
    }
    const char *cursor = strstr(json, pattern);
    if (cursor == NULL) {
        return fallback;
    }
    cursor += strlen(pattern);
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }
    if (*cursor != ':') {
        return fallback;
    }
    cursor++;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }
    char *end = NULL;
    unsigned long value = strtoul(cursor, &end, 10);
    if (end == cursor || value > 900UL) {
        return fallback;
    }
    return (unsigned int)value;
}

static int extract_json_bool(const char *json, const char *key, int fallback) {
    char pattern[64];
    if (snprintf(pattern, sizeof(pattern), "\"%s\"", key) < 0) {
        return fallback;
    }
    const char *cursor = strstr(json, pattern);
    if (cursor == NULL) {
        return fallback;
    }
    cursor += strlen(pattern);
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }
    if (*cursor != ':') {
        return fallback;
    }
    cursor++;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }
    if (strncmp(cursor, "true", 4) == 0) {
        return 1;
    }
    if (strncmp(cursor, "false", 5) == 0) {
        return 0;
    }
    return fallback;
}

static int mkdir_if_missing(const char *path, mode_t mode) {
    if (mkdir(path, mode) == 0 || errno == EEXIST) {
        return 0;
    }
    return -1;
}

static int write_file(const char *path, const char *body) {
    FILE *file = fopen(path, "w");
    if (file == NULL) {
        return -1;
    }
    int result = fputs(body, file) < 0 ? -1 : 0;
    if (fclose(file) != 0) {
        result = -1;
    }
    return result;
}

static int write_python_api_probe_script(const char *workspace) {
    char probe_path[1024];
    int length = snprintf(probe_path, sizeof(probe_path), "%s/.whoathere-api-probe.py", workspace);
    if (length < 0 || (size_t)length >= sizeof(probe_path)) {
        return -1;
    }
    return write_file(
        probe_path,
        "import importlib\n"
        "import sys\n"
        "module = sys.argv[1]\n"
        "mod = importlib.import_module(module)\n"
        "def _call(fn):\n"
        "    try:\n"
        "        fn()\n"
        "    except Exception:\n"
        "        pass\n"
        "for name in ('run', 'main', 'list', 'get', 'request'):\n"
        "    fn = getattr(mod, name, None)\n"
        "    if callable(fn):\n"
        "        _call(fn)\n"
        "for cls_name in ('Client', 'ApiClient', 'APIClient', 'Session'):\n"
        "    cls = getattr(mod, cls_name, None)\n"
        "    if isinstance(cls, type):\n"
        "        obj = None\n"
        "        try:\n"
        "            obj = cls()\n"
        "        except Exception:\n"
        "            obj = None\n"
        "        if obj is not None:\n"
        "            for name in ('list', 'run', 'get', 'request', 'create'):\n"
        "                fn = getattr(obj, name, None)\n"
        "                if callable(fn):\n"
        "                    _call(fn)\n"
    );
}

static int write_binary_file(const char *path, const unsigned char *body, size_t length) {
    FILE *file = fopen(path, "wb");
    if (file == NULL) {
        return -1;
    }
    int result = fwrite(body, 1, length, file) == length ? 0 : -1;
    if (fclose(file) != 0) {
        result = -1;
    }
    return result;
}

static int path_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int safe_relative_path(const char *path) {
    if (path == NULL || path[0] == '\0' || path[0] == '/') {
        return 0;
    }
    if (strstr(path, "..") != NULL) {
        return 0;
    }
    if (strstr(path, "//") != NULL) {
        return 0;
    }
    for (const char *cursor = path; *cursor != '\0'; cursor++) {
        char value = *cursor;
        if ((value >= 'a' && value <= 'z')
            || (value >= 'A' && value <= 'Z')
            || (value >= '0' && value <= '9')
            || value == '/'
            || value == '.'
            || value == '_'
            || value == '-'
            || value == '+') {
            continue;
        }
        return 0;
    }
    return 1;
}

static int safe_python_module(const char *module) {
    if (module == NULL || module[0] == '\0' || strstr(module, "..") != NULL) {
        return 0;
    }
    for (const char *cursor = module; *cursor != '\0'; cursor++) {
        char value = *cursor;
        if ((value >= 'a' && value <= 'z')
            || (value >= 'A' && value <= 'Z')
            || (value >= '0' && value <= '9')
            || value == '_'
            || value == '.') {
            continue;
        }
        return 0;
    }
    return 1;
}

static int make_parent_dirs(char *path) {
    for (char *cursor = path + 1; *cursor != '\0'; cursor++) {
        if (*cursor != '/') {
            continue;
        }
        *cursor = '\0';
        if (mkdir_if_missing(path, 0700) != 0) {
            *cursor = '/';
            return -1;
        }
        *cursor = '/';
    }
    return 0;
}

static int hex_value(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return 10 + value - 'a';
    }
    if (value >= 'A' && value <= 'F') {
        return 10 + value - 'A';
    }
    return -1;
}

static unsigned short read_le16(const unsigned char *bytes) {
    return (unsigned short)bytes[0] | ((unsigned short)bytes[1] << 8);
}

static unsigned int read_le32(const unsigned char *bytes) {
    return (unsigned int)bytes[0]
        | ((unsigned int)bytes[1] << 8)
        | ((unsigned int)bytes[2] << 16)
        | ((unsigned int)bytes[3] << 24);
}

static int decode_hex_payload(const char *hex, unsigned char **out_bytes, size_t *out_length) {
    size_t hex_length = strlen(hex);
    if (hex_length == 0 || hex_length % 2 != 0 || hex_length > (size_t)(2U * 1024U * 1024U)) {
        return -1;
    }
    size_t byte_length = hex_length / 2;
    unsigned char *bytes = malloc(byte_length);
    if (bytes == NULL) {
        return -1;
    }
    for (size_t index = 0; index < byte_length; index++) {
        int high = hex_value(hex[index * 2]);
        int low = hex_value(hex[index * 2 + 1]);
        if (high < 0 || low < 0) {
            free(bytes);
            return -1;
        }
        bytes[index] = (unsigned char)((high << 4) | low);
    }
    *out_bytes = bytes;
    *out_length = byte_length;
    return 0;
}

static int materialize_project_payload(const char *workspace, const char *payload_hex) {
    unsigned char *payload = NULL;
    size_t payload_length = 0;
    if (decode_hex_payload(payload_hex, &payload, &payload_length) != 0) {
        return -1;
    }
    if (payload_length < 8 || memcmp(payload, "WTP1", 4) != 0) {
        free(payload);
        return -1;
    }
    size_t offset = 4;
    unsigned int file_count = read_le32(payload + offset);
    offset += 4;
    if (file_count > 128U) {
        free(payload);
        return -1;
    }
    for (unsigned int index = 0; index < file_count; index++) {
        if (offset + 6 > payload_length) {
            free(payload);
            return -1;
        }
        unsigned short path_length = read_le16(payload + offset);
        offset += 2;
        unsigned int content_length = read_le32(payload + offset);
        offset += 4;
        if (path_length == 0 || content_length > 128U * 1024U || offset + path_length + content_length > payload_length) {
            free(payload);
            return -1;
        }
        char relative_path[512];
        if ((size_t)path_length >= sizeof(relative_path)) {
            free(payload);
            return -1;
        }
        memcpy(relative_path, payload + offset, path_length);
        relative_path[path_length] = '\0';
        offset += path_length;
        if (!safe_relative_path(relative_path)) {
            free(payload);
            return -1;
        }
        char destination[1024];
        int length = snprintf(destination, sizeof(destination), "%s/%s", workspace, relative_path);
        if (length < 0 || (size_t)length >= sizeof(destination)) {
            free(payload);
            return -1;
        }
        char parent_path[1024];
        if (snprintf(parent_path, sizeof(parent_path), "%s", destination) < 0) {
            free(payload);
            return -1;
        }
        if (make_parent_dirs(parent_path) != 0) {
            free(payload);
            return -1;
        }
        if (write_binary_file(destination, payload + offset, content_length) != 0) {
            free(payload);
            return -1;
        }
        offset += content_length;
    }
    free(payload);
    return offset == payload_length ? 0 : -1;
}

static int command_exists(const char *command) {
    char check[512];
    int length = snprintf(check, sizeof(check), WHOATHERE_PATH_PREFIX "command -v %s >/dev/null 2>&1", command);
    if (length < 0 || (size_t)length >= sizeof(check)) {
        return 0;
    }
    int status = system(check);
    return status == 0;
}

static int pip_available(void) {
    return system(WHOATHERE_PIP_PREFIX "$WHOATHERE_PYTHON -m pip --version >/dev/null 2>&1") == 0;
}

static int python_available(void) {
    return system(WHOATHERE_PIP_PREFIX "$WHOATHERE_PYTHON -c 'import sys' >/dev/null 2>&1") == 0;
}

struct command_result {
    int exit_code;
    int timed_out;
    int execution_identity_isolated;
    int runtime_network_telemetry_active;
    unsigned int network_telemetry_events;
    int process_group_cleanup_enforced;
};

static void drain_runtime_telemetry(int fd, struct command_result *result) {
    if (fd < 0) {
        return;
    }
    char event[32];
    while (1) {
        ssize_t count = recv(fd, event, sizeof(event), MSG_DONTWAIT);
        if (count <= 0) {
            return;
        }
        for (ssize_t index = 0; index < count; index++) {
            if (event[index] == 'I') {
                result->execution_identity_isolated = 1;
            } else if (event[index] == 'R') {
                result->runtime_network_telemetry_active = 1;
            } else if (event[index] == 'N') {
                result->network_telemetry_events++;
            }
        }
    }
}

static int write_runtime_telemetry_files(const char *workspace, char *control_dir, size_t capacity) {
    int length = snprintf(control_dir, capacity, "%s.control", workspace);
    if (length < 0 || (size_t)length >= capacity || mkdir(control_dir, 0700) != 0) {
        return -1;
    }
    char node_preload[1024];
    char python_preload[1024];
    char bin_dir[1024];
    if (snprintf(node_preload, sizeof(node_preload), "%s/node-preload.cjs", control_dir) < 0
        || snprintf(python_preload, sizeof(python_preload), "%s/sitecustomize.py", control_dir) < 0
        || snprintf(bin_dir, sizeof(bin_dir), "%s/bin", control_dir) < 0
        || mkdir(bin_dir, 0755) != 0) {
        return -1;
    }
    const char *node_source =
        "'use strict';\n"
        "const fs = require('fs');\n"
        "const fd = Number(process.env.WHOATHERE_TELEMETRY_FD);\n"
        "let networkSent = false;\n"
        "function emit(value) { try { if (Number.isInteger(fd)) fs.writeSync(fd, value); } catch (_) {} }\n"
        "function mark() { if (!networkSent) { networkSent = true; emit('N'); } }\n"
        "function wrap(object, name) { const original = object && object[name]; if (typeof original !== 'function') return; object[name] = function(...args) { mark(); return Reflect.apply(original, this, args); }; }\n"
        "emit('R');\n"
        "const dns = require('dns');\n"
        "['lookup','lookupService','resolve','resolve4','resolve6','resolveAny','resolveCaa','resolveCname','resolveMx','resolveNaptr','resolveNs','resolvePtr','resolveSoa','resolveSrv','resolveTxt','reverse'].forEach((name) => wrap(dns, name));\n"
        "if (dns.promises) ['lookup','lookupService','resolve','resolve4','resolve6','resolveAny','resolveCaa','resolveCname','resolveMx','resolveNaptr','resolveNs','resolvePtr','resolveSoa','resolveSrv','resolveTxt','reverse'].forEach((name) => wrap(dns.promises, name));\n"
        "const net = require('net'); wrap(net.Socket && net.Socket.prototype, 'connect'); wrap(net, 'connect'); wrap(net, 'createConnection');\n"
        "const dgram = require('dgram'); wrap(dgram.Socket && dgram.Socket.prototype, 'connect'); wrap(dgram.Socket && dgram.Socket.prototype, 'send');\n"
        "const tls = require('tls'); wrap(tls, 'connect');\n"
        "const http = require('http'); wrap(http, 'request'); wrap(http, 'get');\n"
        "const https = require('https'); wrap(https, 'request'); wrap(https, 'get');\n"
        "if (typeof globalThis.fetch === 'function') { const originalFetch = globalThis.fetch; globalThis.fetch = function(...args) { mark(); return Reflect.apply(originalFetch, this, args); }; }\n";
    const char *python_source =
        "import os\n"
        "import socket\n"
        "_fd = int(os.environ.get('WHOATHERE_TELEMETRY_FD', '-1'))\n"
        "_network_sent = False\n"
        "def _emit(value):\n"
        "    try:\n"
        "        if _fd >= 0: os.write(_fd, value)\n"
        "    except OSError:\n"
        "        pass\n"
        "def _mark():\n"
        "    global _network_sent\n"
        "    if not _network_sent:\n"
        "        _network_sent = True\n"
        "        _emit(b'N')\n"
        "def _wrap(object, name):\n"
        "    original = getattr(object, name, None)\n"
        "    if original is None: return\n"
        "    def wrapped(*args, **kwargs):\n"
        "        _mark()\n"
        "        return original(*args, **kwargs)\n"
        "    setattr(object, name, wrapped)\n"
        "_emit(b'R')\n"
        "for _name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr', 'create_connection'):\n"
        "    _wrap(socket, _name)\n"
        "for _name in ('connect', 'connect_ex', 'sendto', 'sendmsg'):\n"
        "    _wrap(socket.socket, _name)\n";
    if (write_file(node_preload, node_source) != 0
        || write_file(python_preload, python_source) != 0
        || chmod(node_preload, 0444) != 0
        || chmod(python_preload, 0444) != 0) {
        return -1;
    }
    const char *tools[] = {"curl", "wget", "nc", "ncat", "dig", "host", "nslookup", "ssh", "scp"};
    for (size_t index = 0; index < sizeof(tools) / sizeof(tools[0]); index++) {
        char wrapper[1024];
        if (snprintf(wrapper, sizeof(wrapper), "%s/%s", bin_dir, tools[index]) < 0
            || write_file(wrapper, "#!/bin/sh\nprintf N >&3\nexit 69\n") != 0
            || chmod(wrapper, 0555) != 0) {
            return -1;
        }
    }
    return chmod(control_dir, 0555);
}

static int chown_workspace_tree(const char *path, uid_t uid, gid_t gid) {
    struct stat st;
    if (lstat(path, &st) != 0 || S_ISLNK(st.st_mode)) {
        return -1;
    }
    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        if (dir == NULL) {
            return -1;
        }
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            char child[1024];
            int length = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
            if (length < 0 || (size_t)length >= sizeof(child)
                || chown_workspace_tree(child, uid, gid) != 0) {
                closedir(dir);
                return -1;
            }
        }
        closedir(dir);
    }
    return chown(path, uid, gid);
}

static struct command_result run_shell_fixture_with_boundary(
    const char *workspace,
    const char *control_dir,
    uid_t execution_uid,
    gid_t execution_gid,
    int require_identity_isolation,
    const char *command,
    unsigned int timeout_seconds
) {
    struct command_result result;
    memset(&result, 0, sizeof(result));
    result.exit_code = 70;

    int telemetry_fds[2] = {-1, -1};
    if (control_dir != NULL && socketpair(AF_UNIX, SOCK_DGRAM, 0, telemetry_fds) != 0) {
        return result;
    }

    pid_t pid = fork();
    if (pid < 0) {
        if (telemetry_fds[0] >= 0) close(telemetry_fds[0]);
        if (telemetry_fds[1] >= 0) close(telemetry_fds[1]);
        return result;
    }
    if (pid == 0) {
        if (telemetry_fds[0] >= 0) {
            close(telemetry_fds[0]);
            if (telemetry_fds[1] != WHOATHERE_TELEMETRY_FD) {
                if (dup2(telemetry_fds[1], WHOATHERE_TELEMETRY_FD) < 0) {
                    _exit(70);
                }
                close(telemetry_fds[1]);
            }
            (void)fcntl(WHOATHERE_TELEMETRY_FD, F_SETFD, 0);
        }
        if (setpgid(0, 0) != 0) {
            _exit(70);
        }
        if (chdir(workspace) != 0) {
            _exit(70);
        }
        setenv("HOME", workspace, 1);
        setenv("NPM_TOKEN", "whoathere_fake_npm_token", 1);
        setenv("PYPI_TOKEN", "whoathere_fake_pypi_token", 1);
        setenv("GITHUB_TOKEN", "whoathere_fake_github_token", 1);
        setenv("AWS_ACCESS_KEY_ID", "WHOATHEREFAKEAWSKEY", 1);
        setenv("AWS_SECRET_ACCESS_KEY", "whoathere_fake_aws_secret", 1);
        setenv("KUBECONFIG", "canaries/kubeconfig", 1);
        setenv("VAULT_TOKEN", "whoathere_fake_vault_token", 1);
        setenv("OPENAI_API_KEY", "whoathere_fake_openai_token", 1);
        setenv("CI", "true", 1);
        if (control_dir != NULL) {
            char telemetry_fd[16];
            char node_options[1200];
            char path[1400];
            snprintf(telemetry_fd, sizeof(telemetry_fd), "%d", WHOATHERE_TELEMETRY_FD);
            snprintf(node_options, sizeof(node_options), "--require=%s/node-preload.cjs", control_dir);
            snprintf(path, sizeof(path), "%s/bin:%s", control_dir, WHOATHERE_TOOL_PATH);
            setenv("WHOATHERE_TELEMETRY_FD", telemetry_fd, 1);
            setenv("WHOATHERE_TELEMETRY_DIR", control_dir, 1);
            setenv("NODE_OPTIONS", node_options, 1);
            setenv("PYTHONPATH", control_dir, 1);
            setenv("PATH", path, 1);
        } else {
            setenv("PATH", WHOATHERE_TOOL_PATH, 1);
        }
        if (require_identity_isolation) {
            if (setgroups(0, NULL) != 0
                || setgid(execution_gid) != 0
                || setuid(execution_uid) != 0) {
                _exit(70);
            }
            if (telemetry_fds[1] >= 0) {
                (void)write(WHOATHERE_TELEMETRY_FD, "I", 1);
            }
        }
        freopen("stdout.log", "w", stdout);
        freopen("stderr.log", "w", stderr);
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(70);
    }

    if (telemetry_fds[1] >= 0) {
        close(telemetry_fds[1]);
    }
    int process_group_ready = setpgid(pid, pid) == 0;
    if (!process_group_ready && (errno == EACCES || errno == EPERM)) {
        process_group_ready = getpgid(pid) == pid;
    }

    time_t start = time(NULL);
    int status = 0;
    while (1) {
        drain_runtime_telemetry(telemetry_fds[0], &result);
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            if (WIFEXITED(status)) {
                result.exit_code = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                result.exit_code = 128 + WTERMSIG(status);
            }
            if (process_group_ready) {
                (void)kill(-pid, SIGKILL);
                result.process_group_cleanup_enforced = 1;
            }
            drain_runtime_telemetry(telemetry_fds[0], &result);
            if (telemetry_fds[0] >= 0) close(telemetry_fds[0]);
            return result;
        }
        if (waited < 0) {
            result.exit_code = 70;
            if (process_group_ready) (void)kill(-pid, SIGKILL);
            if (telemetry_fds[0] >= 0) close(telemetry_fds[0]);
            return result;
        }
        if ((unsigned int)(time(NULL) - start) >= timeout_seconds) {
            if (process_group_ready) {
                (void)kill(-pid, SIGKILL);
                result.process_group_cleanup_enforced = 1;
            } else {
                (void)kill(pid, SIGKILL);
            }
            waitpid(pid, &status, 0);
            result.exit_code = 124;
            result.timed_out = 1;
            drain_runtime_telemetry(telemetry_fds[0], &result);
            if (telemetry_fds[0] >= 0) close(telemetry_fds[0]);
            return result;
        }
        usleep(100000);
    }
}

static int prepare_workspace(const char *job_id, char *workspace, size_t workspace_capacity) {
    if (mkdir_if_missing(WHOATHERE_WORK_ROOT, 0711) != 0
        || chmod(WHOATHERE_WORK_ROOT, 0711) != 0) {
        return -1;
    }
    int length = snprintf(workspace, workspace_capacity, "%s/%s", WHOATHERE_WORK_ROOT, job_id);
    if (length < 0 || (size_t)length >= workspace_capacity) {
        return -1;
    }
    if (mkdir(workspace, 0700) != 0) {
        return -1;
    }
    char canaries[512];
    if (snprintf(canaries, sizeof(canaries), "%s/canaries", workspace) < 0) {
        return -1;
    }
    if (mkdir_if_missing(canaries, 0700) != 0) {
        return -1;
    }
    char kubeconfig[512];
    if (snprintf(kubeconfig, sizeof(kubeconfig), "%s/kubeconfig", canaries) < 0) {
        return -1;
    }
    return write_file(kubeconfig, "token: whoathere_fake_kube_token\n");
}

static int safe_job_identifier(const char *value) {
    if (value == NULL || value[0] == '\0') {
        return 0;
    }
    size_t length = 0;
    for (const char *cursor = value; *cursor != '\0'; cursor++) {
        char byte = *cursor;
        if (!((byte >= 'a' && byte <= 'z')
            || (byte >= 'A' && byte <= 'Z')
            || (byte >= '0' && byte <= '9')
            || byte == '-'
            || byte == '_')) {
            return 0;
        }
        length++;
        if (length > 128U) {
            return 0;
        }
    }
    return 1;
}

static int write_npm_fixture(const char *workspace, const char *fixture) {
    char package_json[512];
    char module_js[512];
    if (snprintf(package_json, sizeof(package_json), "%s/package.json", workspace) < 0) {
        return -1;
    }
    if (snprintf(module_js, sizeof(module_js), "%s/index.js", workspace) < 0) {
        return -1;
    }
    if (strcmp(fixture, "clean_npm_lifecycle") == 0) {
        int package_result = write_file(
            package_json,
            "{\"name\":\"whoathere-clean-fixture\",\"version\":\"0.0.1\",\"main\":\"index.js\",\"scripts\":{\"postinstall\":\"node -e \\\"require('fs').writeFileSync('clean.marker','ok')\\\"\"}}\n"
        );
        return package_result || write_file(module_js, "module.exports = { value: 'clean' };\n");
    }
    if (strcmp(fixture, "npm_postinstall_canary_exfil") == 0
        || strcmp(fixture, "npm_prepare_remote_fetch") == 0
        || strcmp(fixture, "npm_darwin_only_payload") == 0
        || strcmp(fixture, "delayed_ci_canary") == 0
        || strcmp(fixture, "dns_tunneling_canary") == 0
        || strcmp(fixture, "https_exfil_canary") == 0
        || strcmp(fixture, "npm_bin_token_theft") == 0
        || strcmp(fixture, "api_compatible_canary_theft") == 0) {
        const char *script_name = strcmp(fixture, "npm_prepare_remote_fetch") == 0 ? "prepare" : "postinstall";
        char body[2048];
        int length = snprintf(
            body,
            sizeof(body),
            "{\"name\":\"whoathere-malicious-fixture\",\"version\":\"0.0.1\",\"main\":\"index.js\",\"bin\":{\"whoathere-fixture\":\"index.js\"},\"scripts\":{\"%s\":\"node -e \\\"const fs=require('fs'); if(process.env.NPM_TOKEN||process.env.GITHUB_TOKEN) fs.writeFileSync('canary-read.marker','1'); fs.writeFileSync('network-attempt.marker','mock-egress'); if(process.env.CI==='true') fs.writeFileSync('ci-activated.marker','1');\\\"\"}}\n",
            script_name
        );
        if (length < 0 || (size_t)length >= sizeof(body)) {
            return -1;
        }
        int package_result = write_file(package_json, body);
        int module_result = write_file(
            module_js,
            "#!/usr/bin/env node\nconst fs = require('fs');\nexports.run = function() { if (process.env.NPM_TOKEN || process.env.GITHUB_TOKEN) fs.writeFileSync('api-canary-read.marker', '1'); };\nif (require.main === module) exports.run();\n"
        );
        chmod(module_js, 0755);
        return package_result || module_result;
    }
    return -1;
}

static int write_python_fixture(const char *workspace, const char *fixture) {
    char setup_py[512];
    char module_py[512];
    char pyproject_toml[512];
    char backend_py[512];
    if (snprintf(setup_py, sizeof(setup_py), "%s/setup.py", workspace) < 0) {
        return -1;
    }
    if (snprintf(module_py, sizeof(module_py), "%s/whoathere_fixture.py", workspace) < 0) {
        return -1;
    }
    if (snprintf(pyproject_toml, sizeof(pyproject_toml), "%s/pyproject.toml", workspace) < 0) {
        return -1;
    }
    if (snprintf(backend_py, sizeof(backend_py), "%s/whoathere_backend.py", workspace) < 0) {
        return -1;
    }
    if (strcmp(fixture, "clean_pip_package") == 0) {
        return write_file(
            setup_py,
            "from setuptools import setup\nsetup(name='whoathere-fixture', version='0.0.1', py_modules=['whoathere_fixture'])\n"
        ) || write_file(module_py, "VALUE = 'clean'\n");
    }
    if (strcmp(fixture, "pypi_pep517_canary") == 0) {
        int pyproject_result = write_file(
            pyproject_toml,
            "[build-system]\nrequires = []\nbuild-backend = \"whoathere_backend\"\nbackend-path = [\".\"]\n"
        );
        int backend_result = write_file(
            backend_py,
            "import os, pathlib, zipfile\n"
            "DIST = 'whoathere_fixture-0.0.1.dist-info'\n"
            "METADATA = 'Metadata-Version: 2.1\\nName: whoathere-fixture\\nVersion: 0.0.1\\n'\n"
            "WHEEL = 'Wheel-Version: 1.0\\nGenerator: whoathere\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n'\n"
            "def _mark():\n"
            "    if os.environ.get('PYPI_TOKEN'):\n"
            "        pathlib.Path('canary-read.marker').write_text('1')\n"
            "def get_requires_for_build_wheel(config_settings=None):\n"
            "    _mark(); return []\n"
            "def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):\n"
            "    _mark(); p = pathlib.Path(metadata_directory) / DIST; p.mkdir(parents=True, exist_ok=True); (p / 'METADATA').write_text(METADATA); (p / 'WHEEL').write_text(WHEEL); return DIST\n"
            "def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):\n"
            "    _mark(); wheel_name = 'whoathere_fixture-0.0.1-py3-none-any.whl'; path = pathlib.Path(wheel_directory) / wheel_name\n"
            "    with zipfile.ZipFile(path, 'w') as z:\n"
            "        z.writestr('whoathere_fixture.py', \"VALUE = 'pep517'\\n\"); z.writestr(DIST + '/METADATA', METADATA); z.writestr(DIST + '/WHEEL', WHEEL); z.writestr(DIST + '/RECORD', '')\n"
            "    return wheel_name\n"
        );
        int module_result = write_file(module_py, "VALUE = 'pep517'\n");
        return pyproject_result || backend_result || module_result;
    }
    if (strcmp(fixture, "pypi_setup_py_canary") == 0
        || strcmp(fixture, "pypi_import_time_canary") == 0
        || strcmp(fixture, "python_import_time_canary") == 0
        || strcmp(fixture, "python_pth_startup_hook") == 0
        || strcmp(fixture, "api_compatible_canary_theft") == 0) {
        int setup_result = write_file(
            setup_py,
            "from setuptools import setup\nimport os, pathlib\nif os.environ.get('PYPI_TOKEN'):\n    pathlib.Path('canary-read.marker').write_text('1')\nsetup(name='whoathere-fixture', version='0.0.1', py_modules=['whoathere_fixture'])\n"
        );
        const char *module_body = strcmp(fixture, "api_compatible_canary_theft") == 0
            ? "import os, pathlib\nVALUE = 'compatible'\ndef run():\n    if os.environ.get('PYPI_TOKEN'):\n        pathlib.Path('api-canary-read.marker').write_text('1')\n    return VALUE\n"
            : "import os, pathlib\nif os.environ.get('PYPI_TOKEN'):\n    pathlib.Path('import-canary-read.marker').write_text('1')\nVALUE = 'loaded'\n";
        int module_result = write_file(module_py, module_body);
        if (strcmp(fixture, "python_pth_startup_hook") == 0) {
            char pth[512];
            if (snprintf(pth, sizeof(pth), "%s/whoathere_hook.pth", workspace) < 0) {
                return -1;
            }
            return setup_result || module_result || write_file(
                pth,
                "import os,pathlib; pathlib.Path('pth-canary-read.marker').write_text('1') if os.environ.get('PYPI_TOKEN') else None\n"
            );
        }
        return setup_result || module_result;
    }
    return -1;
}

static int classification_only_fixture(const char *fixture) {
    return strcmp(fixture, "native_extension_canary") == 0
        || strcmp(fixture, "binary_wheel_native_marker") == 0
        || strcmp(fixture, "direct_git_tarball_canary") == 0
        || strcmp(fixture, "direct_url_vcs_editable") == 0
        || strcmp(fixture, "uv_unpinned_dependency") == 0
        || strcmp(fixture, "npm_transitive_malicious_dependency") == 0;
}

static const char *classification_reason(const char *fixture) {
    if (strcmp(fixture, "native_extension_canary") == 0 || strcmp(fixture, "binary_wheel_native_marker") == 0) {
        return "\"native_or_binary_requires_manual_review\"";
    }
    if (strcmp(fixture, "direct_git_tarball_canary") == 0 || strcmp(fixture, "direct_url_vcs_editable") == 0) {
        return "\"direct_or_vcs_dependency_denied_by_default\"";
    }
    if (strcmp(fixture, "uv_unpinned_dependency") == 0) {
        return "\"uv_unpinned_dependency_requires_last_known_good_or_manual_review\"";
    }
    return "\"fixture_class_requires_manual_review\"";
}

static int write_detonation_response_ex(
    int fd,
    const char *job_id,
    const char *tool,
    const char *command_class,
    const char *fixture,
    const char *status,
    const char *verdict,
    const char *reason_codes_json,
    int exit_code,
    int command_exit_code,
    int timed_out,
    int canary_access,
    int network_attempt,
    int filesystem_write,
    int toolchain_available,
    int sync_back_enabled,
    const char *sync_output_archive_hex,
    unsigned int sync_output_file_count,
    unsigned int sync_output_total_bytes
) {
    char response[8192];
    int length = snprintf(
        response,
        sizeof(response),
        "{\"protocol\":\"whoathere.guest_detonation.v1\",\"schema_version\":\"whoathere.macos_vm.bundle.v1\",\"agent_version\":\"0.3.0\",\"job_id\":\"%s\",\"request_nonce\":\"%s\",\"tool\":\"%s\",\"command_class\":\"%s\",\"fixture\":\"%s\",\"project_workflow\":\"%s\",\"project_api_probe_enabled\":%s,\"status\":\"%s\",\"verdict\":\"%s\",\"reason_codes\":[%s],\"command_exit_code\":%d,\"timed_out\":%s,\"canary_access_detected\":%s,\"network_attempt_detected\":%s,\"filesystem_write_detected\":%s,\"toolchain_available\":%s,\"execution_identity\":\"%s\",\"execution_identity_isolated\":%s,\"runtime_network_telemetry_active\":%s,\"network_telemetry_events\":%u,\"process_group_cleanup_enforced\":%s,\"stdout_captured\":false,\"stderr_captured\":false,\"raw_canary_values_captured\":false,\"sync_back_enabled\":%s,\"host_package_execution_enabled\":false,\"high_risk_package_execution_enabled\":false",
        job_id,
        current_request_nonce,
        tool,
        command_class,
        fixture,
        current_project_workflow,
        current_project_api_probe_enabled ? "true" : "false",
        status,
        verdict,
        reason_codes_json,
        command_exit_code,
        timed_out ? "true" : "false",
        canary_access ? "true" : "false",
        network_attempt ? "true" : "false",
        filesystem_write ? "true" : "false",
        toolchain_available ? "true" : "false",
        current_execution_identity_isolated ? "nobody" : "unverified",
        current_execution_identity_isolated ? "true" : "false",
        current_runtime_network_telemetry_active ? "true" : "false",
        current_network_telemetry_events,
        current_process_group_cleanup_enforced ? "true" : "false",
        sync_back_enabled ? "true" : "false"
    );
    if (length < 0 || (size_t)length >= sizeof(response)) {
        return -1;
    }
    if (write_all(fd, response, (size_t)length) != 0) {
        return -1;
    }
    if (sync_back_enabled && sync_output_archive_hex != NULL) {
        char sync_fields[256];
        int sync_length = snprintf(
            sync_fields,
            sizeof(sync_fields),
            ",\"sync_output_archive_hex\":\""
        );
        if (sync_length < 0 || (size_t)sync_length >= sizeof(sync_fields)) {
            return -1;
        }
        if (write_all(fd, sync_fields, (size_t)sync_length) != 0
            || write_all(fd, sync_output_archive_hex, strlen(sync_output_archive_hex)) != 0) {
            return -1;
        }
        sync_length = snprintf(
            sync_fields,
            sizeof(sync_fields),
            "\",\"sync_output_file_count\":%u,\"sync_output_total_bytes\":%u",
            sync_output_file_count,
            sync_output_total_bytes
        );
        if (sync_length < 0 || (size_t)sync_length >= sizeof(sync_fields)) {
            return -1;
        }
        if (write_all(fd, sync_fields, (size_t)sync_length) != 0) {
            return -1;
        }
    }
    char suffix[64];
    int suffix_length = snprintf(suffix, sizeof(suffix), ",\"exit_code\":%d}\n", exit_code);
    if (suffix_length < 0 || (size_t)suffix_length >= sizeof(suffix)) {
        return -1;
    }
    return write_all(fd, suffix, (size_t)suffix_length);
}

static int write_detonation_response(
    int fd,
    const char *job_id,
    const char *tool,
    const char *command_class,
    const char *fixture,
    const char *status,
    const char *verdict,
    const char *reason_codes_json,
    int exit_code,
    int command_exit_code,
    int timed_out,
    int canary_access,
    int network_attempt,
    int filesystem_write,
    int toolchain_available
) {
    return write_detonation_response_ex(
        fd,
        job_id,
        tool,
        command_class,
        fixture,
        status,
        verdict,
        reason_codes_json,
        exit_code,
        command_exit_code,
        timed_out,
        canary_access,
        network_attempt,
        filesystem_write,
        toolchain_available,
        0,
        NULL,
        0,
        0
    );
}

static int run_detonation_job(int fd, const char *line) {
    current_request_nonce[0] = '\0';
    current_project_workflow[0] = '\0';
    current_project_api_probe_enabled = 0;
    current_execution_identity_isolated = 0;
    current_runtime_network_telemetry_active = 0;
    current_network_telemetry_events = 0;
    current_process_group_cleanup_enforced = 0;
    char job_id[WHOATHERE_MAX_FIELD];
    char tool[WHOATHERE_MAX_FIELD];
    char command_class[WHOATHERE_MAX_FIELD];
    char fixture[WHOATHERE_MAX_FIELD];
    char request_nonce[WHOATHERE_MAX_FIELD];
    if (extract_json_string(line, "job_id", job_id, sizeof(job_id)) != 0
        || extract_json_string(line, "tool", tool, sizeof(tool)) != 0
        || extract_json_string(line, "command_class", command_class, sizeof(command_class)) != 0
        || extract_json_string(line, "fixture", fixture, sizeof(fixture)) != 0
        || extract_json_string(line, "request_nonce", request_nonce, sizeof(request_nonce)) != 0) {
        return write_detonation_response(
            fd,
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "fail_closed",
            "fail_closed_runner_error",
            "\"guest_request_missing_required_fields\"",
            70,
            70,
            0,
            0,
            0,
            0,
            0
        );
    }
    if (!safe_job_identifier(job_id)
        || !safe_job_identifier(request_nonce)
        || !safe_job_identifier(tool)
        || !safe_job_identifier(command_class)
        || !safe_job_identifier(fixture)) {
        return write_detonation_response(
            fd,
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "fail_closed",
            "fail_closed_runner_error",
            "\"guest_request_identifier_rejected\"",
            70,
            70,
            0,
            0,
            0,
            0,
            0
        );
    }
    snprintf(current_request_nonce, sizeof(current_request_nonce), "%s", request_nonce);
    unsigned int timeout_seconds = extract_json_uint(line, "timeout_seconds", 120);
    if (timeout_seconds < 5) {
        timeout_seconds = 5;
    }
    if (timeout_seconds > 900) {
        timeout_seconds = 900;
    }
    int sync_back_requested = extract_json_bool(line, "sync_back_enabled", 0);
    int project_mode = strcmp(fixture, "project_mirror") == 0;
    char project_workflow[WHOATHERE_MAX_FIELD] = "";
    char project_import_module[WHOATHERE_MAX_FIELD] = "";
    char project_requirements_path[WHOATHERE_MAX_FIELD] = "";
    char *project_payload_hex = NULL;
    if (project_mode) {
        project_payload_hex = extract_json_string_alloc(line, "project_payload_hex", (size_t)(2U * 1024U * 1024U));
        if (project_payload_hex == NULL
            || extract_json_string(line, "project_workflow", project_workflow, sizeof(project_workflow)) != 0) {
            free(project_payload_hex);
            return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_payload_or_workflow_missing\"", 70, 70, 0, 0, 0, 0, 0);
        }
        snprintf(current_project_workflow, sizeof(current_project_workflow), "%s", project_workflow);
        current_project_api_probe_enabled = extract_json_bool(line, "project_api_probe_enabled", 0);
        (void)extract_json_string(line, "project_import_module", project_import_module, sizeof(project_import_module));
        (void)extract_json_string(line, "project_requirements_path", project_requirements_path, sizeof(project_requirements_path));
        if ((strcmp(tool, "pip") == 0 || strcmp(tool, "uv") == 0) && current_project_api_probe_enabled && project_import_module[0] == '\0') {
            free(project_payload_hex);
            return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_api_probe_module_missing\"", 70, 70, 0, 0, 0, 0, 0);
        }
        if ((strcmp(tool, "pip") == 0 || strcmp(tool, "uv") == 0) && project_import_module[0] != '\0' && !safe_python_module(project_import_module)) {
            free(project_payload_hex);
            return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_import_module_rejected\"", 70, 70, 0, 0, 0, 0, 0);
        }
        if ((strcmp(tool, "pip") == 0 || strcmp(tool, "uv") == 0) && project_requirements_path[0] != '\0' && !safe_relative_path(project_requirements_path)) {
            free(project_payload_hex);
            return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_requirements_path_rejected\"", 70, 70, 0, 0, 0, 0, 0);
        }
    }

    if (classification_only_fixture(fixture)) {
        return write_detonation_response(
            fd,
            job_id,
            tool,
            command_class,
            fixture,
            "manual_review",
            "manual_review_risky_class",
            classification_reason(fixture),
            20,
            0,
            0,
            0,
            0,
            0,
            1
        );
    }

    char workspace[512];
    if (prepare_workspace(job_id, workspace, sizeof(workspace)) != 0) {
        return write_detonation_response(
            fd,
            job_id,
            tool,
            command_class,
            fixture,
            "fail_closed",
            "fail_closed_runner_error",
            "\"guest_workspace_prepare_failed\"",
            70,
            70,
            0,
            0,
            0,
            0,
            0
        );
    }

    const char *tool_command = NULL;
    const char *shell_command = NULL;
    char shell_command_buffer[4096];
    if (strcmp(tool, "npm") == 0) {
        tool_command = "npm";
        if (project_mode) {
            if (materialize_project_payload(workspace, project_payload_hex) != 0) {
                free(project_payload_hex);
                return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_payload_materialize_failed\"", 70, 70, 0, 0, 0, 0, 0);
            }
            free(project_payload_hex);
            project_payload_hex = NULL;
            const char *api_probe = current_project_api_probe_enabled
                ? " && node -e \"try{const m=require('./'); if(m&&typeof m.run==='function') m.run(); if(typeof m==='function') m();}catch(e){}\""
                : "";
            if (strcmp(project_workflow, "npm_project_install") == 0) {
                int command_length = snprintf(
                    shell_command_buffer,
                    sizeof(shell_command_buffer),
                    "npm install --foreground-scripts --ignore-scripts=false --no-audit --no-fund --offline%s",
                    api_probe
                );
                if (command_length < 0 || (size_t)command_length >= sizeof(shell_command_buffer)) {
                    return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_command_too_long\"", 70, 70, 0, 0, 0, 0, 0);
                }
                shell_command = shell_command_buffer;
            } else if (strcmp(project_workflow, "npm_ci") == 0) {
                int command_length = snprintf(
                    shell_command_buffer,
                    sizeof(shell_command_buffer),
                    "npm ci --foreground-scripts --ignore-scripts=false --no-audit --no-fund --offline%s",
                    api_probe
                );
                if (command_length < 0 || (size_t)command_length >= sizeof(shell_command_buffer)) {
                    return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_command_too_long\"", 70, 70, 0, 0, 0, 0, 0);
                }
                shell_command = shell_command_buffer;
            } else {
                return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_unsupported_workflow", "\"project_workflow_unsupported\"", 20, 20, 0, 0, 0, 0, 0);
            }
        } else if (write_npm_fixture(workspace, fixture) != 0) {
            return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"guest_fixture_prepare_failed\"", 70, 70, 0, 0, 0, 0, 0);
        } else if (strcmp(command_class, "npm_exec_detonation") == 0 || strcmp(fixture, "npm_bin_token_theft") == 0) {
            shell_command = "npm install --foreground-scripts --ignore-scripts=false --no-audit --no-fund && node index.js";
        } else if (strcmp(fixture, "api_compatible_canary_theft") == 0) {
            shell_command = "npm install --foreground-scripts --ignore-scripts=false --no-audit --no-fund && node -e \"require('./index').run()\"";
        } else {
            shell_command = "npm install --foreground-scripts --ignore-scripts=false --no-audit --no-fund";
        }
    } else if (strcmp(tool, "pip") == 0) {
        tool_command = "python3";
        if (project_mode) {
            if (materialize_project_payload(workspace, project_payload_hex) != 0) {
                free(project_payload_hex);
                return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_payload_materialize_failed\"", 70, 70, 0, 0, 0, 0, 0);
            }
            free(project_payload_hex);
            project_payload_hex = NULL;
            const char *import_probe = "";
            char import_probe_buffer[512];
            if (project_import_module[0] != '\0') {
                int import_length = current_project_api_probe_enabled
                    ? snprintf(
                          import_probe_buffer,
                          sizeof(import_probe_buffer),
                          " && PYTHONPATH=\"$WHOATHERE_TELEMETRY_DIR:target\" $WHOATHERE_PYTHON .whoathere-api-probe.py %s",
                          project_import_module
                      )
                    : snprintf(
                          import_probe_buffer,
                          sizeof(import_probe_buffer),
                          " && PYTHONPATH=\"$WHOATHERE_TELEMETRY_DIR:target\" $WHOATHERE_PYTHON -c 'import %s'",
                          project_import_module
                      );
                if (import_length < 0 || (size_t)import_length >= sizeof(import_probe_buffer)) {
                    return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_import_probe_too_long\"", 70, 70, 0, 0, 0, 0, 0);
                }
                if (current_project_api_probe_enabled && write_python_api_probe_script(workspace) != 0) {
                    return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_api_probe_script_write_failed\"", 70, 70, 0, 0, 0, 0, 0);
                }
                import_probe = import_probe_buffer;
            }
            const char *pth_probe = " && if ls *.pth >/dev/null 2>&1; then cp *.pth target/; fi && PYTHONPATH=\"$WHOATHERE_TELEMETRY_DIR:target\" $WHOATHERE_PYTHON -c 'import site; site.addsitedir(\"target\")'";
            if (strcmp(project_workflow, "pip_project_install") == 0) {
                int command_length = snprintf(
                    shell_command_buffer,
                    sizeof(shell_command_buffer),
                    WHOATHERE_PIP_PREFIX "mkdir -p target && $WHOATHERE_PYTHON -m pip install --no-index --no-build-isolation . --target target%s%s",
                    pth_probe,
                    import_probe
                );
                if (command_length < 0 || (size_t)command_length >= sizeof(shell_command_buffer)) {
                    return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_command_too_long\"", 70, 70, 0, 0, 0, 0, 0);
                }
                shell_command = shell_command_buffer;
            } else if (strcmp(project_workflow, "pip_requirements_install") == 0) {
                if (project_requirements_path[0] == '\0') {
                    return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_requirements_path_missing\"", 70, 70, 0, 0, 0, 0, 0);
                }
                int command_length = snprintf(
                    shell_command_buffer,
                    sizeof(shell_command_buffer),
                    WHOATHERE_PIP_PREFIX "mkdir -p target && $WHOATHERE_PYTHON -m pip install --no-index --no-build-isolation -r %s --target target%s%s",
                    project_requirements_path,
                    pth_probe,
                    import_probe
                );
                if (command_length < 0 || (size_t)command_length >= sizeof(shell_command_buffer)) {
                    return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_command_too_long\"", 70, 70, 0, 0, 0, 0, 0);
                }
                shell_command = shell_command_buffer;
            } else {
                return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_unsupported_workflow", "\"project_workflow_unsupported\"", 20, 20, 0, 0, 0, 0, 0);
            }
        } else if (write_python_fixture(workspace, fixture) != 0) {
            return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"guest_fixture_prepare_failed\"", 70, 70, 0, 0, 0, 0, 0);
        } else if (strcmp(fixture, "python_pth_startup_hook") == 0) {
            shell_command = WHOATHERE_PIP_PREFIX "mkdir -p target && cp whoathere_hook.pth target/ && $WHOATHERE_PYTHON -c 'import site; site.addsitedir(\"target\")'";
        } else if (strcmp(fixture, "api_compatible_canary_theft") == 0) {
            shell_command = WHOATHERE_PIP_PREFIX "$WHOATHERE_PYTHON -m pip install --no-index --no-build-isolation . --target target && PYTHONPATH=\"$WHOATHERE_TELEMETRY_DIR:target\" $WHOATHERE_PYTHON -c 'import whoathere_fixture; whoathere_fixture.run()'";
        } else if (strcmp(fixture, "pypi_import_time_canary") == 0 || strcmp(fixture, "python_import_time_canary") == 0) {
            shell_command = WHOATHERE_PIP_PREFIX "$WHOATHERE_PYTHON -m pip install --no-index --no-build-isolation . --target target && PYTHONPATH=\"$WHOATHERE_TELEMETRY_DIR:target\" $WHOATHERE_PYTHON -c 'import whoathere_fixture'";
        } else {
            shell_command = WHOATHERE_PIP_PREFIX "$WHOATHERE_PYTHON -m pip install --no-index --no-build-isolation . --target target";
        }
    } else if (strcmp(tool, "uv") == 0) {
        tool_command = "uv";
        if (project_mode) {
            if (materialize_project_payload(workspace, project_payload_hex) != 0) {
                free(project_payload_hex);
                return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_payload_materialize_failed\"", 70, 70, 0, 0, 0, 0, 0);
            }
            free(project_payload_hex);
            project_payload_hex = NULL;
            const char *import_probe = "";
            char import_probe_buffer[512];
            if (project_import_module[0] != '\0') {
                int import_length = current_project_api_probe_enabled
                    ? snprintf(
                          import_probe_buffer,
                          sizeof(import_probe_buffer),
                          " && PYTHONPATH=\"$WHOATHERE_TELEMETRY_DIR:target\" $WHOATHERE_PYTHON .whoathere-api-probe.py %s",
                          project_import_module
                      )
                    : snprintf(
                          import_probe_buffer,
                          sizeof(import_probe_buffer),
                          " && PYTHONPATH=\"$WHOATHERE_TELEMETRY_DIR:target\" $WHOATHERE_PYTHON -c 'import %s'",
                          project_import_module
                      );
                if (import_length < 0 || (size_t)import_length >= sizeof(import_probe_buffer)) {
                    return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_import_probe_too_long\"", 70, 70, 0, 0, 0, 0, 0);
                }
                if (current_project_api_probe_enabled && write_python_api_probe_script(workspace) != 0) {
                    return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_api_probe_script_write_failed\"", 70, 70, 0, 0, 0, 0, 0);
                }
                import_probe = import_probe_buffer;
            }
            const char *pth_probe = " && if ls *.pth >/dev/null 2>&1; then cp *.pth target/; fi && PYTHONPATH=\"$WHOATHERE_TELEMETRY_DIR:target\" $WHOATHERE_PYTHON -c 'import site; site.addsitedir(\"target\")'";
            if (strcmp(project_workflow, "uv_pip_project_install") == 0) {
                int command_length = snprintf(
                    shell_command_buffer,
                    sizeof(shell_command_buffer),
                    WHOATHERE_PIP_PREFIX "mkdir -p target && uv pip install --no-index --no-build-isolation --python \"$WHOATHERE_PYTHON\" . --target target%s%s",
                    pth_probe,
                    import_probe
                );
                if (command_length < 0 || (size_t)command_length >= sizeof(shell_command_buffer)) {
                    return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_command_too_long\"", 70, 70, 0, 0, 0, 0, 0);
                }
                shell_command = shell_command_buffer;
            } else if (strcmp(project_workflow, "uv_pip_requirements_install") == 0) {
                if (project_requirements_path[0] == '\0') {
                    return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_requirements_path_missing\"", 70, 70, 0, 0, 0, 0, 0);
                }
                int command_length = snprintf(
                    shell_command_buffer,
                    sizeof(shell_command_buffer),
                    WHOATHERE_PIP_PREFIX "mkdir -p target && uv pip install --no-index --no-build-isolation --python \"$WHOATHERE_PYTHON\" -r %s --target target%s%s",
                    project_requirements_path,
                    pth_probe,
                    import_probe
                );
                if (command_length < 0 || (size_t)command_length >= sizeof(shell_command_buffer)) {
                    return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"project_command_too_long\"", 70, 70, 0, 0, 0, 0, 0);
                }
                shell_command = shell_command_buffer;
            } else {
                return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_unsupported_workflow", "\"project_workflow_unsupported\"", 20, 20, 0, 0, 0, 0, 0);
            }
        } else if (write_python_fixture(workspace, fixture) != 0) {
            return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"guest_fixture_prepare_failed\"", 70, 70, 0, 0, 0, 0, 0);
        } else if (strcmp(fixture, "api_compatible_canary_theft") == 0) {
            shell_command = WHOATHERE_PIP_PREFIX "uv pip install --no-index --no-build-isolation --python \"$WHOATHERE_PYTHON\" . --target target && PYTHONPATH=\"$WHOATHERE_TELEMETRY_DIR:target\" $WHOATHERE_PYTHON -c 'import whoathere_fixture; whoathere_fixture.run()'";
        } else {
            shell_command = WHOATHERE_PIP_PREFIX "uv pip install --no-index --no-build-isolation --python \"$WHOATHERE_PYTHON\" . --target target";
        }
    } else {
        return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_unsupported_workflow", "\"unsupported_tool\"", 20, 20, 0, 0, 0, 0, 0);
    }

    int available = strcmp(tool, "pip") == 0 ? pip_available() : command_exists(tool_command);
    if (!available || shell_command == NULL) {
        return write_detonation_response(
            fd,
            job_id,
            tool,
            command_class,
            fixture,
            "fail_closed",
            "fail_closed_tooling_missing",
            "\"guest_toolchain_missing\"",
            20,
            20,
            0,
            0,
            0,
            0,
            available
        );
    }

    struct passwd *untrusted_user = getpwnam("nobody");
    char control_dir[1024];
    char temp_dir[1024];
    if (geteuid() != 0
        || untrusted_user == NULL
        || snprintf(temp_dir, sizeof(temp_dir), "%s/tmp", workspace) < 0
        || mkdir(temp_dir, 0700) != 0
        || write_runtime_telemetry_files(workspace, control_dir, sizeof(control_dir)) != 0
        || chown_workspace_tree(workspace, untrusted_user->pw_uid, untrusted_user->pw_gid) != 0) {
        return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"guest_execution_boundary_prepare_failed\"", 70, 70, 0, 0, 0, 0, available);
    }
    struct command_result command_result = run_shell_fixture_with_boundary(
        workspace,
        control_dir,
        untrusted_user->pw_uid,
        untrusted_user->pw_gid,
        1,
        shell_command,
        timeout_seconds
    );
    current_execution_identity_isolated = command_result.execution_identity_isolated;
    current_runtime_network_telemetry_active = command_result.runtime_network_telemetry_active;
    current_network_telemetry_events = command_result.network_telemetry_events;
    current_process_group_cleanup_enforced = command_result.process_group_cleanup_enforced;
    char marker[512];
    int canary_access = 0;
    int network_attempt = 0;
    int filesystem_write = 0;
    snprintf(marker, sizeof(marker), "%s/canary-read.marker", workspace);
    canary_access = canary_access || path_exists(marker);
    snprintf(marker, sizeof(marker), "%s/import-canary-read.marker", workspace);
    canary_access = canary_access || path_exists(marker);
    snprintf(marker, sizeof(marker), "%s/api-canary-read.marker", workspace);
    canary_access = canary_access || path_exists(marker);
    snprintf(marker, sizeof(marker), "%s/pth-canary-read.marker", workspace);
    canary_access = canary_access || path_exists(marker);
    snprintf(marker, sizeof(marker), "%s/network-attempt.marker", workspace);
    network_attempt = network_attempt || path_exists(marker);
    network_attempt = network_attempt || command_result.network_telemetry_events > 0;
    snprintf(marker, sizeof(marker), "%s/clean.marker", workspace);
    filesystem_write = filesystem_write || path_exists(marker);
    snprintf(marker, sizeof(marker), "%s/ci-activated.marker", workspace);
    filesystem_write = filesystem_write || path_exists(marker);

    if (command_result.timed_out) {
        return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_timeout", "\"guest_command_timeout\"", 20, command_result.exit_code, 1, canary_access, network_attempt, filesystem_write, available);
    }
    if (canary_access || network_attempt) {
        return write_detonation_response(fd, job_id, tool, command_class, fixture, "deny", "deny_malicious_behavior", "\"guest_canary_or_network_signal_observed\"", 20, command_result.exit_code, 0, canary_access, network_attempt, filesystem_write, available);
    }
    if (!command_result.execution_identity_isolated
        || !command_result.runtime_network_telemetry_active
        || !command_result.process_group_cleanup_enforced) {
        return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"guest_execution_boundary_attestation_missing\"", 70, command_result.exit_code, 0, canary_access, network_attempt, filesystem_write, available);
    }
    if (command_result.exit_code != 0) {
        return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"guest_command_failed\"", 20, command_result.exit_code, 0, canary_access, network_attempt, filesystem_write, available);
    }
    if (project_mode && sync_back_requested) {
        char *archive_hex = NULL;
        unsigned int sync_file_count = 0;
        unsigned int sync_total_bytes = 0;
        int archive_result = build_sync_output_archive(
            workspace,
            tool,
            &archive_hex,
            &sync_file_count,
            &sync_total_bytes
        );
        if (archive_result != 0) {
            const char *reason = archive_result == -2
                ? "\"guest_sync_output_symlink_or_special_file\""
                : "\"guest_sync_output_archive_failed\"";
            return write_detonation_response(
                fd,
                job_id,
                tool,
                command_class,
                fixture,
                "fail_closed",
                "fail_closed_sync_output",
                reason,
                20,
                command_result.exit_code,
                0,
                0,
                0,
                filesystem_write,
                available
            );
        }
        int response_result = write_detonation_response_ex(
            fd,
            job_id,
            tool,
            command_class,
            fixture,
            "ok",
            "allow_observed_clean",
            "",
            0,
            command_result.exit_code,
            0,
            0,
            0,
            filesystem_write,
            available,
            1,
            archive_hex,
            sync_file_count,
            sync_total_bytes
        );
        free(archive_hex);
        return response_result;
    }
    return write_detonation_response(fd, job_id, tool, command_class, fixture, "ok", "allow_observed_clean", "", 0, command_result.exit_code, 0, 0, 0, filesystem_write, available);
}

static int serve_detonation_loop(int fd) {
    char *line = calloc(WHOATHERE_MAX_JSON_LINE, 1);
    if (line == NULL) {
        return -1;
    }
    while (read_line(fd, line, WHOATHERE_MAX_JSON_LINE) == 0) {
        if (strstr(line, "whoathere.guest_detonation.v1") == NULL) {
            continue;
        }
        if (run_detonation_job(fd, line) != 0) {
            free(line);
            return -1;
        }
    }
    free(line);
    return 0;
}

int main(void) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 70;
    }

    struct sockaddr_vm address;
    memset(&address, 0, sizeof(address));
    address.svm_family = AF_VSOCK;
    address.svm_cid = VMADDR_CID_HOST;
    address.svm_port = WHOATHERE_GUEST_READY_PORT;

    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("connect");
        close(fd);
        return 70;
    }

    char line[WHOATHERE_MAX_LINE];
    if (read_line(fd, line, sizeof(line)) != 0) {
        fprintf(stderr, "failed to read challenge\n");
        close(fd);
        return 70;
    }

    char challenge[WHOATHERE_MAX_CHALLENGE];
    if (extract_json_string(line, "challenge", challenge, sizeof(challenge)) != 0) {
        fprintf(stderr, "failed to parse challenge\n");
        close(fd);
        return 70;
    }

    char response[WHOATHERE_MAX_LINE];
    int length = snprintf(
        response,
        sizeof(response),
        "{\"agent_version\":\"0.3.0\",\"challenge\":\"%s\",\"npm_available\":%s,\"python3_available\":%s,\"pip_available\":%s,\"protocol\":\"whoathere.guest_ready.v1\",\"status\":\"ready\",\"uv_available\":%s}\n",
        challenge,
        command_exists("npm") ? "true" : "false",
        python_available() ? "true" : "false",
        pip_available() ? "true" : "false",
        command_exists("uv") ? "true" : "false"
    );
    if (length < 0 || (size_t)length >= sizeof(response)) {
        fprintf(stderr, "failed to build response\n");
        close(fd);
        return 70;
    }

    if (write_all(fd, response, (size_t)length) != 0) {
        perror("write");
        close(fd);
        return 70;
    }

    if (serve_detonation_loop(fd) != 0) {
        perror("detonation_loop");
        close(fd);
        return 70;
    }

    close(fd);
    return 0;
}
