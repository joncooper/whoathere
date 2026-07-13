#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

static int write_all(int descriptor, const char *bytes, size_t length) {
    while (length > 0) {
        ssize_t written = write(descriptor, bytes, length);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            return -1;
        }
        bytes += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

int main(int argc, char **argv) {
    static const char report[] =
        "{\"execution_authority\":false,\"package_execution\":false,"
        "\"schema_version\":\"whoathere.linux_vz_package_runtime_probe.v1\","
        "\"status\":\"candidate_runtime_nonexecuting\",\"sync_back\":false}\n";
    static const char usage[] =
        "whoathere package runtime probe: execution authority unavailable\n";

    if (argc == 2 &&
        (strcmp(argv[1], "--runtime-probe") == 0 ||
         strcmp(argv[1], "fork_exec_exit") == 0)) {
        if (write_all(STDOUT_FILENO, report, sizeof(report) - 1) != 0) {
            return 74;
        }
        return 0;
    }
    if (write_all(STDERR_FILENO, usage, sizeof(usage) - 1) != 0) {
        return 74;
    }
    return 64;
}
