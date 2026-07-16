#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define INPUT_COUNT 12
#define FIRST_INPUT_FD 3
#define OPTIONAL_BUILD_CLOSURE_FD (FIRST_INPUT_FD + INPUT_COUNT)
#define RESULT_FD (OPTIONAL_BUILD_CLOSURE_FD + 1)
#define MIN_PRIVATE_FD 32
#define RESULT_LIMIT (256ULL * 1024ULL * 1024ULL)
#define LOG_LIMIT (1024ULL * 1024ULL)
/*
 * The package root runtime can legitimately remain output-silent while an action runs. Keep this
 * finite launcher backstop at the host helper's maximum overall VM timeout so the helper-selected
 * deadline (30--600 seconds, 180 by default) remains authoritative.
 */
#define OUTPUT_IDLE_TIMEOUT_MILLISECONDS (600 * 1000)

static const char *const input_paths[INPUT_COUNT] = {
    "/whoathere/guest-ed25519.seed",
    "/whoathere/inputs/backend-identity.json",
    "/whoathere/inputs/qualified-backend.json",
    "/whoathere/inputs/package-authority-request.json",
    "/whoathere/inputs/execution-grant.json",
    "/whoathere/inputs/artifact.bin",
    "/whoathere/inputs/scenario-plan.json",
    "/whoathere/inputs/scenario-template.json",
    "/whoathere/inputs/guest-ed25519-public-key.bin",
    "/whoathere/inputs/host-ed25519-public-key.bin",
    "/whoathere/inputs/grant-issuer-ed25519-public-key.bin",
    "/whoathere/inputs/execution-runtime-qualification-record.json",
};

static const char *const descriptor_flags[INPUT_COUNT] = {
    "--seed-fd",
    "--backend-identity-fd",
    "--backend-qualification-fd",
    "--authority-request-fd",
    "--execution-grant-fd",
    "--artifact-fd",
    "--scenario-plan-fd",
    "--scenario-template-fd",
    "--guest-evidence-public-key-fd",
    "--host-evidence-public-key-fd",
    "--grant-issuer-public-key-fd",
    "--execution-runtime-qualification-record-fd",
};

static const char optional_build_closure_path[] =
    "/whoathere/inputs/build-closure.bin";
static const char optional_build_closure_flag[] = "--build-closure-fd";

static void fail(const char *reason) {
    fprintf(stderr, "whoathere_execution_descriptor_launcher_failed:%s\n", reason);
    exit(70);
}

static void write_all(int descriptor, const unsigned char *bytes, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(descriptor, bytes + offset, length - offset);
        if (count > 0) {
            offset += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        fail("write_failed");
    }
}

static int open_validated_input(const char *path, mode_t expected_mode, off_t expected_size) {
    int descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) {
        fail("input_open_failed");
    }
    struct stat metadata;
    if (fstat(descriptor, &metadata) != 0
        || !S_ISREG(metadata.st_mode)
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || (metadata.st_mode & 07777) != expected_mode
        || metadata.st_nlink != 1
        || metadata.st_size <= 0
        || (expected_size > 0 && metadata.st_size != expected_size)) {
        close(descriptor);
        fail("input_metadata_invalid");
    }
    int retained = fcntl(descriptor, F_DUPFD_CLOEXEC, MIN_PRIVATE_FD);
    close(descriptor);
    if (retained < 0) {
        fail("input_retain_failed");
    }
    return retained;
}

static int open_optional_validated_input(
    const char *path,
    mode_t expected_mode,
    off_t expected_size
) {
    struct stat metadata;
    if (lstat(path, &metadata) != 0) {
        if (errno == ENOENT) {
            return -1;
        }
        fail("optional_input_stat_failed");
    }
    return open_validated_input(path, expected_mode, expected_size);
}

static int retain_private_descriptor(int descriptor) {
    int retained = fcntl(descriptor, F_DUPFD_CLOEXEC, MIN_PRIVATE_FD);
    if (retained < 0) {
        fail("descriptor_retain_failed");
    }
    return retained;
}

static void close_exec_destination_descriptors(void) {
    for (int descriptor = FIRST_INPUT_FD; descriptor <= RESULT_FD; descriptor++) {
        close(descriptor);
    }
}

static void close_private_descriptors(void) {
    long maximum = sysconf(_SC_OPEN_MAX);
    if (maximum < 0 || maximum > 1 << 20) {
        maximum = 4096;
    }
    for (int descriptor = RESULT_FD + 1; descriptor < maximum; descriptor++) {
        close(descriptor);
    }
}

static void duplicate_for_exec(int source, int destination) {
    if (source == destination) {
        if (fcntl(destination, F_SETFD, 0) != 0) {
            fail("descriptor_flag_failed");
        }
        return;
    }
    if (dup2(source, destination) < 0) {
        fail("descriptor_duplicate_failed");
    }
    if (fcntl(destination, F_SETFD, 0) != 0) {
        fail("descriptor_flag_failed");
    }
}

static int open_output(const char *path) {
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        fail("output_open_failed");
    }
    struct stat metadata;
    if (fstat(descriptor, &metadata) != 0
        || !S_ISREG(metadata.st_mode)
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || (metadata.st_mode & 07777) != 0600
        || metadata.st_nlink != 1
        || metadata.st_size != 0) {
        close(descriptor);
        fail("output_metadata_invalid");
    }
    return descriptor;
}

static void drain_to_file(
    int source,
    int destination,
    uint64_t *total,
    uint64_t maximum,
    int *open_state
) {
    unsigned char buffer[64 * 1024];
    for (;;) {
        ssize_t count = read(source, buffer, sizeof(buffer));
        if (count > 0) {
            if (*total > maximum - (uint64_t)count) {
                fail("output_limit_exceeded");
            }
            write_all(destination, buffer, (size_t)count);
            *total += (uint64_t)count;
            return;
        }
        if (count == 0) {
            close(source);
            *open_state = 0;
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        fail("output_read_failed");
    }
}

int main(void) {
    int retained[INPUT_COUNT];
    for (int index = 0; index < INPUT_COUNT; index++) {
        retained[index] = open_validated_input(
            input_paths[index],
            index == 0 ? 0400 : 0444,
            index == 0 || (index >= 8 && index <= 10) ? 32 : 0
        );
    }
    int retained_build_closure = open_optional_validated_input(
        optional_build_closure_path,
        0444,
        0
    );

    unsigned char seed[32];
    size_t seed_offset = 0;
    while (seed_offset < sizeof(seed)) {
        ssize_t count = read(retained[0], seed + seed_offset, sizeof(seed) - seed_offset);
        if (count > 0) {
            seed_offset += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        fail("seed_read_failed");
    }
    unsigned char extra;
    if (read(retained[0], &extra, 1) != 0) {
        fail("seed_length_invalid");
    }
    close(retained[0]);
    retained[0] = -1;
    if (unlink(input_paths[0]) != 0 || access(input_paths[0], F_OK) == 0 || errno != ENOENT) {
        memset(seed, 0, sizeof(seed));
        fail("seed_path_cleanup_failed");
    }

    int seed_pipe[2];
    int result_pipe[2];
    int log_pipe[2];
    if (pipe2(seed_pipe, O_CLOEXEC) != 0
        || pipe2(result_pipe, O_CLOEXEC) != 0
        || pipe2(log_pipe, O_CLOEXEC) != 0
        || fcntl(result_pipe[0], F_SETFL, O_NONBLOCK) != 0
        || fcntl(log_pipe[0], F_SETFL, O_NONBLOCK) != 0) {
        memset(seed, 0, sizeof(seed));
        fail("pipe_create_failed");
    }
    write_all(seed_pipe[1], seed, sizeof(seed));
    memset(seed, 0, sizeof(seed));
    close(seed_pipe[1]);
    retained[0] = retain_private_descriptor(seed_pipe[0]);
    close(seed_pipe[0]);

    int result_output = open_output("/run/whoathere-package-execution-result.bin");
    int log_output = open_output("/run/whoathere-package-execution-child.log");
    pid_t child = fork();
    if (child < 0) {
        fail("fork_failed");
    }
    if (child == 0) {
        close(result_pipe[0]);
        close(log_pipe[0]);
        close(result_output);
        close(log_output);
        int retained_result_writer = retain_private_descriptor(result_pipe[1]);
        int retained_log_writer = retain_private_descriptor(log_pipe[1]);
        close(result_pipe[1]);
        close(log_pipe[1]);
        close_exec_destination_descriptors();
        duplicate_for_exec(retained_result_writer, RESULT_FD);
        duplicate_for_exec(retained_log_writer, STDOUT_FILENO);
        duplicate_for_exec(retained_log_writer, STDERR_FILENO);
        for (int index = 0; index < INPUT_COUNT; index++) {
            duplicate_for_exec(retained[index], FIRST_INPUT_FD + index);
        }
        if (retained_build_closure >= 0) {
            duplicate_for_exec(retained_build_closure, OPTIONAL_BUILD_CLOSURE_FD);
        }
        close_private_descriptors();
        if (chroot("/runtime") != 0 || chdir("/") != 0) {
            fail("chroot_failed");
        }
        char descriptor_values[INPUT_COUNT + 2][16];
        char *arguments[2 + INPUT_COUNT * 2 + 2 + 2 + 1];
        int argument = 0;
        arguments[argument++] = "/whoathere/package-root-runtime";
        arguments[argument++] = "--execute";
        for (int index = 0; index < INPUT_COUNT; index++) {
            arguments[argument++] = (char *)descriptor_flags[index];
            snprintf(
                descriptor_values[index],
                sizeof(descriptor_values[index]),
                "%d",
                FIRST_INPUT_FD + index
            );
            arguments[argument++] = descriptor_values[index];
        }
        if (retained_build_closure >= 0) {
            arguments[argument++] = (char *)optional_build_closure_flag;
            snprintf(
                descriptor_values[INPUT_COUNT],
                sizeof(descriptor_values[INPUT_COUNT]),
                "%d",
                OPTIONAL_BUILD_CLOSURE_FD
            );
            arguments[argument++] = descriptor_values[INPUT_COUNT];
        }
        arguments[argument++] = "--result-fd";
        snprintf(
            descriptor_values[INPUT_COUNT + 1],
            sizeof(descriptor_values[INPUT_COUNT + 1]),
            "%d",
            RESULT_FD
        );
        arguments[argument++] = descriptor_values[INPUT_COUNT + 1];
        arguments[argument] = NULL;
        char *environment[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", NULL};
        execve(arguments[0], arguments, environment);
        fail("exec_failed");
    }

    close(result_pipe[1]);
    close(log_pipe[1]);
    for (int index = 0; index < INPUT_COUNT; index++) {
        close(retained[index]);
    }
    if (retained_build_closure >= 0) {
        close(retained_build_closure);
    }
    int result_open = 1;
    int log_open = 1;
    uint64_t result_bytes = 0;
    uint64_t log_bytes = 0;
    while (result_open || log_open) {
        struct pollfd descriptors[2] = {
            {.fd = result_open ? result_pipe[0] : -1, .events = POLLIN | POLLHUP | POLLERR},
            {.fd = log_open ? log_pipe[0] : -1, .events = POLLIN | POLLHUP | POLLERR},
        };
        int ready = poll(descriptors, 2, OUTPUT_IDLE_TIMEOUT_MILLISECONDS);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready <= 0) {
            kill(child, SIGKILL);
            fail("output_timeout");
        }
        if (result_open && descriptors[0].revents != 0) {
            drain_to_file(
                result_pipe[0], result_output, &result_bytes, RESULT_LIMIT, &result_open
            );
        }
        if (log_open && descriptors[1].revents != 0) {
            drain_to_file(log_pipe[0], log_output, &log_bytes, LOG_LIMIT, &log_open);
        }
    }
    if (fsync(result_output) != 0 || fsync(log_output) != 0
        || close(result_output) != 0 || close(log_output) != 0) {
        kill(child, SIGKILL);
        fail("output_sync_failed");
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        fail("wait_failed");
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fail("runtime_failed");
    }
    if (result_bytes == 0 || log_bytes == 0) {
        fail("output_empty");
    }
    return 0;
}
