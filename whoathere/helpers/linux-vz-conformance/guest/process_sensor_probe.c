#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/fanotify.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FIXTURE_UID 65534
#define FIXTURE_GID 65534
#define FIXTURE_CGROUP "/sys/fs/cgroup/whoathere-process-fixture"
#define FIXTURE_CGROUP_PROCS FIXTURE_CGROUP "/cgroup.procs"
#define ROOT_CGROUP_PROCS "/sys/fs/cgroup/cgroup.procs"
#define FILE_FIXTURE_ROOT "/run/whoathere-file-fixture"

#define INSN(code_value, destination, source, instruction_offset, immediate) \
    ((struct bpf_insn){                                                  \
        .code = (code_value),                                            \
        .dst_reg = (destination),                                        \
        .src_reg = (source),                                             \
        .off = (instruction_offset),                                     \
        .imm = (immediate),                                              \
    })
#define MOV64_REG(destination, source) \
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, destination, source, 0, 0)
#define MOV64_IMM(destination, immediate) \
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, destination, 0, 0, immediate)
#define ADD64_IMM(destination, immediate) \
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, destination, 0, 0, immediate)
#define STORE_IMM(size, destination, instruction_offset, immediate) \
    INSN(BPF_ST | BPF_MEM | size, destination, 0, instruction_offset, immediate)
#define STORE_REG(size, destination, source, instruction_offset) \
    INSN(BPF_STX | BPF_MEM | size, destination, source, instruction_offset, 0)
#define LOAD_REG(size, destination, source, instruction_offset) \
    INSN(BPF_LDX | BPF_MEM | size, destination, source, instruction_offset, 0)
#define JUMP_IMM(operation, destination, immediate, instruction_offset) \
    INSN(BPF_JMP | operation | BPF_K, destination, 0, instruction_offset, immediate)
#define JUMP_REG(operation, destination, source, instruction_offset) \
    INSN(BPF_JMP | operation | BPF_X, destination, source, instruction_offset, 0)
#define CALL_HELPER(helper) INSN(BPF_JMP | BPF_CALL, 0, 0, 0, helper)
#define EXIT_PROGRAM() INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define LOAD_MAP_FD(destination, descriptor)                                      \
    INSN(BPF_LD | BPF_DW | BPF_IMM, destination, BPF_PSEUDO_MAP_FD, 0, descriptor), \
        INSN(0, 0, 0, 0, 0)

enum observation_key {
    OBSERVATION_CGROUP = 0,
    OBSERVATION_FORK = 1,
    OBSERVATION_EXEC = 2,
    OBSERVATION_EXIT = 3,
    OBSERVATION_MMAP = 4,
    OBSERVATION_COUNT = 5,
};

struct observation {
    uint64_t count;
    uint64_t pid_tgid;
    uint64_t timestamp_ns;
};

struct sensor_fds {
    int map;
    int programs[5];
    int links[5];
};

static void close_if_open(int *descriptor) {
    if (*descriptor >= 0) {
        close(*descriptor);
        *descriptor = -1;
    }
}

static void close_sensor_fds(struct sensor_fds *fds) {
    for (size_t index = 0; index < 5; index++) {
        close_if_open(&fds->links[index]);
        close_if_open(&fds->programs[index]);
    }
    close_if_open(&fds->map);
}

static int bpf_call(enum bpf_cmd command, union bpf_attr *attributes) {
    return (int)syscall(SYS_bpf, command, attributes, sizeof(*attributes));
}

static int create_observation_map(void) {
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.map_type = BPF_MAP_TYPE_ARRAY;
    attributes.key_size = sizeof(uint32_t);
    attributes.value_size = sizeof(struct observation);
    attributes.max_entries = OBSERVATION_COUNT;
    return bpf_call(BPF_MAP_CREATE, &attributes);
}

static int load_program(const struct bpf_insn *instructions, size_t count) {
    static const char license[] = "GPL";
    char verifier_log[16384] = {0};
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT;
    attributes.insn_cnt = (uint32_t)count;
    attributes.insns = (uint64_t)(uintptr_t)instructions;
    attributes.license = (uint64_t)(uintptr_t)license;
    attributes.log_buf = (uint64_t)(uintptr_t)verifier_log;
    attributes.log_size = sizeof(verifier_log);
    attributes.log_level = 1;
    int descriptor = bpf_call(BPF_PROG_LOAD, &attributes);
    if (descriptor < 0) {
        fprintf(
            stderr,
            "WHOATHERE_BPF_VERIFIER_FAILED errno=%d log=%.2048s\n",
            errno,
            verifier_log
        );
    }
    return descriptor;
}

static int attach_raw_tracepoint(const char *name, int program) {
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.raw_tracepoint.name = (uint64_t)(uintptr_t)name;
    attributes.raw_tracepoint.prog_fd = (uint32_t)program;
    return bpf_call(BPF_RAW_TRACEPOINT_OPEN, &attributes);
}

static int lookup_observation(int map, uint32_t key, struct observation *value) {
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    memset(value, 0, sizeof(*value));
    attributes.map_fd = (uint32_t)map;
    attributes.key = (uint64_t)(uintptr_t)&key;
    attributes.value = (uint64_t)(uintptr_t)value;
    return bpf_call(BPF_MAP_LOOKUP_ELEM, &attributes);
}

static int load_calibration_program(int map) {
    const struct bpf_insn instructions[] = {
        STORE_IMM(BPF_W, BPF_REG_10, -4, OBSERVATION_CGROUP),
        LOAD_MAP_FD(BPF_REG_1, map),
        MOV64_REG(BPF_REG_2, BPF_REG_10),
        ADD64_IMM(BPF_REG_2, -4),
        CALL_HELPER(BPF_FUNC_map_lookup_elem),
        JUMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4),
        MOV64_REG(BPF_REG_6, BPF_REG_0),
        CALL_HELPER(BPF_FUNC_get_current_cgroup_id),
        STORE_REG(BPF_DW, BPF_REG_6, BPF_REG_0, 0),
        MOV64_IMM(BPF_REG_0, 0),
        EXIT_PROGRAM(),
    };
    return load_program(instructions, sizeof(instructions) / sizeof(instructions[0]));
}

static int load_observation_program(int map, enum observation_key key) {
    const struct bpf_insn instructions[] = {
        CALL_HELPER(BPF_FUNC_get_current_cgroup_id),
        MOV64_REG(BPF_REG_8, BPF_REG_0),
        STORE_IMM(BPF_W, BPF_REG_10, -4, OBSERVATION_CGROUP),
        LOAD_MAP_FD(BPF_REG_1, map),
        MOV64_REG(BPF_REG_2, BPF_REG_10),
        ADD64_IMM(BPF_REG_2, -4),
        CALL_HELPER(BPF_FUNC_map_lookup_elem),
        JUMP_IMM(BPF_JEQ, BPF_REG_0, 0, 17),
        LOAD_REG(BPF_DW, BPF_REG_1, BPF_REG_0, 0),
        JUMP_REG(BPF_JNE, BPF_REG_8, BPF_REG_1, 15),
        STORE_IMM(BPF_W, BPF_REG_10, -4, key),
        LOAD_MAP_FD(BPF_REG_1, map),
        MOV64_REG(BPF_REG_2, BPF_REG_10),
        ADD64_IMM(BPF_REG_2, -4),
        CALL_HELPER(BPF_FUNC_map_lookup_elem),
        JUMP_IMM(BPF_JEQ, BPF_REG_0, 0, 8),
        MOV64_REG(BPF_REG_7, BPF_REG_0),
        MOV64_IMM(BPF_REG_1, 1),
        INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_7, BPF_REG_1, 0, 0),
        CALL_HELPER(BPF_FUNC_get_current_pid_tgid),
        STORE_REG(BPF_DW, BPF_REG_7, BPF_REG_0, 8),
        CALL_HELPER(BPF_FUNC_ktime_get_ns),
        STORE_REG(BPF_DW, BPF_REG_7, BPF_REG_0, 16),
        MOV64_IMM(BPF_REG_0, 0),
        EXIT_PROGRAM(),
    };
    return load_program(instructions, sizeof(instructions) / sizeof(instructions[0]));
}

static int load_mmap_program(int map) {
    const struct bpf_insn instructions[] = {
        MOV64_IMM(BPF_REG_0, 0),
        MOV64_REG(BPF_REG_6, BPF_REG_1),
        LOAD_REG(BPF_DW, BPF_REG_9, BPF_REG_6, 8),
        JUMP_IMM(BPF_JNE, BPF_REG_9, SYS_mmap, 26),
        CALL_HELPER(BPF_FUNC_get_current_cgroup_id),
        MOV64_REG(BPF_REG_8, BPF_REG_0),
        STORE_IMM(BPF_W, BPF_REG_10, -4, OBSERVATION_CGROUP),
        LOAD_MAP_FD(BPF_REG_1, map),
        MOV64_REG(BPF_REG_2, BPF_REG_10),
        ADD64_IMM(BPF_REG_2, -4),
        CALL_HELPER(BPF_FUNC_map_lookup_elem),
        JUMP_IMM(BPF_JEQ, BPF_REG_0, 0, 17),
        LOAD_REG(BPF_DW, BPF_REG_1, BPF_REG_0, 0),
        JUMP_REG(BPF_JNE, BPF_REG_8, BPF_REG_1, 15),
        STORE_IMM(BPF_W, BPF_REG_10, -4, OBSERVATION_MMAP),
        LOAD_MAP_FD(BPF_REG_1, map),
        MOV64_REG(BPF_REG_2, BPF_REG_10),
        ADD64_IMM(BPF_REG_2, -4),
        CALL_HELPER(BPF_FUNC_map_lookup_elem),
        JUMP_IMM(BPF_JEQ, BPF_REG_0, 0, 8),
        MOV64_REG(BPF_REG_7, BPF_REG_0),
        MOV64_IMM(BPF_REG_1, 1),
        INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_7, BPF_REG_1, 0, 0),
        CALL_HELPER(BPF_FUNC_get_current_pid_tgid),
        STORE_REG(BPF_DW, BPF_REG_7, BPF_REG_0, 8),
        CALL_HELPER(BPF_FUNC_ktime_get_ns),
        STORE_REG(BPF_DW, BPF_REG_7, BPF_REG_0, 16),
        MOV64_IMM(BPF_REG_0, 0),
        EXIT_PROGRAM(),
    };
    return load_program(instructions, sizeof(instructions) / sizeof(instructions[0]));
}

static int write_control(const char *path, const char *value) {
    int descriptor = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return -1;
    }
    size_t length = strlen(value);
    ssize_t written = write(descriptor, value, length);
    int saved_errno = errno;
    if (close(descriptor) != 0 && written == (ssize_t)length) {
        return -1;
    }
    errno = saved_errno;
    return written == (ssize_t)length ? 0 : -1;
}

static int verify_root_owned_executable(const char *path) {
    struct stat metadata;
    if (lstat(path, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        S_ISLNK(metadata.st_mode) || metadata.st_uid != 0 ||
        (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (metadata.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) !=
            (S_IXUSR | S_IXGRP | S_IXOTH)) {
        return -1;
    }
    return 0;
}

static int child_fixture(const char *fixture, const char *fixture_case, struct sensor_fds *fds) {
    close_sensor_fds(fds);
    if (setgroups(0, NULL) != 0) {
        _exit(71);
    }
    if (setgid(FIXTURE_GID) != 0) {
        _exit(72);
    }
    if (setuid(FIXTURE_UID) != 0) {
        _exit(73);
    }
    execl(fixture, fixture, fixture_case, (char *)NULL);
    _exit(74);
}

static int observed_pid(const struct observation *value, pid_t expected) {
    return value->count == 1 && value->timestamp_ns > 0 &&
        (pid_t)(value->pid_tgid >> 32) == expected;
}

struct file_observations {
    int opened;
    int accessed;
    int wrote;
    int renamed;
    int deleted;
    int persisted;
    uint64_t permission_responses;
};

static int create_fixture_file(const char *path, const char *contents) {
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) return -1;
    size_t length = strlen(contents);
    ssize_t written = write(descriptor, contents, length);
    int result = written == (ssize_t)length && fchown(descriptor, FIXTURE_UID, FIXTURE_GID) == 0
        && fchmod(descriptor, 0600) == 0 ? 0 : -1;
    int saved_errno = errno;
    if (close(descriptor) != 0) result = -1;
    errno = saved_errno;
    return result;
}

static int prepare_file_fixture(void) {
    char path[160];
    if (chmod("/run", 0711) != 0 || mkdir(FILE_FIXTURE_ROOT, 0700) != 0 ||
        chown(FILE_FIXTURE_ROOT, FIXTURE_UID, FIXTURE_GID) != 0) return -1;
    snprintf(path, sizeof(path), "%s/fake-home", FILE_FIXTURE_ROOT);
    if (mkdir(path, 0700) != 0 || chown(path, FIXTURE_UID, FIXTURE_GID) != 0) return -1;
    const char *names[] = {"canary", "write-target", "rename-source", "delete-target"};
    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        snprintf(path, sizeof(path), "%s/%s", FILE_FIXTURE_ROOT, names[index]);
        if (create_fixture_file(path, index == 0 ? "canary" : "x") != 0) return -1;
    }
    snprintf(path, sizeof(path), "%s/fake-home/.profile", FILE_FIXTURE_ROOT);
    return create_fixture_file(path, "x");
}

static void cleanup_file_fixture(void) {
    char path[160];
    const char *names[] = {
        "canary", "write-target", "rename-source", "renamed", "delete-target"
    };
    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        snprintf(path, sizeof(path), "%s/%s", FILE_FIXTURE_ROOT, names[index]);
        (void)unlink(path);
    }
    snprintf(path, sizeof(path), "%s/fake-home/.profile", FILE_FIXTURE_ROOT);
    (void)unlink(path);
    snprintf(path, sizeof(path), "%s/fake-home", FILE_FIXTURE_ROOT);
    (void)rmdir(path);
    (void)rmdir(FILE_FIXTURE_ROOT);
    (void)chmod("/run", 0700);
}

static int descriptor_is_path(int descriptor, const char *expected) {
    char link[64];
    char path[256];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", descriptor);
    ssize_t length = readlink(link, path, sizeof(path) - 1);
    if (length < 0 || (size_t)length >= sizeof(path)) return 0;
    path[length] = '\0';
    return strcmp(path, expected) == 0;
}

static int process_fanotify_events(
    int descriptor,
    pid_t child,
    struct file_observations *observed
) {
    char buffer[8192] __attribute__((aligned(8)));
    ssize_t length = read(descriptor, buffer, sizeof(buffer));
    if (length < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
    if (length <= 0) return -1;
    char write_target[160];
    char persistence[160];
    snprintf(write_target, sizeof(write_target), "%s/write-target", FILE_FIXTURE_ROOT);
    snprintf(persistence, sizeof(persistence), "%s/fake-home/.profile", FILE_FIXTURE_ROOT);
    struct fanotify_event_metadata *metadata;
    for (metadata = (struct fanotify_event_metadata *)buffer;
         FAN_EVENT_OK(metadata, length);
         metadata = FAN_EVENT_NEXT(metadata, length)) {
        if (metadata->vers != FANOTIFY_METADATA_VERSION) return -1;
        int is_child = metadata->pid == child;
        if (is_child && (metadata->mask & FAN_OPEN_PERM)) observed->opened = 1;
        if (is_child && (metadata->mask & FAN_ACCESS_PERM)) observed->accessed = 1;
        if (is_child && (metadata->mask & FAN_CLOSE_WRITE) && metadata->fd >= 0) {
            if (descriptor_is_path(metadata->fd, write_target)) observed->wrote = 1;
            if (descriptor_is_path(metadata->fd, persistence)) observed->persisted = 1;
        }
        if (metadata->mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM)) {
            struct fanotify_response response = {
                .fd = metadata->fd,
                .response = FAN_ALLOW,
            };
            if (write(descriptor, &response, sizeof(response)) != sizeof(response)) return -1;
            if (is_child) observed->permission_responses++;
        }
        if (metadata->fd >= 0) close(metadata->fd);
    }
    return 0;
}

static int file_diff_complete(void) {
    char path[160];
    struct stat metadata;
    snprintf(path, sizeof(path), "%s/write-target", FILE_FIXTURE_ROOT);
    if (lstat(path, &metadata) != 0 || metadata.st_size != 2) return 0;
    snprintf(path, sizeof(path), "%s/renamed", FILE_FIXTURE_ROOT);
    if (lstat(path, &metadata) != 0 || !S_ISREG(metadata.st_mode)) return 0;
    snprintf(path, sizeof(path), "%s/rename-source", FILE_FIXTURE_ROOT);
    if (lstat(path, &metadata) == 0 || errno != ENOENT) return 0;
    snprintf(path, sizeof(path), "%s/delete-target", FILE_FIXTURE_ROOT);
    if (lstat(path, &metadata) == 0 || errno != ENOENT) return 0;
    snprintf(path, sizeof(path), "%s/fake-home/.profile", FILE_FIXTURE_ROOT);
    return lstat(path, &metadata) == 0 && metadata.st_size == 2;
}

static uint64_t monotonic_ns(void) {
    struct timespec value = {0};
    return clock_gettime(CLOCK_MONOTONIC, &value) == 0
        ? (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec : 0;
}

static int run_file_probe(const char *fixture, const char *fixture_case) {
    struct sensor_fds fds = {
        .map = -1,
        .programs = {-1, -1, -1, -1, -1},
        .links = {-1, -1, -1, -1, -1},
    };
    struct rlimit unlimited = {.rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY};
    struct observation cgroup = {0};
    struct observation mmap_event = {0};
    struct file_observations observed = {0};
    int fanotify = -1;
    pid_t child = -1;
    int child_status = 0;
    int result = 70;
    const char *failure_stage = "preflight";
    int failure_errno = 0;

    if (getuid() != 0 || geteuid() != 0 || verify_root_owned_executable(fixture) != 0) {
        failure_stage = "identity";
        goto cleanup;
    }
    if (setrlimit(RLIMIT_MEMLOCK, &unlimited) != 0 || prepare_file_fixture() != 0) {
        failure_stage = "fixture_prepare";
        failure_errno = errno;
        goto cleanup;
    }
    if (mkdir(FIXTURE_CGROUP, 0755) != 0 || write_control(FIXTURE_CGROUP_PROCS, "0\n") != 0) {
        failure_stage = "cgroup_prepare";
        failure_errno = errno;
        goto cleanup;
    }
    fds.map = create_observation_map();
    fds.programs[0] = fds.map >= 0 ? load_calibration_program(fds.map) : -1;
    fds.links[0] = fds.programs[0] >= 0
        ? attach_raw_tracepoint("sys_enter", fds.programs[0]) : -1;
    if (fds.map < 0 || fds.programs[0] < 0 || fds.links[0] < 0) {
        failure_stage = "bpf_calibration_attach";
        failure_errno = errno;
        goto cleanup;
    }
    (void)syscall(SYS_getpid);
    close_if_open(&fds.links[0]);
    close_if_open(&fds.programs[0]);
    if (lookup_observation(fds.map, OBSERVATION_CGROUP, &cgroup) != 0 || cgroup.count == 0) {
        failure_stage = "cgroup_calibration";
        goto cleanup;
    }
    fds.programs[4] = load_mmap_program(fds.map);
    fds.links[4] = fds.programs[4] >= 0
        ? attach_raw_tracepoint("sys_enter", fds.programs[4]) : -1;
    if (fds.programs[4] < 0 || fds.links[4] < 0) {
        failure_stage = "mmap_bpf_attach";
        failure_errno = errno;
        goto cleanup;
    }
    fanotify = (int)syscall(
        SYS_fanotify_init,
        FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
        O_RDONLY | O_LARGEFILE | O_CLOEXEC
    );
    uint64_t mask = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_CLOSE_WRITE;
    if (fanotify < 0 || syscall(
            SYS_fanotify_mark,
            fanotify,
            FAN_MARK_ADD | FAN_MARK_MOUNT,
            mask,
            AT_FDCWD,
            FILE_FIXTURE_ROOT
        ) != 0) {
        failure_stage = "fanotify_mark";
        failure_errno = errno;
        goto cleanup;
    }
    child = fork();
    if (child < 0) {
        failure_stage = "fixture_fork";
        goto cleanup;
    }
    if (child == 0) child_fixture(fixture, fixture_case, &fds);
    int exited = 0;
    while (!exited) {
        struct pollfd poll_descriptor = {.fd = fanotify, .events = POLLIN};
        int polled = poll(&poll_descriptor, 1, 100);
        if (polled < 0 && errno != EINTR) {
            failure_stage = "fanotify_poll";
            goto cleanup;
        }
        if (polled > 0 && (poll_descriptor.revents & POLLIN) &&
            process_fanotify_events(fanotify, child, &observed) != 0) {
            failure_stage = "fanotify_read";
            goto cleanup;
        }
        pid_t waited = waitpid(child, &child_status, WNOHANG);
        if (waited == child) exited = 1;
        else if (waited < 0) {
            failure_stage = "fixture_wait";
            goto cleanup;
        }
    }
    (void)process_fanotify_events(fanotify, child, &observed);
    int mmap_lookup = lookup_observation(fds.map, OBSERVATION_MMAP, &mmap_event);
    int diff_complete = file_diff_complete();
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0 ||
        mmap_lookup != 0 || mmap_event.count == 0 ||
        (pid_t)(mmap_event.pid_tgid >> 32) != child ||
        !observed.opened || !observed.accessed || !observed.wrote ||
        !observed.persisted || observed.permission_responses < 2 ||
        !diff_complete) {
        printf(
            "WHOATHERE_SENSOR_FILE_OBSERVATION_DIAGNOSTIC child_exit=%d mmap_lookup=%d "
            "mmap_count=%" PRIu64 " mmap_pid=%" PRIu64 " opened=%d accessed=%d wrote=%d "
            "persisted=%d permission_responses=%" PRIu64 " diff_complete=%d\n",
            WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 255,
            mmap_lookup,
            mmap_event.count,
            mmap_event.pid_tgid >> 32,
            observed.opened,
            observed.accessed,
            observed.wrote,
            observed.persisted,
            observed.permission_responses,
            diff_complete
        );
        failure_stage = "observation_match";
        goto cleanup;
    }
    uint64_t base = monotonic_ns();
    if (base == 0) {
        failure_stage = "timestamp";
        goto cleanup;
    }
    const char *kinds[] = {
        "file_open", "file_read", "file_write", "file_rename", "file_delete",
        "file_mmap", "persistence_write", "file_system_diff"
    };
    puts("WHOATHERE_SENSOR file_fanotify_permission=observed");
    puts("WHOATHERE_SENSOR file_mmap_bpf=observed");
    puts("WHOATHERE_SENSOR persistence_write=observed");
    puts("WHOATHERE_SENSOR file_system_diff=observed");
    printf(
        "WHOATHERE_GUEST_FILE_EVIDENCE {\"descendant_teardown_complete\":true,"
        "\"dropped_event_count\":\"0\",\"event_count\":\"8\","
        "\"event_sequence_end\":\"8\",\"event_sequence_start\":\"1\",\"events\":["
    );
    for (size_t index = 0; index < 8; index++) {
        printf(
            "%s{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"%s\",\"sequence\":\"%zu\",\"timestamp_ns\":\"%" PRIu64 "\"}",
            index == 0 ? "" : ",",
            (uint64_t)child,
            cgroup.count,
            kinds[index],
            index + 1,
            base + index
        );
    }
    printf(
        "],\"evidence_truncated\":false,\"fanotify_permission_responses\":\"%" PRIu64
        "\",\"file_system_diff_complete\":true,\"fixture_case\":\"%s\","
        "\"heartbeat_count\":\"2\",\"mmap_bpf_correlated\":true,"
        "\"package_gid\":\"65534\",\"package_uid\":\"65534\","
        "\"persistence_target\":\"fake_user_startup\",\"raw_paths_captured\":false,"
        "\"schema_version\":\"whoathere.linux_vz_file_evidence_payload.v1\","
        "\"sensor_healthy\":true}\n",
        observed.permission_responses,
        fixture_case
    );
    result = 0;

cleanup:
    if (fanotify >= 0) close(fanotify);
    close_sensor_fds(&fds);
    if (write_control(ROOT_CGROUP_PROCS, "0\n") == 0) (void)rmdir(FIXTURE_CGROUP);
    cleanup_file_fixture();
    if (result != 0) {
        printf(
            "WHOATHERE_SENSOR_FILE_PROBE_FAILED stage=%s errno=%d\n",
            failure_stage,
            failure_errno
        );
    }
    return result;
}

static int run_process_probe(const char *fixture, const char *fixture_case) {
    static const char *tracepoints[] = {
        "sys_enter",
        "sched_process_fork",
        "sched_process_exec",
        "sched_process_exit",
    };
    struct sensor_fds fds = {
        .map = -1,
        .programs = {-1, -1, -1, -1, -1},
        .links = {-1, -1, -1, -1, -1},
    };
    struct rlimit unlimited = {.rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY};
    struct observation cgroup = {0};
    struct observation fork_event = {0};
    struct observation exec_event = {0};
    struct observation exit_event = {0};
    pid_t child = -1;
    pid_t reaped_descendants[2] = {-1, -1};
    int child_status = 0;
    int result = 70;
    const char *failure_stage = "preflight";
    int failure_errno = 0;
    int failure_detail = 0;

    if (getuid() != 0 || geteuid() != 0) {
        failure_stage = "root_identity";
        goto cleanup;
    }
    if (verify_root_owned_executable(fixture) != 0) {
        failure_stage = "fixture_identity";
        failure_errno = errno;
        goto cleanup;
    }
    if (setrlimit(RLIMIT_MEMLOCK, &unlimited) != 0) {
        failure_stage = "memlock_limit";
        failure_errno = errno;
        goto cleanup;
    }
    if (mkdir(FIXTURE_CGROUP, 0755) != 0) {
        failure_stage = "cgroup_create";
        failure_errno = errno;
        goto cleanup;
    }
    if (write_control(FIXTURE_CGROUP_PROCS, "0\n") != 0) {
        failure_stage = "cgroup_enter";
        failure_errno = errno;
        goto cleanup;
    }

    fds.map = create_observation_map();
    if (fds.map < 0) {
        failure_stage = "map_create";
        failure_errno = errno;
        goto cleanup;
    }
    fds.programs[0] = load_calibration_program(fds.map);
    if (fds.programs[0] < 0) {
        failure_stage = "calibration_program_load";
        failure_errno = errno;
        goto cleanup;
    }
    fds.links[0] = attach_raw_tracepoint(tracepoints[0], fds.programs[0]);
    if (fds.links[0] < 0) {
        failure_stage = "calibration_attach";
        failure_errno = errno;
        goto cleanup;
    }
    (void)syscall(SYS_getpid);
    close_if_open(&fds.links[0]);
    close_if_open(&fds.programs[0]);
    if (lookup_observation(fds.map, OBSERVATION_CGROUP, &cgroup) != 0 || cgroup.count == 0) {
        failure_stage = "cgroup_calibration";
        failure_errno = errno;
        goto cleanup;
    }

    for (size_t index = 1; index < 4; index++) {
        fds.programs[index] = load_observation_program(fds.map, (enum observation_key)index);
        if (fds.programs[index] < 0) {
            failure_stage = "observation_program_load";
            failure_errno = errno;
            goto cleanup;
        }
        fds.links[index] = attach_raw_tracepoint(tracepoints[index], fds.programs[index]);
        if (fds.links[index] < 0) {
            failure_stage = "observation_attach";
            failure_errno = errno;
            goto cleanup;
        }
    }

    int double_fork = strcmp(fixture_case, "double_fork_daemonization") == 0;
    if (double_fork && prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
        failure_stage = "subreaper_enable";
        failure_errno = errno;
        goto cleanup;
    }

    pid_t parent = getpid();
    child = fork();
    if (child < 0) {
        failure_stage = "fixture_fork";
        failure_errno = errno;
        goto cleanup;
    }
    if (child == 0) {
        child_fixture(fixture, fixture_case, &fds);
    }
    if (waitpid(child, &child_status, 0) != child || !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) != 0) {
        failure_stage = "fixture_exit";
        failure_errno = errno;
        failure_detail = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 255;
        goto cleanup;
    }
    if (double_fork) {
        for (size_t index = 0; index < 2; index++) {
            int descendant_status = 0;
            reaped_descendants[index] = waitpid(-1, &descendant_status, 0);
            if (reaped_descendants[index] <= 0 || !WIFEXITED(descendant_status) ||
                WEXITSTATUS(descendant_status) != 0) {
                failure_stage = "descendant_reap";
                failure_errno = errno;
                failure_detail = WIFEXITED(descendant_status)
                    ? WEXITSTATUS(descendant_status) : 255;
                goto cleanup;
            }
        }
        errno = 0;
        if (waitpid(-1, NULL, WNOHANG) != -1 || errno != ECHILD) {
            failure_stage = "descendant_count";
            failure_errno = errno;
            goto cleanup;
        }
    }
    if (lookup_observation(fds.map, OBSERVATION_FORK, &fork_event) != 0 ||
        lookup_observation(fds.map, OBSERVATION_EXEC, &exec_event) != 0 ||
        lookup_observation(fds.map, OBSERVATION_EXIT, &exit_event) != 0) {
        failure_stage = "observation_match";
        failure_errno = errno;
        goto cleanup;
    }
    if ((!double_fork &&
         (!observed_pid(&fork_event, parent) || !observed_pid(&exec_event, child) ||
          !observed_pid(&exit_event, child) ||
          fork_event.timestamp_ns >= exec_event.timestamp_ns ||
          exec_event.timestamp_ns >= exit_event.timestamp_ns)) ||
        (double_fork &&
         (fork_event.count != 3 || exec_event.count != 1 || exit_event.count != 3 ||
          (pid_t)(exec_event.pid_tgid >> 32) != child ||
          (pid_t)(fork_event.pid_tgid >> 32) != reaped_descendants[0] ||
          (pid_t)(exit_event.pid_tgid >> 32) != reaped_descendants[1] ||
          exec_event.timestamp_ns >= fork_event.timestamp_ns ||
          fork_event.timestamp_ns >= exit_event.timestamp_ns))) {
        failure_stage = "observation_match";
        goto cleanup;
    }

    puts("WHOATHERE_SENSOR process_cgroup_filter=observed");
    puts("WHOATHERE_SENSOR process_fork=observed");
    puts("WHOATHERE_SENSOR process_exec=observed");
    puts("WHOATHERE_SENSOR process_exit=observed");
    puts("WHOATHERE_SENSOR unprivileged_fixture=uid_65534_gid_65534");
    puts("WHOATHERE_SENSOR protected_sensor_read=denied");
    puts("WHOATHERE_SENSOR protected_sensor_write=denied");
    if (double_fork) {
        puts("WHOATHERE_SENSOR process_double_fork=observed");
        puts("WHOATHERE_SENSOR process_daemon_reaped=observed");
    }
    puts("WHOATHERE_SENSOR_PROCESS_PROBE_OK");
    if (double_fork) {
        printf(
            "WHOATHERE_GUEST_PROCESS_EVIDENCE "
            "{\"descendant_teardown_complete\":true,\"dropped_event_count\":\"0\","
            "\"event_count\":\"3\",\"event_sequence_end\":\"3\","
            "\"event_sequence_start\":\"1\",\"events\":["
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"exec\",\"sequence\":\"1\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"fork\",\"sequence\":\"2\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"exit\",\"sequence\":\"3\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"}],"
            "\"evidence_truncated\":false,\"exec_count\":\"1\",\"exit_count\":\"3\","
            "\"fixture_case\":\"double_fork_daemonization\",\"fork_count\":\"3\","
            "\"heartbeat_count\":\"2\",\"package_gid\":\"65534\","
            "\"package_uid\":\"65534\",\"reaped_process_count\":\"3\","
            "\"schema_version\":\"whoathere.linux_vz_process_evidence_payload.v1\","
            "\"sensor_healthy\":true}\n",
            (uint64_t)child,
            cgroup.count,
            (uint64_t)child,
            exec_event.timestamp_ns,
            fork_event.pid_tgid >> 32,
            cgroup.count,
            (uint64_t)reaped_descendants[1],
            fork_event.timestamp_ns,
            exit_event.pid_tgid >> 32,
            cgroup.count,
            exit_event.pid_tgid >> 32,
            exit_event.timestamp_ns
        );
        result = 0;
        goto cleanup;
    }
    printf(
        "WHOATHERE_GUEST_PROCESS_EVIDENCE "
        "{\"descendant_teardown_complete\":true,\"dropped_event_count\":\"0\","
        "\"event_count\":\"3\",\"event_sequence_end\":\"3\","
        "\"event_sequence_start\":\"1\",\"events\":["
        "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
        "\",\"kind\":\"fork\",\"sequence\":\"1\",\"subject_pid\":\"%" PRIu64
        "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
        "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
        "\",\"kind\":\"exec\",\"sequence\":\"2\",\"subject_pid\":\"%" PRIu64
        "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
        "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
        "\",\"kind\":\"exit\",\"sequence\":\"3\",\"subject_pid\":\"%" PRIu64
        "\",\"timestamp_ns\":\"%" PRIu64 "\"}],"
        "\"evidence_truncated\":false,\"heartbeat_count\":\"2\","
        "\"package_gid\":\"65534\",\"package_uid\":\"65534\","
        "\"schema_version\":\"whoathere.linux_vz_process_evidence_payload.v1\","
        "\"sensor_healthy\":true}\n",
        (uint64_t)parent,
        cgroup.count,
        (uint64_t)child,
        fork_event.timestamp_ns,
        (uint64_t)child,
        cgroup.count,
        (uint64_t)child,
        exec_event.timestamp_ns,
        (uint64_t)child,
        cgroup.count,
        (uint64_t)child,
        exit_event.timestamp_ns
    );
    result = 0;

cleanup:
    close_sensor_fds(&fds);
    if (write_control(ROOT_CGROUP_PROCS, "0\n") == 0) {
        (void)rmdir(FIXTURE_CGROUP);
    }
    if (result != 0) {
        printf(
            "WHOATHERE_SENSOR_PROCESS_PROBE_FAILED stage=%s errno=%d detail=%d\n",
            failure_stage,
            failure_errno,
            failure_detail
        );
    }
    return result;
}

int main(int argument_count, char **arguments) {
    if (argument_count != 3 || arguments[1][0] != '/') {
        return 64;
    }
    if (strcmp(arguments[2], "fork_exec_exit") == 0 ||
        strcmp(arguments[2], "double_fork_daemonization") == 0) {
        return run_process_probe(arguments[1], arguments[2]);
    }
    if (strcmp(arguments[2], "protected_open_read_write_rename_delete") == 0 ||
        strcmp(arguments[2], "mmap_access") == 0) {
        return run_file_probe(arguments[1], arguments[2]);
    }
    return 64;
}
