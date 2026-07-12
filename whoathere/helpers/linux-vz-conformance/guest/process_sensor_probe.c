#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/fanotify.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
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
#define REPARENT_REPORT_FD 3
#define REPARENT_REPORT_MAGIC 0x57545052U
#define SESSION_REPORT_MAGIC 0x57545353U
#define CREDENTIAL_REPORT_MAGIC 0x57544352U
#define DYNAMIC_REPORT_MAGIC 0x5754444cU
#define DYNAMIC_MARKER UINT64_C(0x57544c4942465831)
#define DYNAMIC_LIBRARY_PATH "/whoathere/dynamic-fixture-library.so"
#define NETWORK_REPORT_MAGIC 0x57544e34U
#define NETWORK6_REPORT_MAGIC 0x57544e36U
#define UDP_REPORT_MAGIC 0x57545534U
#define LOOPBACK_REPORT_MAGIC 0x57544c34U
#define NETWORK_INTERFACE "eth0"
#define NETWORK_SOURCE_ADDRESS "192.0.2.2"
#define NETWORK_TARGET_ADDRESS "192.0.2.1"
#define NETWORK6_SOURCE_ADDRESS "2001:db8::2"
#define NETWORK6_TARGET_ADDRESS "2001:db8::1"
#define NETWORK_TARGET_PORT 443
#define UDP_PAYLOAD_LENGTH 16
#define LOOPBACK_ADDRESS "127.0.0.1"
#define LOOPBACK_TARGET_PORT 40552
#define SENSOR_PROGRAM_COUNT 8

struct reparent_report {
    uint32_t magic;
    int32_t child_pid;
};

struct session_report {
    uint32_t magic;
    int32_t process_pid;
    int32_t prior_session_id;
    int32_t prior_process_group_id;
    int32_t session_id;
    int32_t process_group_id;
};

struct credential_report {
    uint32_t magic;
    int32_t process_pid;
    uint32_t uid;
    uint32_t effective_uid;
    uint32_t gid;
    uint32_t effective_gid;
    int32_t supplementary_group_count;
};

struct dynamic_report {
    uint32_t magic;
    int32_t process_pid;
    uint64_t marker;
};

struct network_report {
    uint32_t magic;
    int32_t process_pid;
    uint64_t socket_inode;
    uint32_t source_address;
    uint32_t target_address;
    uint16_t source_port;
    uint16_t target_port;
    int32_t connect_errno;
};

struct network6_report {
    uint32_t magic;
    int32_t process_pid;
    uint64_t socket_inode;
    struct in6_addr source_address;
    struct in6_addr target_address;
    uint16_t source_port;
    uint16_t target_port;
    int32_t connect_errno;
};

struct udp_report {
    uint32_t magic;
    int32_t process_pid;
    uint64_t socket_inode;
    uint32_t source_address;
    uint32_t target_address;
    uint16_t source_port;
    uint16_t target_port;
    uint32_t payload_length;
};

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
    OBSERVATION_SETGROUPS = 5,
    OBSERVATION_SETGID = 6,
    OBSERVATION_SETUID = 7,
    OBSERVATION_CONNECT = 8,
    OBSERVATION_SENDTO = 9,
    OBSERVATION_COUNT = 10,
};

struct observation {
    uint64_t count;
    uint64_t pid_tgid;
    uint64_t timestamp_ns;
};

struct sensor_fds {
    int map;
    int programs[SENSOR_PROGRAM_COUNT];
    int links[SENSOR_PROGRAM_COUNT];
};

static void close_if_open(int *descriptor) {
    if (*descriptor >= 0) {
        close(*descriptor);
        *descriptor = -1;
    }
}

static void close_sensor_fds(struct sensor_fds *fds) {
    for (size_t index = 0; index < SENSOR_PROGRAM_COUNT; index++) {
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

static int load_syscall_program(int map, enum observation_key key, int syscall_number) {
    const struct bpf_insn instructions[] = {
        MOV64_IMM(BPF_REG_0, 0),
        MOV64_REG(BPF_REG_6, BPF_REG_1),
        LOAD_REG(BPF_DW, BPF_REG_9, BPF_REG_6, 8),
        JUMP_IMM(BPF_JNE, BPF_REG_9, syscall_number, 26),
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

static int child_fixture(
    const char *fixture,
    const char *fixture_case,
    struct sensor_fds *fds,
    int report_fd
) {
    close_sensor_fds(fds);
    if (report_fd >= 0) {
        if (report_fd != REPARENT_REPORT_FD) {
            if (dup2(report_fd, REPARENT_REPORT_FD) < 0) _exit(68);
            close(report_fd);
        } else if (fcntl(REPARENT_REPORT_FD, F_SETFD, 0) != 0) {
            _exit(68);
        }
    } else {
        close(REPARENT_REPORT_FD);
    }
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
        .programs = {-1, -1, -1, -1, -1, -1, -1, -1},
        .links = {-1, -1, -1, -1, -1, -1, -1, -1},
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
    fds.programs[4] = load_syscall_program(fds.map, OBSERVATION_MMAP, SYS_mmap);
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
    if (child == 0) child_fixture(fixture, fixture_case, &fds, -1);
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

static int read_exact_reparent_report(int descriptor, struct reparent_report *report) {
    size_t offset = 0;
    while (offset < sizeof(*report)) {
        ssize_t length = read(descriptor, (char *)report + offset, sizeof(*report) - offset);
        if (length < 0 && errno == EINTR) continue;
        if (length <= 0) return -1;
        offset += (size_t)length;
    }
    char trailing = 0;
    ssize_t length;
    do {
        length = read(descriptor, &trailing, 1);
    } while (length < 0 && errno == EINTR);
    return length == 0 && report->magic == REPARENT_REPORT_MAGIC && report->child_pid > 0
        ? 0 : -1;
}

static int read_exact_session_report(int descriptor, struct session_report *report) {
    size_t offset = 0;
    while (offset < sizeof(*report)) {
        ssize_t length = read(descriptor, (char *)report + offset, sizeof(*report) - offset);
        if (length < 0 && errno == EINTR) continue;
        if (length <= 0) return -1;
        offset += (size_t)length;
    }
    char trailing = 0;
    ssize_t length;
    do {
        length = read(descriptor, &trailing, 1);
    } while (length < 0 && errno == EINTR);
    return length == 0 && report->magic == SESSION_REPORT_MAGIC && report->process_pid > 0
        ? 0 : -1;
}

static int read_exact_credential_report(int descriptor, struct credential_report *report) {
    size_t offset = 0;
    while (offset < sizeof(*report)) {
        ssize_t length = read(descriptor, (char *)report + offset, sizeof(*report) - offset);
        if (length < 0 && errno == EINTR) continue;
        if (length <= 0) return -1;
        offset += (size_t)length;
    }
    char trailing = 0;
    ssize_t length;
    do {
        length = read(descriptor, &trailing, 1);
    } while (length < 0 && errno == EINTR);
    return length == 0 && report->magic == CREDENTIAL_REPORT_MAGIC && report->process_pid > 0
        ? 0 : -1;
}

static int read_exact_dynamic_report(int descriptor, struct dynamic_report *report) {
    size_t offset = 0;
    while (offset < sizeof(*report)) {
        ssize_t length = read(descriptor, (char *)report + offset, sizeof(*report) - offset);
        if (length < 0 && errno == EINTR) continue;
        if (length <= 0) return -1;
        offset += (size_t)length;
    }
    char trailing = 0;
    ssize_t length;
    do {
        length = read(descriptor, &trailing, 1);
    } while (length < 0 && errno == EINTR);
    return length == 0 && report->magic == DYNAMIC_REPORT_MAGIC &&
        report->process_pid > 0 && report->marker == DYNAMIC_MARKER ? 0 : -1;
}

static int cgroup_contains_pid(pid_t expected) {
    int descriptor = open(FIXTURE_CGROUP_PROCS, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return 0;
    char buffer[4096];
    ssize_t length = read(descriptor, buffer, sizeof(buffer) - 1);
    int saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    if (length <= 0 || (size_t)length >= sizeof(buffer)) return 0;
    buffer[length] = '\0';
    char *cursor = buffer;
    while (*cursor != '\0') {
        errno = 0;
        char *end = NULL;
        long value = strtol(cursor, &end, 10);
        if (errno != 0 || end == cursor || (*end != '\n' && *end != '\0')) return 0;
        if (value == expected) return 1;
        cursor = *end == '\n' ? end + 1 : end;
    }
    return 0;
}

static int proc_identity_matches(pid_t child, pid_t expected_parent) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", child);
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return 0;
    char buffer[4096];
    ssize_t length = read(descriptor, buffer, sizeof(buffer) - 1);
    int saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    if (length <= 0 || (size_t)length >= sizeof(buffer)) return 0;
    buffer[length] = '\0';
    char *parent_line = strstr(buffer, "\nPPid:\t");
    char *uid_line = strstr(buffer, "\nUid:\t");
    char *gid_line = strstr(buffer, "\nGid:\t");
    unsigned long parent = 0;
    unsigned long uid[4] = {0};
    unsigned long gid[4] = {0};
    if (parent_line == NULL || uid_line == NULL || gid_line == NULL ||
        sscanf(parent_line + 7, "%lu", &parent) != 1 ||
        sscanf(uid_line + 6, "%lu\t%lu\t%lu\t%lu", &uid[0], &uid[1], &uid[2], &uid[3]) != 4 ||
        sscanf(gid_line + 6, "%lu\t%lu\t%lu\t%lu", &gid[0], &gid[1], &gid[2], &gid[3]) != 4) {
        return 0;
    }
    for (size_t index = 0; index < 4; index++) {
        if (uid[index] != FIXTURE_UID || gid[index] != FIXTURE_GID) return 0;
    }
    return parent == (unsigned long)expected_parent && cgroup_contains_pid(child);
}

static int proc_has_no_supplementary_groups(pid_t child) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", child);
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return 0;
    char buffer[4096];
    ssize_t length = read(descriptor, buffer, sizeof(buffer) - 1);
    int saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    if (length <= 0 || (size_t)length >= sizeof(buffer)) return 0;
    buffer[length] = '\0';
    char *groups = strstr(buffer, "\nGroups:\t");
    if (groups == NULL) return 0;
    groups += 9;
    while (*groups == ' ' || *groups == '\t') groups++;
    return *groups == '\n';
}

static int proc_maps_contains_dynamic_library(pid_t child) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", child);
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return 0;
    char buffer[16384];
    ssize_t length = read(descriptor, buffer, sizeof(buffer) - 1);
    int saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    if (length <= 0 || (size_t)length >= sizeof(buffer)) return 0;
    buffer[length] = '\0';
    char *line = buffer;
    while (*line != '\0') {
        char *end = strchr(line, '\n');
        if (end == NULL) return 0;
        *end = '\0';
        if (strstr(line, " r-xp ") != NULL) {
            char *mapped_path = strstr(line, DYNAMIC_LIBRARY_PATH);
            if (mapped_path != NULL && strcmp(mapped_path, DYNAMIC_LIBRARY_PATH) == 0) return 1;
        }
        line = end + 1;
    }
    return 0;
}

static int dynamic_library_open_observed(int fanotify, pid_t child) {
    char buffer[4096] __attribute__((aligned(8)));
    int observed = 0;
    for (;;) {
        ssize_t length = read(fanotify, buffer, sizeof(buffer));
        if (length < 0 && errno == EINTR) continue;
        if (length < 0 && errno == EAGAIN) break;
        if (length <= 0) return 0;
        struct fanotify_event_metadata *metadata;
        for (metadata = (struct fanotify_event_metadata *)buffer;
             FAN_EVENT_OK(metadata, length);
             metadata = FAN_EVENT_NEXT(metadata, length)) {
            if (metadata->vers != FANOTIFY_METADATA_VERSION) return 0;
            if (metadata->pid == child && (metadata->mask & FAN_OPEN)) observed = 1;
            if (metadata->fd >= 0) close(metadata->fd);
        }
    }
    return observed;
}

static int read_exact_network_report(int descriptor, struct network_report *report) {
    size_t offset = 0;
    while (offset < sizeof(*report)) {
        ssize_t length = read(descriptor, (char *)report + offset, sizeof(*report) - offset);
        if (length < 0 && errno == EINTR) continue;
        if (length <= 0) return -1;
        offset += (size_t)length;
    }
    char trailing = 0;
    ssize_t length;
    do {
        length = read(descriptor, &trailing, 1);
    } while (length < 0 && errno == EINTR);
    struct in_addr source = {0};
    struct in_addr target = {0};
    return length == 0 && report->magic == NETWORK_REPORT_MAGIC &&
        report->process_pid > 0 && report->socket_inode > 0 &&
        inet_pton(AF_INET, NETWORK_SOURCE_ADDRESS, &source) == 1 &&
        inet_pton(AF_INET, NETWORK_TARGET_ADDRESS, &target) == 1 &&
        report->source_address == source.s_addr && report->target_address == target.s_addr &&
        report->source_port > 0 && report->target_port == NETWORK_TARGET_PORT &&
        report->connect_errno == EINPROGRESS ? 0 : -1;
}

static int read_exact_network6_report(int descriptor, struct network6_report *report) {
    size_t offset = 0;
    while (offset < sizeof(*report)) {
        ssize_t length = read(descriptor, (char *)report + offset, sizeof(*report) - offset);
        if (length < 0 && errno == EINTR) continue;
        if (length <= 0) return -1;
        offset += (size_t)length;
    }
    char trailing = 0;
    ssize_t length;
    do {
        length = read(descriptor, &trailing, 1);
    } while (length < 0 && errno == EINTR);
    struct in6_addr source = IN6ADDR_ANY_INIT;
    struct in6_addr target = IN6ADDR_ANY_INIT;
    return length == 0 && report->magic == NETWORK6_REPORT_MAGIC &&
        report->process_pid > 0 && report->socket_inode > 0 &&
        inet_pton(AF_INET6, NETWORK6_SOURCE_ADDRESS, &source) == 1 &&
        inet_pton(AF_INET6, NETWORK6_TARGET_ADDRESS, &target) == 1 &&
        memcmp(&report->source_address, &source, sizeof(source)) == 0 &&
        memcmp(&report->target_address, &target, sizeof(target)) == 0 &&
        report->source_port > 0 && report->target_port == NETWORK_TARGET_PORT &&
        report->connect_errno == EINPROGRESS ? 0 : -1;
}

static int read_exact_udp_report(int descriptor, struct udp_report *report) {
    size_t offset = 0;
    while (offset < sizeof(*report)) {
        ssize_t length = read(descriptor, (char *)report + offset, sizeof(*report) - offset);
        if (length < 0 && errno == EINTR) continue;
        if (length <= 0) return -1;
        offset += (size_t)length;
    }
    char trailing = 0;
    ssize_t length;
    do {
        length = read(descriptor, &trailing, 1);
    } while (length < 0 && errno == EINTR);
    struct in_addr source = {0};
    struct in_addr target = {0};
    return length == 0 && report->magic == UDP_REPORT_MAGIC &&
        report->process_pid > 0 && report->socket_inode > 0 &&
        inet_pton(AF_INET, NETWORK_SOURCE_ADDRESS, &source) == 1 &&
        inet_pton(AF_INET, NETWORK_TARGET_ADDRESS, &target) == 1 &&
        report->source_address == source.s_addr && report->target_address == target.s_addr &&
        report->source_port > 0 && report->target_port == NETWORK_TARGET_PORT &&
        report->payload_length == UDP_PAYLOAD_LENGTH ? 0 : -1;
}

static int read_exact_loopback_report(int descriptor, struct network_report *report) {
    size_t offset = 0;
    while (offset < sizeof(*report)) {
        ssize_t length = read(descriptor, (char *)report + offset, sizeof(*report) - offset);
        if (length < 0 && errno == EINTR) continue;
        if (length <= 0) return -1;
        offset += (size_t)length;
    }
    char trailing = 0;
    ssize_t length;
    do {
        length = read(descriptor, &trailing, 1);
    } while (length < 0 && errno == EINTR);
    struct in_addr loopback = {0};
    return length == 0 && report->magic == LOOPBACK_REPORT_MAGIC &&
        report->process_pid > 0 && report->socket_inode > 0 &&
        inet_pton(AF_INET, LOOPBACK_ADDRESS, &loopback) == 1 &&
        report->source_address == loopback.s_addr && report->target_address == loopback.s_addr &&
        report->source_port > 0 && report->target_port == LOOPBACK_TARGET_PORT &&
        report->connect_errno == 0 ? 0 : -1;
}

static int add_route_attribute(
    struct nlmsghdr *header,
    size_t maximum,
    unsigned short type,
    const void *value,
    size_t length
) {
    size_t aligned = NLMSG_ALIGN(header->nlmsg_len);
    size_t attribute_length = RTA_LENGTH(length);
    if (aligned + RTA_ALIGN(attribute_length) > maximum) return -1;
    struct rtattr *attribute = (struct rtattr *)((char *)header + aligned);
    attribute->rta_type = type;
    attribute->rta_len = (unsigned short)attribute_length;
    memcpy(RTA_DATA(attribute), value, length);
    header->nlmsg_len = (unsigned int)(aligned + RTA_ALIGN(attribute_length));
    return 0;
}

static int send_route_request(struct nlmsghdr *request) {
    int descriptor = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (descriptor < 0) return -1;
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    int result = -1;
    if (bind(descriptor, (const struct sockaddr *)&local, sizeof(local)) != 0) goto done;
    request->nlmsg_seq = 1;
    if (sendto(
            descriptor,
            request,
            request->nlmsg_len,
            0,
            (const struct sockaddr *)&kernel,
            sizeof(kernel)
        ) != (ssize_t)request->nlmsg_len) goto done;
    _Alignas(struct nlmsghdr) char response[4096];
    for (;;) {
        ssize_t length = recv(descriptor, response, sizeof(response), 0);
        if (length < 0 && errno == EINTR) continue;
        if (length <= 0) goto done;
        for (struct nlmsghdr *header = (struct nlmsghdr *)response;
             NLMSG_OK(header, length);
             header = NLMSG_NEXT(header, length)) {
            if (header->nlmsg_seq != request->nlmsg_seq) continue;
            if (header->nlmsg_type != NLMSG_ERROR ||
                header->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) goto done;
            struct nlmsgerr *error = (struct nlmsgerr *)NLMSG_DATA(header);
            if (error->error != 0) {
                errno = -error->error;
                goto done;
            }
            result = 0;
            goto done;
        }
    }
done:
    close(descriptor);
    return result;
}

static int prepare_ipv6_sinkhole(void) {
    const struct {
        const char *path;
        const char *value;
    } controls[] = {
        {"/proc/sys/net/ipv6/conf/eth0/disable_ipv6", "1\n"},
        {"/proc/sys/net/ipv6/conf/eth0/autoconf", "0\n"},
        {"/proc/sys/net/ipv6/conf/eth0/accept_ra", "0\n"},
        {"/proc/sys/net/ipv6/conf/eth0/router_solicitations", "0\n"},
        {"/proc/sys/net/ipv6/conf/eth0/dad_transmits", "0\n"},
        {"/proc/sys/net/ipv6/conf/eth0/addr_gen_mode", "1\n"},
        {"/proc/sys/net/ipv6/conf/eth0/mldv2_unsolicited_report_interval", "60000\n"},
        {"/proc/sys/net/ipv6/conf/eth0/disable_ipv6", "0\n"},
    };
    for (size_t index = 0; index < sizeof(controls) / sizeof(controls[0]); index++) {
        if (write_control(controls[index].path, controls[index].value) != 0) return -1;
    }
    int control = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (control < 0) return -1;
    struct ifreq interface;
    memset(&interface, 0, sizeof(interface));
    strncpy(interface.ifr_name, NETWORK_INTERFACE, IFNAMSIZ - 1);
    if (ioctl(control, SIOCGIFFLAGS, &interface) != 0) {
        close(control);
        return -1;
    }
    interface.ifr_flags |= IFF_UP;
    if (ioctl(control, SIOCSIFFLAGS, &interface) != 0) {
        close(control);
        return -1;
    }
    close(control);
    unsigned int interface_index = if_nametoindex(NETWORK_INTERFACE);
    struct in6_addr source = IN6ADDR_ANY_INIT;
    struct in6_addr target = IN6ADDR_ANY_INIT;
    if (interface_index == 0 ||
        inet_pton(AF_INET6, NETWORK6_SOURCE_ADDRESS, &source) != 1 ||
        inet_pton(AF_INET6, NETWORK6_TARGET_ADDRESS, &target) != 1) return -1;

    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
        char attributes[96];
    } address_request;
    memset(&address_request, 0, sizeof(address_request));
    address_request.header.nlmsg_len = NLMSG_LENGTH(sizeof(address_request.address));
    address_request.header.nlmsg_type = RTM_NEWADDR;
    address_request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    address_request.address.ifa_family = AF_INET6;
    address_request.address.ifa_prefixlen = 64;
    address_request.address.ifa_flags = IFA_F_NODAD;
    address_request.address.ifa_scope = RT_SCOPE_UNIVERSE;
    address_request.address.ifa_index = interface_index;
    if (add_route_attribute(
            &address_request.header,
            sizeof(address_request),
            IFA_ADDRESS,
            &source,
            sizeof(source)
        ) != 0 || send_route_request(&address_request.header) != 0) return -1;

    struct {
        struct nlmsghdr header;
        struct ndmsg neighbor;
        char attributes[96];
    } neighbor_request;
    memset(&neighbor_request, 0, sizeof(neighbor_request));
    neighbor_request.header.nlmsg_len = NLMSG_LENGTH(sizeof(neighbor_request.neighbor));
    neighbor_request.header.nlmsg_type = RTM_NEWNEIGH;
    neighbor_request.header.nlmsg_flags =
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    neighbor_request.neighbor.ndm_family = AF_INET6;
    neighbor_request.neighbor.ndm_ifindex = (int)interface_index;
    neighbor_request.neighbor.ndm_state = NUD_PERMANENT;
    neighbor_request.neighbor.ndm_type = RTN_UNICAST;
    const unsigned char target_mac[6] = {0x02, 0x57, 0x48, 0x4f, 0x41, 0xfe};
    if (add_route_attribute(
            &neighbor_request.header,
            sizeof(neighbor_request),
            NDA_DST,
            &target,
            sizeof(target)
        ) != 0 ||
        add_route_attribute(
            &neighbor_request.header,
            sizeof(neighbor_request),
            NDA_LLADDR,
            target_mac,
            sizeof(target_mac)
        ) != 0 || send_route_request(&neighbor_request.header) != 0) return -1;
    return 0;
}

static int set_interface_address(int descriptor, unsigned long request, const char *address) {
    struct ifreq interface;
    memset(&interface, 0, sizeof(interface));
    strncpy(interface.ifr_name, NETWORK_INTERFACE, IFNAMSIZ - 1);
    struct sockaddr_in *socket_address = (struct sockaddr_in *)&interface.ifr_addr;
    socket_address->sin_family = AF_INET;
    if (inet_pton(AF_INET, address, &socket_address->sin_addr) != 1) return -1;
    return ioctl(descriptor, request, &interface);
}

static int prepare_ipv4_sinkhole(void) {
    if (write_control("/proc/sys/net/ipv6/conf/eth0/disable_ipv6", "1\n") != 0) return -1;
    int descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) return -1;
    int result = -1;
    struct ifreq interface;
    memset(&interface, 0, sizeof(interface));
    strncpy(interface.ifr_name, NETWORK_INTERFACE, IFNAMSIZ - 1);
    if (ioctl(descriptor, SIOCGIFFLAGS, &interface) != 0) goto done;
    interface.ifr_flags |= IFF_UP;
    if (ioctl(descriptor, SIOCSIFFLAGS, &interface) != 0 ||
        set_interface_address(descriptor, SIOCSIFADDR, NETWORK_SOURCE_ADDRESS) != 0 ||
        set_interface_address(descriptor, SIOCSIFNETMASK, "255.255.255.0") != 0) goto done;

    struct arpreq neighbor;
    memset(&neighbor, 0, sizeof(neighbor));
    struct sockaddr_in *protocol = (struct sockaddr_in *)&neighbor.arp_pa;
    protocol->sin_family = AF_INET;
    if (inet_pton(AF_INET, NETWORK_TARGET_ADDRESS, &protocol->sin_addr) != 1) goto done;
    neighbor.arp_ha.sa_family = ARPHRD_ETHER;
    const unsigned char target_mac[6] = {0x02, 0x57, 0x48, 0x4f, 0x41, 0xfe};
    memcpy(neighbor.arp_ha.sa_data, target_mac, sizeof(target_mac));
    neighbor.arp_flags = ATF_COM | ATF_PERM;
    strncpy(neighbor.arp_dev, NETWORK_INTERFACE, sizeof(neighbor.arp_dev) - 1);
    if (ioctl(descriptor, SIOCSARP, &neighbor) != 0) goto done;
    result = 0;
done:
    close(descriptor);
    return result;
}

static int prepare_loopback_sinkhole(void) {
    int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (descriptor < 0) return -1;
    struct ifreq interface;
    memset(&interface, 0, sizeof(interface));
    strncpy(interface.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(descriptor, SIOCGIFFLAGS, &interface) != 0) {
        close(descriptor);
        return -1;
    }
    interface.ifr_flags |= IFF_UP;
    int reuse = 1;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(LOOPBACK_TARGET_PORT),
    };
    if (ioctl(descriptor, SIOCSIFFLAGS, &interface) != 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        inet_pton(AF_INET, LOOPBACK_ADDRESS, &address.sin_addr) != 1 ||
        bind(descriptor, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(descriptor, 1) != 0) {
        close(descriptor);
        return -1;
    }
    return descriptor;
}

static void cleanup_loopback_sinkhole(void) {
    int descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) return;
    struct ifreq interface;
    memset(&interface, 0, sizeof(interface));
    strncpy(interface.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(descriptor, SIOCGIFFLAGS, &interface) == 0) {
        interface.ifr_flags &= (short)~IFF_UP;
        (void)ioctl(descriptor, SIOCSIFFLAGS, &interface);
    }
    close(descriptor);
}

static int accept_exact_loopback_peer(int listener, const struct network_report *report) {
    struct sockaddr_in peer = {0};
    socklen_t peer_length = sizeof(peer);
    int descriptor = accept4(
        listener,
        (struct sockaddr *)&peer,
        &peer_length,
        SOCK_CLOEXEC
    );
    if (descriptor < 0) return -1;
    struct sockaddr_in local = {0};
    socklen_t local_length = sizeof(local);
    struct in_addr loopback = {0};
    if (peer_length != sizeof(peer) || peer.sin_family != AF_INET ||
        peer.sin_addr.s_addr != report->source_address ||
        ntohs(peer.sin_port) != report->source_port ||
        getsockname(descriptor, (struct sockaddr *)&local, &local_length) != 0 ||
        local_length != sizeof(local) || local.sin_family != AF_INET ||
        inet_pton(AF_INET, LOOPBACK_ADDRESS, &loopback) != 1 ||
        local.sin_addr.s_addr != loopback.s_addr || ntohs(local.sin_port) != LOOPBACK_TARGET_PORT) {
        close(descriptor);
        return -1;
    }
    return descriptor;
}

static void cleanup_ipv4_sinkhole(void) {
    int descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) return;
    struct ifreq interface;
    memset(&interface, 0, sizeof(interface));
    strncpy(interface.ifr_name, NETWORK_INTERFACE, IFNAMSIZ - 1);
    if (ioctl(descriptor, SIOCGIFFLAGS, &interface) == 0) {
        interface.ifr_flags &= (short)~IFF_UP;
        (void)ioctl(descriptor, SIOCSIFFLAGS, &interface);
    }
    close(descriptor);
}

static int proc_tcp_contains_ipv4_sinkhole(const struct network_report *report) {
    FILE *stream = fopen("/proc/net/tcp", "re");
    if (stream == NULL) return 0;
    char expected_local[14];
    snprintf(expected_local, sizeof(expected_local), "020200C0:%04X", report->source_port);
    const char *expected_remote = "010200C0:01BB";
    char line[512];
    int observed = 0;
    while (fgets(line, sizeof(line), stream) != NULL) {
        char local[14] = {0};
        char remote[14] = {0};
        char state[3] = {0};
        unsigned long long inode = 0;
        if (sscanf(
                line,
                " %*d: %13s %13s %2s %*s %*s %*s %*u %*u %llu",
                local,
                remote,
                state,
                &inode
            ) == 4 && strcmp(local, expected_local) == 0 &&
            strcmp(remote, expected_remote) == 0 && strcmp(state, "02") == 0 &&
            inode == report->socket_inode) {
            observed = 1;
            break;
        }
    }
    if (fclose(stream) != 0) return 0;
    return observed;
}

static int proc_udp_contains_ipv4_sinkhole(const struct udp_report *report) {
    FILE *stream = fopen("/proc/net/udp", "re");
    if (stream == NULL) return 0;
    char expected_local[14];
    snprintf(expected_local, sizeof(expected_local), "020200C0:%04X", report->source_port);
    const char *expected_remote = "00000000:0000";
    char line[512];
    int observed = 0;
    while (fgets(line, sizeof(line), stream) != NULL) {
        char local[14] = {0};
        char remote[14] = {0};
        char state[3] = {0};
        unsigned long long inode = 0;
        if (sscanf(
                line,
                " %*d: %13s %13s %2s %*s %*s %*s %*u %*u %llu",
                local,
                remote,
                state,
                &inode
            ) == 4 && strcmp(local, expected_local) == 0 &&
            strcmp(remote, expected_remote) == 0 && strcmp(state, "07") == 0 &&
            inode == report->socket_inode) {
            observed = 1;
            break;
        }
    }
    if (fclose(stream) != 0) return 0;
    return observed;
}

static int proc_tcp_contains_loopback_sinkhole(const struct network_report *report) {
    FILE *stream = fopen("/proc/net/tcp", "re");
    if (stream == NULL) return 0;
    char expected_local[14];
    char expected_remote[14];
    snprintf(expected_local, sizeof(expected_local), "0100007F:%04X", report->source_port);
    snprintf(expected_remote, sizeof(expected_remote), "0100007F:%04X", report->target_port);
    char line[512];
    int observed = 0;
    while (fgets(line, sizeof(line), stream) != NULL) {
        char local[14] = {0};
        char remote[14] = {0};
        char state[3] = {0};
        unsigned long long inode = 0;
        if (sscanf(
                line,
                " %*d: %13s %13s %2s %*s %*s %*s %*u %*u %llu",
                local,
                remote,
                state,
                &inode
            ) == 4 && strcmp(local, expected_local) == 0 &&
            strcmp(remote, expected_remote) == 0 && strcmp(state, "01") == 0 &&
            inode == report->socket_inode) {
            observed = 1;
            break;
        }
    }
    if (fclose(stream) != 0) return 0;
    return observed;
}

static void proc_ipv6_address(const struct in6_addr *address, char output[33]) {
    for (size_t word = 0; word < 4; word++) {
        const unsigned char *bytes = &address->s6_addr[word * 4];
        snprintf(
            output + word * 8,
            9,
            "%02X%02X%02X%02X",
            bytes[3],
            bytes[2],
            bytes[1],
            bytes[0]
        );
    }
    output[32] = '\0';
}

static int proc_tcp_contains_ipv6_sinkhole(const struct network6_report *report) {
    FILE *stream = fopen("/proc/net/tcp6", "re");
    if (stream == NULL) return 0;
    char source_address[33];
    char target_address[33];
    char expected_local[38];
    char expected_remote[38];
    proc_ipv6_address(&report->source_address, source_address);
    proc_ipv6_address(&report->target_address, target_address);
    snprintf(expected_local, sizeof(expected_local), "%s:%04X", source_address, report->source_port);
    snprintf(expected_remote, sizeof(expected_remote), "%s:%04X", target_address, report->target_port);
    char line[640];
    int observed = 0;
    while (fgets(line, sizeof(line), stream) != NULL) {
        char local[38] = {0};
        char remote[38] = {0};
        char state[3] = {0};
        unsigned long long inode = 0;
        if (sscanf(
                line,
                " %*d: %37s %37s %2s %*s %*s %*s %*u %*u %llu",
                local,
                remote,
                state,
                &inode
            ) == 4 && strcmp(local, expected_local) == 0 &&
            strcmp(remote, expected_remote) == 0 && strcmp(state, "02") == 0 &&
            inode == report->socket_inode) {
            observed = 1;
            break;
        }
    }
    if (fclose(stream) != 0) return 0;
    return observed;
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
        .programs = {-1, -1, -1, -1, -1, -1, -1, -1},
        .links = {-1, -1, -1, -1, -1, -1, -1, -1},
    };
    struct rlimit unlimited = {.rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY};
    struct observation cgroup = {0};
    struct observation fork_event = {0};
    struct observation exec_event = {0};
    struct observation exit_event = {0};
    struct observation setgroups_event = {0};
    struct observation setgid_event = {0};
    struct observation setuid_event = {0};
    struct observation connect_event = {0};
    struct observation sendto_event = {0};
    pid_t child = -1;
    pid_t reaped_descendants[2] = {-1, -1};
    struct reparent_report reparent_report = {0};
    struct session_report session_report = {0};
    struct credential_report credential_report = {0};
    struct dynamic_report dynamic_report = {0};
    struct network_report network_report = {0};
    struct network6_report network6_report = {0};
    struct udp_report udp_report = {0};
    struct network_report loopback_report = {0};
    uint64_t reparent_timestamp = 0;
    uint64_t session_timestamp = 0;
    uint64_t dynamic_timestamp = 0;
    uint64_t network_timestamp = 0;
    int report_pipe[2] = {-1, -1};
    int dynamic_fanotify = -1;
    int loopback_listener = -1;
    int loopback_peer = -1;
    int ipv4_prepared = 0;
    int ipv6_prepared = 0;
    int loopback_prepared = 0;
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
    int reparent = strcmp(fixture_case, "reparenting") == 0;
    int setsid_escape = strcmp(fixture_case, "setsid_escape") == 0;
    int credential_change = strcmp(fixture_case, "credential_change") == 0;
    int dynamic_library_load = strcmp(fixture_case, "dynamic_library_load") == 0;
    int ipv4_connect = strcmp(fixture_case, "ipv4_connect") == 0;
    int ipv6_connect = strcmp(fixture_case, "ipv6_connect") == 0;
    int udp_send = strcmp(fixture_case, "udp_send") == 0;
    int loopback_connect = strcmp(fixture_case, "loopback_connect") == 0;
    int network_connect = ipv4_connect || ipv6_connect || loopback_connect;
    int network_activity = network_connect || udp_send;
    if (credential_change) {
        const enum observation_key keys[] = {
            OBSERVATION_SETGROUPS, OBSERVATION_SETGID, OBSERVATION_SETUID
        };
        const int syscalls[] = {SYS_setgroups, SYS_setgid, SYS_setuid};
        for (size_t index = 0; index < 3; index++) {
            size_t program_index = index + 4;
            fds.programs[program_index] = load_syscall_program(
                fds.map,
                keys[index],
                syscalls[index]
            );
            if (fds.programs[program_index] < 0) {
                failure_stage = "credential_program_load";
                failure_errno = errno;
                goto cleanup;
            }
            fds.links[program_index] = attach_raw_tracepoint(
                "sys_enter",
                fds.programs[program_index]
            );
            if (fds.links[program_index] < 0) {
                failure_stage = "credential_attach";
                failure_errno = errno;
                goto cleanup;
            }
        }
    }
    if (network_activity) {
        fds.programs[7] = load_syscall_program(
            fds.map,
            udp_send ? OBSERVATION_SENDTO : OBSERVATION_CONNECT,
            udp_send ? SYS_sendto : SYS_connect
        );
        fds.links[7] = fds.programs[7] >= 0
            ? attach_raw_tracepoint("sys_enter", fds.programs[7]) : -1;
        if (fds.programs[7] < 0 || fds.links[7] < 0) {
            failure_stage = udp_send ? "network_sendto_attach" : "network_connect_attach";
            failure_errno = errno;
            goto cleanup;
        }
        if (ipv4_connect || udp_send) {
            if (prepare_ipv4_sinkhole() != 0) {
                failure_stage = "ipv4_sinkhole_prepare";
                failure_errno = errno;
                goto cleanup;
            }
            ipv4_prepared = 1;
        } else if (ipv6_connect) {
            if (prepare_ipv6_sinkhole() != 0) {
                failure_stage = "ipv6_sinkhole_prepare";
                failure_errno = errno;
                goto cleanup;
            }
            ipv6_prepared = 1;
        } else {
            loopback_listener = prepare_loopback_sinkhole();
            if (loopback_listener < 0) {
                failure_stage = "loopback_sinkhole_prepare";
                failure_errno = errno;
                goto cleanup;
            }
            loopback_prepared = 1;
        }
    }
    if ((double_fork || reparent) && prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
        failure_stage = "subreaper_enable";
        failure_errno = errno;
        goto cleanup;
    }
    if (dynamic_library_load) {
        dynamic_fanotify = (int)syscall(
            SYS_fanotify_init,
            FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK,
            O_RDONLY | O_LARGEFILE | O_CLOEXEC
        );
        if (dynamic_fanotify < 0 || syscall(
                SYS_fanotify_mark,
                dynamic_fanotify,
                FAN_MARK_ADD,
                FAN_OPEN,
                AT_FDCWD,
                DYNAMIC_LIBRARY_PATH
            ) != 0) {
            failure_stage = "dynamic_fanotify_mark";
            failure_errno = errno;
            goto cleanup;
        }
    }
    if ((reparent || setsid_escape || credential_change || dynamic_library_load ||
         network_activity) &&
        pipe2(report_pipe, O_CLOEXEC) != 0) {
        failure_stage = "process_report_pipe";
        failure_errno = errno;
        goto cleanup;
    }

    pid_t parent = getpid();
    pid_t parent_session = getsid(0);
    pid_t parent_process_group = getpgrp();
    if (parent_session < 0 || parent_process_group < 0) {
        failure_stage = "parent_session";
        goto cleanup;
    }
    child = fork();
    if (child < 0) {
        failure_stage = "fixture_fork";
        failure_errno = errno;
        goto cleanup;
    }
    if (child == 0) {
        close_if_open(&report_pipe[0]);
        child_fixture(
            fixture,
            fixture_case,
            &fds,
            (reparent || setsid_escape || credential_change || dynamic_library_load ||
             network_activity)
                ? report_pipe[1] : -1
        );
    }
    if (dynamic_library_load) {
        puts("WHOATHERE_SENSOR dynamic_library_load=observed");
        puts("WHOATHERE_SENSOR dynamic_library_target=measured_inert_fixture_library");
    }
    close_if_open(&report_pipe[1]);
    if (setsid_escape) {
        if (read_exact_session_report(report_pipe[0], &session_report) != 0) {
            failure_stage = "session_report";
            failure_errno = errno;
            goto cleanup;
        }
        close_if_open(&report_pipe[0]);
        pid_t observed_session = getsid(child);
        pid_t observed_process_group = getpgid(child);
        if (session_report.process_pid != child ||
            session_report.prior_session_id != parent_session ||
            session_report.prior_process_group_id != parent_process_group ||
            session_report.session_id != child ||
            session_report.process_group_id != child ||
            observed_session != child || observed_process_group != child ||
            observed_session == parent_session ||
            observed_process_group == parent_process_group ||
            !proc_identity_matches(child, parent)) {
            failure_stage = "session_identity";
            goto cleanup;
        }
        session_timestamp = monotonic_ns();
        if (session_timestamp == 0) {
            failure_stage = "session_timestamp";
            goto cleanup;
        }
    }
    if (credential_change) {
        if (read_exact_credential_report(report_pipe[0], &credential_report) != 0) {
            failure_stage = "credential_report";
            failure_errno = errno;
            goto cleanup;
        }
        close_if_open(&report_pipe[0]);
        if (credential_report.process_pid != child ||
            credential_report.uid != FIXTURE_UID ||
            credential_report.effective_uid != FIXTURE_UID ||
            credential_report.gid != FIXTURE_GID ||
            credential_report.effective_gid != FIXTURE_GID ||
            credential_report.supplementary_group_count != 0 ||
            !proc_identity_matches(child, parent) ||
            !proc_has_no_supplementary_groups(child)) {
            failure_stage = "credential_identity";
            goto cleanup;
        }
    }
    if (dynamic_library_load) {
        if (read_exact_dynamic_report(report_pipe[0], &dynamic_report) != 0) {
            failure_stage = "dynamic_report";
            failure_errno = errno;
            goto cleanup;
        }
        close_if_open(&report_pipe[0]);
        if (dynamic_report.process_pid != child ||
            !proc_identity_matches(child, parent) ||
            !proc_has_no_supplementary_groups(child) ||
            !proc_maps_contains_dynamic_library(child) ||
            !dynamic_library_open_observed(dynamic_fanotify, child)) {
            failure_stage = "dynamic_identity";
            goto cleanup;
        }
        dynamic_timestamp = monotonic_ns();
        if (dynamic_timestamp == 0) {
            failure_stage = "dynamic_timestamp";
            goto cleanup;
        }
    }
    if (ipv4_connect) {
        if (read_exact_network_report(report_pipe[0], &network_report) != 0) {
            failure_stage = "ipv4_report";
            failure_errno = errno;
            goto cleanup;
        }
        close_if_open(&report_pipe[0]);
        if (network_report.process_pid != child ||
            !proc_identity_matches(child, parent) ||
            !proc_has_no_supplementary_groups(child) ||
            !proc_tcp_contains_ipv4_sinkhole(&network_report)) {
            failure_stage = "ipv4_live_socket";
            goto cleanup;
        }
        network_timestamp = monotonic_ns();
        if (network_timestamp == 0) {
            failure_stage = "ipv4_timestamp";
            goto cleanup;
        }
    }
    if (ipv6_connect) {
        if (read_exact_network6_report(report_pipe[0], &network6_report) != 0) {
            failure_stage = "ipv6_report";
            failure_errno = errno;
            goto cleanup;
        }
        close_if_open(&report_pipe[0]);
        if (network6_report.process_pid != child ||
            !proc_identity_matches(child, parent) ||
            !proc_has_no_supplementary_groups(child) ||
            !proc_tcp_contains_ipv6_sinkhole(&network6_report)) {
            failure_stage = "ipv6_live_socket";
            goto cleanup;
        }
        network_timestamp = monotonic_ns();
        if (network_timestamp == 0) {
            failure_stage = "ipv6_timestamp";
            goto cleanup;
        }
    }
    if (loopback_connect) {
        if (read_exact_loopback_report(report_pipe[0], &loopback_report) != 0) {
            failure_stage = "loopback_report";
            failure_errno = errno;
            goto cleanup;
        }
        close_if_open(&report_pipe[0]);
        loopback_peer = accept_exact_loopback_peer(loopback_listener, &loopback_report);
        if (loopback_report.process_pid != child || loopback_peer < 0 ||
            !proc_identity_matches(child, parent) ||
            !proc_has_no_supplementary_groups(child) ||
            !proc_tcp_contains_loopback_sinkhole(&loopback_report)) {
            failure_stage = "loopback_live_socket";
            goto cleanup;
        }
        network_timestamp = monotonic_ns();
        if (network_timestamp == 0) {
            failure_stage = "loopback_timestamp";
            goto cleanup;
        }
    }
    if (udp_send) {
        if (read_exact_udp_report(report_pipe[0], &udp_report) != 0) {
            failure_stage = "udp_report";
            failure_errno = errno;
            goto cleanup;
        }
        close_if_open(&report_pipe[0]);
        if (udp_report.process_pid != child ||
            !proc_identity_matches(child, parent) ||
            !proc_has_no_supplementary_groups(child) ||
            !proc_udp_contains_ipv4_sinkhole(&udp_report)) {
            failure_stage = "udp_live_socket";
            goto cleanup;
        }
        network_timestamp = monotonic_ns();
        if (network_timestamp == 0) {
            failure_stage = "udp_timestamp";
            goto cleanup;
        }
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
    if (reparent) {
        if (read_exact_reparent_report(report_pipe[0], &reparent_report) != 0) {
            failure_stage = "reparent_report";
            failure_errno = errno;
            goto cleanup;
        }
        close_if_open(&report_pipe[0]);
        if (!proc_identity_matches(reparent_report.child_pid, parent)) {
            failure_stage = "reparent_identity";
            goto cleanup;
        }
        reparent_timestamp = monotonic_ns();
        int descendant_status = 0;
        reaped_descendants[0] = waitpid(reparent_report.child_pid, &descendant_status, 0);
        if (reaped_descendants[0] != reparent_report.child_pid ||
            !WIFEXITED(descendant_status) || WEXITSTATUS(descendant_status) != 0) {
            failure_stage = "reparent_reap";
            failure_errno = errno;
            failure_detail = WIFEXITED(descendant_status) ? WEXITSTATUS(descendant_status) : 255;
            goto cleanup;
        }
        errno = 0;
        if (waitpid(-1, NULL, WNOHANG) != -1 || errno != ECHILD) {
            failure_stage = "reparent_descendant_count";
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
    if (credential_change &&
        (lookup_observation(fds.map, OBSERVATION_SETGROUPS, &setgroups_event) != 0 ||
         lookup_observation(fds.map, OBSERVATION_SETGID, &setgid_event) != 0 ||
         lookup_observation(fds.map, OBSERVATION_SETUID, &setuid_event) != 0)) {
        failure_stage = "credential_observation_lookup";
        failure_errno = errno;
        goto cleanup;
    }
    if (network_connect &&
        lookup_observation(fds.map, OBSERVATION_CONNECT, &connect_event) != 0) {
        failure_stage = "network_observation_lookup";
        failure_errno = errno;
        goto cleanup;
    }
    if (udp_send &&
        lookup_observation(fds.map, OBSERVATION_SENDTO, &sendto_event) != 0) {
        failure_stage = "network_sendto_observation_lookup";
        failure_errno = errno;
        goto cleanup;
    }
    if ((!double_fork && !reparent && !setsid_escape && !credential_change &&
         !dynamic_library_load && !network_activity &&
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
          fork_event.timestamp_ns >= exit_event.timestamp_ns)) ||
        (reparent &&
         (fork_event.count != 2 || exec_event.count != 1 || exit_event.count != 2 ||
          (pid_t)(exec_event.pid_tgid >> 32) != child ||
          (pid_t)(fork_event.pid_tgid >> 32) != child ||
          (pid_t)(exit_event.pid_tgid >> 32) != reparent_report.child_pid ||
          reparent_timestamp == 0 || exec_event.timestamp_ns >= fork_event.timestamp_ns ||
          fork_event.timestamp_ns >= reparent_timestamp ||
          reparent_timestamp >= exit_event.timestamp_ns)) ||
        (setsid_escape &&
         (!observed_pid(&fork_event, parent) || !observed_pid(&exec_event, child) ||
          !observed_pid(&exit_event, child) || session_timestamp == 0 ||
          fork_event.timestamp_ns >= exec_event.timestamp_ns ||
          exec_event.timestamp_ns >= session_timestamp ||
          session_timestamp >= exit_event.timestamp_ns)) ||
        (credential_change &&
         (!observed_pid(&fork_event, parent) || !observed_pid(&setgroups_event, child) ||
          !observed_pid(&setgid_event, child) || !observed_pid(&setuid_event, child) ||
          !observed_pid(&exec_event, child) || !observed_pid(&exit_event, child) ||
          fork_event.timestamp_ns >= setgroups_event.timestamp_ns ||
          setgroups_event.timestamp_ns >= setgid_event.timestamp_ns ||
          setgid_event.timestamp_ns >= setuid_event.timestamp_ns ||
          setuid_event.timestamp_ns >= exec_event.timestamp_ns ||
          exec_event.timestamp_ns >= exit_event.timestamp_ns)) ||
        (dynamic_library_load &&
         (!observed_pid(&fork_event, parent) || exec_event.count != 2 ||
          (pid_t)(exec_event.pid_tgid >> 32) != child ||
          !observed_pid(&exit_event, child) || dynamic_timestamp == 0 ||
          fork_event.timestamp_ns >= exec_event.timestamp_ns ||
          exec_event.timestamp_ns >= dynamic_timestamp ||
          dynamic_timestamp >= exit_event.timestamp_ns)) ||
        (network_connect &&
         (!observed_pid(&fork_event, parent) || !observed_pid(&exec_event, child) ||
          !observed_pid(&connect_event, child) || !observed_pid(&exit_event, child) ||
          network_timestamp == 0 || fork_event.timestamp_ns >= exec_event.timestamp_ns ||
          exec_event.timestamp_ns >= connect_event.timestamp_ns ||
          connect_event.timestamp_ns >= network_timestamp ||
          network_timestamp >= exit_event.timestamp_ns)) ||
        (udp_send &&
         (!observed_pid(&fork_event, parent) || !observed_pid(&exec_event, child) ||
          !observed_pid(&sendto_event, child) || !observed_pid(&exit_event, child) ||
          network_timestamp == 0 || fork_event.timestamp_ns >= exec_event.timestamp_ns ||
          exec_event.timestamp_ns >= sendto_event.timestamp_ns ||
          sendto_event.timestamp_ns >= network_timestamp ||
          network_timestamp >= exit_event.timestamp_ns))) {
        if (reparent) {
            printf(
                "WHOATHERE_SENSOR_REPARENT_OBSERVATION_DIAGNOSTIC "
                "fork_count=%" PRIu64 " exec_count=%" PRIu64 " exit_count=%" PRIu64
                " launcher=%d reported_child=%d fork_actor=%" PRIu64
                " exec_actor=%" PRIu64 " exit_actor=%" PRIu64
                " exec_ns=%" PRIu64 " fork_ns=%" PRIu64 " reparent_ns=%" PRIu64
                " exit_ns=%" PRIu64 "\n",
                fork_event.count,
                exec_event.count,
                exit_event.count,
                child,
                reparent_report.child_pid,
                fork_event.pid_tgid >> 32,
                exec_event.pid_tgid >> 32,
                exit_event.pid_tgid >> 32,
                exec_event.timestamp_ns,
                fork_event.timestamp_ns,
                reparent_timestamp,
                exit_event.timestamp_ns
            );
        }
        if (setsid_escape) {
            printf(
                "WHOATHERE_SENSOR_SESSION_OBSERVATION_DIAGNOSTIC "
                "fork_count=%" PRIu64 " exec_count=%" PRIu64 " exit_count=%" PRIu64
                " child=%d fork_actor=%" PRIu64 " exec_actor=%" PRIu64
                " exit_actor=%" PRIu64 " parent_sid=%d parent_pgid=%d"
                " child_sid=%d child_pgid=%d fork_ns=%" PRIu64 " exec_ns=%" PRIu64
                " session_ns=%" PRIu64 " exit_ns=%" PRIu64 "\n",
                fork_event.count,
                exec_event.count,
                exit_event.count,
                child,
                fork_event.pid_tgid >> 32,
                exec_event.pid_tgid >> 32,
                exit_event.pid_tgid >> 32,
                parent_session,
                parent_process_group,
                session_report.session_id,
                session_report.process_group_id,
                fork_event.timestamp_ns,
                exec_event.timestamp_ns,
                session_timestamp,
                exit_event.timestamp_ns
            );
        }
        if (credential_change) {
            printf(
                "WHOATHERE_SENSOR_CREDENTIAL_OBSERVATION_DIAGNOSTIC "
                "fork_count=%" PRIu64 " setgroups_count=%" PRIu64
                " setgid_count=%" PRIu64 " setuid_count=%" PRIu64
                " exec_count=%" PRIu64 " exit_count=%" PRIu64
                " child=%d fork_actor=%" PRIu64 " setgroups_actor=%" PRIu64
                " setgid_actor=%" PRIu64 " setuid_actor=%" PRIu64
                " exec_actor=%" PRIu64 " exit_actor=%" PRIu64 "\n",
                fork_event.count,
                setgroups_event.count,
                setgid_event.count,
                setuid_event.count,
                exec_event.count,
                exit_event.count,
                child,
                fork_event.pid_tgid >> 32,
                setgroups_event.pid_tgid >> 32,
                setgid_event.pid_tgid >> 32,
                setuid_event.pid_tgid >> 32,
                exec_event.pid_tgid >> 32,
                exit_event.pid_tgid >> 32
            );
        }
        if (dynamic_library_load) {
            printf(
                "WHOATHERE_SENSOR_DYNAMIC_LIBRARY_DIAGNOSTIC "
                "fork_count=%" PRIu64 " exec_count=%" PRIu64 " exit_count=%" PRIu64
                " child=%d exec_actor=%" PRIu64 " fork_ns=%" PRIu64
                " exec_ns=%" PRIu64 " dynamic_ns=%" PRIu64 " exit_ns=%" PRIu64 "\n",
                fork_event.count,
                exec_event.count,
                exit_event.count,
                child,
                exec_event.pid_tgid >> 32,
                fork_event.timestamp_ns,
                exec_event.timestamp_ns,
                dynamic_timestamp,
                exit_event.timestamp_ns
            );
        }
        if (network_connect) {
            printf(
                "WHOATHERE_SENSOR_NETWORK_OBSERVATION_DIAGNOSTIC "
                "fork_count=%" PRIu64 " exec_count=%" PRIu64
                " connect_count=%" PRIu64 " exit_count=%" PRIu64
                " child=%d source_port=%u fork_ns=%" PRIu64
                " exec_ns=%" PRIu64 " connect_ns=%" PRIu64
                " live_socket_ns=%" PRIu64 " exit_ns=%" PRIu64 "\n",
                fork_event.count,
                exec_event.count,
                connect_event.count,
                exit_event.count,
                child,
                ipv4_connect ? network_report.source_port :
                    (ipv6_connect ? network6_report.source_port : loopback_report.source_port),
                fork_event.timestamp_ns,
                exec_event.timestamp_ns,
                connect_event.timestamp_ns,
                network_timestamp,
                exit_event.timestamp_ns
            );
        }
        if (udp_send) {
            printf(
                "WHOATHERE_SENSOR_UDP_OBSERVATION_DIAGNOSTIC "
                "fork_count=%" PRIu64 " exec_count=%" PRIu64
                " sendto_count=%" PRIu64 " exit_count=%" PRIu64
                " child=%d source_port=%u fork_ns=%" PRIu64
                " exec_ns=%" PRIu64 " sendto_ns=%" PRIu64
                " live_socket_ns=%" PRIu64 " exit_ns=%" PRIu64 "\n",
                fork_event.count,
                exec_event.count,
                sendto_event.count,
                exit_event.count,
                child,
                udp_report.source_port,
                fork_event.timestamp_ns,
                exec_event.timestamp_ns,
                sendto_event.timestamp_ns,
                network_timestamp,
                exit_event.timestamp_ns
            );
        }
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
    if (reparent) {
        puts("WHOATHERE_SENSOR process_reparenting=observed");
        puts("WHOATHERE_SENSOR process_subreaper_teardown=observed");
    }
    if (setsid_escape) {
        puts("WHOATHERE_SENSOR process_setsid=observed");
        puts("WHOATHERE_SENSOR process_session_escape=observed");
    }
    if (credential_change) {
        puts("WHOATHERE_SENSOR process_credential_change=observed");
        puts(
            "WHOATHERE_SENSOR process_credentials="
            "uid_65534_gid_65534_no_supplementary_groups"
        );
    }
    if (ipv4_connect) {
        puts("WHOATHERE_SENSOR network_ipv4_connect=observed");
        puts("WHOATHERE_SENSOR network_socket_state=syn_sent");
        puts("WHOATHERE_SENSOR network_target=documentation_sinkhole_192_0_2_1_443");
    }
    if (ipv6_connect) {
        puts("WHOATHERE_SENSOR network_ipv6_connect=observed");
        puts("WHOATHERE_SENSOR network_socket_state=syn_sent");
        puts("WHOATHERE_SENSOR network_target=documentation_sinkhole_2001_db8_1_443");
    }
    if (udp_send) {
        puts("WHOATHERE_SENSOR network_udp_send=observed");
        puts("WHOATHERE_SENSOR network_socket_state=unconnected_bound");
        puts("WHOATHERE_SENSOR network_payload=whoathere_udp_v1_16_bytes");
        puts("WHOATHERE_SENSOR network_target=documentation_sinkhole_192_0_2_1_443");
    }
    if (loopback_connect) {
        puts("WHOATHERE_SENSOR network_loopback_connect=observed");
        puts("WHOATHERE_SENSOR network_socket_state=established");
        puts("WHOATHERE_SENSOR network_loopback_peer=accepted");
        puts("WHOATHERE_SENSOR network_target=guest_loopback_sinkhole_127_0_0_1_40552");
    }
    puts("WHOATHERE_SENSOR_PROCESS_PROBE_OK");
    if (network_activity) {
        const char *network_family = ipv6_connect ? "ipv6" : "ipv4";
        const char *network_source = loopback_connect ? LOOPBACK_ADDRESS :
            (ipv6_connect ? NETWORK6_SOURCE_ADDRESS : NETWORK_SOURCE_ADDRESS);
        const char *network_target = loopback_connect ? LOOPBACK_ADDRESS :
            (ipv6_connect ? NETWORK6_TARGET_ADDRESS : NETWORK_TARGET_ADDRESS);
        const char *network_event_kind = udp_send ? "sendto" : "connect";
        const char *network_action = udp_send ? "udp_send" : "tcp_connect";
        const char *network_protocol = udp_send ? "udp" : "tcp";
        const char *network_socket_state = udp_send ? "unconnected_bound" :
            (loopback_connect ? "established" : "syn_sent");
        uint16_t network_source_port = udp_send ? udp_report.source_port :
            (ipv4_connect ? network_report.source_port :
                (ipv6_connect ? network6_report.source_port : loopback_report.source_port));
        uint16_t network_target_port = loopback_connect
            ? LOOPBACK_TARGET_PORT : NETWORK_TARGET_PORT;
        uint64_t network_event_timestamp = udp_send
            ? sendto_event.timestamp_ns : connect_event.timestamp_ns;
        printf(
            "WHOATHERE_GUEST_NETWORK_EVIDENCE "
            "{\"descendant_teardown_complete\":true,\"dropped_event_count\":\"0\","
            "\"event_count\":\"4\",\"event_sequence_end\":\"4\","
            "\"event_sequence_start\":\"1\",\"events\":["
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"fork\",\"sequence\":\"1\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"exec\",\"sequence\":\"2\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"%s\",\"sequence\":\"3\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"exit\",\"sequence\":\"4\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"}],"
            "\"evidence_truncated\":false,\"fixture_case\":\"%s\","
            "\"heartbeat_count\":\"2\",\"network_action\":\"%s\","
            "\"network_family\":\"%s\",\"network_protocol\":\"%s\","
            "\"network_socket_state\":\"%s\","
            "\"network_source\":\"%s\",\"network_source_port\":\"%u\","
            "\"network_target\":\"%s\",\"network_target_port\":\"%u\","
            "\"package_gid\":\"65534\",\"package_uid\":\"65534\","
            "\"reaped_process_count\":\"1\","
            "\"schema_version\":\"whoathere.linux_vz_network_evidence_payload.v1\","
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
            network_event_kind,
            (uint64_t)child,
            network_event_timestamp,
            (uint64_t)child,
            cgroup.count,
            (uint64_t)child,
            exit_event.timestamp_ns,
            fixture_case,
            network_action,
            network_family,
            network_protocol,
            network_socket_state,
            network_source,
            network_source_port,
            network_target,
            network_target_port
        );
        result = 0;
        goto cleanup;
    }
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
    if (dynamic_library_load) {
        printf(
            "WHOATHERE_GUEST_PROCESS_EVIDENCE "
            "{\"descendant_teardown_complete\":true,\"dropped_event_count\":\"0\","
            "\"dynamic_library_load_count\":\"1\","
            "\"dynamic_library_target\":\"measured_inert_fixture_library\","
            "\"event_count\":\"4\",\"event_sequence_end\":\"4\","
            "\"event_sequence_start\":\"1\",\"events\":["
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"fork\",\"sequence\":\"1\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"exec\",\"sequence\":\"2\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"dynamic_library_load\",\"sequence\":\"3\","
            "\"subject_pid\":\"%" PRIu64 "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"exit\",\"sequence\":\"4\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"}],"
            "\"evidence_truncated\":false,\"exec_count\":\"2\",\"exit_count\":\"1\","
            "\"fixture_case\":\"dynamic_library_load\",\"fork_count\":\"1\","
            "\"heartbeat_count\":\"2\",\"package_gid\":\"65534\","
            "\"package_uid\":\"65534\",\"reaped_process_count\":\"1\","
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
            dynamic_timestamp,
            (uint64_t)child,
            cgroup.count,
            (uint64_t)child,
            exit_event.timestamp_ns
        );
        result = 0;
        goto cleanup;
    }
    if (reparent) {
        printf(
            "WHOATHERE_GUEST_PROCESS_EVIDENCE "
            "{\"descendant_teardown_complete\":true,\"dropped_event_count\":\"0\","
            "\"event_count\":\"4\",\"event_sequence_end\":\"4\","
            "\"event_sequence_start\":\"1\",\"events\":["
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"exec\",\"sequence\":\"1\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"fork\",\"sequence\":\"2\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"reparent\",\"sequence\":\"3\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"exit\",\"sequence\":\"4\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"}],"
            "\"evidence_truncated\":false,\"exec_count\":\"1\",\"exit_count\":\"2\","
            "\"fixture_case\":\"reparenting\",\"fork_count\":\"2\","
            "\"heartbeat_count\":\"2\",\"package_gid\":\"65534\","
            "\"package_uid\":\"65534\",\"reaped_process_count\":\"2\","
            "\"reparent_target\":\"protected_subreaper\","
            "\"reparented_process_count\":\"1\","
            "\"schema_version\":\"whoathere.linux_vz_process_evidence_payload.v1\","
            "\"sensor_healthy\":true}\n",
            (uint64_t)child,
            cgroup.count,
            (uint64_t)child,
            exec_event.timestamp_ns,
            fork_event.pid_tgid >> 32,
            cgroup.count,
            (uint64_t)reparent_report.child_pid,
            fork_event.timestamp_ns,
            (uint64_t)parent,
            cgroup.count,
            (uint64_t)reparent_report.child_pid,
            reparent_timestamp,
            exit_event.pid_tgid >> 32,
            cgroup.count,
            exit_event.pid_tgid >> 32,
            exit_event.timestamp_ns
        );
        result = 0;
        goto cleanup;
    }
    if (setsid_escape) {
        printf(
            "WHOATHERE_GUEST_PROCESS_EVIDENCE "
            "{\"descendant_teardown_complete\":true,\"dropped_event_count\":\"0\","
            "\"event_count\":\"4\",\"event_sequence_end\":\"4\","
            "\"event_sequence_start\":\"1\",\"events\":["
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"fork\",\"sequence\":\"1\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"exec\",\"sequence\":\"2\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"setsid\",\"sequence\":\"3\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"exit\",\"sequence\":\"4\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"}],"
            "\"evidence_truncated\":false,\"exec_count\":\"1\",\"exit_count\":\"1\","
            "\"fixture_case\":\"setsid_escape\",\"fork_count\":\"1\","
            "\"heartbeat_count\":\"2\",\"package_gid\":\"65534\","
            "\"package_uid\":\"65534\",\"reaped_process_count\":\"1\","
            "\"schema_version\":\"whoathere.linux_vz_process_evidence_payload.v1\","
            "\"sensor_healthy\":true,\"session_escape_count\":\"1\","
            "\"session_target\":\"new_session_leader\"}\n",
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
            session_timestamp,
            (uint64_t)child,
            cgroup.count,
            (uint64_t)child,
            exit_event.timestamp_ns
        );
        result = 0;
        goto cleanup;
    }
    if (credential_change) {
        printf(
            "WHOATHERE_GUEST_PROCESS_EVIDENCE "
            "{\"credential_change_count\":\"3\","
            "\"credential_target\":\"uid_65534_gid_65534_no_supplementary_groups\","
            "\"descendant_teardown_complete\":true,\"dropped_event_count\":\"0\","
            "\"event_count\":\"6\",\"event_sequence_end\":\"6\","
            "\"event_sequence_start\":\"1\",\"events\":["
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"fork\",\"sequence\":\"1\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"setgroups\",\"sequence\":\"2\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"setgid\",\"sequence\":\"3\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"setuid\",\"sequence\":\"4\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"exec\",\"sequence\":\"5\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"},"
            "{\"actor_pid\":\"%" PRIu64 "\",\"cgroup_id\":\"%" PRIu64
            "\",\"kind\":\"exit\",\"sequence\":\"6\",\"subject_pid\":\"%" PRIu64
            "\",\"timestamp_ns\":\"%" PRIu64 "\"}],"
            "\"evidence_truncated\":false,\"exec_count\":\"1\",\"exit_count\":\"1\","
            "\"fixture_case\":\"credential_change\",\"fork_count\":\"1\","
            "\"heartbeat_count\":\"2\",\"package_gid\":\"65534\","
            "\"package_uid\":\"65534\",\"reaped_process_count\":\"1\","
            "\"schema_version\":\"whoathere.linux_vz_process_evidence_payload.v1\","
            "\"sensor_healthy\":true}\n",
            (uint64_t)parent,
            cgroup.count,
            (uint64_t)child,
            fork_event.timestamp_ns,
            (uint64_t)child,
            cgroup.count,
            (uint64_t)child,
            setgroups_event.timestamp_ns,
            (uint64_t)child,
            cgroup.count,
            (uint64_t)child,
            setgid_event.timestamp_ns,
            (uint64_t)child,
            cgroup.count,
            (uint64_t)child,
            setuid_event.timestamp_ns,
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
    if (ipv4_prepared) cleanup_ipv4_sinkhole();
    if (ipv6_prepared) cleanup_ipv4_sinkhole();
    if (loopback_prepared) cleanup_loopback_sinkhole();
    if (dynamic_fanotify >= 0) close(dynamic_fanotify);
    if (loopback_peer >= 0) close(loopback_peer);
    if (loopback_listener >= 0) close(loopback_listener);
    close_if_open(&report_pipe[0]);
    close_if_open(&report_pipe[1]);
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
        strcmp(arguments[2], "double_fork_daemonization") == 0 ||
        strcmp(arguments[2], "reparenting") == 0 ||
        strcmp(arguments[2], "setsid_escape") == 0 ||
        strcmp(arguments[2], "credential_change") == 0 ||
        strcmp(arguments[2], "dynamic_library_load") == 0 ||
        strcmp(arguments[2], "ipv4_connect") == 0 ||
        strcmp(arguments[2], "ipv6_connect") == 0 ||
        strcmp(arguments[2], "udp_send") == 0 ||
        strcmp(arguments[2], "loopback_connect") == 0) {
        return run_process_probe(arguments[1], arguments[2]);
    }
    if (strcmp(arguments[2], "protected_open_read_write_rename_delete") == 0 ||
        strcmp(arguments[2], "mmap_access") == 0) {
        return run_file_probe(arguments[1], arguments[2]);
    }
    return 64;
}
