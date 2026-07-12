#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define FIXTURE_UID 65534
#define FIXTURE_GID 65534
#define FIXTURE_CGROUP "/sys/fs/cgroup/whoathere-process-fixture"
#define FIXTURE_CGROUP_PROCS FIXTURE_CGROUP "/cgroup.procs"
#define ROOT_CGROUP_PROCS "/sys/fs/cgroup/cgroup.procs"

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
    OBSERVATION_COUNT = 4,
};

struct observation {
    uint64_t count;
    uint64_t pid_tgid;
};

struct sensor_fds {
    int map;
    int programs[4];
    int links[4];
};

static void close_if_open(int *descriptor) {
    if (*descriptor >= 0) {
        close(*descriptor);
        *descriptor = -1;
    }
}

static void close_sensor_fds(struct sensor_fds *fds) {
    for (size_t index = 0; index < 4; index++) {
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
    return bpf_call(BPF_PROG_LOAD, &attributes);
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
        JUMP_IMM(BPF_JEQ, BPF_REG_0, 0, 15),
        LOAD_REG(BPF_DW, BPF_REG_1, BPF_REG_0, 0),
        JUMP_REG(BPF_JNE, BPF_REG_8, BPF_REG_1, 13),
        STORE_IMM(BPF_W, BPF_REG_10, -4, key),
        LOAD_MAP_FD(BPF_REG_1, map),
        MOV64_REG(BPF_REG_2, BPF_REG_10),
        ADD64_IMM(BPF_REG_2, -4),
        CALL_HELPER(BPF_FUNC_map_lookup_elem),
        JUMP_IMM(BPF_JEQ, BPF_REG_0, 0, 6),
        MOV64_REG(BPF_REG_7, BPF_REG_0),
        MOV64_IMM(BPF_REG_1, 1),
        INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_7, BPF_REG_1, 0, 0),
        CALL_HELPER(BPF_FUNC_get_current_pid_tgid),
        STORE_REG(BPF_DW, BPF_REG_7, BPF_REG_0, 8),
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

static int child_fixture(const char *fixture, struct sensor_fds *fds) {
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
    execl(fixture, fixture, (char *)NULL);
    _exit(74);
}

static int observed_pid(const struct observation *value, pid_t expected) {
    return value->count >= 1 && (pid_t)(value->pid_tgid >> 32) == expected;
}

static int run_probe(const char *fixture) {
    static const char *tracepoints[] = {
        "sys_enter",
        "sched_process_fork",
        "sched_process_exec",
        "sched_process_exit",
    };
    struct sensor_fds fds = {.map = -1, .programs = {-1, -1, -1, -1}, .links = {-1, -1, -1, -1}};
    struct rlimit unlimited = {.rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY};
    struct observation cgroup = {0};
    struct observation fork_event = {0};
    struct observation exec_event = {0};
    struct observation exit_event = {0};
    pid_t child = -1;
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

    pid_t parent = getpid();
    child = fork();
    if (child < 0) {
        failure_stage = "fixture_fork";
        failure_errno = errno;
        goto cleanup;
    }
    if (child == 0) {
        child_fixture(fixture, &fds);
    }
    if (waitpid(child, &child_status, 0) != child || !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) != 0) {
        failure_stage = "fixture_exit";
        failure_errno = errno;
        failure_detail = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 255;
        goto cleanup;
    }
    if (lookup_observation(fds.map, OBSERVATION_FORK, &fork_event) != 0 ||
        lookup_observation(fds.map, OBSERVATION_EXEC, &exec_event) != 0 ||
        lookup_observation(fds.map, OBSERVATION_EXIT, &exit_event) != 0 ||
        !observed_pid(&fork_event, parent) || !observed_pid(&exec_event, child) ||
        !observed_pid(&exit_event, child)) {
        failure_stage = "observation_match";
        failure_errno = errno;
        goto cleanup;
    }

    puts("WHOATHERE_SENSOR process_cgroup_filter=observed");
    puts("WHOATHERE_SENSOR process_fork=observed");
    puts("WHOATHERE_SENSOR process_exec=observed");
    puts("WHOATHERE_SENSOR process_exit=observed");
    puts("WHOATHERE_SENSOR unprivileged_fixture=uid_65534_gid_65534");
    puts("WHOATHERE_SENSOR protected_sensor_read=denied");
    puts("WHOATHERE_SENSOR protected_sensor_write=denied");
    puts("WHOATHERE_SENSOR_PROCESS_PROBE_OK");
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
    if (argument_count != 2 || arguments[1][0] != '/') {
        return 64;
    }
    return run_probe(arguments[1]);
}
