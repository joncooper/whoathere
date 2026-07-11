#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/fanotify.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int probe_fanotify(void) {
    int descriptor = (int)syscall(
        SYS_fanotify_init,
        FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK,
        O_RDONLY | O_CLOEXEC
    );
    if (descriptor >= 0) {
        close(descriptor);
        puts("WHOATHERE_CAPABILITY fanotify_init=available");
        return 0;
    }
    if (errno == ENOSYS) {
        puts("WHOATHERE_CAPABILITY fanotify_init=unsupported");
    } else if (errno == EPERM || errno == EACCES) {
        puts("WHOATHERE_CAPABILITY fanotify_init=permission_denied");
    } else {
        printf("WHOATHERE_CAPABILITY fanotify_init=error_%d\n", errno);
    }
    return 1;
}

static int probe_bpf_program_load(void) {
    const struct bpf_insn program[] = {
        {
            .code = BPF_ALU64 | BPF_MOV | BPF_K,
            .dst_reg = BPF_REG_0,
            .src_reg = 0,
            .off = 0,
            .imm = 0,
        },
        {
            .code = BPF_JMP | BPF_EXIT,
            .dst_reg = 0,
            .src_reg = 0,
            .off = 0,
            .imm = 0,
        },
    };
    static const char license[] = "GPL";
    char verifier_log[4096] = {0};
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attributes.insn_cnt = (uint32_t)(sizeof(program) / sizeof(program[0]));
    attributes.insns = (uint64_t)(uintptr_t)program;
    attributes.license = (uint64_t)(uintptr_t)license;
    attributes.log_buf = (uint64_t)(uintptr_t)verifier_log;
    attributes.log_size = sizeof(verifier_log);
    attributes.log_level = 1;

    int descriptor = (int)syscall(SYS_bpf, BPF_PROG_LOAD, &attributes, sizeof(attributes));
    if (descriptor >= 0) {
        close(descriptor);
        puts("WHOATHERE_CAPABILITY bpf_program_load=available");
        return 0;
    }
    if (errno == ENOSYS) {
        puts("WHOATHERE_CAPABILITY bpf_program_load=unsupported");
    } else if (errno == EPERM || errno == EACCES) {
        puts("WHOATHERE_CAPABILITY bpf_program_load=permission_denied");
    } else {
        printf("WHOATHERE_CAPABILITY bpf_program_load=error_%d\n", errno);
    }
    return 1;
}

int main(void) {
    int failed = 0;
    failed |= probe_fanotify();
    failed |= probe_bpf_program_load();
    return failed == 0 ? 0 : 1;
}
