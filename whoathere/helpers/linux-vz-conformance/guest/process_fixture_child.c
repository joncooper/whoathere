#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char *sensor_path = "/whoathere/process-sensor-probe";
static const char *fixture_root = "/run/whoathere-file-fixture";
static const char *dynamic_driver_path = "/whoathere/dynamic-library-driver";
static const char *dynamic_library_path = "/whoathere/dynamic-fixture-library.so";
#define REPARENT_REPORT_FD 3
#define REPARENT_REPORT_MAGIC 0x57545052U
#define SESSION_REPORT_MAGIC 0x57545353U
#define CREDENTIAL_REPORT_MAGIC 0x57544352U
#define NETWORK_REPORT_MAGIC 0x57544e34U
#define NETWORK6_REPORT_MAGIC 0x57544e36U
#define UDP_REPORT_MAGIC 0x57545534U
#define UDP_PAYLOAD "WHOATHERE_UDP_V1"
#define LOOPBACK_REPORT_MAGIC 0x57544c34U
#define LOOPBACK_TARGET_PORT 40552
#define PRIVATE_REPORT_MAGIC 0x57545034U
#define LINK_LOCAL_REPORT_MAGIC 0x57544b34U
#define METADATA_REPORT_MAGIC 0x57544d34U
#define PUBLIC_REPORT_MAGIC 0x57544234U
#define DNS_PLAINTEXT_REPORT_MAGIC 0x57544434U
#define DNS_MALFORMED_REPORT_MAGIC 0x57545834U
#define ENCRYPTED_DNS_REPORT_MAGIC 0x57544534U
#define HOST_FRAME_REPORT_MAGIC 0x57544846U
#define HOST_FRAME_TRIGGER_COUNT 512U
#define HOST_FRAME_PAYLOAD_LENGTH 16U
#define TERM_RESISTANCE_REPORT_MAGIC 0x57545452U
#define VM_STOP_REPORT_MAGIC 0x57545653U
#define GUEST_SENSOR_DEATH_REPORT_MAGIC 0x57544744U
#define PACKAGE_ISOLATION_REPORT_MAGIC 0x57545049U
#define PROTECTED_ASSET_COUNT 7U
#define BACKGROUND_LISTENER_REPORT_MAGIC 0x57544c53U
#define BACKGROUND_LISTENER_PORT 40552U
static const unsigned char dns_plaintext_query[] = {
    0x57, 0x54, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x09, 'w', 'h', 'o', 'a', 't', 'h', 'e', 'r', 'e',
    0x07, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0x00, 0x00, 0x01, 0x00, 0x01,
};
static const unsigned char dns_malformed_query[] = {
    0x57, 0x55, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

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

struct host_frame_report {
    uint32_t magic;
    int32_t process_pid;
    uint32_t source_address;
    uint32_t target_address;
    uint16_t source_port;
    uint16_t target_port;
    uint32_t payload_length;
    uint32_t transmitted_count;
};

struct term_resistance_report {
    uint32_t magic;
    int32_t process_pid;
};

struct vm_stop_report {
    uint32_t magic;
    int32_t process_pid;
};

struct guest_sensor_death_report {
    uint32_t magic;
    int32_t process_pid;
};

struct package_isolation_report {
    uint32_t magic;
    int32_t process_pid;
    uint32_t asset_count;
    uint32_t read_denied_mask;
    uint32_t write_denied_mask;
};

struct background_listener_report {
    uint32_t magic;
    int32_t process_pid;
    uint64_t socket_inode;
    uint32_t address;
    uint16_t port;
};

static int protected_sensor_denied(void) {
    int descriptor = open(sensor_path, O_WRONLY | O_CLOEXEC);
    if (descriptor >= 0) {
        close(descriptor);
        return 76;
    }
    if (errno != EACCES && errno != EPERM && errno != EROFS) {
        return 77;
    }
    descriptor = open(sensor_path, O_RDONLY | O_CLOEXEC);
    if (descriptor >= 0) {
        close(descriptor);
        return 78;
    }
    return errno == EACCES || errno == EPERM ? 0 : 79;
}

static int protected_asset_access_denied(const char *path, int flags) {
    errno = 0;
    int descriptor = open(path, flags | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor >= 0) {
        close(descriptor);
        return 0;
    }
    return errno == EACCES || errno == EPERM;
}

static int all_protected_assets_denied(void) {
    static const char *const paths[PROTECTED_ASSET_COUNT] = {
        "/whoathere/capability-probe",
        "/whoathere/guest-ed25519.seed",
        "/whoathere/guest-signer",
        "/whoathere/process-sensor-probe",
        "/whoathere/modules/vsock.ko",
        "/whoathere/modules/vmw_vsock_virtio_transport_common.ko",
        "/whoathere/modules/vmw_vsock_virtio_transport.ko",
    };
    uint32_t read_denied_mask = 0;
    uint32_t write_denied_mask = 0;
    for (uint32_t index = 0; index < PROTECTED_ASSET_COUNT; index++) {
        if (protected_asset_access_denied(paths[index], O_RDONLY)) {
            read_denied_mask |= UINT32_C(1) << index;
        }
        if (protected_asset_access_denied(paths[index], O_WRONLY)) {
            write_denied_mask |= UINT32_C(1) << index;
        }
    }
    const struct package_isolation_report report = {
        .magic = PACKAGE_ISOLATION_REPORT_MAGIC,
        .process_pid = getpid(),
        .asset_count = PROTECTED_ASSET_COUNT,
        .read_denied_mask = read_denied_mask,
        .write_denied_mask = write_denied_mask,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) return 179;
    errno = saved_errno;
    return written == (ssize_t)sizeof(report) ? 0 : 180;
}

static int write_exact(const char *path, const char *value) {
    int descriptor = open(path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
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

static int file_fixture(void) {
    char path[160];
    char renamed[160];
    snprintf(path, sizeof(path), "%s/canary", fixture_root);
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char byte = 0;
    if (descriptor < 0 || read(descriptor, &byte, 1) != 1 || byte != 'c') {
        if (descriptor >= 0) close(descriptor);
        return 80;
    }
    if (close(descriptor) != 0) {
        return 81;
    }
    snprintf(path, sizeof(path), "%s/write-target", fixture_root);
    if (write_exact(path, "w") != 0) {
        return 82;
    }
    snprintf(path, sizeof(path), "%s/rename-source", fixture_root);
    snprintf(renamed, sizeof(renamed), "%s/renamed", fixture_root);
    if (rename(path, renamed) != 0) {
        return 83;
    }
    snprintf(path, sizeof(path), "%s/delete-target", fixture_root);
    if (unlink(path) != 0) {
        return 84;
    }
    snprintf(path, sizeof(path), "%s/canary", fixture_root);
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return 85;
    }
    void *mapping = mmap(NULL, 1, PROT_READ, MAP_PRIVATE, descriptor, 0);
    if (mapping == MAP_FAILED || *(volatile char *)mapping != 'c' || munmap(mapping, 1) != 0 ||
        close(descriptor) != 0) {
        return 86;
    }
    snprintf(path, sizeof(path), "%s/fake-home/.profile", fixture_root);
    if (write_exact(path, "p") != 0) {
        return 87;
    }
    return 0;
}

static int double_fork_daemonization(void) {
    pid_t intermediate = fork();
    if (intermediate < 0) return 88;
    if (intermediate > 0) return 0;
    if (setsid() < 0) _exit(89);
    pid_t daemon = fork();
    if (daemon < 0) _exit(90);
    if (daemon > 0) _exit(0);
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 200000000};
    if (nanosleep(&pause, NULL) != 0) _exit(91);
    _exit(0);
}

static int reparenting(void) {
    pid_t child = fork();
    if (child < 0) return 92;
    if (child == 0) {
        close(REPARENT_REPORT_FD);
        const struct timespec pause = {.tv_sec = 0, .tv_nsec = 200000000};
        if (nanosleep(&pause, NULL) != 0) _exit(93);
        _exit(0);
    }
    const struct reparent_report report = {
        .magic = REPARENT_REPORT_MAGIC,
        .child_pid = child,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) return 94;
    errno = saved_errno;
    return written == (ssize_t)sizeof(report) ? 0 : 95;
}

static int reparented_child(void) {
    pid_t child = fork();
    if (child < 0) return 168;
    if (child == 0) {
        close(REPARENT_REPORT_FD);
        for (;;) (void)pause();
    }
    const struct reparent_report report = {
        .magic = REPARENT_REPORT_MAGIC,
        .child_pid = child,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) return 169;
    errno = saved_errno;
    return written == (ssize_t)sizeof(report) ? 0 : 170;
}

static int background_listener(void) {
    pid_t child = fork();
    if (child < 0) return 171;
    if (child > 0) {
        close(REPARENT_REPORT_FD);
        return 0;
    }
    int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    int reuse = 1;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(BACKGROUND_LISTENER_PORT),
    };
    struct stat metadata;
    if (descriptor < 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1 ||
        bind(descriptor, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(descriptor, 1) != 0 || fstat(descriptor, &metadata) != 0) {
        _exit(172);
    }
    const struct background_listener_report report = {
        .magic = BACKGROUND_LISTENER_REPORT_MAGIC,
        .process_pid = getpid(),
        .socket_inode = metadata.st_ino,
        .address = address.sin_addr.s_addr,
        .port = BACKGROUND_LISTENER_PORT,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) _exit(173);
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) _exit(174);
    for (;;) (void)pause();
}

static int setsid_escape(void) {
    const pid_t process_pid = getpid();
    const pid_t prior_session_id = getsid(0);
    const pid_t prior_process_group_id = getpgrp();
    if (prior_session_id < 0 || prior_process_group_id < 0) return 96;
    const pid_t session_id = setsid();
    const pid_t process_group_id = getpgrp();
    if (session_id != process_pid || process_group_id != process_pid) return 97;
    const struct session_report report = {
        .magic = SESSION_REPORT_MAGIC,
        .process_pid = process_pid,
        .prior_session_id = prior_session_id,
        .prior_process_group_id = prior_process_group_id,
        .session_id = session_id,
        .process_group_id = process_group_id,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) return 98;
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) return 99;
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 200000000};
    return nanosleep(&pause, NULL) == 0 ? 0 : 100;
}

static int escaped_session(void) {
    const pid_t process_pid = getpid();
    const pid_t prior_session_id = getsid(0);
    const pid_t prior_process_group_id = getpgrp();
    if (prior_session_id < 0 || prior_process_group_id < 0) return 164;
    const pid_t session_id = setsid();
    const pid_t process_group_id = getpgrp();
    if (session_id != process_pid || process_group_id != process_pid) return 165;
    const struct session_report report = {
        .magic = SESSION_REPORT_MAGIC,
        .process_pid = process_pid,
        .prior_session_id = prior_session_id,
        .prior_process_group_id = prior_process_group_id,
        .session_id = session_id,
        .process_group_id = process_group_id,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) return 166;
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) return 167;
    for (;;) (void)pause();
}

static int credential_change(void) {
    const int group_count = getgroups(0, NULL);
    if (group_count != 0) return 101;
    const struct credential_report report = {
        .magic = CREDENTIAL_REPORT_MAGIC,
        .process_pid = getpid(),
        .uid = getuid(),
        .effective_uid = geteuid(),
        .gid = getgid(),
        .effective_gid = getegid(),
        .supplementary_group_count = group_count,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) return 102;
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) return 103;
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 200000000};
    return nanosleep(&pause, NULL) == 0 ? 0 : 104;
}

static int dynamic_library_load(void) {
    execl(
        dynamic_driver_path,
        dynamic_driver_path,
        dynamic_library_path,
        (char *)NULL
    );
    return 105;
}

static int ipv4_connect(void) {
    int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP);
    if (descriptor < 0) return 106;
    struct sockaddr_in target = {
        .sin_family = AF_INET,
        .sin_port = htons(443),
    };
    if (inet_pton(AF_INET, "192.0.2.1", &target.sin_addr) != 1) {
        close(descriptor);
        return 107;
    }
    errno = 0;
    int connected = connect(descriptor, (const struct sockaddr *)&target, sizeof(target));
    int connect_errno = errno;
    if (connected != -1 || connect_errno != EINPROGRESS) {
        close(descriptor);
        return 108;
    }
    struct sockaddr_in source = {0};
    socklen_t source_length = sizeof(source);
    struct stat metadata;
    if (getsockname(descriptor, (struct sockaddr *)&source, &source_length) != 0 ||
        source_length != sizeof(source) || source.sin_family != AF_INET ||
        source.sin_port == 0 || fstat(descriptor, &metadata) != 0) {
        close(descriptor);
        return 109;
    }
    const struct network_report report = {
        .magic = NETWORK_REPORT_MAGIC,
        .process_pid = getpid(),
        .socket_inode = metadata.st_ino,
        .source_address = source.sin_addr.s_addr,
        .target_address = target.sin_addr.s_addr,
        .source_port = ntohs(source.sin_port),
        .target_port = ntohs(target.sin_port),
        .connect_errno = connect_errno,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) {
        close(descriptor);
        return 110;
    }
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) {
        close(descriptor);
        return 111;
    }
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 200000000};
    int result = nanosleep(&pause, NULL) == 0 ? 0 : 112;
    if (close(descriptor) != 0 && result == 0) result = 113;
    return result;
}

static int ipv6_connect(void) {
    int descriptor = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP);
    if (descriptor < 0) return 114;
    struct sockaddr_in6 target = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(443),
    };
    if (inet_pton(AF_INET6, "2001:db8::1", &target.sin6_addr) != 1) {
        close(descriptor);
        return 115;
    }
    errno = 0;
    int connected = connect(descriptor, (const struct sockaddr *)&target, sizeof(target));
    int connect_errno = errno;
    if (connected != -1 || connect_errno != EINPROGRESS) {
        close(descriptor);
        return 116;
    }
    struct sockaddr_in6 source = {0};
    socklen_t source_length = sizeof(source);
    struct stat metadata;
    if (getsockname(descriptor, (struct sockaddr *)&source, &source_length) != 0 ||
        source_length != sizeof(source) || source.sin6_family != AF_INET6 ||
        source.sin6_port == 0 || fstat(descriptor, &metadata) != 0) {
        close(descriptor);
        return 117;
    }
    const struct network6_report report = {
        .magic = NETWORK6_REPORT_MAGIC,
        .process_pid = getpid(),
        .socket_inode = metadata.st_ino,
        .source_address = source.sin6_addr,
        .target_address = target.sin6_addr,
        .source_port = ntohs(source.sin6_port),
        .target_port = ntohs(target.sin6_port),
        .connect_errno = connect_errno,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) {
        close(descriptor);
        return 118;
    }
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) {
        close(descriptor);
        return 119;
    }
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 200000000};
    int result = nanosleep(&pause, NULL) == 0 ? 0 : 120;
    if (close(descriptor) != 0 && result == 0) result = 121;
    return result;
}

static int udp_send(void) {
    int descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
    if (descriptor < 0) return 122;
    struct sockaddr_in source = {
        .sin_family = AF_INET,
        .sin_port = 0,
    };
    struct sockaddr_in target = {
        .sin_family = AF_INET,
        .sin_port = htons(443),
    };
    if (inet_pton(AF_INET, "192.0.2.2", &source.sin_addr) != 1 ||
        inet_pton(AF_INET, "192.0.2.1", &target.sin_addr) != 1 ||
        bind(descriptor, (const struct sockaddr *)&source, sizeof(source)) != 0) {
        close(descriptor);
        return 123;
    }
    if (sendto(
            descriptor,
            UDP_PAYLOAD,
            sizeof(UDP_PAYLOAD) - 1,
            0,
            (const struct sockaddr *)&target,
            sizeof(target)
        ) != (ssize_t)(sizeof(UDP_PAYLOAD) - 1)) {
        close(descriptor);
        return 124;
    }
    socklen_t source_length = sizeof(source);
    struct stat metadata;
    if (getsockname(descriptor, (struct sockaddr *)&source, &source_length) != 0 ||
        source_length != sizeof(source) || source.sin_family != AF_INET ||
        source.sin_port == 0 || fstat(descriptor, &metadata) != 0) {
        close(descriptor);
        return 125;
    }
    const struct udp_report report = {
        .magic = UDP_REPORT_MAGIC,
        .process_pid = getpid(),
        .socket_inode = metadata.st_ino,
        .source_address = source.sin_addr.s_addr,
        .target_address = target.sin_addr.s_addr,
        .source_port = ntohs(source.sin_port),
        .target_port = ntohs(target.sin_port),
        .payload_length = sizeof(UDP_PAYLOAD) - 1,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) {
        close(descriptor);
        return 126;
    }
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) {
        close(descriptor);
        return 127;
    }
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 200000000};
    int result = nanosleep(&pause, NULL) == 0 ? 0 : 128;
    if (close(descriptor) != 0 && result == 0) result = 129;
    return result;
}

static int host_frame_overflow(void) {
    int descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    if (descriptor < 0) return 161;
    struct sockaddr_in source = {
        .sin_family = AF_INET,
        .sin_port = 0,
    };
    struct sockaddr_in target = {
        .sin_family = AF_INET,
        .sin_port = htons(443),
    };
    if (inet_pton(AF_INET, "192.0.2.2", &source.sin_addr) != 1 ||
        inet_pton(AF_INET, "192.0.2.1", &target.sin_addr) != 1 ||
        bind(descriptor, (const struct sockaddr *)&source, sizeof(source)) != 0) {
        close(descriptor);
        return 162;
    }
    socklen_t source_length = sizeof(source);
    if (getsockname(descriptor, (struct sockaddr *)&source, &source_length) != 0 ||
        source_length != sizeof(source) || source.sin_family != AF_INET ||
        source.sin_port == 0) {
        close(descriptor);
        return 163;
    }
    for (uint32_t sequence = 0; sequence < HOST_FRAME_TRIGGER_COUNT; sequence++) {
        uint32_t payload[4] = {
            htonl(HOST_FRAME_REPORT_MAGIC),
            htonl(sequence),
            htonl(~sequence),
            htonl(HOST_FRAME_TRIGGER_COUNT),
        };
        if (sendto(
                descriptor,
                payload,
                sizeof(payload),
                0,
                (const struct sockaddr *)&target,
                sizeof(target)
            ) != (ssize_t)sizeof(payload)) {
            close(descriptor);
            return 164;
        }
    }
    const struct host_frame_report report = {
        .magic = HOST_FRAME_REPORT_MAGIC,
        .process_pid = getpid(),
        .source_address = source.sin_addr.s_addr,
        .target_address = target.sin_addr.s_addr,
        .source_port = ntohs(source.sin_port),
        .target_port = ntohs(target.sin_port),
        .payload_length = HOST_FRAME_PAYLOAD_LENGTH,
        .transmitted_count = HOST_FRAME_TRIGGER_COUNT,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) {
        close(descriptor);
        return 165;
    }
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) {
        close(descriptor);
        return 166;
    }
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 200000000};
    int result = nanosleep(&pause, NULL) == 0 ? 0 : 167;
    if (close(descriptor) != 0 && result == 0) result = 168;
    return result;
}

static int loopback_connect(void) {
    int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (descriptor < 0) return 130;
    struct sockaddr_in target = {
        .sin_family = AF_INET,
        .sin_port = htons(LOOPBACK_TARGET_PORT),
    };
    if (inet_pton(AF_INET, "127.0.0.1", &target.sin_addr) != 1 ||
        connect(descriptor, (const struct sockaddr *)&target, sizeof(target)) != 0) {
        close(descriptor);
        return 131;
    }
    struct sockaddr_in source = {0};
    socklen_t source_length = sizeof(source);
    struct stat metadata;
    if (getsockname(descriptor, (struct sockaddr *)&source, &source_length) != 0 ||
        source_length != sizeof(source) || source.sin_family != AF_INET ||
        source.sin_port == 0 || fstat(descriptor, &metadata) != 0) {
        close(descriptor);
        return 132;
    }
    const struct network_report report = {
        .magic = LOOPBACK_REPORT_MAGIC,
        .process_pid = getpid(),
        .socket_inode = metadata.st_ino,
        .source_address = source.sin_addr.s_addr,
        .target_address = target.sin_addr.s_addr,
        .source_port = ntohs(source.sin_port),
        .target_port = ntohs(target.sin_port),
        .connect_errno = 0,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) {
        close(descriptor);
        return 133;
    }
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) {
        close(descriptor);
        return 134;
    }
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 200000000};
    int result = nanosleep(&pause, NULL) == 0 ? 0 : 135;
    if (close(descriptor) != 0 && result == 0) result = 136;
    return result;
}

static int classified_address_connect(
    const char *target_address,
    uint16_t target_port,
    uint32_t report_magic
) {
    int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP);
    if (descriptor < 0) return 137;
    struct sockaddr_in target = {
        .sin_family = AF_INET,
        .sin_port = htons(target_port),
    };
    if (inet_pton(AF_INET, target_address, &target.sin_addr) != 1) {
        close(descriptor);
        return 138;
    }
    errno = 0;
    int connected = connect(descriptor, (const struct sockaddr *)&target, sizeof(target));
    int connect_errno = errno;
    if (connected != -1 || connect_errno != EINPROGRESS) {
        close(descriptor);
        return 139;
    }
    struct sockaddr_in source = {0};
    socklen_t source_length = sizeof(source);
    struct stat metadata;
    if (getsockname(descriptor, (struct sockaddr *)&source, &source_length) != 0 ||
        source_length != sizeof(source) || source.sin_family != AF_INET ||
        source.sin_port == 0 || fstat(descriptor, &metadata) != 0) {
        close(descriptor);
        return 140;
    }
    const struct network_report report = {
        .magic = report_magic,
        .process_pid = getpid(),
        .socket_inode = metadata.st_ino,
        .source_address = source.sin_addr.s_addr,
        .target_address = target.sin_addr.s_addr,
        .source_port = ntohs(source.sin_port),
        .target_port = ntohs(target.sin_port),
        .connect_errno = connect_errno,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) {
        close(descriptor);
        return 141;
    }
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) {
        close(descriptor);
        return 142;
    }
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 200000000};
    int result = nanosleep(&pause, NULL) == 0 ? 0 : 143;
    if (close(descriptor) != 0 && result == 0) result = 144;
    return result;
}

static int private_address_connect(void) {
    return classified_address_connect("10.0.0.1", 443, PRIVATE_REPORT_MAGIC);
}

static int link_local_connect(void) {
    return classified_address_connect("169.254.100.1", 443, LINK_LOCAL_REPORT_MAGIC);
}

static int metadata_address_connect(void) {
    return classified_address_connect("169.254.169.254", 443, METADATA_REPORT_MAGIC);
}

static int public_address_connect(void) {
    return classified_address_connect("198.51.100.1", 443, PUBLIC_REPORT_MAGIC);
}

static int encrypted_dns_connect(void) {
    return classified_address_connect("192.0.2.53", 853, ENCRYPTED_DNS_REPORT_MAGIC);
}

static int dns_send_query(
    const unsigned char *payload,
    size_t payload_length,
    uint32_t report_magic,
    int error_base
) {
    int descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
    if (descriptor < 0) return error_base;
    struct sockaddr_in source = {
        .sin_family = AF_INET,
        .sin_port = 0,
    };
    struct sockaddr_in target = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
    };
    if (inet_pton(AF_INET, "192.0.2.2", &source.sin_addr) != 1 ||
        inet_pton(AF_INET, "192.0.2.53", &target.sin_addr) != 1 ||
        bind(descriptor, (const struct sockaddr *)&source, sizeof(source)) != 0) {
        close(descriptor);
        return error_base + 1;
    }
    if (sendto(
            descriptor,
            payload,
            payload_length,
            0,
            (const struct sockaddr *)&target,
            sizeof(target)
        ) != (ssize_t)payload_length) {
        close(descriptor);
        return error_base + 2;
    }
    socklen_t source_length = sizeof(source);
    struct stat metadata;
    if (getsockname(descriptor, (struct sockaddr *)&source, &source_length) != 0 ||
        source_length != sizeof(source) || source.sin_family != AF_INET ||
        source.sin_port == 0 || fstat(descriptor, &metadata) != 0) {
        close(descriptor);
        return error_base + 3;
    }
    const struct udp_report report = {
        .magic = report_magic,
        .process_pid = getpid(),
        .socket_inode = metadata.st_ino,
        .source_address = source.sin_addr.s_addr,
        .target_address = target.sin_addr.s_addr,
        .source_port = ntohs(source.sin_port),
        .target_port = ntohs(target.sin_port),
        .payload_length = payload_length,
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) {
        close(descriptor);
        return error_base + 4;
    }
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) {
        close(descriptor);
        return error_base + 5;
    }
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 200000000};
    int result = nanosleep(&pause, NULL) == 0 ? 0 : error_base + 6;
    if (close(descriptor) != 0 && result == 0) result = error_base + 7;
    return result;
}

static int dns_plaintext(void) {
    return dns_send_query(
        dns_plaintext_query, sizeof(dns_plaintext_query),
        DNS_PLAINTEXT_REPORT_MAGIC, 145
    );
}

static int dns_malformed(void) {
    return dns_send_query(
        dns_malformed_query, sizeof(dns_malformed_query),
        DNS_MALFORMED_REPORT_MAGIC, 153
    );
}

static int term_resistance(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_IGN;
    if (sigemptyset(&action.sa_mask) != 0 || sigaction(SIGTERM, &action, NULL) != 0) {
        return 161;
    }
    const struct term_resistance_report report = {
        .magic = TERM_RESISTANCE_REPORT_MAGIC,
        .process_pid = getpid(),
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) return 162;
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) return 163;
    for (;;) (void)pause();
}

static int vm_stop(void) {
    const struct vm_stop_report report = {
        .magic = VM_STOP_REPORT_MAGIC,
        .process_pid = getpid(),
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) return 175;
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) return 176;
    for (;;) (void)pause();
}

static int guest_sensor_death(void) {
    const struct guest_sensor_death_report report = {
        .magic = GUEST_SENSOR_DEATH_REPORT_MAGIC,
        .process_pid = getpid(),
    };
    ssize_t written = write(REPARENT_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(REPARENT_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) return 177;
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) return 178;
    for (;;) (void)pause();
}

static int bpf_program_types(void) {
    static const unsigned char payload[8] = {
        'W', 'H', 'O', 'A', 'B', 'P', 'F', 'X'
    };
    if (getpid() <= 0) return 179;
    ssize_t sent;
    do {
        sent = send(REPARENT_REPORT_FD, payload, sizeof(payload), MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    return sent == (ssize_t)sizeof(payload) ? 0 : 180;
}

int main(int argument_count, char **arguments) {
    if (argument_count != 2 || getuid() != 65534 || geteuid() != 65534 ||
        getgid() != 65534 || getegid() != 65534) {
        return 75;
    }
    int denied = protected_sensor_denied();
    if (denied != 0) return denied;
    if (strcmp(arguments[1], "fork_exec_exit") == 0) return 0;
    if (strcmp(arguments[1], "host_sensor_death") == 0) return 0;
    if (strcmp(arguments[1], "all_protected_assets_denied") == 0) {
        return all_protected_assets_denied();
    }
    if (strcmp(arguments[1], "normal_exit") == 0) return 0;
    if (strcmp(arguments[1], "timeout") == 0) {
        for (;;) (void)pause();
    }
    if (strcmp(arguments[1], "vm_stop") == 0) return vm_stop();
    if (strcmp(arguments[1], "guest_sensor_death") == 0) return guest_sensor_death();
    if (strcmp(arguments[1], "term_resistance") == 0) return term_resistance();
    if (strcmp(arguments[1], "double_fork_daemonization") == 0) {
        return double_fork_daemonization();
    }
    if (strcmp(arguments[1], "reparenting") == 0) return reparenting();
    if (strcmp(arguments[1], "reparented_child") == 0) return reparented_child();
    if (strcmp(arguments[1], "background_listener") == 0) return background_listener();
    if (strcmp(arguments[1], "setsid_escape") == 0) return setsid_escape();
    if (strcmp(arguments[1], "escaped_session") == 0) return escaped_session();
    if (strcmp(arguments[1], "credential_change") == 0) return credential_change();
    if (strcmp(arguments[1], "dynamic_library_load") == 0) return dynamic_library_load();
    if (strcmp(arguments[1], "ipv4_connect") == 0) return ipv4_connect();
    if (strcmp(arguments[1], "ipv6_connect") == 0) return ipv6_connect();
    if (strcmp(arguments[1], "udp_send") == 0) return udp_send();
    if (strcmp(arguments[1], "loopback_connect") == 0) return loopback_connect();
    if (strcmp(arguments[1], "private_address_connect") == 0) return private_address_connect();
    if (strcmp(arguments[1], "link_local_connect") == 0) return link_local_connect();
    if (strcmp(arguments[1], "metadata_address_connect") == 0) {
        return metadata_address_connect();
    }
    if (strcmp(arguments[1], "public_address_connect") == 0) return public_address_connect();
    if (strcmp(arguments[1], "dns_plaintext") == 0) return dns_plaintext();
    if (strcmp(arguments[1], "dns_malformed") == 0) return dns_malformed();
    if (strcmp(arguments[1], "encrypted_dns_connect") == 0) return encrypted_dns_connect();
    if (strcmp(arguments[1], "host_frame_overflow") == 0) return host_frame_overflow();
    if (strcmp(arguments[1], "bpf_program_types") == 0) return bpf_program_types();
    if (strcmp(arguments[1], "fanotify_permission") == 0 ||
        strcmp(arguments[1], "protected_open_read_write_rename_delete") == 0 ||
        strcmp(arguments[1], "mmap_access") == 0) {
        return file_fixture();
    }
    return 64;
}
