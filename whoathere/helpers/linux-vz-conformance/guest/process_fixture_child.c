#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char *sensor_path = "/whoathere/process-sensor-probe";
static const char *fixture_root = "/run/whoathere-file-fixture";

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

int main(int argument_count, char **arguments) {
    if (argument_count != 2 || getuid() != 65534 || geteuid() != 65534 ||
        getgid() != 65534 || getegid() != 65534) {
        return 75;
    }
    int denied = protected_sensor_denied();
    if (denied != 0) return denied;
    if (strcmp(arguments[1], "fork_exec_exit") == 0) return 0;
    if (strcmp(arguments[1], "double_fork_daemonization") == 0) {
        return double_fork_daemonization();
    }
    if (strcmp(arguments[1], "protected_open_read_write_rename_delete") == 0 ||
        strcmp(arguments[1], "mmap_access") == 0) {
        return file_fixture();
    }
    return 64;
}
