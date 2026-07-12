#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#define DYNAMIC_REPORT_FD 3
#define DYNAMIC_REPORT_MAGIC 0x5754444cU
#define DYNAMIC_MARKER UINT64_C(0x57544c4942465831)

struct dynamic_report {
    uint32_t magic;
    int32_t process_pid;
    uint64_t marker;
};

typedef uint64_t (*marker_function)(void);

int main(int argument_count, char **arguments) {
    if (argument_count != 2 || getuid() != 65534 || geteuid() != 65534 ||
        getgid() != 65534 || getegid() != 65534 ||
        getgroups(0, NULL) != 0) {
        return 75;
    }
    void *library = dlopen(arguments[1], RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) return 76;
    marker_function marker = (marker_function)dlsym(
        library,
        "whoathere_dynamic_fixture_marker"
    );
    if (marker == NULL) return 77;
    uint64_t value = marker();
    if (value != DYNAMIC_MARKER) return 78;
    const struct dynamic_report report = {
        .magic = DYNAMIC_REPORT_MAGIC,
        .process_pid = getpid(),
        .marker = value,
    };
    ssize_t written = write(DYNAMIC_REPORT_FD, &report, sizeof(report));
    int saved_errno = errno;
    if (close(DYNAMIC_REPORT_FD) != 0 && written == (ssize_t)sizeof(report)) return 79;
    errno = saved_errno;
    if (written != (ssize_t)sizeof(report)) return 80;
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 200000000};
    if (nanosleep(&pause, NULL) != 0) return 81;
    return dlclose(library) == 0 ? 0 : 82;
}
