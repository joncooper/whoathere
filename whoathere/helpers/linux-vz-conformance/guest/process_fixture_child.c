#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argument_count, char **arguments) {
    (void)arguments;
    if (argument_count != 1 || getuid() != 65534 || geteuid() != 65534 ||
        getgid() != 65534 || getegid() != 65534) {
        return 75;
    }

    int descriptor = open("/whoathere/process-sensor-probe", O_WRONLY | O_CLOEXEC);
    if (descriptor >= 0) {
        close(descriptor);
        return 76;
    }
    if (errno != EACCES && errno != EPERM && errno != EROFS) {
        return 77;
    }
    descriptor = open("/whoathere/process-sensor-probe", O_RDONLY | O_CLOEXEC);
    if (descriptor >= 0) {
        close(descriptor);
        return 78;
    }
    if (errno != EACCES && errno != EPERM) {
        return 79;
    }
    return 0;
}
