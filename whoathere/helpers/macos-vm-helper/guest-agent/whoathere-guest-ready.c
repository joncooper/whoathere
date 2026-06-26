#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/vsock.h>
#include <unistd.h>

#ifndef AF_VSOCK
#error "AF_VSOCK is required for the WhoaThere guest readiness agent"
#endif

#define WHOATHERE_GUEST_READY_PORT 47078U
#define WHOATHERE_MAX_LINE 4096
#define WHOATHERE_MAX_CHALLENGE 128

static int read_line(int fd, char *buffer, size_t capacity) {
    size_t used = 0;
    while (used + 1 < capacity) {
        char byte = '\0';
        ssize_t count = read(fd, &byte, 1);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (count == 0) {
            break;
        }
        if (byte == '\n') {
            break;
        }
        buffer[used++] = byte;
    }
    buffer[used] = '\0';
    return used > 0 ? 0 : -1;
}

static int extract_json_string(const char *json, const char *key, char *output, size_t output_capacity) {
    char pattern[64];
    if (snprintf(pattern, sizeof(pattern), "\"%s\"", key) < 0) {
        return -1;
    }
    const char *cursor = strstr(json, pattern);
    if (cursor == NULL) {
        return -1;
    }
    cursor += strlen(pattern);
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }
    if (*cursor != ':') {
        return -1;
    }
    cursor++;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }
    if (*cursor != '"') {
        return -1;
    }
    cursor++;

    size_t used = 0;
    while (*cursor != '\0' && *cursor != '"') {
        if (*cursor == '\\') {
            return -1;
        }
        if (used + 1 >= output_capacity) {
            return -1;
        }
        output[used++] = *cursor++;
    }
    if (*cursor != '"') {
        return -1;
    }
    output[used] = '\0';
    return used > 0 ? 0 : -1;
}

static int write_all(int fd, const char *buffer, size_t length) {
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(fd, buffer + written, length - written);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (count == 0) {
            return -1;
        }
        written += (size_t)count;
    }
    return 0;
}

int main(void) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 70;
    }

    struct sockaddr_vm address;
    memset(&address, 0, sizeof(address));
    address.svm_family = AF_VSOCK;
    address.svm_cid = VMADDR_CID_HOST;
    address.svm_port = WHOATHERE_GUEST_READY_PORT;

    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("connect");
        close(fd);
        return 70;
    }

    char line[WHOATHERE_MAX_LINE];
    if (read_line(fd, line, sizeof(line)) != 0) {
        fprintf(stderr, "failed to read challenge\n");
        close(fd);
        return 70;
    }

    char challenge[WHOATHERE_MAX_CHALLENGE];
    if (extract_json_string(line, "challenge", challenge, sizeof(challenge)) != 0) {
        fprintf(stderr, "failed to parse challenge\n");
        close(fd);
        return 70;
    }

    char response[WHOATHERE_MAX_LINE];
    int length = snprintf(
        response,
        sizeof(response),
        "{\"agent_version\":\"0.1.0\",\"challenge\":\"%s\",\"protocol\":\"whoathere.guest_ready.v1\",\"status\":\"ready\"}\n",
        challenge
    );
    if (length < 0 || (size_t)length >= sizeof(response)) {
        fprintf(stderr, "failed to build response\n");
        close(fd);
        return 70;
    }

    if (write_all(fd, response, (size_t)length) != 0) {
        perror("write");
        close(fd);
        return 70;
    }

    close(fd);
    return 0;
}
