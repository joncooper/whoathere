#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static uint64_t output_offset = 0;

static void fail(const char *message) {
    fprintf(stderr, "canonical_newc: %s\n", message);
    exit(1);
}

static void write_bytes(FILE *output, const void *bytes, size_t length) {
    if (length > 0 && fwrite(bytes, 1, length, output) != length) {
        fail("write failed");
    }
    output_offset += length;
}

static void write_padding(FILE *output, uint64_t alignment) {
    static const unsigned char zeros[512] = {0};
    uint64_t remainder = output_offset % alignment;
    if (remainder != 0) {
        write_bytes(output, zeros, (size_t)(alignment - remainder));
    }
}

static void write_header(
    FILE *output,
    uint32_t inode,
    uint32_t mode,
    uint32_t link_count,
    uint32_t file_size,
    uint32_t name_size
) {
    char header[111];
    int length = snprintf(
        header,
        sizeof(header),
        "070701%08" PRIx32 "%08" PRIx32 "%08x%08x%08" PRIx32
        "%08x%08" PRIx32 "%08x%08x%08x%08x%08" PRIx32 "%08x",
        inode,
        mode,
        0,
        0,
        link_count,
        0,
        file_size,
        0,
        0,
        0,
        0,
        name_size,
        0
    );
    if (length != 110) {
        fail("header encoding failed");
    }
    write_bytes(output, header, 110);
}

static void write_name(FILE *output, const char *name) {
    write_bytes(output, name, strlen(name) + 1);
    write_padding(output, 4);
}

static uint32_t checked_file_size(const char *path) {
    struct stat metadata;
    if (lstat(path, &metadata) != 0) {
        fail("input stat failed");
    }
    if (!S_ISREG(metadata.st_mode) || S_ISLNK(metadata.st_mode)) {
        fail("input must be a regular non-symlink file");
    }
    if (metadata.st_size < 0 || (uint64_t)metadata.st_size > UINT32_MAX) {
        fail("input exceeds newc size limit");
    }
    return (uint32_t)metadata.st_size;
}

static void write_file_entry(
    FILE *output,
    uint32_t inode,
    uint32_t mode,
    const char *archive_name,
    const char *source_path
) {
    uint32_t file_size = checked_file_size(source_path);
    size_t name_size = strlen(archive_name) + 1;
    if (name_size > UINT32_MAX) {
        fail("archive name exceeds newc size limit");
    }
    write_header(
        output,
        inode,
        mode,
        1,
        file_size,
        (uint32_t)name_size
    );
    write_name(output, archive_name);

    FILE *input = fopen(source_path, "rb");
    if (input == NULL) {
        fail("input open failed");
    }
    unsigned char buffer[64 * 1024];
    uint32_t remaining = file_size;
    while (remaining > 0) {
        size_t requested = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        size_t count = fread(buffer, 1, requested, input);
        if (count != requested) {
            fclose(input);
            fail("input read failed");
        }
        write_bytes(output, buffer, count);
        remaining -= (uint32_t)count;
    }
    if (fclose(input) != 0) {
        fail("input close failed");
    }
    write_padding(output, 4);
}

static void write_directory_entry(
    FILE *output,
    uint32_t inode,
    uint32_t mode,
    const char *archive_name
) {
    size_t name_size = strlen(archive_name) + 1;
    if (name_size > UINT32_MAX) {
        fail("archive name exceeds newc size limit");
    }
    write_header(output, inode, mode, 2, 0, (uint32_t)name_size);
    write_name(output, archive_name);
}

static void write_trailer(FILE *output) {
    static const char trailer[] = "TRAILER!!!";
    write_header(output, 6, 0, 1, 0, sizeof(trailer));
    write_name(output, trailer);
    write_padding(output, 512);
}

int main(int argument_count, char **arguments) {
    if (argument_count != 9) {
        fprintf(
            stderr,
            "usage: canonical_newc OUTPUT INIT CAPABILITY_PROBE PROCESS_SENSOR "
            "PROCESS_FIXTURE DYNAMIC_DRIVER DYNAMIC_LIBRARY FIXTURE_BUNDLE\n"
        );
        return 64;
    }
    if (checked_file_size(arguments[2]) == 0 || checked_file_size(arguments[3]) == 0 ||
        checked_file_size(arguments[4]) == 0 || checked_file_size(arguments[5]) == 0 ||
        checked_file_size(arguments[6]) == 0 || checked_file_size(arguments[7]) == 0 ||
        checked_file_size(arguments[8]) == 0) {
        fail("input must not be empty");
    }

    FILE *output = fopen(arguments[1], "wbx");
    if (output == NULL) {
        fprintf(stderr, "canonical_newc: output open failed: %s\n", strerror(errno));
        return 1;
    }
    write_file_entry(output, 1, 0100755, "init", arguments[2]);
    write_directory_entry(output, 2, 0040711, "whoathere");
    write_file_entry(output, 3, 0100700, "whoathere/capability-probe", arguments[3]);
    write_file_entry(output, 4, 0100700, "whoathere/process-sensor-probe", arguments[4]);
    write_file_entry(output, 5, 0100555, "whoathere/process-fixture-child", arguments[5]);
    write_file_entry(output, 6, 0100555, "whoathere/dynamic-library-driver", arguments[6]);
    write_file_entry(output, 7, 0100444, "whoathere/dynamic-fixture-library.so", arguments[7]);
    write_file_entry(output, 8, 0100444, "whoathere/process-fixture-bundle.json", arguments[8]);
    write_trailer(output);
    if (fclose(output) != 0) {
        fail("output close failed");
    }
    return 0;
}
