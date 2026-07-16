#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static uint64_t output_offset = 0;

static void fail(const char *message) {
    fprintf(stderr, "canonical_execution_bundle_newc: %s\n", message);
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
    if (metadata.st_size <= 0 || (uint64_t)metadata.st_size > UINT32_MAX) {
        fail("input size invalid");
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
    uint32_t name_size = (uint32_t)(strlen(archive_name) + 1);
    write_header(output, inode, mode, 1, file_size, name_size);
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
    uint32_t name_size = (uint32_t)(strlen(archive_name) + 1);
    write_header(output, inode, mode, 2, 0, name_size);
    write_name(output, archive_name);
}

static void write_trailer(FILE *output, uint32_t inode) {
    static const char trailer[] = "TRAILER!!!";
    write_header(output, inode, 0, 1, 0, sizeof(trailer));
    write_name(output, trailer);
    write_padding(output, 512);
}

int main(int argument_count, char **arguments) {
    static const char *const archive_names[] = {
        "init",
        "whoathere/execution-descriptor-launcher",
        "whoathere/execution-runtime-manifest.json",
        "whoathere/guest-ed25519.seed",
        "whoathere/inputs/bundle-manifest.json",
        "whoathere/inputs/backend-identity.json",
        "whoathere/inputs/qualified-backend.json",
        "whoathere/inputs/package-authority-request.json",
        "whoathere/inputs/execution-grant.json",
        "whoathere/inputs/artifact.bin",
        "whoathere/inputs/scenario-plan.json",
        "whoathere/inputs/scenario-template.json",
        "whoathere/inputs/guest-ed25519-public-key.bin",
        "whoathere/inputs/host-ed25519-public-key.bin",
        "whoathere/inputs/grant-issuer-ed25519-public-key.bin",
        "whoathere/inputs/execution-runtime-qualification-record.json",
        "whoathere/inputs/runtime-clone-binding.json",
    };
    static const uint32_t modes[] = {
        0100755, 0100500, 0100444, 0100400, 0100444, 0100444, 0100444,
        0100444, 0100444, 0100444, 0100444, 0100444, 0100444, 0100444,
        0100444, 0100444, 0100444,
    };
    const int file_count = (int)(sizeof(archive_names) / sizeof(archive_names[0]));
    if (argument_count != file_count + 2 && argument_count != file_count + 3) {
        fprintf(
            stderr,
            "usage: canonical_execution_bundle_newc OUTPUT INIT LAUNCHER RUNTIME_MANIFEST SIGNING_SEED BUNDLE_MANIFEST BACKEND_IDENTITY QUALIFIED_BACKEND AUTHORITY_REQUEST EXECUTION_GRANT ARTIFACT PLAN TEMPLATE GUEST_PUBLIC_KEY HOST_PUBLIC_KEY GRANT_PUBLIC_KEY QUALIFICATION_RECORD CLONE_BINDING [BUILD_CLOSURE]\n"
        );
        return 64;
    }
    for (int index = 2; index < argument_count; index++) {
        checked_file_size(arguments[index]);
    }
    FILE *output = fopen(arguments[1], "wbx");
    if (output == NULL) {
        fprintf(
            stderr,
            "canonical_execution_bundle_newc: output open failed: %s\n",
            strerror(errno)
        );
        return 1;
    }
    write_directory_entry(output, 1, 0040711, "whoathere");
    write_directory_entry(output, 2, 0040711, "whoathere/inputs");
    for (int index = 0; index < file_count; index++) {
        write_file_entry(
            output,
            (uint32_t)(index + 3),
            modes[index],
            archive_names[index],
            arguments[index + 2]
        );
    }
    uint32_t next_inode = (uint32_t)(file_count + 3);
    if (argument_count == file_count + 3) {
        write_file_entry(
            output,
            next_inode++,
            0100444,
            "whoathere/inputs/build-closure.bin",
            arguments[file_count + 2]
        );
    }
    write_trailer(output, next_inode);
    if (fclose(output) != 0) {
        fail("output close failed");
    }
    return 0;
}
