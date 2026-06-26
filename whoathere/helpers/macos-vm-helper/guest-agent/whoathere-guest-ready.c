#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/vsock.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef AF_VSOCK
#error "AF_VSOCK is required for the WhoaThere guest readiness agent"
#endif

#define WHOATHERE_GUEST_READY_PORT 47078U
#define WHOATHERE_MAX_LINE 4096
#define WHOATHERE_MAX_CHALLENGE 128
#define WHOATHERE_MAX_FIELD 256
#define WHOATHERE_WORK_ROOT "/private/var/tmp/whoathere-detonation"

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

static unsigned int extract_json_uint(const char *json, const char *key, unsigned int fallback) {
    char pattern[64];
    if (snprintf(pattern, sizeof(pattern), "\"%s\"", key) < 0) {
        return fallback;
    }
    const char *cursor = strstr(json, pattern);
    if (cursor == NULL) {
        return fallback;
    }
    cursor += strlen(pattern);
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }
    if (*cursor != ':') {
        return fallback;
    }
    cursor++;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        cursor++;
    }
    char *end = NULL;
    unsigned long value = strtoul(cursor, &end, 10);
    if (end == cursor || value > 900UL) {
        return fallback;
    }
    return (unsigned int)value;
}

static int mkdir_if_missing(const char *path, mode_t mode) {
    if (mkdir(path, mode) == 0 || errno == EEXIST) {
        return 0;
    }
    return -1;
}

static int write_file(const char *path, const char *body) {
    FILE *file = fopen(path, "w");
    if (file == NULL) {
        return -1;
    }
    int result = fputs(body, file) < 0 ? -1 : 0;
    if (fclose(file) != 0) {
        result = -1;
    }
    return result;
}

static int path_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int command_exists(const char *command) {
    char check[512];
    int length = snprintf(check, sizeof(check), "command -v %s >/dev/null 2>&1", command);
    if (length < 0 || (size_t)length >= sizeof(check)) {
        return 0;
    }
    int status = system(check);
    return status == 0;
}

struct command_result {
    int exit_code;
    int timed_out;
};

static struct command_result run_shell_fixture(
    const char *workspace,
    const char *command,
    unsigned int timeout_seconds
) {
    struct command_result result;
    result.exit_code = 70;
    result.timed_out = 0;

    pid_t pid = fork();
    if (pid < 0) {
        return result;
    }
    if (pid == 0) {
        if (chdir(workspace) != 0) {
            _exit(70);
        }
        setenv("HOME", workspace, 1);
        setenv("NPM_TOKEN", "whoathere_fake_npm_token", 1);
        setenv("PYPI_TOKEN", "whoathere_fake_pypi_token", 1);
        setenv("GITHUB_TOKEN", "whoathere_fake_github_token", 1);
        setenv("AWS_ACCESS_KEY_ID", "WHOATHEREFAKEAWSKEY", 1);
        setenv("AWS_SECRET_ACCESS_KEY", "whoathere_fake_aws_secret", 1);
        setenv("KUBECONFIG", "canaries/kubeconfig", 1);
        setenv("VAULT_TOKEN", "whoathere_fake_vault_token", 1);
        setenv("OPENAI_API_KEY", "whoathere_fake_openai_token", 1);
        setenv("CI", "true", 1);
        freopen("stdout.log", "w", stdout);
        freopen("stderr.log", "w", stderr);
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(70);
    }

    time_t start = time(NULL);
    int status = 0;
    while (1) {
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            if (WIFEXITED(status)) {
                result.exit_code = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                result.exit_code = 128 + WTERMSIG(status);
            }
            return result;
        }
        if (waited < 0) {
            result.exit_code = 70;
            return result;
        }
        if ((unsigned int)(time(NULL) - start) >= timeout_seconds) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            result.exit_code = 124;
            result.timed_out = 1;
            return result;
        }
        usleep(100000);
    }
}

static int prepare_workspace(const char *job_id, char *workspace, size_t workspace_capacity) {
    if (mkdir_if_missing(WHOATHERE_WORK_ROOT, 0700) != 0) {
        return -1;
    }
    int length = snprintf(workspace, workspace_capacity, "%s/%s", WHOATHERE_WORK_ROOT, job_id);
    if (length < 0 || (size_t)length >= workspace_capacity) {
        return -1;
    }
    if (mkdir_if_missing(workspace, 0700) != 0) {
        return -1;
    }
    char canaries[512];
    if (snprintf(canaries, sizeof(canaries), "%s/canaries", workspace) < 0) {
        return -1;
    }
    if (mkdir_if_missing(canaries, 0700) != 0) {
        return -1;
    }
    char kubeconfig[512];
    if (snprintf(kubeconfig, sizeof(kubeconfig), "%s/kubeconfig", canaries) < 0) {
        return -1;
    }
    return write_file(kubeconfig, "token: whoathere_fake_kube_token\n");
}

static int write_npm_fixture(const char *workspace, const char *fixture) {
    char package_json[512];
    if (snprintf(package_json, sizeof(package_json), "%s/package.json", workspace) < 0) {
        return -1;
    }
    if (strcmp(fixture, "clean_npm_lifecycle") == 0) {
        return write_file(
            package_json,
            "{\"name\":\"whoathere-clean-fixture\",\"version\":\"0.0.1\",\"scripts\":{\"postinstall\":\"node -e \\\"require('fs').writeFileSync('clean.marker','ok')\\\"\"}}\n"
        );
    }
    if (strcmp(fixture, "npm_postinstall_canary_exfil") == 0
        || strcmp(fixture, "npm_prepare_remote_fetch") == 0
        || strcmp(fixture, "npm_darwin_only_payload") == 0
        || strcmp(fixture, "delayed_ci_canary") == 0
        || strcmp(fixture, "dns_tunneling_canary") == 0
        || strcmp(fixture, "https_exfil_canary") == 0) {
        const char *script_name = strcmp(fixture, "npm_prepare_remote_fetch") == 0 ? "prepare" : "postinstall";
        char body[2048];
        int length = snprintf(
            body,
            sizeof(body),
            "{\"name\":\"whoathere-malicious-fixture\",\"version\":\"0.0.1\",\"scripts\":{\"%s\":\"node -e \\\"const fs=require('fs'); if(process.env.NPM_TOKEN||process.env.GITHUB_TOKEN) fs.writeFileSync('canary-read.marker','1'); fs.writeFileSync('network-attempt.marker','mock-egress'); if(process.env.CI==='true') fs.writeFileSync('ci-activated.marker','1');\\\"\"}}\n",
            script_name
        );
        if (length < 0 || (size_t)length >= sizeof(body)) {
            return -1;
        }
        return write_file(package_json, body);
    }
    return -1;
}

static int write_python_fixture(const char *workspace, const char *fixture) {
    char setup_py[512];
    char module_py[512];
    if (snprintf(setup_py, sizeof(setup_py), "%s/setup.py", workspace) < 0) {
        return -1;
    }
    if (snprintf(module_py, sizeof(module_py), "%s/whoathere_fixture.py", workspace) < 0) {
        return -1;
    }
    if (strcmp(fixture, "clean_pip_package") == 0) {
        return write_file(
            setup_py,
            "from setuptools import setup\nsetup(name='whoathere-fixture', version='0.0.1', py_modules=['whoathere_fixture'])\n"
        ) || write_file(module_py, "VALUE = 'clean'\n");
    }
    if (strcmp(fixture, "pypi_pep517_canary") == 0
        || strcmp(fixture, "pypi_setup_py_canary") == 0
        || strcmp(fixture, "pypi_import_time_canary") == 0
        || strcmp(fixture, "python_import_time_canary") == 0) {
        int setup_result = write_file(
            setup_py,
            "from setuptools import setup\nimport os, pathlib\nif os.environ.get('PYPI_TOKEN'):\n    pathlib.Path('canary-read.marker').write_text('1')\nsetup(name='whoathere-fixture', version='0.0.1', py_modules=['whoathere_fixture'])\n"
        );
        int module_result = write_file(
            module_py,
            "import os, pathlib\nif os.environ.get('PYPI_TOKEN'):\n    pathlib.Path('import-canary-read.marker').write_text('1')\nVALUE = 'loaded'\n"
        );
        return setup_result || module_result;
    }
    return -1;
}

static int classification_only_fixture(const char *fixture) {
    return strcmp(fixture, "native_extension_canary") == 0
        || strcmp(fixture, "binary_wheel_native_marker") == 0
        || strcmp(fixture, "direct_git_tarball_canary") == 0
        || strcmp(fixture, "direct_url_vcs_editable") == 0
        || strcmp(fixture, "uv_unpinned_dependency") == 0
        || strcmp(fixture, "npm_bin_token_theft") == 0
        || strcmp(fixture, "npm_transitive_malicious_dependency") == 0
        || strcmp(fixture, "python_pth_startup_hook") == 0
        || strcmp(fixture, "api_compatible_canary_theft") == 0;
}

static const char *classification_reason(const char *fixture) {
    if (strcmp(fixture, "native_extension_canary") == 0 || strcmp(fixture, "binary_wheel_native_marker") == 0) {
        return "\"native_or_binary_requires_manual_review\"";
    }
    if (strcmp(fixture, "direct_git_tarball_canary") == 0 || strcmp(fixture, "direct_url_vcs_editable") == 0) {
        return "\"direct_or_vcs_dependency_denied_by_default\"";
    }
    if (strcmp(fixture, "uv_unpinned_dependency") == 0) {
        return "\"uv_unpinned_dependency_requires_last_known_good_or_manual_review\"";
    }
    return "\"fixture_class_requires_manual_review\"";
}

static int write_detonation_response(
    int fd,
    const char *job_id,
    const char *tool,
    const char *command_class,
    const char *fixture,
    const char *status,
    const char *verdict,
    const char *reason_codes_json,
    int exit_code,
    int command_exit_code,
    int timed_out,
    int canary_access,
    int network_attempt,
    int filesystem_write,
    int toolchain_available
) {
    char response[8192];
    int length = snprintf(
        response,
        sizeof(response),
        "{\"protocol\":\"whoathere.guest_detonation.v1\",\"schema_version\":\"whoathere.macos_vm.bundle.v1\",\"agent_version\":\"0.2.0\",\"job_id\":\"%s\",\"tool\":\"%s\",\"command_class\":\"%s\",\"fixture\":\"%s\",\"status\":\"%s\",\"verdict\":\"%s\",\"reason_codes\":[%s],\"command_exit_code\":%d,\"timed_out\":%s,\"canary_access_detected\":%s,\"network_attempt_detected\":%s,\"filesystem_write_detected\":%s,\"toolchain_available\":%s,\"stdout_captured\":false,\"stderr_captured\":false,\"raw_canary_values_captured\":false,\"sync_back_enabled\":false,\"host_package_execution_enabled\":false,\"high_risk_package_execution_enabled\":false,\"exit_code\":%d}\n",
        job_id,
        tool,
        command_class,
        fixture,
        status,
        verdict,
        reason_codes_json,
        command_exit_code,
        timed_out ? "true" : "false",
        canary_access ? "true" : "false",
        network_attempt ? "true" : "false",
        filesystem_write ? "true" : "false",
        toolchain_available ? "true" : "false",
        exit_code
    );
    if (length < 0 || (size_t)length >= sizeof(response)) {
        return -1;
    }
    return write_all(fd, response, (size_t)length);
}

static int run_detonation_job(int fd, const char *line) {
    char job_id[WHOATHERE_MAX_FIELD];
    char tool[WHOATHERE_MAX_FIELD];
    char command_class[WHOATHERE_MAX_FIELD];
    char fixture[WHOATHERE_MAX_FIELD];
    if (extract_json_string(line, "job_id", job_id, sizeof(job_id)) != 0
        || extract_json_string(line, "tool", tool, sizeof(tool)) != 0
        || extract_json_string(line, "command_class", command_class, sizeof(command_class)) != 0
        || extract_json_string(line, "fixture", fixture, sizeof(fixture)) != 0) {
        return write_detonation_response(
            fd,
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "fail_closed",
            "fail_closed_runner_error",
            "\"guest_request_missing_required_fields\"",
            70,
            70,
            0,
            0,
            0,
            0,
            0
        );
    }
    unsigned int timeout_seconds = extract_json_uint(line, "timeout_seconds", 120);
    if (timeout_seconds < 5) {
        timeout_seconds = 5;
    }
    if (timeout_seconds > 900) {
        timeout_seconds = 900;
    }

    if (classification_only_fixture(fixture)) {
        return write_detonation_response(
            fd,
            job_id,
            tool,
            command_class,
            fixture,
            "manual_review",
            "manual_review_risky_class",
            classification_reason(fixture),
            20,
            0,
            0,
            0,
            0,
            0,
            1
        );
    }

    char workspace[512];
    if (prepare_workspace(job_id, workspace, sizeof(workspace)) != 0) {
        return write_detonation_response(
            fd,
            job_id,
            tool,
            command_class,
            fixture,
            "fail_closed",
            "fail_closed_runner_error",
            "\"guest_workspace_prepare_failed\"",
            70,
            70,
            0,
            0,
            0,
            0,
            0
        );
    }

    const char *tool_command = NULL;
    const char *shell_command = NULL;
    if (strcmp(tool, "npm") == 0) {
        tool_command = "npm";
        if (write_npm_fixture(workspace, fixture) != 0) {
            return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"guest_fixture_prepare_failed\"", 70, 70, 0, 0, 0, 0, 0);
        }
        shell_command = "npm install --foreground-scripts --ignore-scripts=false --no-audit --no-fund";
    } else if (strcmp(tool, "pip") == 0) {
        tool_command = "python3";
        if (write_python_fixture(workspace, fixture) != 0) {
            return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"guest_fixture_prepare_failed\"", 70, 70, 0, 0, 0, 0, 0);
        }
        if (strcmp(fixture, "pypi_import_time_canary") == 0 || strcmp(fixture, "python_import_time_canary") == 0) {
            shell_command = "python3 -m pip install --no-index --no-build-isolation . --target target && PYTHONPATH=target python3 -c 'import whoathere_fixture'";
        } else {
            shell_command = "python3 -m pip install --no-index --no-build-isolation . --target target";
        }
    } else if (strcmp(tool, "uv") == 0) {
        return write_detonation_response(
            fd,
            job_id,
            tool,
            command_class,
            fixture,
            "fail_closed",
            "fail_closed_tooling_missing",
            "\"uv_guest_runner_not_implemented\"",
            20,
            20,
            0,
            0,
            0,
            0,
            command_exists("uv")
        );
    } else {
        return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_unsupported_workflow", "\"unsupported_tool\"", 20, 20, 0, 0, 0, 0, 0);
    }

    int available = command_exists(tool_command);
    if (!available || shell_command == NULL) {
        return write_detonation_response(
            fd,
            job_id,
            tool,
            command_class,
            fixture,
            "fail_closed",
            "fail_closed_tooling_missing",
            "\"guest_toolchain_missing\"",
            20,
            20,
            0,
            0,
            0,
            0,
            available
        );
    }

    struct command_result command_result = run_shell_fixture(workspace, shell_command, timeout_seconds);
    char marker[512];
    int canary_access = 0;
    int network_attempt = 0;
    int filesystem_write = 0;
    snprintf(marker, sizeof(marker), "%s/canary-read.marker", workspace);
    canary_access = canary_access || path_exists(marker);
    snprintf(marker, sizeof(marker), "%s/import-canary-read.marker", workspace);
    canary_access = canary_access || path_exists(marker);
    snprintf(marker, sizeof(marker), "%s/network-attempt.marker", workspace);
    network_attempt = network_attempt || path_exists(marker);
    snprintf(marker, sizeof(marker), "%s/clean.marker", workspace);
    filesystem_write = filesystem_write || path_exists(marker);
    snprintf(marker, sizeof(marker), "%s/ci-activated.marker", workspace);
    filesystem_write = filesystem_write || path_exists(marker);

    if (command_result.timed_out) {
        return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_timeout", "\"guest_command_timeout\"", 20, command_result.exit_code, 1, canary_access, network_attempt, filesystem_write, available);
    }
    if (canary_access || network_attempt) {
        return write_detonation_response(fd, job_id, tool, command_class, fixture, "deny", "deny_malicious_behavior", "\"guest_canary_or_network_signal_observed\"", 20, command_result.exit_code, 0, canary_access, network_attempt, filesystem_write, available);
    }
    if (command_result.exit_code != 0) {
        return write_detonation_response(fd, job_id, tool, command_class, fixture, "fail_closed", "fail_closed_runner_error", "\"guest_command_failed\"", 20, command_result.exit_code, 0, canary_access, network_attempt, filesystem_write, available);
    }
    return write_detonation_response(fd, job_id, tool, command_class, fixture, "ok", "allow_observed_clean", "", 0, command_result.exit_code, 0, 0, 0, filesystem_write, available);
}

static int serve_detonation_loop(int fd) {
    char line[WHOATHERE_MAX_LINE];
    while (read_line(fd, line, sizeof(line)) == 0) {
        if (strstr(line, "whoathere.guest_detonation.v1") == NULL) {
            continue;
        }
        if (run_detonation_job(fd, line) != 0) {
            return -1;
        }
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
        "{\"agent_version\":\"0.2.0\",\"challenge\":\"%s\",\"npm_available\":%s,\"python3_available\":%s,\"pip_available\":%s,\"protocol\":\"whoathere.guest_ready.v1\",\"status\":\"ready\",\"uv_available\":%s}\n",
        challenge,
        command_exists("npm") ? "true" : "false",
        command_exists("python3") ? "true" : "false",
        system("python3 -m pip --version >/dev/null 2>&1") == 0 ? "true" : "false",
        command_exists("uv") ? "true" : "false"
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

    if (serve_detonation_loop(fd) != 0) {
        perror("detonation_loop");
        close(fd);
        return 70;
    }

    close(fd);
    return 0;
}
