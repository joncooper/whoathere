#!/usr/bin/env python3
"""Hermetic source-contract tests for the package execution guest init."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
INIT_TEMPLATE = (
    REPO_ROOT
    / "whoathere"
    / "helpers"
    / "linux-vz-package-execution-runtime"
    / "execution"
    / "guest"
    / "init.template"
)


def assert_in_order(source: str, *tokens: str) -> None:
    cursor = 0
    for token in tokens:
        position = source.find(token, cursor)
        assert position >= 0, f"missing or misordered init contract token: {token!r}"
        cursor = position + len(token)


def main() -> None:
    source = INIT_TEMPLATE.read_text(encoding="utf-8")
    call = "quiesce_kernel_console_for_evidence"

    calls = [line.strip() for line in source.splitlines()].count(call)
    assert calls == 2, f"expected exactly two console-quiesce calls, found {calls}"

    partial_start = source.index("if ! /whoathere/execution-descriptor-launcher; then")
    partial_end = source.index("\nfi\n", partial_start)
    partial_path = source[partial_start:partial_end]
    assert_in_order(
        partial_path,
        call,
        "emit_base64_file WHOATHERE_PACKAGE_EXECUTION_PARTIAL_RESULT_BASE64",
        "emit_base64_file WHOATHERE_PACKAGE_EXECUTION_CHILD_LOG_BASE64",
        "fail package_runtime_failed",
    )

    complete_start = partial_end + len("\nfi\n")
    complete_end = source.index('\n"$busybox" rm -f', complete_start)
    complete_path = source[complete_start:complete_end]
    assert_in_order(
        complete_path,
        "[ ! -e /whoathere/guest-ed25519.seed ] || fail signing_seed_path_retained",
        call,
        "emit_base64_file WHOATHERE_PACKAGE_EXECUTION_RESULT_BASE64",
        "emit_base64_file WHOATHERE_PACKAGE_EXECUTION_CHILD_LOG_BASE64",
    )

    function_start = source.index(f"{call}() {{")
    function_end = source.index("\n}\n", function_start)
    function = source[function_start:function_end]
    assert "[ -w /proc/sys/kernel/printk ] || fail" in function
    assert "|| fail kernel_console_control_failed" in function
    assert 'console_level=$("$busybox" awk' in function
    assert '[ "$console_level" = 1 ] || fail' in function
    assert '"$busybox" sleep 0.1 || fail' in function

    print("execution_runtime_init_selftest=passed")


if __name__ == "__main__":
    main()
