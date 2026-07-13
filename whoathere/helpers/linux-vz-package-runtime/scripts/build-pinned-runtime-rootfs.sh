#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 /absolute/input-directory /absolute/new-output-directory" >&2
    exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/runtime-inputs-common.sh"

input_dir=$1
final_output=$2
runtime_require_absolute_path "$final_output"
for command in awk cmp docker file find jq shasum stat zig; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command missing: $command" >&2
        exit 69
    fi
done
runtime_verify_inputs "$input_dir"
runtime_verify_container_image
if [ "$(zig version)" != 0.15.2 ]; then
    echo "pinned Zig 0.15.2 is required" >&2
    exit 69
fi
if [ -e "$final_output" ] || [ -L "$final_output" ]; then
    echo "output path must not already exist" >&2
    exit 73
fi

output_parent=$(dirname -- "$final_output")
output_name=$(basename -- "$final_output")
case "$output_name" in
    ""|"."|"..") echo "invalid output directory name" >&2; exit 64 ;;
esac
mkdir -p "$output_parent"
output_parent=$(CDPATH= cd -- "$output_parent" && pwd -P)
final_output="$output_parent/$output_name"
work_output=$(mktemp -d "$output_parent/.${output_name}.tmp.XXXXXX")
build_root=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-linux-vz-runtime.XXXXXX")
cleanup() {
    rm -rf "$build_root"
    if [ -n "$work_output" ]; then
        rm -rf "$work_output"
    fi
}
trap cleanup EXIT HUP INT TERM

runner_source="$runtime_source_dir/guest/package_runtime_probe.c"
runner="$build_root/whoathere-package-runtime-probe"
zig cc -target aarch64-linux-musl -O2 -Wall -Wextra -Werror -fno-ident -static -s \
    -o "$runner" "$runner_source"
case "$(file "$runner")" in
    *"ELF 64-bit"*"ARM aarch64"*"statically linked"*"stripped"*) ;;
    *) echo "runtime probe is not a stripped static aarch64 Linux executable" >&2; exit 65 ;;
esac

mkdir -p "$work_output/artifacts"
docker run --rm --network none \
    -v "$input_dir:/inputs:ro" \
    -v "$work_output:/work" \
    -v "$runner:/runner/whoathere-package-runtime-probe:ro" \
    -v "$script_dir/build-rootfs-in-container.sh:/whoathere-builder:ro" \
    "$runtime_container_image" sh /whoathere-builder

artifacts="$work_output/artifacts"
for path in \
    "$artifacts/rootfs.tar" "$artifacts/rootfs.ext2" \
    "$artifacts/package-runtime-probe" "$artifacts/node-version.txt" \
    "$artifacts/npm-version.txt" "$artifacts/python-version.txt" \
    "$artifacts/pip-version.txt" "$artifacts/probe-report.json" \
    "$artifacts/node-sha256.txt" "$artifacts/npm-cli-sha256.txt" \
    "$artifacts/python-sha256.txt" "$artifacts/pip-entrypoint-sha256.txt"
do
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        echo "builder omitted a required runtime artifact" >&2
        exit 65
    fi
done

node_version=$(tr -d '\n' < "$artifacts/node-version.txt")
npm_version=$(tr -d '\n' < "$artifacts/npm-version.txt")
python_version=$(tr -d '\n' < "$artifacts/python-version.txt")
pip_version=$(tr -d '\n' < "$artifacts/pip-version.txt")
test "$node_version" = v24.17.0
test "$npm_version" = 11.12.1
test "$python_version" = 'Python 3.14.5'
case "$pip_version" in
    'pip 26.1.2 from '*'/pip (python 3.14)') ;;
    *) echo "builder returned the wrong pip identity" >&2; exit 65 ;;
esac

digest() {
    printf 'sha256:%s\n' "$(shasum -a 256 "$1" | awk '{print $1}')"
}
byte_length() {
    stat -f '%z' "$1"
}

rootfs_sha256=$(digest "$artifacts/rootfs.ext2")
rootfs_byte_length=$(byte_length "$artifacts/rootfs.ext2")
rootfs_tar_sha256=$(digest "$artifacts/rootfs.tar")
rootfs_tar_byte_length=$(byte_length "$artifacts/rootfs.tar")
package_runner_sha256=$(digest "$artifacts/package-runtime-probe")
runtime_inputs_lock_sha256=$(digest "$runtime_input_lock")
runtime_probe_source_sha256=$(digest "$runner_source")
builder_source_sha256=$(digest "$script_dir/build-pinned-runtime-rootfs.sh")
container_builder_source_sha256=$(digest "$script_dir/build-rootfs-in-container.sh")
node_executable_sha256="sha256:$(tr -d '\n' < "$artifacts/node-sha256.txt")"
npm_cli_sha256="sha256:$(tr -d '\n' < "$artifacts/npm-cli-sha256.txt")"
python_executable_sha256="sha256:$(tr -d '\n' < "$artifacts/python-sha256.txt")"
pip_entrypoint_sha256="sha256:$(tr -d '\n' < "$artifacts/pip-entrypoint-sha256.txt")"

jq -ncS \
    --arg architecture aarch64 \
    --arg alpine_release 3.24.1 \
    --arg builder_source_sha256 "$builder_source_sha256" \
    --arg container_builder_source_sha256 "$container_builder_source_sha256" \
    --arg image_state candidate_exact_bytes_not_yet_independently_qualified \
    --arg node_executable_sha256 "$node_executable_sha256" \
    --arg node_version "$node_version" \
    --arg npm_cli_sha256 "$npm_cli_sha256" \
    --arg npm_version "$npm_version" \
    --arg package_runner_sha256 "$package_runner_sha256" \
    --arg pip_entrypoint_sha256 "$pip_entrypoint_sha256" \
    --arg pip_version 26.1.2 \
    --arg python_executable_sha256 "$python_executable_sha256" \
    --arg python_version 3.14.5 \
    --arg rootfs_byte_length "$rootfs_byte_length" \
    --arg rootfs_format raw_ext2_block_image_v1 \
    --arg rootfs_sha256 "$rootfs_sha256" \
    --arg rootfs_tar_byte_length "$rootfs_tar_byte_length" \
    --arg rootfs_tar_sha256 "$rootfs_tar_sha256" \
    --arg rootfs_uuid "$runtime_rootfs_uuid" \
    --arg runtime_container_arm64_image_id "$runtime_container_arm64_image_id" \
    --arg runtime_container_digest "$runtime_container_digest" \
    --arg runtime_inputs_lock_sha256 "$runtime_inputs_lock_sha256" \
    --arg runtime_probe_source_sha256 "$runtime_probe_source_sha256" \
    --arg schema_version whoathere.linux_vz_package_runtime_manifest.v1 \
    --arg source_minirootfs_sha256 sha256:f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259 \
    --arg reproducible_epoch "$runtime_reproducible_epoch" \
    --arg zig_version 0.15.2 \
    '{architecture:$architecture,alpine_release:$alpine_release,builder_source_sha256:$builder_source_sha256,candidate_runtime_qualification:"required",container_builder_source_sha256:$container_builder_source_sha256,external_network:"structurally_absent",image_state:$image_state,node_executable_sha256:$node_executable_sha256,node_version:$node_version,npm_cli_sha256:$npm_cli_sha256,npm_version:$npm_version,package_execution:false,package_gid:"65534",package_runner_mode:"nonexecuting_runtime_probe_with_closed_sensor_alias",package_runner_sha256:$package_runner_sha256,package_uid:"65534",pip_entrypoint_sha256:$pip_entrypoint_sha256,pip_version:$pip_version,python_executable_sha256:$python_executable_sha256,python_version:$python_version,reproducible_epoch:$reproducible_epoch,rootfs_byte_length:$rootfs_byte_length,rootfs_format:$rootfs_format,rootfs_sha256:$rootfs_sha256,rootfs_tar_byte_length:$rootfs_tar_byte_length,rootfs_tar_sha256:$rootfs_tar_sha256,rootfs_uuid:$rootfs_uuid,runtime_container_arm64_image_id:$runtime_container_arm64_image_id,runtime_container_digest:$runtime_container_digest,runtime_inputs_lock_sha256:$runtime_inputs_lock_sha256,runtime_probe_source_sha256:$runtime_probe_source_sha256,schema_version:$schema_version,source_minirootfs_sha256:$source_minirootfs_sha256,sync_back:false,zig_version:$zig_version}' \
    > "$artifacts/runtime-manifest.json"
cp "$runtime_input_lock" "$artifacts/runtime-inputs.lock"
rm -f "$artifacts/node-version.txt" "$artifacts/npm-version.txt" \
    "$artifacts/python-version.txt" "$artifacts/pip-version.txt" "$artifacts/probe-report.json" \
    "$artifacts/node-sha256.txt" "$artifacts/npm-cli-sha256.txt" \
    "$artifacts/python-sha256.txt" "$artifacts/pip-entrypoint-sha256.txt"
if [ -e "$final_output" ] || [ -L "$final_output" ]; then
    echo "output path appeared during build" >&2
    exit 73
fi
mv "$artifacts" "$final_output"
work_output=
printf '%s\n' "$final_output/runtime-manifest.json"
