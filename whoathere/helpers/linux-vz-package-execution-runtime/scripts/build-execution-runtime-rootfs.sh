#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 /absolute/input-directory /absolute/package-root-runtime /absolute/new-output-directory" >&2
    exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
runtime_common_dir=$(CDPATH= cd -- "$script_dir/../../linux-vz-package-runtime/scripts" && pwd)
. "$runtime_common_dir/runtime-inputs-common.sh"
runtime_script_dir=$runtime_common_dir
runtime_source_dir=$(CDPATH= cd -- "$runtime_script_dir/.." && pwd)
runtime_input_lock="$runtime_source_dir/config/runtime-inputs.lock"
whoathere_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)

input_dir=$1
runner=$2
final_output=$3
runtime_require_absolute_path "$runner"
runtime_require_absolute_path "$final_output"
for command in awk cmp docker file find jq shasum stat; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command missing: $command" >&2
        exit 69
    fi
done
runtime_verify_inputs "$input_dir"
runtime_verify_container_image
if [ ! -f "$runner" ] || [ -L "$runner" ]; then
    echo "package root runtime must be a regular non-symlink file" >&2
    exit 66
fi
case "$(file "$runner")" in
    *"ELF 64-bit"*"ARM aarch64"*"statically linked"*"stripped"*) ;;
    *) echo "package root runtime is not a stripped static aarch64 Linux executable" >&2; exit 65 ;;
esac
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
cleanup() {
    if [ -n "$work_output" ]; then
        rm -rf "$work_output"
    fi
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work_output/artifacts"
docker run --rm --network none \
    -v "$input_dir:/inputs:ro" \
    -v "$work_output:/work" \
    -v "$runner:/runner/whoathere-linux-vz-package-root-runtime:ro" \
    -v "$script_dir/build-rootfs-in-container.sh:/whoathere-builder:ro" \
    "$runtime_container_image" sh /whoathere-builder

artifacts="$work_output/artifacts"
for path in \
    "$artifacts/rootfs.tar" "$artifacts/rootfs.ext2" \
    "$artifacts/package-root-runtime" "$artifacts/node-version.txt" \
    "$artifacts/npm-version.txt" "$artifacts/python-version.txt" \
    "$artifacts/pip-version.txt" "$artifacts/node-sha256.txt" \
    "$artifacts/npm-cli-sha256.txt" "$artifacts/python-sha256.txt" \
    "$artifacts/pip-entrypoint-sha256.txt"
do
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        echo "builder omitted a required execution-runtime artifact" >&2
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
source_closure_digest() {
    {
        find "$whoathere_root/crates" -type f \( -name '*.rs' -o -name Cargo.toml \) -print
        printf '%s\n' "$whoathere_root/Cargo.toml" "$whoathere_root/Cargo.lock"
    } | LC_ALL=C sort | while IFS= read -r path; do
        relative=${path#"$whoathere_root/"}
        printf '%s\t%s\t%s\n' "$relative" "$(stat -f '%z' "$path")" \
            "$(shasum -a 256 "$path" | awk '{print $1}')"
    done | shasum -a 256 | awk '{print "sha256:" $1}'
}

rootfs_sha256=$(digest "$artifacts/rootfs.ext2")
rootfs_byte_length=$(byte_length "$artifacts/rootfs.ext2")
rootfs_tar_sha256=$(digest "$artifacts/rootfs.tar")
rootfs_tar_byte_length=$(byte_length "$artifacts/rootfs.tar")
package_runner_sha256=$(digest "$artifacts/package-root-runtime")
package_runner_byte_length=$(byte_length "$artifacts/package-root-runtime")
runtime_inputs_lock_sha256=$(digest "$runtime_input_lock")
runtime_common_source_sha256=$(digest "$runtime_common_dir/runtime-inputs-common.sh")
builder_source_sha256=$(digest "$script_dir/build-execution-runtime-rootfs.sh")
container_builder_source_sha256=$(digest "$script_dir/build-rootfs-in-container.sh")
runtime_source_closure_sha256=$(source_closure_digest)
cargo_lock_sha256=$(digest "$whoathere_root/Cargo.lock")
workspace_manifest_sha256=$(digest "$whoathere_root/Cargo.toml")
node_executable_sha256="sha256:$(tr -d '\n' < "$artifacts/node-sha256.txt")"
npm_cli_sha256="sha256:$(tr -d '\n' < "$artifacts/npm-cli-sha256.txt")"
python_executable_sha256="sha256:$(tr -d '\n' < "$artifacts/python-sha256.txt")"
pip_entrypoint_sha256="sha256:$(tr -d '\n' < "$artifacts/pip-entrypoint-sha256.txt")"

jq -ncS \
    --arg alpine_release 3.24.1 \
    --arg builder_source_sha256 "$builder_source_sha256" \
    --arg cargo_lock_sha256 "$cargo_lock_sha256" \
    --arg container_builder_source_sha256 "$container_builder_source_sha256" \
    --arg node_executable_sha256 "$node_executable_sha256" \
    --arg node_version "$node_version" \
    --arg npm_cli_sha256 "$npm_cli_sha256" \
    --arg npm_version "$npm_version" \
    --arg package_runner_byte_length "$package_runner_byte_length" \
    --arg package_runner_sha256 "$package_runner_sha256" \
    --arg pip_entrypoint_sha256 "$pip_entrypoint_sha256" \
    --arg python_executable_sha256 "$python_executable_sha256" \
    --arg rootfs_byte_length "$rootfs_byte_length" \
    --arg rootfs_sha256 "$rootfs_sha256" \
    --arg rootfs_tar_byte_length "$rootfs_tar_byte_length" \
    --arg rootfs_tar_sha256 "$rootfs_tar_sha256" \
    --arg rootfs_uuid "$runtime_rootfs_uuid" \
    --arg runtime_container_arm64_image_id "$runtime_container_arm64_image_id" \
    --arg runtime_container_digest "$runtime_container_digest" \
    --arg runtime_common_source_sha256 "$runtime_common_source_sha256" \
    --arg runtime_inputs_lock_sha256 "$runtime_inputs_lock_sha256" \
    --arg runtime_source_closure_sha256 "$runtime_source_closure_sha256" \
    --arg workspace_manifest_sha256 "$workspace_manifest_sha256" \
    --arg reproducible_epoch "$runtime_reproducible_epoch" \
    '{alpine_release:$alpine_release,architecture:"aarch64",builder_source_sha256:$builder_source_sha256,candidate_runtime_qualification:"required",cargo_lock_sha256:$cargo_lock_sha256,container_builder_source_sha256:$container_builder_source_sha256,external_network:"structurally_absent",image_state:"candidate_exact_bytes_not_yet_execution_qualified",node_executable_sha256:$node_executable_sha256,node_version:$node_version,npm_cli_sha256:$npm_cli_sha256,npm_version:$npm_version,package_execution:false,package_execution_authority:"structurally_unavailable_until_verified_qualification_and_signed_one_use_grant",package_gid:"65534",package_runner_byte_length:$package_runner_byte_length,package_runner_mode:"fixed_root_coordinator_authenticated_evidence_v1",package_runner_path:"/whoathere/package-root-runtime",package_runner_sha256:$package_runner_sha256,package_uid:"65534",pip_entrypoint_sha256:$pip_entrypoint_sha256,pip_version:"26.1.2",python_executable_sha256:$python_executable_sha256,python_version:"3.14.5",reproducible_epoch:$reproducible_epoch,rootfs_byte_length:$rootfs_byte_length,rootfs_format:"raw_ext2_block_image_v1",rootfs_sha256:$rootfs_sha256,rootfs_tar_byte_length:$rootfs_tar_byte_length,rootfs_tar_sha256:$rootfs_tar_sha256,rootfs_uuid:$rootfs_uuid,runtime_common_source_sha256:$runtime_common_source_sha256,runtime_container_arm64_image_id:$runtime_container_arm64_image_id,runtime_container_digest:$runtime_container_digest,runtime_inputs_lock_sha256:$runtime_inputs_lock_sha256,runtime_source_closure_sha256:$runtime_source_closure_sha256,schema_version:"whoathere.linux_vz_package_execution_runtime_manifest.v1",source_minirootfs_sha256:"sha256:f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259",sync_back:false,workspace_manifest_sha256:$workspace_manifest_sha256}' \
    > "$artifacts/runtime-manifest.json"
cp "$runtime_input_lock" "$artifacts/runtime-inputs.lock"
rm -f "$artifacts/node-version.txt" "$artifacts/npm-version.txt" \
    "$artifacts/python-version.txt" "$artifacts/pip-version.txt" \
    "$artifacts/node-sha256.txt" "$artifacts/npm-cli-sha256.txt" \
    "$artifacts/python-sha256.txt" "$artifacts/pip-entrypoint-sha256.txt"
if [ -e "$final_output" ] || [ -L "$final_output" ]; then
    echo "output path appeared during build" >&2
    exit 73
fi
mv "$artifacts" "$final_output"
work_output=
printf '%s\n' "$final_output/runtime-manifest.json"
