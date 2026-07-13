#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 /absolute/input-directory /absolute/image-directory" >&2
    exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/runtime-inputs-common.sh"
input_dir=$1
image=$2
runtime_require_absolute_path "$image"
for command in awk cmp docker file find jq shasum stat; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command missing: $command" >&2
        exit 69
    fi
done
runtime_verify_inputs "$input_dir"
runtime_verify_container_image
if [ ! -d "$image" ] || [ -L "$image" ]; then
    echo "runtime image directory must be a non-symlink directory" >&2
    exit 66
fi
for name in rootfs.tar rootfs.ext2 package-runtime-probe runtime-manifest.json runtime-inputs.lock; do
    if [ ! -f "$image/$name" ] || [ -L "$image/$name" ]; then
        echo "required runtime image file missing: $name" >&2
        exit 66
    fi
done
if [ -n "$(find "$image" -type l -print -quit)" ] || \
   [ "$(find "$image" -type f | wc -l | tr -d ' ')" != 5 ]
then
    echo "runtime image directory contains unexpected files" >&2
    exit 65
fi
if ! cmp -s "$runtime_input_lock" "$image/runtime-inputs.lock"; then
    echo "runtime image lock copy mismatch" >&2
    exit 65
fi

manifest="$image/runtime-manifest.json"
canonical_manifest=$(mktemp "${TMPDIR:-/tmp}/whoathere-runtime-manifest.XXXXXX")
cleanup() {
    rm -f "$canonical_manifest"
}
trap cleanup EXIT HUP INT TERM
jq -cS . "$manifest" > "$canonical_manifest"
if ! cmp -s "$canonical_manifest" "$manifest"; then
    echo "runtime manifest is not canonical sorted compact JSON" >&2
    exit 65
fi
expected_keys='["alpine_release","architecture","builder_source_sha256","candidate_runtime_qualification","container_builder_source_sha256","external_network","image_state","node_executable_sha256","node_version","npm_cli_sha256","npm_version","package_execution","package_gid","package_runner_mode","package_runner_sha256","package_uid","pip_entrypoint_sha256","pip_version","python_executable_sha256","python_version","reproducible_epoch","rootfs_byte_length","rootfs_format","rootfs_sha256","rootfs_tar_byte_length","rootfs_tar_sha256","rootfs_uuid","runtime_container_arm64_image_id","runtime_container_digest","runtime_inputs_lock_sha256","runtime_probe_source_sha256","schema_version","source_minirootfs_sha256","sync_back","zig_version"]'
if [ "$(jq -c 'keys' "$manifest")" != "$expected_keys" ]; then
    echo "runtime manifest key set mismatch" >&2
    exit 65
fi
require_value() {
    field=$1
    expected=$2
    actual=$(jq -r --arg field "$field" '.[$field]' "$manifest")
    if [ "$actual" != "$expected" ]; then
        echo "runtime manifest value mismatch: $field" >&2
        exit 65
    fi
}
require_hash() {
    field=$1
    path=$2
    require_value "$field" "sha256:$(shasum -a 256 "$path" | awk '{print $1}')"
}
require_value schema_version whoathere.linux_vz_package_runtime_manifest.v1
require_value architecture aarch64
require_value alpine_release 3.24.1
require_value image_state candidate_exact_bytes_not_yet_independently_qualified
require_value candidate_runtime_qualification required
require_value rootfs_format raw_ext2_block_image_v1
require_value rootfs_uuid "$runtime_rootfs_uuid"
require_value reproducible_epoch "$runtime_reproducible_epoch"
require_value runtime_container_digest "$runtime_container_digest"
require_value runtime_container_arm64_image_id "$runtime_container_arm64_image_id"
require_value source_minirootfs_sha256 sha256:f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259
require_value node_version v24.17.0
require_value npm_version 11.12.1
require_value python_version 3.14.5
require_value pip_version 26.1.2
require_value package_uid 65534
require_value package_gid 65534
require_value package_runner_mode nonexecuting_runtime_probe_with_closed_sensor_alias
require_value external_network structurally_absent
require_value zig_version 0.15.2
require_value package_execution false
require_value sync_back false
require_value rootfs_byte_length "$(stat -f '%z' "$image/rootfs.ext2")"
require_value rootfs_tar_byte_length "$(stat -f '%z' "$image/rootfs.tar")"
require_hash rootfs_sha256 "$image/rootfs.ext2"
require_hash rootfs_tar_sha256 "$image/rootfs.tar"
require_hash package_runner_sha256 "$image/package-runtime-probe"
require_hash runtime_inputs_lock_sha256 "$runtime_input_lock"
require_hash runtime_probe_source_sha256 "$runtime_source_dir/guest/package_runtime_probe.c"
require_hash builder_source_sha256 "$script_dir/build-pinned-runtime-rootfs.sh"
require_hash container_builder_source_sha256 "$script_dir/build-rootfs-in-container.sh"
case "$(file "$image/package-runtime-probe")" in
    *"ELF 64-bit"*"ARM aarch64"*"statically linked"*"stripped"*) ;;
    *) echo "runtime probe binary contract mismatch" >&2; exit 65 ;;
esac

docker run --rm --network none \
    -v "$input_dir:/inputs:ro" \
    -v "$image:/image:ro" \
    -v "$script_dir/verify-rootfs-in-container.sh:/whoathere-verifier:ro" \
    "$runtime_container_image" sh /whoathere-verifier
printf '%s\n' '{"candidate_runtime_qualified":false,"execution_authority":false,"package_execution":false,"status":"verified_exact_candidate_runtime","sync_back":false}'
