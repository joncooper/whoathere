#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 /absolute/input-directory /absolute/package-root-runtime /absolute/image-directory" >&2
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
image=$3
runtime_require_absolute_path "$runner"
runtime_require_absolute_path "$image"
for command in awk cmp docker file find jq shasum stat; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command missing: $command" >&2
        exit 69
    fi
done
runtime_verify_inputs "$input_dir"
runtime_verify_container_image
if [ ! -f "$runner" ] || [ -L "$runner" ] || [ ! -d "$image" ] || [ -L "$image" ]; then
    echo "execution runtime verification input invalid" >&2
    exit 66
fi
for name in rootfs.tar rootfs.ext2 package-root-runtime runtime-manifest.json runtime-inputs.lock; do
    if [ ! -f "$image/$name" ] || [ -L "$image/$name" ]; then
        echo "required execution-runtime image file missing: $name" >&2
        exit 66
    fi
done
if [ -n "$(find "$image" -type l -print -quit)" ] || \
   [ "$(find "$image" -type f | wc -l | tr -d ' ')" != 5 ]
then
    echo "execution-runtime image directory contains unexpected files" >&2
    exit 65
fi
cmp "$runtime_input_lock" "$image/runtime-inputs.lock"
cmp "$runner" "$image/package-root-runtime"

manifest="$image/runtime-manifest.json"
canonical_manifest=$(mktemp "${TMPDIR:-/tmp}/whoathere-execution-runtime-manifest.XXXXXX")
cleanup() { rm -f "$canonical_manifest"; }
trap cleanup EXIT HUP INT TERM
jq -cS . "$manifest" > "$canonical_manifest"
cmp "$canonical_manifest" "$manifest"
expected_keys='["alpine_release","architecture","builder_source_sha256","candidate_runtime_qualification","cargo_lock_sha256","container_builder_source_sha256","external_network","image_state","node_executable_sha256","node_version","npm_cli_sha256","npm_version","package_execution","package_execution_authority","package_gid","package_runner_byte_length","package_runner_mode","package_runner_path","package_runner_sha256","package_uid","pip_entrypoint_sha256","pip_version","python_executable_sha256","python_version","reproducible_epoch","rootfs_byte_length","rootfs_format","rootfs_sha256","rootfs_tar_byte_length","rootfs_tar_sha256","rootfs_uuid","runtime_common_source_sha256","runtime_container_arm64_image_id","runtime_container_digest","runtime_inputs_lock_sha256","runtime_source_closure_sha256","schema_version","source_minirootfs_sha256","sync_back","workspace_manifest_sha256"]'
if [ "$(jq -c 'keys' "$manifest")" != "$expected_keys" ]; then
    echo "execution runtime manifest key set mismatch" >&2
    exit 65
fi

require_value() {
    field=$1
    expected=$2
    actual=$(jq -r --arg field "$field" '.[$field]' "$manifest")
    if [ "$actual" != "$expected" ]; then
        echo "execution runtime manifest value mismatch: $field" >&2
        exit 65
    fi
}
require_hash() {
    field=$1
    path=$2
    require_value "$field" "sha256:$(shasum -a 256 "$path" | awk '{print $1}')"
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

require_value schema_version whoathere.linux_vz_package_execution_runtime_manifest.v1
require_value architecture aarch64
require_value alpine_release 3.24.1
require_value image_state candidate_exact_bytes_not_yet_execution_qualified
require_value candidate_runtime_qualification required
require_value package_execution_authority structurally_unavailable_until_verified_qualification_and_signed_one_use_grant
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
require_value node_executable_sha256 sha256:cc4c34a01f8ce88bd220f59876de049754c6c73789157e380a095504224aa9e1
require_value npm_cli_sha256 sha256:8e5f6f3429f8cdbe693cdc29904e9d5a7b127a494bd15c804bd54c7403bfcbe7
require_value python_executable_sha256 sha256:95f57c0555bdc6237e2a70f1c88e0bcef04732131f2023728ea9c5baa63964c4
require_value pip_entrypoint_sha256 sha256:6d1f19b17ef3ab9b6d3532be2198766bb1709c83da6a6684152b8af1930da6fa
require_value package_uid 65534
require_value package_gid 65534
require_value package_runner_mode fixed_root_coordinator_authenticated_evidence_v1
require_value package_runner_path /whoathere/package-root-runtime
require_value external_network structurally_absent
require_value package_execution false
require_value sync_back false
require_value package_runner_byte_length "$(stat -f '%z' "$runner")"
require_value rootfs_byte_length "$(stat -f '%z' "$image/rootfs.ext2")"
require_value rootfs_tar_byte_length "$(stat -f '%z' "$image/rootfs.tar")"
require_hash rootfs_sha256 "$image/rootfs.ext2"
require_hash rootfs_tar_sha256 "$image/rootfs.tar"
require_hash package_runner_sha256 "$runner"
require_hash runtime_inputs_lock_sha256 "$runtime_input_lock"
require_hash runtime_common_source_sha256 "$runtime_common_dir/runtime-inputs-common.sh"
require_hash cargo_lock_sha256 "$whoathere_root/Cargo.lock"
require_hash workspace_manifest_sha256 "$whoathere_root/Cargo.toml"
require_hash builder_source_sha256 "$script_dir/build-execution-runtime-rootfs.sh"
require_hash container_builder_source_sha256 "$script_dir/build-rootfs-in-container.sh"
require_value runtime_source_closure_sha256 "$(source_closure_digest)"
case "$(file "$runner")" in
    *"ELF 64-bit"*"ARM aarch64"*"statically linked"*"stripped"*) ;;
    *) echo "execution runtime binary contract mismatch" >&2; exit 65 ;;
esac

docker run --rm --network none \
    -v "$input_dir:/inputs:ro" \
    -v "$image:/image:ro" \
    -v "$script_dir/verify-rootfs-in-container.sh:/whoathere-verifier:ro" \
    "$runtime_container_image" sh /whoathere-verifier
printf '%s\n' '{"execution_authority":false,"package_execution":false,"status":"verified_exact_execution_runtime_candidate","sync_back":false}'
