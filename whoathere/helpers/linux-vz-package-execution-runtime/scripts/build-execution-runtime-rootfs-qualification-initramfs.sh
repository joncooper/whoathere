#!/bin/sh
set -eu
umask 077

if [ "$#" -ne 5 ]; then
    echo "usage: $0 /absolute/base-initramfs /absolute/execution-runtime-manifest.json /absolute/guest-ed25519.seed sha256:PUBLIC_KEY_DIGEST /absolute/new-output-directory" >&2
    exit 64
fi

base_initramfs=$1
runtime_manifest=$2
guest_seed=$3
public_key_sha256=$4
final_output=$5
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
init_template="$source_dir/qualification/guest/init.template"
newc_source="$source_dir/qualification/tools/canonical_execution_runtime_rootfs_qualification_newc.c"

for path in "$base_initramfs" "$runtime_manifest" "$guest_seed" "$final_output"; do
    case "$path" in
        /*) ;;
        *) echo "all file and output paths must be absolute" >&2; exit 64 ;;
    esac
done
for path in "$base_initramfs" "$runtime_manifest" "$guest_seed" "$init_template" "$newc_source"; do
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        echo "qualification input must be a regular non-symlink file: $path" >&2
        exit 66
    fi
done
if [ "$(stat -f '%z' "$guest_seed")" -ne 32 ]; then
    echo "guest signing seed must contain exactly 32 bytes" >&2
    exit 65
fi
if ! printf '%s\n' "$public_key_sha256" | grep -Eq '^sha256:[0-9a-f]{64}$'; then
    echo "guest public-key digest is invalid" >&2
    exit 64
fi
if [ -e "$final_output" ] || [ -L "$final_output" ]; then
    echo "output path must not already exist" >&2
    exit 73
fi
for command in cmp gzip jq sed shasum stat xcrun; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command missing: $command" >&2
        exit 69
    fi
done

canonical_manifest=$(mktemp "${TMPDIR:-/tmp}/whoathere-execution-runtime-manifest.XXXXXX")
cleanup_manifest() {
    rm -f "$canonical_manifest"
}
trap cleanup_manifest EXIT HUP INT TERM
jq -cS . "$runtime_manifest" > "$canonical_manifest"
if ! cmp -s "$canonical_manifest" "$runtime_manifest"; then
    echo "execution runtime manifest is not canonical newline-terminated JSON" >&2
    exit 65
fi
if [ "$(jq -er '.schema_version' "$runtime_manifest")" != \
     whoathere.linux_vz_package_execution_runtime_manifest.v1 ] || \
   [ "$(jq -er '.candidate_runtime_qualification' "$runtime_manifest")" != required ] || \
   [ "$(jq -er '.image_state' "$runtime_manifest")" != \
     candidate_exact_bytes_not_yet_execution_qualified ] || \
   [ "$(jq -er '.package_execution' "$runtime_manifest")" != false ] || \
   [ "$(jq -er '.sync_back' "$runtime_manifest")" != false ]
then
    echo "execution runtime manifest policy is invalid" >&2
    exit 65
fi

runtime_sha256=$(jq -er '.package_runner_sha256' "$runtime_manifest")
rootfs_sha256=$(jq -er '.rootfs_sha256' "$runtime_manifest")
rootfs_byte_length=$(jq -er '.rootfs_byte_length' "$runtime_manifest")
node_sha256=$(jq -er '.node_executable_sha256' "$runtime_manifest")
npm_cli_sha256=$(jq -er '.npm_cli_sha256' "$runtime_manifest")
python_sha256=$(jq -er '.python_executable_sha256' "$runtime_manifest")
pip_entrypoint_sha256=$(jq -er '.pip_entrypoint_sha256' "$runtime_manifest")
manifest_sha256="sha256:$(shasum -a 256 "$runtime_manifest" | awk '{print $1}')"
for digest in \
    "$runtime_sha256" "$rootfs_sha256" "$node_sha256" "$npm_cli_sha256" \
    "$python_sha256" "$pip_entrypoint_sha256" "$manifest_sha256"
do
    if ! printf '%s\n' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$'; then
        echo "execution runtime manifest contains an invalid digest" >&2
        exit 65
    fi
done

output_parent=$(dirname -- "$final_output")
output_name=$(basename -- "$final_output")
case "$output_name" in
    ""|"."|"..") echo "invalid output directory name" >&2; exit 64 ;;
esac
mkdir -p "$output_parent"
output_parent=$(CDPATH= cd -- "$output_parent" && pwd -P)
final_output="$output_parent/$output_name"
work_output=$(mktemp -d "$output_parent/.${output_name}.tmp.XXXXXX")
build_root=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-execution-runtime-rootfs-qualification.XXXXXX")
cleanup() {
    rm -rf "$build_root"
    if [ -n "$work_output" ]; then
        rm -rf "$work_output"
    fi
    cleanup_manifest
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$work_output/overlay/whoathere"

sed \
    -e "s|__WHOATHERE_RUNTIME_SHA256__|$runtime_sha256|g" \
    -e "s|__WHOATHERE_ROOTFS_SHA256__|$rootfs_sha256|g" \
    -e "s|__WHOATHERE_MANIFEST_SHA256__|$manifest_sha256|g" \
    -e "s|__WHOATHERE_NODE_SHA256__|$node_sha256|g" \
    -e "s|__WHOATHERE_NPM_CLI_SHA256__|$npm_cli_sha256|g" \
    -e "s|__WHOATHERE_PYTHON_SHA256__|$python_sha256|g" \
    -e "s|__WHOATHERE_PIP_ENTRYPOINT_SHA256__|$pip_entrypoint_sha256|g" \
    -e "s|__WHOATHERE_PUBLIC_KEY_SHA256__|$public_key_sha256|g" \
    "$init_template" > "$work_output/overlay/init"
if grep -q '__WHOATHERE_' "$work_output/overlay/init"; then
    echo "qualification init substitution was incomplete" >&2
    exit 65
fi
cp "$runtime_manifest" "$work_output/overlay/whoathere/execution-runtime-manifest.json"
cp "$guest_seed" "$work_output/overlay/whoathere/guest-ed25519.seed"
chmod 0755 "$work_output/overlay/init"
chmod 0711 "$work_output/overlay/whoathere"
chmod 0400 "$work_output/overlay/whoathere/execution-runtime-manifest.json" \
    "$work_output/overlay/whoathere/guest-ed25519.seed"

native_cc=$(xcrun --find clang)
native_sdk=$(xcrun --show-sdk-path)
"$native_cc" -O2 -Wall -Wextra -Werror -fno-ident -isysroot "$native_sdk" \
    -o "$build_root/canonical-execution-runtime-rootfs-qualification-newc" \
    "$newc_source"
overlay="$work_output/whoathere-execution-runtime-rootfs-qualification-overlay.cpio"
"$build_root/canonical-execution-runtime-rootfs-qualification-newc" \
    "$overlay" \
    "$work_output/overlay/init" \
    "$work_output/overlay/whoathere/execution-runtime-manifest.json" \
    "$work_output/overlay/whoathere/guest-ed25519.seed"
overlay_gzip="$overlay.gz"
gzip -n -9 -c "$overlay" > "$overlay_gzip"
final_initramfs="$work_output/whoathere-execution-runtime-rootfs-qualification-initramfs-virt"
cp "$base_initramfs" "$final_initramfs"
chmod 0600 "$final_initramfs"
/bin/cat "$overlay_gzip" >> "$final_initramfs"
chmod 0600 "$overlay" "$overlay_gzip" "$final_initramfs"

base_initramfs_sha256="sha256:$(shasum -a 256 "$base_initramfs" | awk '{print $1}')"
init_sha256="sha256:$(shasum -a 256 "$work_output/overlay/init" | awk '{print $1}')"
init_source_sha256="sha256:$(shasum -a 256 "$init_template" | awk '{print $1}')"
newc_source_sha256="sha256:$(shasum -a 256 "$newc_source" | awk '{print $1}')"
builder_source_sha256="sha256:$(shasum -a 256 "$script_dir/build-execution-runtime-rootfs-qualification-initramfs.sh" | awk '{print $1}')"
overlay_sha256="sha256:$(shasum -a 256 "$overlay" | awk '{print $1}')"
overlay_gzip_sha256="sha256:$(shasum -a 256 "$overlay_gzip" | awk '{print $1}')"
final_initramfs_sha256="sha256:$(shasum -a 256 "$final_initramfs" | awk '{print $1}')"

jq -ncS \
    --arg base_initramfs_sha256 "$base_initramfs_sha256" \
    --arg builder_source_sha256 "$builder_source_sha256" \
    --arg final_initramfs_sha256 "$final_initramfs_sha256" \
    --arg guest_public_key_sha256 "$public_key_sha256" \
    --arg init_sha256 "$init_sha256" \
    --arg init_source_sha256 "$init_source_sha256" \
    --arg manifest_sha256 "$manifest_sha256" \
    --arg newc_source_sha256 "$newc_source_sha256" \
    --arg node_sha256 "$node_sha256" \
    --arg npm_cli_sha256 "$npm_cli_sha256" \
    --arg overlay_gzip_sha256 "$overlay_gzip_sha256" \
    --arg overlay_sha256 "$overlay_sha256" \
    --arg pip_entrypoint_sha256 "$pip_entrypoint_sha256" \
    --arg python_sha256 "$python_sha256" \
    --arg rootfs_byte_length "$rootfs_byte_length" \
    --arg rootfs_sha256 "$rootfs_sha256" \
    --arg runtime_sha256 "$runtime_sha256" \
    '{architecture:"aarch64",base_initramfs_sha256:$base_initramfs_sha256,builder_source_sha256:$builder_source_sha256,candidate_runtime_manifest_sha256:$manifest_sha256,candidate_runtime_rootfs_byte_length:$rootfs_byte_length,candidate_runtime_rootfs_sha256:$rootfs_sha256,execution_authority_issued:false,external_network:"host_raw_frame_sinkhole_no_external_route",guest_evidence_public_key_sha256:$guest_public_key_sha256,node_executable_sha256:$node_sha256,npm_cli_sha256:$npm_cli_sha256,package_execution:false,package_execution_runtime_sha256:$runtime_sha256,pip_entrypoint_sha256:$pip_entrypoint_sha256,python_executable_sha256:$python_sha256,qualification_init_sha256:$init_sha256,qualification_init_source_sha256:$init_source_sha256,qualification_initramfs_sha256:$final_initramfs_sha256,qualification_operation:"fixed_root_coordinator_custody_probe_from_exact_read_only_rootfs",qualification_overlay_cpio_gzip_sha256:$overlay_gzip_sha256,qualification_overlay_cpio_sha256:$overlay_sha256,rootfs_attachment:"virtio_block_read_only",schema_version:"whoathere.linux_vz_package_execution_runtime_rootfs_qualification_image_manifest.v1",sync_back:false,writer_source_sha256:$newc_source_sha256}' \
    > "$work_output/manifest.json"
chmod 0600 "$work_output/manifest.json"
rm -f "$work_output/overlay/whoathere/guest-ed25519.seed"

if [ -e "$final_output" ] || [ -L "$final_output" ]; then
    echo "output path appeared during build" >&2
    exit 73
fi
mv "$work_output" "$final_output"
work_output=
printf '%s\n' "$final_output/manifest.json"
