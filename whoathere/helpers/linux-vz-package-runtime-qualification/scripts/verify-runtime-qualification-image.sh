#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 /absolute/qualified-image /absolute/rootfs.ext2 /absolute/runtime-manifest.json /absolute/image" >&2
    exit 64
fi

base_image=$1
runtime_rootfs=$2
runtime_manifest=$3
image=$4
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
whoathere_root=$(CDPATH= cd -- "$source_dir/../.." && pwd)

for path in "$base_image" "$runtime_rootfs" "$runtime_manifest" "$image"; do
    case "$path" in
        /*) ;;
        *) echo "all paths must be absolute" >&2; exit 64 ;;
    esac
done
for command in cpio file find gzip jq shasum sort stat; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command missing: $command" >&2
        exit 69
    fi
done

base_manifest="$base_image/manifest.json"
base_initramfs="$base_image/whoathere-signed-initramfs-virt"
manifest="$image/manifest.json"
overlay="$image/whoathere-runtime-qualification-overlay.cpio"
overlay_gzip="$image/whoathere-runtime-qualification-overlay.cpio.gz"
initramfs="$image/whoathere-runtime-qualification-initramfs-virt"
agent="$image/overlay/whoathere/runtime-qualification-agent"
module_bundle="$image/overlay/whoathere/runtime-module-bundle.json"
image_runtime_manifest="$image/overlay/whoathere/runtime-manifest.json"
base_vsock="$base_image/overlay/whoathere/modules/vsock.ko"
base_vsock_common="$base_image/overlay/whoathere/modules/vmw_vsock_virtio_transport_common.ko"
base_vsock_transport="$base_image/overlay/whoathere/modules/vmw_vsock_virtio_transport.ko"
for path in \
    "$base_manifest" "$base_initramfs" "$runtime_rootfs" "$runtime_manifest" \
    "$manifest" "$overlay" "$overlay_gzip" "$initramfs" "$image/Image-virt" \
    "$image/config-6.18.35-0-virt" "$image/System.map-6.18.35-0-virt" \
    "$image/overlay/init" "$agent" "$module_bundle" "$image_runtime_manifest" \
    "$base_vsock" "$base_vsock_common" "$base_vsock_transport" \
    "$image/overlay/whoathere/modules/virtio_blk.ko" \
    "$image/overlay/whoathere/modules/crc16.ko" \
    "$image/overlay/whoathere/modules/mbcache.ko" \
    "$image/overlay/whoathere/modules/jbd2.ko" \
    "$image/overlay/whoathere/modules/ext4.ko"
do
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        echo "required regular non-symlink file missing: $path" >&2
        exit 66
    fi
done

canonical_manifest=$(mktemp "${TMPDIR:-/tmp}/whoathere-runtime-qualification-manifest.XXXXXX")
canonical_module_bundle=$(mktemp "${TMPDIR:-/tmp}/whoathere-runtime-module-bundle.XXXXXX")
combined_tmp=$(mktemp "${TMPDIR:-/tmp}/whoathere-runtime-qualification-initramfs.XXXXXX")
extract_root=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-runtime-qualification-overlay.XXXXXX")
rust_source_list=$(mktemp "${TMPDIR:-/tmp}/whoathere-runtime-qualification-rust-source.XXXXXX")
cleanup() {
    rm -f "$canonical_manifest" "$canonical_module_bundle" "$combined_tmp" \
        "$rust_source_list"
    rm -rf "$extract_root"
}
trap cleanup EXIT HUP INT TERM

jq -cS . "$manifest" > "$canonical_manifest"
if ! cmp -s "$canonical_manifest" "$manifest"; then
    echo "qualification image manifest must be canonical sorted compact JSON" >&2
    exit 65
fi
expected_keys='["architecture","base_signed_initramfs_sha256","base_signed_manifest_sha256","builder_source_sha256","candidate_package_runner_sha256","candidate_runtime_manifest_sha256","candidate_runtime_rootfs_byte_length","candidate_runtime_rootfs_sha256","canonical_newc_source_sha256","cargo_lock_sha256","cargo_zigbuild_version","external_network","guest_signer_sha256","image_state","kernel_image_sha256","kernel_release","package_execution","process_sensor_probe_sha256","runtime_qualification_agent_sha256","runtime_qualification_agent_source_sha256","runtime_qualification_init_sha256","runtime_qualification_init_source_sha256","runtime_qualification_initramfs_sha256","runtime_qualification_module_bundle_sha256","runtime_qualification_operation","runtime_qualification_overlay_cpio_gzip_sha256","runtime_qualification_overlay_cpio_sha256","rust_source_tree_sha256","rustc_version","schema_version","sync_back_policy","verifier_source_sha256","zig_version"]'
if [ "$(jq -c 'keys' "$manifest")" != "$expected_keys" ]; then
    echo "qualification image manifest key set mismatch" >&2
    exit 65
fi

require_value() {
    field=$1
    expected=$2
    actual=$(jq -r --arg field "$field" '.[$field]' "$manifest")
    if [ "$actual" != "$expected" ]; then
        echo "qualification image manifest value mismatch: $field" >&2
        exit 65
    fi
}
require_hash() {
    field=$1
    path=$2
    require_value "$field" "sha256:$(shasum -a 256 "$path" | awk '{print $1}')"
}

require_value schema_version whoathere.linux_vz_package_runtime_qualification_image_manifest.v1
require_value architecture aarch64
require_value image_state candidate_unqualified
require_value kernel_release 6.18.35-0-virt
require_value runtime_qualification_operation fixed_nonexecuting_probe
require_value external_network host_raw_frame_sinkhole_no_external_route
require_value package_execution false
require_value sync_back_policy structurally_absent
require_value rustc_version 'rustc 1.91.1 (ed61e7d7e 2025-11-07)'
require_value cargo_zigbuild_version 'cargo-zigbuild 0.21.6'
require_value zig_version 0.15.2
require_hash base_signed_manifest_sha256 "$base_manifest"
require_hash base_signed_initramfs_sha256 "$base_initramfs"
require_hash kernel_image_sha256 "$image/Image-virt"
require_hash runtime_qualification_init_sha256 "$image/overlay/init"
require_hash runtime_qualification_init_source_sha256 "$source_dir/guest/init"
require_hash runtime_qualification_agent_sha256 "$agent"
require_hash runtime_qualification_agent_source_sha256 \
    "$whoathere_root/crates/whoathere-macos-vm/src/bin/whoathere-linux-vz-runtime-qualification-agent.rs"
require_hash runtime_qualification_module_bundle_sha256 "$module_bundle"
require_hash runtime_qualification_overlay_cpio_sha256 "$overlay"
require_hash runtime_qualification_overlay_cpio_gzip_sha256 "$overlay_gzip"
require_hash runtime_qualification_initramfs_sha256 "$initramfs"
require_hash builder_source_sha256 "$script_dir/build-runtime-qualification-image.sh"
require_hash verifier_source_sha256 "$script_dir/verify-runtime-qualification-image.sh"
require_hash canonical_newc_source_sha256 \
    "$source_dir/tools/canonical_runtime_qualification_newc.c"
require_hash cargo_lock_sha256 "$whoathere_root/Cargo.lock"
{
    printf '%s\n' "$whoathere_root/Cargo.toml"
    find "$whoathere_root/crates" -type f \( -name '*.rs' -o -name Cargo.toml \) -print
} | LC_ALL=C sort > "$rust_source_list"
rust_source_tree_sha256="sha256:$({
    while IFS= read -r source_path; do
        relative_path=${source_path#"$whoathere_root/"}
        source_length=$(stat -f '%z' "$source_path")
        printf '%s\0%s\0' "$relative_path" "$source_length"
        /bin/cat "$source_path"
    done < "$rust_source_list"
} | shasum -a 256 | awk '{print $1}')"
require_value rust_source_tree_sha256 "$rust_source_tree_sha256"
require_hash candidate_runtime_rootfs_sha256 "$runtime_rootfs"
require_value candidate_runtime_rootfs_byte_length "$(stat -f '%z' "$runtime_rootfs")"
require_hash candidate_runtime_manifest_sha256 "$runtime_manifest"
require_value candidate_package_runner_sha256 \
    "$(jq -er '.package_runner_sha256' "$runtime_manifest")"
require_value process_sensor_probe_sha256 \
    "$(jq -er '.process_sensor_probe_sha256' "$base_manifest")"
require_value guest_signer_sha256 "$(jq -er '.guest_signer_sha256' "$base_manifest")"
if ! cmp -s "$runtime_manifest" "$image_runtime_manifest" || \
   ! cmp -s "$base_image/Image-virt" "$image/Image-virt" || \
   ! cmp -s "$base_image/config-6.18.35-0-virt" "$image/config-6.18.35-0-virt" || \
   ! cmp -s "$base_image/System.map-6.18.35-0-virt" "$image/System.map-6.18.35-0-virt"
then
    echo "qualification image copied-input mismatch" >&2
    exit 65
fi

case "$(file "$agent")" in
    *"ELF 64-bit"*"ARM aarch64"*"statically linked"*"stripped"*) ;;
    *) echo "runtime qualification agent binary contract mismatch" >&2; exit 65 ;;
esac
expanded_overlay_hash="sha256:$(gzip -dc "$overlay_gzip" | shasum -a 256 | awk '{print $1}')"
require_value runtime_qualification_overlay_cpio_sha256 "$expanded_overlay_hash"
cp "$base_initramfs" "$combined_tmp"
/bin/cat "$overlay_gzip" >> "$combined_tmp"
if ! cmp -s "$combined_tmp" "$initramfs"; then
    echo "runtime qualification initramfs concatenation mismatch" >&2
    exit 65
fi

jq -cS . "$module_bundle" | tr -d '\n' > "$canonical_module_bundle"
if ! cmp -s "$canonical_module_bundle" "$module_bundle"; then
    echo "runtime module bundle must be canonical JSON without a trailing newline" >&2
    exit 65
fi
expected_module_keys='["kernel_release","modules","schema_version"]'
expected_entry_keys='["load_order","path","sha256"]'
if [ "$(jq -c 'keys' "$module_bundle")" != "$expected_module_keys" ] || \
   [ "$(jq -er '.schema_version' "$module_bundle")" != \
     whoathere.linux_vz_runtime_module_bundle.v1 ] || \
   [ "$(jq -er '.kernel_release' "$module_bundle")" != 6.18.35-0-virt ] || \
   [ "$(jq -er '.modules | length' "$module_bundle")" != 8 ] || \
   [ "$(jq -c '[.modules[].load_order]' "$module_bundle")" != \
     '["1","2","3","4","5","6","7","8"]' ] || \
   [ "$(jq -c '[.modules[].path]' "$module_bundle")" != \
     '["/whoathere/modules/vsock.ko","/whoathere/modules/vmw_vsock_virtio_transport_common.ko","/whoathere/modules/vmw_vsock_virtio_transport.ko","/whoathere/modules/virtio_blk.ko","/whoathere/modules/crc16.ko","/whoathere/modules/mbcache.ko","/whoathere/modules/jbd2.ko","/whoathere/modules/ext4.ko"]' ] || \
   [ "$(jq -c '[.modules[] | keys] | unique' "$module_bundle")" != "[$expected_entry_keys]" ]
then
    echo "runtime module bundle schema mismatch" >&2
    exit 65
fi
module_path() {
    case "$1" in
        /whoathere/modules/vsock.ko) printf '%s\n' "$base_vsock" ;;
        /whoathere/modules/vmw_vsock_virtio_transport_common.ko) \
            printf '%s\n' "$base_vsock_common" ;;
        /whoathere/modules/vmw_vsock_virtio_transport.ko) \
            printf '%s\n' "$base_vsock_transport" ;;
        /whoathere/modules/virtio_blk.ko) \
            printf '%s\n' "$image/overlay/whoathere/modules/virtio_blk.ko" ;;
        /whoathere/modules/crc16.ko) \
            printf '%s\n' "$image/overlay/whoathere/modules/crc16.ko" ;;
        /whoathere/modules/mbcache.ko) \
            printf '%s\n' "$image/overlay/whoathere/modules/mbcache.ko" ;;
        /whoathere/modules/jbd2.ko) \
            printf '%s\n' "$image/overlay/whoathere/modules/jbd2.ko" ;;
        /whoathere/modules/ext4.ko) \
            printf '%s\n' "$image/overlay/whoathere/modules/ext4.ko" ;;
        *) exit 65 ;;
    esac
}
index=0
while [ "$index" -lt 8 ]; do
    path=$(jq -er --argjson index "$index" '.modules[$index].path' "$module_bundle")
    digest=$(jq -er --argjson index "$index" '.modules[$index].sha256' "$module_bundle")
    actual="sha256:$(shasum -a 256 "$(module_path "$path")" | awk '{print $1}')"
    if [ "$digest" != "$actual" ]; then
        echo "runtime module bundle digest mismatch: $path" >&2
        exit 65
    fi
    index=$((index + 1))
done

entries=$(cpio -it < "$overlay" 2>/dev/null)
expected_entries=$(printf 'init\nwhoathere\nwhoathere/runtime-qualification-agent\nwhoathere/runtime-module-bundle.json\nwhoathere/runtime-manifest.json\nwhoathere/modules\nwhoathere/modules/virtio_blk.ko\nwhoathere/modules/crc16.ko\nwhoathere/modules/mbcache.ko\nwhoathere/modules/jbd2.ko\nwhoathere/modules/ext4.ko')
if [ "$entries" != "$expected_entries" ]; then
    echo "runtime qualification overlay entry set or order mismatch" >&2
    exit 65
fi
(
    cd "$extract_root"
    cpio -idmu < "$overlay" >/dev/null 2>&1
)
for relative in \
    init \
    whoathere/runtime-qualification-agent \
    whoathere/runtime-module-bundle.json \
    whoathere/runtime-manifest.json \
    whoathere/modules/virtio_blk.ko \
    whoathere/modules/crc16.ko \
    whoathere/modules/mbcache.ko \
    whoathere/modules/jbd2.ko \
    whoathere/modules/ext4.ko
do
    if ! cmp -s "$extract_root/$relative" "$image/overlay/$relative"; then
        echo "runtime qualification overlay content mismatch: $relative" >&2
        exit 65
    fi
done
if [ "$(stat -f '%Lp' "$extract_root/init")" != 755 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere")" != 711 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere/runtime-qualification-agent")" != 700 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere/runtime-module-bundle.json")" != 400 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere/runtime-manifest.json")" != 400 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere/modules")" != 700 ] || \
   [ "$(find "$extract_root/whoathere/modules" -type f -exec stat -f '%Lp' {} \; | sort -u)" != 400 ]
then
    echo "runtime qualification overlay protection modes mismatch" >&2
    exit 65
fi

printf '%s\n' '{"execution_authority":false,"image_state":"candidate_unqualified","package_execution":false,"status":"verified","sync_back":false}'
