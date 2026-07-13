#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 /absolute/qualified-image /absolute/rootfs.ext2 /absolute/runtime-manifest.json /absolute/output" >&2
    exit 64
fi

base_image=$1
runtime_rootfs=$2
runtime_manifest=$3
final_output=$4
expected_modloop_sha256=f969d12c8e23b486c8df651f04a4a9767f32fee16aed385c23462c31ea6cb47b
expected_virtio_blk_sha256=80341fdb0869f5df4813b7bfb4a1cd77d2f6cd7c26c04fc15706cbc44d680ef6
expected_crc16_sha256=aa3b4ec2b12323f416110ad11f6d0009faa0af0754c4de74e77e3e6c00e4001b
expected_mbcache_sha256=7dbb40f7268e2bdabd80ca16d21e84c869134aea15b511d302c63f3095d6103d
expected_jbd2_sha256=d4e7753266771b7682afdcac4efbd5195d24e69d0c09054252f754092aaee840
expected_ext4_sha256=bfdaa7958c82ad518a9e798a6cf550bc4408f0b4039c4dfac2376184b1ed732b
expected_rustc_version='rustc 1.91.1 (ed61e7d7e 2025-11-07)'
expected_cargo_zigbuild_version='cargo-zigbuild 0.21.6'
expected_zig_version=0.15.2
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
whoathere_root=$(CDPATH= cd -- "$source_dir/../.." && pwd)

for path in "$base_image" "$runtime_rootfs" "$runtime_manifest" "$final_output"; do
    case "$path" in
        /*) ;;
        *) echo "all paths must be absolute" >&2; exit 64 ;;
    esac
done
if [ ! -d "$base_image" ] || [ -L "$base_image" ]; then
    echo "qualified image must be a non-symlink directory" >&2
    exit 66
fi
for path in "$runtime_rootfs" "$runtime_manifest"; do
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        echo "runtime input must be a regular non-symlink file: $path" >&2
        exit 66
    fi
done
if [ -e "$final_output" ] || [ -L "$final_output" ]; then
    echo "output path must not already exist" >&2
    exit 73
fi
for command in cargo cargo-zigbuild file gzip jq rustc shasum unsquashfs xcrun; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command missing: $command" >&2
        exit 69
    fi
done
zig=${ZIG:-$(command -v zig || true)}
case "$zig" in
    /*) ;;
    *) echo "absolute zig compiler missing" >&2; exit 69 ;;
esac
rustc_version=$(rustc --version)
cargo_zigbuild_version=$(cargo-zigbuild --version)
zig_version=$($zig version)
if [ "$rustc_version" != "$expected_rustc_version" ] || \
   [ "$cargo_zigbuild_version" != "$expected_cargo_zigbuild_version" ] || \
   [ "$zig_version" != "$expected_zig_version" ]
then
    echo "pinned runtime-qualification toolchain mismatch" >&2
    exit 69
fi

base_manifest="$base_image/manifest.json"
base_initramfs="$base_image/whoathere-signed-initramfs-virt"
base_kernel="$base_image/Image-virt"
base_config="$base_image/config-6.18.35-0-virt"
base_system_map="$base_image/System.map-6.18.35-0-virt"
base_modloop="$base_image/boot/modloop-virt"
base_vsock="$base_image/overlay/whoathere/modules/vsock.ko"
base_vsock_common="$base_image/overlay/whoathere/modules/vmw_vsock_virtio_transport_common.ko"
base_vsock_transport="$base_image/overlay/whoathere/modules/vmw_vsock_virtio_transport.ko"
for path in \
    "$base_manifest" "$base_initramfs" "$base_kernel" "$base_config" \
    "$base_system_map" "$base_modloop" "$base_vsock" "$base_vsock_common" \
    "$base_vsock_transport"
do
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        echo "qualified image input missing: $path" >&2
        exit 66
    fi
done
if [ "$(jq -er '.schema_version' "$base_manifest")" != \
     whoathere.linux_vz_signed_inert_image_manifest.v1 ] || \
   [ "$(jq -er '.architecture' "$base_manifest")" != aarch64 ] || \
   [ "$(jq -er '.kernel_release' "$base_manifest")" != 6.18.35-0-virt ] || \
   [ "$(jq -er '.external_network' "$base_manifest")" != no_external_route ] || \
   [ "$(jq -er '.package_execution' "$base_manifest")" != disabled ] || \
   [ "$(jq -er '.sync_back_policy' "$base_manifest")" != structurally_absent ]
then
    echo "qualified image policy mismatch" >&2
    exit 65
fi
require_manifest_hash() {
    field=$1
    path=$2
    expected="sha256:$(shasum -a 256 "$path" | awk '{print $1}')"
    if [ "$(jq -er --arg field "$field" '.[$field]' "$base_manifest")" != "$expected" ]; then
        echo "qualified image hash mismatch: $field" >&2
        exit 65
    fi
}
require_manifest_hash whoathere_signed_initramfs_sha256 "$base_initramfs"
require_manifest_hash kernel_image_sha256 "$base_kernel"
require_manifest_hash source_modloop_sha256 "$base_modloop"
require_manifest_hash vsock_core_sha256 "$base_vsock"
require_manifest_hash virtio_vsock_common_sha256 "$base_vsock_common"
require_manifest_hash virtio_vsock_transport_sha256 "$base_vsock_transport"
if [ "$(shasum -a 256 "$base_modloop" | awk '{print $1}')" != "$expected_modloop_sha256" ]; then
    echo "qualified image modloop identity mismatch" >&2
    exit 65
fi

runtime_rootfs_sha256="sha256:$(shasum -a 256 "$runtime_rootfs" | awk '{print $1}')"
runtime_rootfs_byte_length=$(stat -f '%z' "$runtime_rootfs")
runtime_manifest_sha256="sha256:$(shasum -a 256 "$runtime_manifest" | awk '{print $1}')"
runtime_runner_sha256=$(jq -er '.package_runner_sha256' "$runtime_manifest")
if [ "$(jq -er '.schema_version' "$runtime_manifest")" != \
     whoathere.linux_vz_package_runtime_manifest.v1 ] || \
   [ "$(jq -er '.rootfs_sha256' "$runtime_manifest")" != "$runtime_rootfs_sha256" ] || \
   [ "$(jq -er '.rootfs_byte_length' "$runtime_manifest")" != "$runtime_rootfs_byte_length" ] || \
   [ "$(jq -er '.rootfs_uuid' "$runtime_manifest")" != \
     57484f41-5448-4552-5254-554e54494d45 ] || \
   [ "$(jq -er '.package_runner_mode' "$runtime_manifest")" != \
     nonexecuting_runtime_probe_with_closed_sensor_alias ] || \
   [ "$(jq -er '.package_execution' "$runtime_manifest")" != false ] || \
   [ "$(jq -er '.sync_back' "$runtime_manifest")" != false ]
then
    echo "candidate runtime manifest binding mismatch" >&2
    exit 65
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
output=$work_output
build_root=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-runtime-qualification-build.XXXXXX")
cleanup() {
    rm -rf "$build_root"
    if [ -n "$work_output" ]; then
        rm -rf "$work_output"
    fi
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$output/overlay/whoathere/modules" "$build_root/modules"
module_root=modules/6.18.35-0-virt/kernel
unsquashfs -f -d "$build_root/modloop" "$base_modloop" \
    "$module_root/drivers/block/virtio_blk.ko" \
    "$module_root/lib/crc/crc16.ko" \
    "$module_root/fs/mbcache.ko" \
    "$module_root/fs/jbd2/jbd2.ko" \
    "$module_root/fs/ext4/ext4.ko" >/dev/null
virtio_blk="$build_root/modloop/$module_root/drivers/block/virtio_blk.ko"
crc16="$build_root/modloop/$module_root/lib/crc/crc16.ko"
mbcache="$build_root/modloop/$module_root/fs/mbcache.ko"
jbd2="$build_root/modloop/$module_root/fs/jbd2/jbd2.ko"
ext4="$build_root/modloop/$module_root/fs/ext4/ext4.ko"
if [ "$(shasum -a 256 "$virtio_blk" | awk '{print $1}')" != "$expected_virtio_blk_sha256" ] || \
   [ "$(shasum -a 256 "$crc16" | awk '{print $1}')" != "$expected_crc16_sha256" ] || \
   [ "$(shasum -a 256 "$mbcache" | awk '{print $1}')" != "$expected_mbcache_sha256" ] || \
   [ "$(shasum -a 256 "$jbd2" | awk '{print $1}')" != "$expected_jbd2_sha256" ] || \
   [ "$(shasum -a 256 "$ext4" | awk '{print $1}')" != "$expected_ext4_sha256" ]
then
    echo "pinned block/ext module identity mismatch" >&2
    exit 65
fi

export CARGO_TARGET_DIR="$build_root/rust-target"
export CARGO_ZIGBUILD_CACHE_DIR="$build_root/cargo-zigbuild-cache"
export CARGO_ZIGBUILD_ZIG_PATH="$zig"
export ZIG_GLOBAL_CACHE_DIR="$build_root/zig-global-cache"
export ZIG_LOCAL_CACHE_DIR="$build_root/zig-local-cache"
cargo zigbuild \
    --manifest-path "$whoathere_root/Cargo.toml" \
    --locked --offline -q \
    -p whoathere-macos-vm \
    --bin whoathere-linux-vz-runtime-qualification-agent \
    --target aarch64-unknown-linux-musl \
    --release
agent="$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/whoathere-linux-vz-runtime-qualification-agent"
case "$(file "$agent")" in
    *"ELF 64-bit"*"ARM aarch64"*"statically linked"*"stripped"*) ;;
    *) echo "runtime qualification agent binary contract mismatch" >&2; exit 65 ;;
esac

cp "$source_dir/guest/init" "$output/overlay/init"
cp "$agent" "$output/overlay/whoathere/runtime-qualification-agent"
cp "$runtime_manifest" "$output/overlay/whoathere/runtime-manifest.json"
cp "$virtio_blk" "$output/overlay/whoathere/modules/virtio_blk.ko"
cp "$crc16" "$output/overlay/whoathere/modules/crc16.ko"
cp "$mbcache" "$output/overlay/whoathere/modules/mbcache.ko"
cp "$jbd2" "$output/overlay/whoathere/modules/jbd2.ko"
cp "$ext4" "$output/overlay/whoathere/modules/ext4.ko"
chmod 0755 "$output/overlay/init"
chmod 0711 "$output/overlay/whoathere"
chmod 0700 "$output/overlay/whoathere/runtime-qualification-agent" \
    "$output/overlay/whoathere/modules"
chmod 0400 "$output/overlay/whoathere/runtime-manifest.json" \
    "$output/overlay/whoathere/modules/"*.ko

module_bundle_tmp="$build_root/runtime-module-bundle.json.tmp"
jq -ncS \
    --arg vsock "$(jq -er '.vsock_core_sha256' "$base_manifest")" \
    --arg common "$(jq -er '.virtio_vsock_common_sha256' "$base_manifest")" \
    --arg transport "$(jq -er '.virtio_vsock_transport_sha256' "$base_manifest")" \
    --arg virtio_blk "sha256:$expected_virtio_blk_sha256" \
    --arg crc16 "sha256:$expected_crc16_sha256" \
    --arg mbcache "sha256:$expected_mbcache_sha256" \
    --arg jbd2 "sha256:$expected_jbd2_sha256" \
    --arg ext4 "sha256:$expected_ext4_sha256" \
    '{kernel_release:"6.18.35-0-virt",modules:[{load_order:"1",path:"/whoathere/modules/vsock.ko",sha256:$vsock},{load_order:"2",path:"/whoathere/modules/vmw_vsock_virtio_transport_common.ko",sha256:$common},{load_order:"3",path:"/whoathere/modules/vmw_vsock_virtio_transport.ko",sha256:$transport},{load_order:"4",path:"/whoathere/modules/virtio_blk.ko",sha256:$virtio_blk},{load_order:"5",path:"/whoathere/modules/crc16.ko",sha256:$crc16},{load_order:"6",path:"/whoathere/modules/mbcache.ko",sha256:$mbcache},{load_order:"7",path:"/whoathere/modules/jbd2.ko",sha256:$jbd2},{load_order:"8",path:"/whoathere/modules/ext4.ko",sha256:$ext4}],schema_version:"whoathere.linux_vz_runtime_module_bundle.v1"}' \
    > "$module_bundle_tmp"
tr -d '\n' < "$module_bundle_tmp" > "$output/overlay/whoathere/runtime-module-bundle.json"
chmod 0400 "$output/overlay/whoathere/runtime-module-bundle.json"

native_cc=$(xcrun --find clang)
native_sdk=$(xcrun --show-sdk-path)
"$native_cc" -O2 -Wall -Wextra -Werror -fno-ident -isysroot "$native_sdk" \
    -o "$build_root/canonical-runtime-qualification-newc" \
    "$source_dir/tools/canonical_runtime_qualification_newc.c"
"$build_root/canonical-runtime-qualification-newc" \
    "$output/whoathere-runtime-qualification-overlay.cpio" \
    "$output/overlay/init" \
    "$output/overlay/whoathere/runtime-qualification-agent" \
    "$output/overlay/whoathere/runtime-module-bundle.json" \
    "$output/overlay/whoathere/runtime-manifest.json" \
    "$output/overlay/whoathere/modules/virtio_blk.ko" \
    "$output/overlay/whoathere/modules/crc16.ko" \
    "$output/overlay/whoathere/modules/mbcache.ko" \
    "$output/overlay/whoathere/modules/jbd2.ko" \
    "$output/overlay/whoathere/modules/ext4.ko"
gzip -n -9 -c "$output/whoathere-runtime-qualification-overlay.cpio" \
    > "$output/whoathere-runtime-qualification-overlay.cpio.gz"
cp "$base_initramfs" "$output/whoathere-runtime-qualification-initramfs-virt"
/bin/cat "$output/whoathere-runtime-qualification-overlay.cpio.gz" \
    >> "$output/whoathere-runtime-qualification-initramfs-virt"
cp "$base_kernel" "$output/Image-virt"
cp "$base_config" "$output/config-6.18.35-0-virt"
cp "$base_system_map" "$output/System.map-6.18.35-0-virt"
chmod 0644 \
    "$output/whoathere-runtime-qualification-overlay.cpio" \
    "$output/whoathere-runtime-qualification-overlay.cpio.gz" \
    "$output/whoathere-runtime-qualification-initramfs-virt" \
    "$output/Image-virt" "$output/config-6.18.35-0-virt" \
    "$output/System.map-6.18.35-0-virt"

base_manifest_sha256="sha256:$(shasum -a 256 "$base_manifest" | awk '{print $1}')"
base_initramfs_sha256="sha256:$(shasum -a 256 "$base_initramfs" | awk '{print $1}')"
kernel_sha256="sha256:$(shasum -a 256 "$output/Image-virt" | awk '{print $1}')"
init_sha256="sha256:$(shasum -a 256 "$output/overlay/init" | awk '{print $1}')"
agent_sha256="sha256:$(shasum -a 256 "$output/overlay/whoathere/runtime-qualification-agent" | awk '{print $1}')"
module_bundle_sha256="sha256:$(shasum -a 256 "$output/overlay/whoathere/runtime-module-bundle.json" | awk '{print $1}')"
overlay_sha256="sha256:$(shasum -a 256 "$output/whoathere-runtime-qualification-overlay.cpio" | awk '{print $1}')"
overlay_gzip_sha256="sha256:$(shasum -a 256 "$output/whoathere-runtime-qualification-overlay.cpio.gz" | awk '{print $1}')"
qualification_initramfs_sha256="sha256:$(shasum -a 256 "$output/whoathere-runtime-qualification-initramfs-virt" | awk '{print $1}')"
builder_source_sha256="sha256:$(shasum -a 256 "$script_dir/build-runtime-qualification-image.sh" | awk '{print $1}')"
verifier_source_sha256="sha256:$(shasum -a 256 "$script_dir/verify-runtime-qualification-image.sh" | awk '{print $1}')"
newc_source_sha256="sha256:$(shasum -a 256 "$source_dir/tools/canonical_runtime_qualification_newc.c" | awk '{print $1}')"
agent_source_sha256="sha256:$(shasum -a 256 "$whoathere_root/crates/whoathere-macos-vm/src/bin/whoathere-linux-vz-runtime-qualification-agent.rs" | awk '{print $1}')"
init_source_sha256="sha256:$(shasum -a 256 "$source_dir/guest/init" | awk '{print $1}')"
cargo_lock_sha256="sha256:$(shasum -a 256 "$whoathere_root/Cargo.lock" | awk '{print $1}')"
process_sensor_sha256=$(jq -er '.process_sensor_probe_sha256' "$base_manifest")
guest_signer_sha256=$(jq -er '.guest_signer_sha256' "$base_manifest")

jq -ncS \
    --arg agent_sha256 "$agent_sha256" \
    --arg agent_source_sha256 "$agent_source_sha256" \
    --arg base_initramfs_sha256 "$base_initramfs_sha256" \
    --arg base_manifest_sha256 "$base_manifest_sha256" \
    --arg builder_source_sha256 "$builder_source_sha256" \
    --arg cargo_lock_sha256 "$cargo_lock_sha256" \
    --arg cargo_zigbuild_version "$cargo_zigbuild_version" \
    --arg guest_signer_sha256 "$guest_signer_sha256" \
    --arg init_sha256 "$init_sha256" \
    --arg init_source_sha256 "$init_source_sha256" \
    --arg kernel_sha256 "$kernel_sha256" \
    --arg module_bundle_sha256 "$module_bundle_sha256" \
    --arg newc_source_sha256 "$newc_source_sha256" \
    --arg overlay_gzip_sha256 "$overlay_gzip_sha256" \
    --arg overlay_sha256 "$overlay_sha256" \
    --arg process_sensor_sha256 "$process_sensor_sha256" \
    --arg qualification_initramfs_sha256 "$qualification_initramfs_sha256" \
    --arg rootfs_byte_length "$runtime_rootfs_byte_length" \
    --arg rootfs_sha256 "$runtime_rootfs_sha256" \
    --arg runtime_manifest_sha256 "$runtime_manifest_sha256" \
    --arg runner_sha256 "$runtime_runner_sha256" \
    --arg rustc_version "$rustc_version" \
    --arg verifier_source_sha256 "$verifier_source_sha256" \
    --arg zig_version "$zig_version" \
    '{architecture:"aarch64",base_signed_initramfs_sha256:$base_initramfs_sha256,base_signed_manifest_sha256:$base_manifest_sha256,builder_source_sha256:$builder_source_sha256,candidate_package_runner_sha256:$runner_sha256,candidate_runtime_manifest_sha256:$runtime_manifest_sha256,candidate_runtime_rootfs_byte_length:$rootfs_byte_length,candidate_runtime_rootfs_sha256:$rootfs_sha256,canonical_newc_source_sha256:$newc_source_sha256,cargo_lock_sha256:$cargo_lock_sha256,cargo_zigbuild_version:$cargo_zigbuild_version,external_network:"host_raw_frame_sinkhole_no_external_route",guest_signer_sha256:$guest_signer_sha256,image_state:"candidate_unqualified",kernel_image_sha256:$kernel_sha256,kernel_release:"6.18.35-0-virt",package_execution:false,process_sensor_probe_sha256:$process_sensor_sha256,runtime_qualification_agent_sha256:$agent_sha256,runtime_qualification_agent_source_sha256:$agent_source_sha256,runtime_qualification_init_sha256:$init_sha256,runtime_qualification_init_source_sha256:$init_source_sha256,runtime_qualification_initramfs_sha256:$qualification_initramfs_sha256,runtime_qualification_module_bundle_sha256:$module_bundle_sha256,runtime_qualification_operation:"fixed_nonexecuting_probe",runtime_qualification_overlay_cpio_gzip_sha256:$overlay_gzip_sha256,runtime_qualification_overlay_cpio_sha256:$overlay_sha256,rustc_version:$rustc_version,schema_version:"whoathere.linux_vz_package_runtime_qualification_image_manifest.v1",sync_back_policy:"structurally_absent",verifier_source_sha256:$verifier_source_sha256,zig_version:$zig_version}' \
    > "$output/manifest.json"

if [ -e "$final_output" ] || [ -L "$final_output" ]; then
    echo "output path appeared during build" >&2
    exit 73
fi
mv "$work_output" "$final_output"
work_output=
printf '%s\n' "$final_output/manifest.json"
