#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 /absolute/alpine-virt-3.24.1-aarch64.iso /absolute/guest-ed25519.seed /absolute/output-dir" >&2
    exit 64
fi

iso=$1
guest_seed=$2
final_output=$3
expected_iso_sha256=c81699152db11d2a6dbb7d75348d632fcf5811eff414d7e71876a8bb6d48bc02
expected_modloop_sha256=f969d12c8e23b486c8df651f04a4a9767f32fee16aed385c23462c31ea6cb47b
expected_vsock_core_sha256=5194b3adc4f6bb3408b45a609fdc8ac68aa42fbcdacb7a0cbd04b4c1fd5dc43d
expected_vsock_common_sha256=486eb756080f0477d93476c0819c2616c1b8f14e3c8feef11d453d411a510e97
expected_vsock_transport_sha256=5411ae552bfc5600995b1a17365302dfd53d8aa000b0393a83f61ad3eb7f9072
expected_rustc_version='rustc 1.91.1 (ed61e7d7e 2025-11-07)'
expected_cargo_zigbuild_version='cargo-zigbuild 0.21.6'
expected_zig_version=0.15.2
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
whoathere_root=$(CDPATH= cd -- "$source_dir/../.." && pwd)

for path in "$iso" "$guest_seed" "$final_output"; do
    case "$path" in
        /*) ;;
        *) echo "all paths must be absolute" >&2; exit 64 ;;
    esac
done
if [ ! -f "$iso" ] || [ -L "$iso" ]; then
    echo "ISO must be a regular non-symlink file" >&2
    exit 66
fi
if [ ! -f "$guest_seed" ] || [ -L "$guest_seed" ] || \
   [ "$(stat -f '%z' "$guest_seed")" != 32 ] || \
   [ "$(stat -f '%Lp' "$guest_seed")" != 600 ] || \
   [ "$(stat -f '%u' "$guest_seed")" != "$(id -u)" ]
then
    echo "guest seed must be an owner-owned 32-byte mode-0600 regular non-symlink file" >&2
    exit 66
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
output=$work_output
build_root=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-signed-vz-build.XXXXXX")
cleanup() {
    rm -rf "$build_root"
    if [ -n "$work_output" ]; then
        rm -rf "$work_output"
    fi
}
trap cleanup EXIT HUP INT TERM

for command in bsdtar cargo cargo-zigbuild file gzip jq rustc shasum unsquashfs xcrun; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command missing: $command" >&2
        exit 69
    fi
done
zig=${ZIG:-$(command -v zig || true)}
if [ -z "$zig" ]; then
    echo "zig compiler missing" >&2
    exit 69
fi
case "$zig" in
    /*) ;;
    *) echo "zig path must be absolute" >&2; exit 69 ;;
esac
zig_version=$($zig version)
rustc_version=$(rustc --version)
cargo_zigbuild_version=$(cargo-zigbuild --version)
if [ "$zig_version" != "$expected_zig_version" ] || \
   [ "$rustc_version" != "$expected_rustc_version" ] || \
   [ "$cargo_zigbuild_version" != "$expected_cargo_zigbuild_version" ]
then
    echo "pinned guest-signer toolchain mismatch" >&2
    exit 69
fi

actual_iso_sha256=$(shasum -a 256 "$iso" | awk '{print $1}')
if [ "$actual_iso_sha256" != "$expected_iso_sha256" ]; then
    echo "Alpine ISO SHA-256 mismatch" >&2
    exit 65
fi

mkdir -p "$output/overlay/whoathere/modules" "$output/boot" "$output/modloop-extract"
"$script_dir/build-alpine-inert-image.sh" "$iso" "$output/base-generation" >/dev/null
bsdtar -xf "$iso" -C "$output" boot/modloop-virt
actual_modloop_sha256=$(shasum -a 256 "$output/boot/modloop-virt" | awk '{print $1}')
if [ "$actual_modloop_sha256" != "$expected_modloop_sha256" ]; then
    echo "Alpine modloop SHA-256 mismatch" >&2
    exit 65
fi

module_root=modules/6.18.35-0-virt/kernel/net/vmw_vsock
unsquashfs -f -d "$output/modloop-extract" "$output/boot/modloop-virt" \
    "$module_root/vsock.ko" \
    "$module_root/vmw_vsock_virtio_transport_common.ko" \
    "$module_root/vmw_vsock_virtio_transport.ko" >/dev/null
vsock_core="$output/modloop-extract/$module_root/vsock.ko"
vsock_common="$output/modloop-extract/$module_root/vmw_vsock_virtio_transport_common.ko"
vsock_transport="$output/modloop-extract/$module_root/vmw_vsock_virtio_transport.ko"
if [ "$(shasum -a 256 "$vsock_core" | awk '{print $1}')" != "$expected_vsock_core_sha256" ] || \
   [ "$(shasum -a 256 "$vsock_common" | awk '{print $1}')" != "$expected_vsock_common_sha256" ] || \
   [ "$(shasum -a 256 "$vsock_transport" | awk '{print $1}')" != "$expected_vsock_transport_sha256" ]
then
    echo "pinned virtio-vsock module SHA-256 mismatch" >&2
    exit 65
fi

export CARGO_TARGET_DIR="$build_root/rust-target"
export CARGO_ZIGBUILD_CACHE_DIR="$build_root/cargo-zigbuild-cache"
export CARGO_ZIGBUILD_ZIG_PATH="$zig"
export ZIG_GLOBAL_CACHE_DIR="$build_root/zig-global-cache"
export ZIG_LOCAL_CACHE_DIR="$build_root/zig-local-cache"
cargo zigbuild \
    --manifest-path "$whoathere_root/Cargo.toml" \
    -q \
    -p whoathere-macos-vm \
    --bin whoathere-linux-vz-guest-signer \
    --target aarch64-unknown-linux-musl \
    --release
guest_signer="$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/whoathere-linux-vz-guest-signer"
case "$(file "$guest_signer")" in
    *"ELF 64-bit"*"ARM aarch64"*"statically linked"*"stripped"*) ;;
    *) echo "guest signer is not a stripped static aarch64 Linux executable" >&2; exit 65 ;;
esac

cp "$source_dir/guest/signed_init" "$output/overlay/init"
cp "$guest_signer" "$output/overlay/whoathere/guest-signer"
cp "$guest_seed" "$output/overlay/whoathere/guest-ed25519.seed"
cp "$vsock_core" "$output/overlay/whoathere/modules/vsock.ko"
cp "$vsock_common" "$output/overlay/whoathere/modules/vmw_vsock_virtio_transport_common.ko"
cp "$vsock_transport" "$output/overlay/whoathere/modules/vmw_vsock_virtio_transport.ko"
chmod 0755 "$output/overlay/init"
chmod 0711 "$output/overlay/whoathere"
chmod 0700 "$output/overlay/whoathere/guest-signer" "$output/overlay/whoathere/modules"
chmod 0600 "$output/overlay/whoathere/guest-ed25519.seed"
chmod 0400 "$output/overlay/whoathere/modules/"*.ko

native_cc=$(xcrun --find clang)
native_sdk=$(xcrun --show-sdk-path)
"$native_cc" -O2 -Wall -Wextra -Werror -fno-ident -isysroot "$native_sdk" \
    -o "$build_root/canonical-signed-newc" "$source_dir/tools/canonical_signed_newc.c"
touch -t 202607120000.00 \
    "$output/overlay/init" \
    "$output/overlay/whoathere" \
    "$output/overlay/whoathere/guest-signer" \
    "$output/overlay/whoathere/guest-ed25519.seed" \
    "$output/overlay/whoathere/modules" \
    "$output/overlay/whoathere/modules/"*.ko
"$build_root/canonical-signed-newc" \
    "$output/whoathere-signed-overlay.cpio" \
    "$output/overlay/init" \
    "$output/overlay/whoathere/guest-signer" \
    "$output/overlay/whoathere/guest-ed25519.seed" \
    "$output/overlay/whoathere/modules/vsock.ko" \
    "$output/overlay/whoathere/modules/vmw_vsock_virtio_transport_common.ko" \
    "$output/overlay/whoathere/modules/vmw_vsock_virtio_transport.ko"
gzip -n -9 -c "$output/whoathere-signed-overlay.cpio" > "$output/whoathere-signed-overlay.cpio.gz"
cp "$output/base-generation/whoathere-initramfs-virt" "$output/whoathere-signed-initramfs-virt"
/bin/cat "$output/whoathere-signed-overlay.cpio.gz" >> "$output/whoathere-signed-initramfs-virt"
cp "$output/base-generation/Image-virt" "$output/Image-virt"
cp "$output/base-generation/config-6.18.35-0-virt" "$output/config-6.18.35-0-virt"
cp "$output/base-generation/System.map-6.18.35-0-virt" "$output/System.map-6.18.35-0-virt"
chmod 0644 \
    "$output/whoathere-signed-overlay.cpio" \
    "$output/whoathere-signed-overlay.cpio.gz" \
    "$output/whoathere-signed-initramfs-virt" \
    "$output/Image-virt" \
    "$output/config-6.18.35-0-virt" \
    "$output/System.map-6.18.35-0-virt"

base_manifest="$output/base-generation/manifest.json"
base_generation_manifest_sha256=$(shasum -a 256 "$base_manifest" | awk '{print $1}')
kernel_image_sha256=$(shasum -a 256 "$output/Image-virt" | awk '{print $1}')
kernel_config_sha256=$(shasum -a 256 "$output/config-6.18.35-0-virt" | awk '{print $1}')
guest_init_sha256=$(shasum -a 256 "$output/overlay/init" | awk '{print $1}')
guest_init_source_sha256=$(shasum -a 256 "$source_dir/guest/signed_init" | awk '{print $1}')
guest_signer_sha256=$(shasum -a 256 "$output/overlay/whoathere/guest-signer" | awk '{print $1}')
guest_signer_source_sha256=$(shasum -a 256 "$whoathere_root/crates/whoathere-macos-vm/src/bin/whoathere-linux-vz-guest-signer.rs" | awk '{print $1}')
process_sensor_probe_sha256=$(jq -er '.process_sensor_probe_sha256' "$base_manifest")
process_fixture_child_sha256=$(jq -er '.process_fixture_child_sha256' "$base_manifest")
process_fixture_bundle_sha256=$(jq -er '.process_fixture_bundle_sha256' "$base_manifest")
dynamic_library_driver_sha256=$(jq -er '.dynamic_library_driver_sha256' "$base_manifest")
dynamic_fixture_library_sha256=$(jq -er '.dynamic_fixture_library_sha256' "$base_manifest")
signed_overlay_cpio_sha256=$(shasum -a 256 "$output/whoathere-signed-overlay.cpio" | awk '{print $1}')
signed_overlay_cpio_gzip_sha256=$(shasum -a 256 "$output/whoathere-signed-overlay.cpio.gz" | awk '{print $1}')
signed_initramfs_sha256=$(shasum -a 256 "$output/whoathere-signed-initramfs-virt" | awk '{print $1}')
builder_source_sha256=$(shasum -a 256 "$script_dir/build-alpine-signed-inert-image.sh" | awk '{print $1}')
canonical_signed_newc_source_sha256=$(shasum -a 256 "$source_dir/tools/canonical_signed_newc.c" | awk '{print $1}')
cargo_lock_sha256=$(shasum -a 256 "$whoathere_root/Cargo.lock" | awk '{print $1}')
kernel_btf_sha256=$(jq -er '.kernel_btf_sha256' "$base_manifest")

cat > "$output/manifest.json" <<EOF
{"architecture":"aarch64","base_generation_manifest_sha256":"sha256:$base_generation_manifest_sha256","base_generation_schema_version":"whoathere.linux_vz_inert_image_manifest.v5","builder_source_sha256":"sha256:$builder_source_sha256","canonical_signed_newc_source_sha256":"sha256:$canonical_signed_newc_source_sha256","cargo_lock_sha256":"sha256:$cargo_lock_sha256","cargo_zigbuild_version":"$cargo_zigbuild_version","dynamic_fixture_library_sha256":"$dynamic_fixture_library_sha256","dynamic_library_driver_sha256":"$dynamic_library_driver_sha256","external_network":"no_external_route","guest_init_sha256":"sha256:$guest_init_sha256","guest_init_source_sha256":"sha256:$guest_init_source_sha256","guest_seed_provisioning":"root_owned_mode_0600_initramfs_path","guest_signer_sha256":"sha256:$guest_signer_sha256","guest_signer_source_sha256":"sha256:$guest_signer_source_sha256","image_state":"candidate_unqualified","kernel_btf_sha256":"$kernel_btf_sha256","kernel_config_sha256":"sha256:$kernel_config_sha256","kernel_image_sha256":"sha256:$kernel_image_sha256","kernel_release":"6.18.35-0-virt","package_execution":"disabled","process_fixture_bundle_sha256":"$process_fixture_bundle_sha256","process_fixture_child_sha256":"$process_fixture_child_sha256","process_sensor_probe_sha256":"$process_sensor_probe_sha256","root_disk":"structurally_absent","rustc_version":"$rustc_version","schema_version":"whoathere.linux_vz_signed_inert_image_manifest.v1","signed_overlay_cpio_gzip_sha256":"sha256:$signed_overlay_cpio_gzip_sha256","signed_overlay_cpio_sha256":"sha256:$signed_overlay_cpio_sha256","source_iso_sha256":"sha256:$actual_iso_sha256","source_modloop_sha256":"sha256:$actual_modloop_sha256","sync_back_policy":"structurally_absent","virtio_vsock_common_sha256":"sha256:$expected_vsock_common_sha256","virtio_vsock_transport_sha256":"sha256:$expected_vsock_transport_sha256","vsock_core_sha256":"sha256:$expected_vsock_core_sha256","whoathere_signed_initramfs_sha256":"sha256:$signed_initramfs_sha256","zig_version":"$zig_version"}
EOF

if [ -e "$final_output" ] || [ -L "$final_output" ]; then
    echo "output path appeared during build" >&2
    exit 73
fi
mv "$work_output" "$final_output"
work_output=
echo "$final_output/manifest.json"
