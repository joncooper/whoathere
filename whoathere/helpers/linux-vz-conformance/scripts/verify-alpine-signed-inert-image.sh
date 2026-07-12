#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 /absolute/alpine-virt-3.24.1-aarch64.iso /absolute/guest-ed25519.seed /absolute/image-dir" >&2
    exit 64
fi

iso=$1
guest_seed=$2
image=$3
expected_iso_sha256=c81699152db11d2a6dbb7d75348d632fcf5811eff414d7e71876a8bb6d48bc02
expected_modloop_sha256=f969d12c8e23b486c8df651f04a4a9767f32fee16aed385c23462c31ea6cb47b
expected_vsock_core_sha256=5194b3adc4f6bb3408b45a609fdc8ac68aa42fbcdacb7a0cbd04b4c1fd5dc43d
expected_vsock_common_sha256=486eb756080f0477d93476c0819c2616c1b8f14e3c8feef11d453d411a510e97
expected_vsock_transport_sha256=5411ae552bfc5600995b1a17365302dfd53d8aa000b0393a83f61ad3eb7f9072
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
whoathere_root=$(CDPATH= cd -- "$source_dir/../.." && pwd)

for path in "$iso" "$guest_seed" "$image"; do
    case "$path" in
        /*) ;;
        *) echo "all paths must be absolute" >&2; exit 64 ;;
    esac
done
for command in cpio file gzip jq shasum; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command missing: $command" >&2
        exit 69
    fi
done

manifest="$image/manifest.json"
overlay="$image/whoathere-signed-overlay.cpio"
overlay_gzip="$image/whoathere-signed-overlay.cpio.gz"
initramfs="$image/whoathere-signed-initramfs-virt"
base="$image/base-generation"
for path in \
    "$iso" "$guest_seed" "$manifest" "$overlay" "$overlay_gzip" "$initramfs" \
    "$image/Image-virt" "$image/config-6.18.35-0-virt" \
    "$image/System.map-6.18.35-0-virt" "$image/boot/modloop-virt" \
    "$image/overlay/init" "$image/overlay/whoathere/guest-signer" \
    "$image/overlay/whoathere/guest-ed25519.seed" \
    "$image/overlay/whoathere/modules/vsock.ko" \
    "$image/overlay/whoathere/modules/vmw_vsock_virtio_transport_common.ko" \
    "$image/overlay/whoathere/modules/vmw_vsock_virtio_transport.ko"
do
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        echo "required regular non-symlink file missing: $path" >&2
        exit 66
    fi
done

canonical_manifest=$(mktemp "${TMPDIR:-/tmp}/whoathere-signed-manifest.XXXXXX")
extract_root=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-signed-overlay.XXXXXX")
combined_tmp=$(mktemp "${TMPDIR:-/tmp}/whoathere-signed-initramfs.XXXXXX")
cleanup() {
    rm -f "$canonical_manifest" "$combined_tmp"
    rm -rf "$extract_root"
}
trap cleanup EXIT HUP INT TERM

jq -cS . "$manifest" > "$canonical_manifest"
if ! cmp -s "$canonical_manifest" "$manifest"; then
    echo "signed manifest must be canonical sorted compact JSON" >&2
    exit 65
fi
expected_keys='["architecture","base_generation_manifest_sha256","base_generation_schema_version","builder_source_sha256","canonical_signed_newc_source_sha256","cargo_lock_sha256","cargo_zigbuild_version","external_network","guest_init_sha256","guest_init_source_sha256","guest_seed_provisioning","guest_signer_sha256","guest_signer_source_sha256","image_state","kernel_btf_sha256","kernel_config_sha256","kernel_image_sha256","kernel_release","package_execution","process_fixture_child_sha256","process_sensor_probe_sha256","root_disk","rustc_version","schema_version","signed_overlay_cpio_gzip_sha256","signed_overlay_cpio_sha256","source_iso_sha256","source_modloop_sha256","sync_back_policy","virtio_vsock_common_sha256","virtio_vsock_transport_sha256","vsock_core_sha256","whoathere_signed_initramfs_sha256","zig_version"]'
if [ "$(jq -c 'keys' "$manifest")" != "$expected_keys" ]; then
    echo "signed manifest key set mismatch" >&2
    exit 65
fi

require_value() {
    field=$1
    expected=$2
    actual=$(jq -er --arg field "$field" '.[$field]' "$manifest")
    if [ "$actual" != "$expected" ]; then
        echo "signed manifest value mismatch: $field" >&2
        exit 65
    fi
}
require_hash() {
    field=$1
    path=$2
    require_value "$field" "sha256:$(shasum -a 256 "$path" | awk '{print $1}')"
}

require_value schema_version whoathere.linux_vz_signed_inert_image_manifest.v1
require_value architecture aarch64
require_value base_generation_schema_version whoathere.linux_vz_inert_image_manifest.v5
require_value image_state candidate_unqualified
require_value kernel_release 6.18.35-0-virt
require_value kernel_btf_sha256 sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb
require_value guest_seed_provisioning root_owned_mode_0600_initramfs_path
require_value external_network no_external_route
require_value package_execution disabled
require_value root_disk structurally_absent
require_value sync_back_policy structurally_absent
require_value rustc_version 'rustc 1.91.1 (ed61e7d7e 2025-11-07)'
require_value cargo_zigbuild_version 'cargo-zigbuild 0.21.6'
require_value zig_version 0.15.2
require_value source_iso_sha256 "sha256:$expected_iso_sha256"
require_value source_modloop_sha256 "sha256:$expected_modloop_sha256"
require_value vsock_core_sha256 "sha256:$expected_vsock_core_sha256"
require_value virtio_vsock_common_sha256 "sha256:$expected_vsock_common_sha256"
require_value virtio_vsock_transport_sha256 "sha256:$expected_vsock_transport_sha256"

require_hash source_iso_sha256 "$iso"
require_hash source_modloop_sha256 "$image/boot/modloop-virt"
require_hash base_generation_manifest_sha256 "$base/manifest.json"
require_hash builder_source_sha256 "$script_dir/build-alpine-signed-inert-image.sh"
require_hash canonical_signed_newc_source_sha256 "$source_dir/tools/canonical_signed_newc.c"
require_hash cargo_lock_sha256 "$whoathere_root/Cargo.lock"
require_hash kernel_image_sha256 "$image/Image-virt"
require_hash kernel_config_sha256 "$image/config-6.18.35-0-virt"
require_hash guest_init_sha256 "$image/overlay/init"
require_hash guest_init_source_sha256 "$source_dir/guest/signed_init"
require_hash guest_signer_sha256 "$image/overlay/whoathere/guest-signer"
require_hash guest_signer_source_sha256 "$whoathere_root/crates/whoathere-macos-vm/src/bin/whoathere-linux-vz-guest-signer.rs"
require_hash signed_overlay_cpio_sha256 "$overlay"
require_hash signed_overlay_cpio_gzip_sha256 "$overlay_gzip"
require_hash whoathere_signed_initramfs_sha256 "$initramfs"
require_hash vsock_core_sha256 "$image/overlay/whoathere/modules/vsock.ko"
require_hash virtio_vsock_common_sha256 "$image/overlay/whoathere/modules/vmw_vsock_virtio_transport_common.ko"
require_hash virtio_vsock_transport_sha256 "$image/overlay/whoathere/modules/vmw_vsock_virtio_transport.ko"
require_value process_sensor_probe_sha256 "$(jq -er '.process_sensor_probe_sha256' "$base/manifest.json")"
require_value process_fixture_child_sha256 "$(jq -er '.process_fixture_child_sha256' "$base/manifest.json")"

"$script_dir/verify-alpine-inert-image.sh" "$iso" "$base" >/dev/null
case "$(file "$image/overlay/whoathere/guest-signer")" in
    *"ELF 64-bit"*"ARM aarch64"*"statically linked"*"stripped"*) ;;
    *) echo "guest signer binary contract mismatch" >&2; exit 65 ;;
esac
expanded_overlay_hash="sha256:$(gzip -dc "$overlay_gzip" | shasum -a 256 | awk '{print $1}')"
require_value signed_overlay_cpio_sha256 "$expanded_overlay_hash"
cp "$base/whoathere-initramfs-virt" "$combined_tmp"
/bin/cat "$overlay_gzip" >> "$combined_tmp"
if ! cmp -s "$combined_tmp" "$initramfs"; then
    echo "signed initramfs concatenation mismatch" >&2
    exit 65
fi

entries=$(cpio -it < "$overlay" 2>/dev/null)
expected_entries=$(printf 'init\nwhoathere\nwhoathere/guest-signer\nwhoathere/guest-ed25519.seed\nwhoathere/modules\nwhoathere/modules/vsock.ko\nwhoathere/modules/vmw_vsock_virtio_transport_common.ko\nwhoathere/modules/vmw_vsock_virtio_transport.ko')
if [ "$entries" != "$expected_entries" ]; then
    echo "signed overlay entry set or order mismatch" >&2
    exit 65
fi
(
    cd "$extract_root"
    cpio -idmu < "$overlay" >/dev/null 2>&1
)
if ! cmp -s "$extract_root/init" "$image/overlay/init" || \
   ! cmp -s "$extract_root/whoathere/guest-signer" "$image/overlay/whoathere/guest-signer" || \
   ! cmp -s "$extract_root/whoathere/guest-ed25519.seed" "$guest_seed" || \
   ! cmp -s "$extract_root/whoathere/modules/vsock.ko" "$image/overlay/whoathere/modules/vsock.ko" || \
   ! cmp -s "$extract_root/whoathere/modules/vmw_vsock_virtio_transport_common.ko" "$image/overlay/whoathere/modules/vmw_vsock_virtio_transport_common.ko" || \
   ! cmp -s "$extract_root/whoathere/modules/vmw_vsock_virtio_transport.ko" "$image/overlay/whoathere/modules/vmw_vsock_virtio_transport.ko"
then
    echo "signed overlay content mismatch" >&2
    exit 65
fi
if [ "$(stat -f '%Lp' "$extract_root/init")" != 755 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere")" != 711 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere/guest-signer")" != 700 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere/guest-ed25519.seed")" != 600 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere/modules")" != 700 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere/modules/vsock.ko")" != 400 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere/modules/vmw_vsock_virtio_transport_common.ko")" != 400 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere/modules/vmw_vsock_virtio_transport.ko")" != 400 ]
then
    echo "signed overlay protection modes mismatch" >&2
    exit 65
fi

printf '%s\n' '{"execution_authority":false,"image_state":"candidate_unqualified","package_execution":false,"status":"verified","sync_back":false}'
