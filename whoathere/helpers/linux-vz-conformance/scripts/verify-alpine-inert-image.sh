#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 /absolute/path/alpine-virt-3.24.1-aarch64.iso /absolute/image-dir" >&2
    exit 64
fi

iso=$1
image=$2
expected_iso_sha256=c81699152db11d2a6dbb7d75348d632fcf5811eff414d7e71876a8bb6d48bc02
expected_source_kernel_pe_sha256=47970e0ee0478fe5c60824a89f162d5a353fa29466e5d3bddb0f9c506f1ed756
expected_kernel_image_sha256=8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd
expected_base_initramfs_sha256=fc1aad923040d23bea79f62bef4a8e2481162e89a5c42245903df1a85134a527
expected_kernel_btf_sha256=d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)

case "$iso" in
    /*) ;;
    *) echo "ISO path must be absolute" >&2; exit 64 ;;
esac
case "$image" in
    /*) ;;
    *) echo "image path must be absolute" >&2; exit 64 ;;
esac

for command in jq shasum cpio file; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command missing: $command" >&2
        exit 69
    fi
done

manifest="$image/manifest.json"
kernel="$image/Image-virt"
source_kernel_pe="$image/base/boot/vmlinuz-virt"
base_initramfs="$image/base/boot/initramfs-virt"
overlay_cpio="$image/whoathere-overlay.cpio"
overlay_cpio_gzip="$image/whoathere-overlay.cpio.gz"
combined_initramfs="$image/whoathere-initramfs-virt"
config="$image/config-6.18.35-0-virt"
system_map="$image/System.map-6.18.35-0-virt"
guest_init="$image/overlay/init"
capability_probe="$image/overlay/whoathere/capability-probe"
process_sensor_probe="$image/overlay/whoathere/process-sensor-probe"
process_fixture_child="$image/overlay/whoathere/process-fixture-child"

for path in \
    "$iso" "$manifest" "$kernel" "$source_kernel_pe" "$base_initramfs" "$overlay_cpio" \
    "$overlay_cpio_gzip" \
    "$combined_initramfs" "$config" "$system_map" "$guest_init" "$capability_probe" \
    "$process_sensor_probe" "$process_fixture_child"
do
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        echo "required regular non-symlink file missing: $path" >&2
        exit 66
    fi
done

canonical_manifest=$(mktemp "${TMPDIR:-/tmp}/whoathere-linux-vz-manifest.XXXXXX")
extract_root=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-linux-vz-overlay.XXXXXX")
cleanup() {
    rm -f "$canonical_manifest"
    rm -rf "$extract_root"
}
trap cleanup EXIT HUP INT TERM

jq -cS . "$manifest" > "$canonical_manifest"
if ! cmp -s "$canonical_manifest" "$manifest"; then
    echo "manifest must be canonical sorted compact JSON" >&2
    exit 65
fi

expected_keys='["architecture","base_initramfs_sha256","builder_source_sha256","canonical_newc_source_sha256","capability_probe_sha256","capability_probe_source_sha256","config_sha256","external_network","guest_init_sha256","guest_init_source_sha256","image_state","kernel_btf_sha256","kernel_extraction","kernel_gzip_payload_offset","kernel_image_sha256","kernel_release","overlay_cpio_gzip_sha256","overlay_cpio_sha256","process_fixture_child_sha256","process_fixture_child_source_sha256","process_sensor_probe_sha256","process_sensor_probe_source_sha256","schema_version","source_iso_sha256","source_kernel_pe_sha256","source_url","sync_back_policy","system_map_sha256","whoathere_initramfs_sha256","zig_version"]'
if [ "$(jq -c 'keys' "$manifest")" != "$expected_keys" ]; then
    echo "manifest key set mismatch" >&2
    exit 65
fi

require_value() {
    field=$1
    expected=$2
    actual=$(jq -er --arg field "$field" '.[$field]' "$manifest")
    if [ "$actual" != "$expected" ]; then
        echo "manifest value mismatch: $field" >&2
        exit 65
    fi
}

require_hash() {
    field=$1
    path=$2
    actual="sha256:$(shasum -a 256 "$path" | awk '{print $1}')"
    require_value "$field" "$actual"
}

require_value schema_version whoathere.linux_vz_inert_image_manifest.v5
require_value architecture aarch64
require_value kernel_release 6.18.35-0-virt
require_value kernel_btf_sha256 "sha256:$expected_kernel_btf_sha256"
require_value image_state candidate_unqualified
require_value external_network no_external_route
require_value sync_back_policy structurally_absent
require_value kernel_extraction gzip_payload_from_pinned_pe_efi_kernel
require_value kernel_gzip_payload_offset 51832
require_value source_url https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/alpine-virt-3.24.1-aarch64.iso
require_value source_iso_sha256 "sha256:$expected_iso_sha256"
require_value source_kernel_pe_sha256 "sha256:$expected_source_kernel_pe_sha256"
require_value kernel_image_sha256 "sha256:$expected_kernel_image_sha256"
require_value base_initramfs_sha256 "sha256:$expected_base_initramfs_sha256"
require_hash source_iso_sha256 "$iso"
require_hash source_kernel_pe_sha256 "$source_kernel_pe"
require_hash kernel_image_sha256 "$kernel"
require_hash base_initramfs_sha256 "$base_initramfs"
require_hash builder_source_sha256 "$script_dir/build-alpine-inert-image.sh"
require_hash overlay_cpio_sha256 "$overlay_cpio"
require_hash overlay_cpio_gzip_sha256 "$overlay_cpio_gzip"
require_hash whoathere_initramfs_sha256 "$combined_initramfs"
require_hash config_sha256 "$config"
require_hash system_map_sha256 "$system_map"
require_hash guest_init_sha256 "$guest_init"
require_hash guest_init_source_sha256 "$source_dir/guest/init"
require_hash capability_probe_sha256 "$capability_probe"
require_hash capability_probe_source_sha256 "$source_dir/guest/capability_probe.c"
require_hash process_sensor_probe_sha256 "$process_sensor_probe"
require_hash process_sensor_probe_source_sha256 "$source_dir/guest/process_sensor_probe.c"
require_hash process_fixture_child_sha256 "$process_fixture_child"
require_hash process_fixture_child_source_sha256 "$source_dir/guest/process_fixture_child.c"
require_hash canonical_newc_source_sha256 "$source_dir/tools/canonical_newc.c"

extracted_kernel_hash="sha256:$(tail -c +51833 "$source_kernel_pe" | gunzip -c 2>/dev/null | shasum -a 256 | awk '{print $1}')"
require_value kernel_image_sha256 "$extracted_kernel_hash"
case "$(file "$source_kernel_pe")" in
    *"PE32+ executable"*"EFI application"*"Aarch64"*) ;;
    *) echo "source kernel is not the pinned Aarch64 PE/EFI image" >&2; exit 65 ;;
esac
case "$(file "$kernel")" in
    *"Linux kernel ARM64 boot executable Image"*) ;;
    *) echo "extracted kernel is not an ARM64 boot Image" >&2; exit 65 ;;
esac

expanded_overlay_hash="sha256:$(gunzip -c "$overlay_cpio_gzip" | shasum -a 256 | awk '{print $1}')"
require_value overlay_cpio_sha256 "$expanded_overlay_hash"
combined_stream_hash="sha256:$(/bin/cat "$base_initramfs" "$overlay_cpio_gzip" | shasum -a 256 | awk '{print $1}')"
require_value whoathere_initramfs_sha256 "$combined_stream_hash"

entries=$(cpio -it < "$overlay_cpio" 2>/dev/null)
expected_entries=$(printf 'init\nwhoathere\nwhoathere/capability-probe\nwhoathere/process-sensor-probe\nwhoathere/process-fixture-child')
if [ "$entries" != "$expected_entries" ]; then
    echo "canonical overlay entry set or order mismatch" >&2
    exit 65
fi
(
    cd "$extract_root"
    cpio -idmu < "$overlay_cpio" >/dev/null 2>&1
)
if ! cmp -s "$extract_root/init" "$guest_init" || \
   ! cmp -s "$extract_root/whoathere/capability-probe" "$capability_probe" || \
   ! cmp -s "$extract_root/whoathere/process-sensor-probe" "$process_sensor_probe" || \
   ! cmp -s "$extract_root/whoathere/process-fixture-child" "$process_fixture_child"; then
    echo "canonical overlay content mismatch" >&2
    exit 65
fi
if [ "$(stat -f '%Lp' "$extract_root/init")" != 755 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere")" != 711 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere/capability-probe")" != 700 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere/process-sensor-probe")" != 700 ] || \
   [ "$(stat -f '%Lp' "$extract_root/whoathere/process-fixture-child")" != 555 ]; then
    echo "canonical overlay protection modes mismatch" >&2
    exit 65
fi

probe_description=$(file "$capability_probe")
case "$probe_description" in
    *"ARM aarch64"*"statically linked"*"stripped"*) ;;
    *) echo "capability probe is not a stripped static aarch64 Linux executable" >&2; exit 65 ;;
esac
for binary in "$process_sensor_probe" "$process_fixture_child"; do
    binary_description=$(file "$binary")
    case "$binary_description" in
        *"ARM aarch64"*"statically linked"*"stripped"*) ;;
        *) echo "process sensor fixture is not a stripped static aarch64 Linux executable" >&2; exit 65 ;;
    esac
done

for required_config in \
    CONFIG_BPF=y \
    CONFIG_BPF_SYSCALL=y \
    CONFIG_BPF_JIT=y \
    CONFIG_CGROUPS=y \
    CONFIG_CGROUP_BPF=y \
    CONFIG_FANOTIFY=y \
    CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y \
    CONFIG_DEBUG_INFO_BTF=y \
    CONFIG_VIRTIO=y \
    CONFIG_VIRTIO_CONSOLE=y
do
    if ! grep -qx "$required_config" "$config"; then
        echo "required kernel configuration missing: $required_config" >&2
        exit 65
    fi
done

printf '%s\n' '{"image_state":"candidate_unqualified","package_execution":false,"status":"verified","sync_back":false}'
