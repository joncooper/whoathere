#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 /absolute/path/alpine-virt-3.24.1-aarch64.iso /absolute/image-dir" >&2
    exit 64
fi

iso=$1
image=$2
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
kernel="$image/vmlinuz-virt"
base_initramfs="$image/base/boot/initramfs-virt"
overlay_cpio="$image/whoathere-overlay.cpio"
combined_initramfs="$image/whoathere-initramfs-virt"
config="$image/config-6.18.35-0-virt"
system_map="$image/System.map-6.18.35-0-virt"
guest_init="$image/overlay/init"
capability_probe="$image/overlay/whoathere/capability-probe"

for path in \
    "$iso" "$manifest" "$kernel" "$base_initramfs" "$overlay_cpio" \
    "$combined_initramfs" "$config" "$system_map" "$guest_init" "$capability_probe"
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

expected_keys='["architecture","base_initramfs_sha256","builder_source_sha256","canonical_newc_source_sha256","capability_probe_sha256","capability_probe_source_sha256","config_sha256","external_network","guest_init_sha256","guest_init_source_sha256","image_state","kernel_release","kernel_sha256","overlay_cpio_sha256","schema_version","source_iso_sha256","source_url","sync_back_policy","system_map_sha256","whoathere_initramfs_sha256","zig_version"]'
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

require_value schema_version whoathere.linux_vz_inert_image_manifest.v1
require_value architecture aarch64
require_value kernel_release 6.18.35-0-virt
require_value image_state candidate_unqualified
require_value external_network no_external_route
require_value sync_back_policy structurally_absent
require_value source_url https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/alpine-virt-3.24.1-aarch64.iso
require_hash source_iso_sha256 "$iso"
require_hash kernel_sha256 "$kernel"
require_hash base_initramfs_sha256 "$base_initramfs"
require_hash builder_source_sha256 "$script_dir/build-alpine-inert-image.sh"
require_hash overlay_cpio_sha256 "$overlay_cpio"
require_hash whoathere_initramfs_sha256 "$combined_initramfs"
require_hash config_sha256 "$config"
require_hash system_map_sha256 "$system_map"
require_hash guest_init_sha256 "$guest_init"
require_hash guest_init_source_sha256 "$source_dir/guest/init"
require_hash capability_probe_sha256 "$capability_probe"
require_hash capability_probe_source_sha256 "$source_dir/guest/capability_probe.c"
require_hash canonical_newc_source_sha256 "$source_dir/tools/canonical_newc.c"

combined_stream_hash="sha256:$(/bin/cat "$base_initramfs" "$overlay_cpio" | shasum -a 256 | awk '{print $1}')"
require_value whoathere_initramfs_sha256 "$combined_stream_hash"

entries=$(cpio -it < "$overlay_cpio" 2>/dev/null)
expected_entries=$(printf 'init\nwhoathere\nwhoathere/capability-probe')
if [ "$entries" != "$expected_entries" ]; then
    echo "canonical overlay entry set or order mismatch" >&2
    exit 65
fi
(
    cd "$extract_root"
    cpio -idmu < "$overlay_cpio" >/dev/null 2>&1
)
if ! cmp -s "$extract_root/init" "$guest_init" || \
   ! cmp -s "$extract_root/whoathere/capability-probe" "$capability_probe"; then
    echo "canonical overlay content mismatch" >&2
    exit 65
fi

probe_description=$(file "$capability_probe")
case "$probe_description" in
    *"ARM aarch64"*"statically linked"*"stripped"*) ;;
    *) echo "capability probe is not a stripped static aarch64 Linux executable" >&2; exit 65 ;;
esac

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
