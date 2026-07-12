#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 /absolute/path/alpine-virt-3.24.1-aarch64.iso /absolute/output-dir" >&2
    exit 64
fi

iso=$1
final_output=$2
expected_iso_sha256=c81699152db11d2a6dbb7d75348d632fcf5811eff414d7e71876a8bb6d48bc02
expected_source_kernel_pe_sha256=47970e0ee0478fe5c60824a89f162d5a353fa29466e5d3bddb0f9c506f1ed756
kernel_gzip_payload_offset=51832
expected_kernel_image_sha256=8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd
expected_kernel_btf_sha256=d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)

case "$iso" in
    /*) ;;
    *) echo "ISO path must be absolute" >&2; exit 64 ;;
esac
case "$final_output" in
    /*) ;;
    *) echo "output path must be absolute" >&2; exit 64 ;;
esac
if [ ! -f "$iso" ] || [ -L "$iso" ]; then
    echo "ISO must be a regular non-symlink file" >&2
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
if [ -e "$final_output" ] || [ -L "$final_output" ]; then
    echo "output path must not already exist" >&2
    exit 73
fi
work_output=$(mktemp -d "$output_parent/.${output_name}.tmp.XXXXXX")
output=$work_output

zig_cache_root=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-zig-cache.XXXXXX")
combined_initramfs_tmp=
tmp_manifest=
copy_tmp=
overlay_cpio_tmp=
overlay_gzip_tmp=
kernel_image_tmp=
cleanup() {
    rm -rf "$zig_cache_root"
    if [ -n "$work_output" ]; then
        rm -rf "$work_output"
    fi
    if [ -n "$combined_initramfs_tmp" ]; then
        rm -f "$combined_initramfs_tmp"
    fi
    if [ -n "$tmp_manifest" ]; then
        rm -f "$tmp_manifest"
    fi
    if [ -n "$copy_tmp" ]; then
        rm -f "$copy_tmp"
    fi
    if [ -n "$overlay_cpio_tmp" ]; then
        rm -f "$overlay_cpio_tmp"
    fi
    if [ -n "$overlay_gzip_tmp" ]; then
        rm -f "$overlay_gzip_tmp"
    fi
    if [ -n "$kernel_image_tmp" ]; then
        rm -f "$kernel_image_tmp"
    fi
}
trap cleanup EXIT HUP INT TERM
export ZIG_GLOBAL_CACHE_DIR="$zig_cache_root/global"
export ZIG_LOCAL_CACHE_DIR="$zig_cache_root/local"

copy_regular_file() {
    copy_tmp="$2.tmp.$$"
    cp "$1" "$copy_tmp"
    chmod 0644 "$copy_tmp"
    mv -f "$copy_tmp" "$2"
    copy_tmp=
}

actual_iso_sha256=$(shasum -a 256 "$iso" | awk '{print $1}')
if [ "$actual_iso_sha256" != "$expected_iso_sha256" ]; then
    echo "Alpine ISO SHA-256 mismatch" >&2
    exit 65
fi

zig=${ZIG:-$(command -v zig || true)}
if [ -z "$zig" ] || [ ! -x "$zig" ]; then
    echo "zig compiler is required to build the measured aarch64 Linux capability probe" >&2
    exit 69
fi
zig_version=$("$zig" version)
native_cc=$(xcrun --find clang 2>/dev/null || true)
native_sdk=$(xcrun --show-sdk-path 2>/dev/null || true)
if [ -z "$native_cc" ] || [ ! -x "$native_cc" ] || [ -z "$native_sdk" ] || [ ! -d "$native_sdk" ]; then
    echo "Xcode clang is required to build the canonical initramfs archive writer" >&2
    exit 69
fi

mkdir -p "$output/base" "$output/overlay/whoathere"
bsdtar -xf "$iso" -C "$output/base" \
    boot/vmlinuz-virt \
    boot/initramfs-virt \
    boot/config-6.18.35-0-virt \
    boot/System.map-6.18.35-0-virt

source_kernel_pe_sha256=$(shasum -a 256 "$output/base/boot/vmlinuz-virt" | awk '{print $1}')
if [ "$source_kernel_pe_sha256" != "$expected_source_kernel_pe_sha256" ]; then
    echo "Alpine source kernel PE SHA-256 mismatch" >&2
    exit 65
fi
kernel_image_tmp="$output/.Image-virt.tmp.$$"
if tail -c +$((kernel_gzip_payload_offset + 1)) "$output/base/boot/vmlinuz-virt" | \
   gunzip -c 2>/dev/null > "$kernel_image_tmp"
then
    :
else
    decompressor_status=$?
    if [ "$decompressor_status" -ne 2 ]; then
        echo "Alpine kernel gzip payload extraction failed" >&2
        exit 65
    fi
fi
kernel_image_sha256=$(shasum -a 256 "$kernel_image_tmp" | awk '{print $1}')
if [ "$kernel_image_sha256" != "$expected_kernel_image_sha256" ]; then
    echo "Alpine raw kernel Image SHA-256 mismatch" >&2
    exit 65
fi
case "$(file "$kernel_image_tmp")" in
    *"Linux kernel ARM64 boot executable Image"*) ;;
    *) echo "Alpine extracted kernel is not an ARM64 boot Image" >&2; exit 65 ;;
esac
chmod 0644 "$kernel_image_tmp"
mv "$kernel_image_tmp" "$output/Image-virt"
kernel_image_tmp=

cp "$source_dir/guest/init" "$output/overlay/init"
chmod 0755 "$output/overlay/init"
"$zig" cc \
    -target aarch64-linux-musl \
    -O2 \
    -Wall \
    -Wextra \
    -Werror \
    -static \
    -s \
    -fno-ident \
    -Wl,--build-id=none \
    -o "$output/overlay/whoathere/capability-probe" \
    "$source_dir/guest/capability_probe.c"
chmod 0755 "$output/overlay/whoathere/capability-probe"
"$zig" cc \
    -target aarch64-linux-musl \
    -O2 \
    -Wall \
    -Wextra \
    -Werror \
    -static \
    -s \
    -fno-ident \
    -Wl,--build-id=none \
    -o "$output/overlay/whoathere/process-sensor-probe" \
    "$source_dir/guest/process_sensor_probe.c"
chmod 0755 "$output/overlay/whoathere/process-sensor-probe"
"$zig" cc \
    -target aarch64-linux-musl \
    -O2 \
    -Wall \
    -Wextra \
    -Werror \
    -static \
    -s \
    -fno-ident \
    -Wl,--build-id=none \
    -o "$output/overlay/whoathere/process-fixture-child" \
    "$source_dir/guest/process_fixture_child.c"
chmod 0755 "$output/overlay/whoathere/process-fixture-child"
"$native_cc" \
    -O2 \
    -Wall \
    -Wextra \
    -Werror \
    -fno-ident \
    -isysroot "$native_sdk" \
    -o "$zig_cache_root/canonical-newc" \
    "$source_dir/tools/canonical_newc.c"
touch -t 202607110000.00 \
    "$output/overlay/init" \
    "$output/overlay/whoathere" \
    "$output/overlay/whoathere/capability-probe" \
    "$output/overlay/whoathere/process-sensor-probe" \
    "$output/overlay/whoathere/process-fixture-child"

overlay_cpio_tmp="$output/.whoathere-overlay.cpio.tmp.$$"
"$zig_cache_root/canonical-newc" \
    "$overlay_cpio_tmp" \
    "$output/overlay/init" \
    "$output/overlay/whoathere/capability-probe" \
    "$output/overlay/whoathere/process-sensor-probe" \
    "$output/overlay/whoathere/process-fixture-child"
mv -f "$overlay_cpio_tmp" "$output/whoathere-overlay.cpio"
overlay_cpio_tmp=

overlay_gzip_tmp="$output/.whoathere-overlay.cpio.gz.tmp.$$"
gzip -n -9 -c "$output/whoathere-overlay.cpio" > "$overlay_gzip_tmp"
chmod 0644 "$overlay_gzip_tmp"
mv -f "$overlay_gzip_tmp" "$output/whoathere-overlay.cpio.gz"
overlay_gzip_tmp=

combined_initramfs_tmp="$output/.whoathere-initramfs-virt.tmp.$$"
cp "$output/base/boot/initramfs-virt" "$combined_initramfs_tmp"
chmod 0644 "$combined_initramfs_tmp"
/bin/cat "$output/whoathere-overlay.cpio.gz" >> "$combined_initramfs_tmp"
mv -f "$combined_initramfs_tmp" "$output/whoathere-initramfs-virt"
combined_initramfs_tmp=
copy_regular_file "$output/base/boot/config-6.18.35-0-virt" "$output/config-6.18.35-0-virt"
copy_regular_file "$output/base/boot/System.map-6.18.35-0-virt" "$output/System.map-6.18.35-0-virt"

kernel_image_sha256=$(shasum -a 256 "$output/Image-virt" | awk '{print $1}')
base_initramfs_sha256=$(shasum -a 256 "$output/base/boot/initramfs-virt" | awk '{print $1}')
builder_source_sha256=$(shasum -a 256 "$script_dir/build-alpine-inert-image.sh" | awk '{print $1}')
combined_initramfs_sha256=$(shasum -a 256 "$output/whoathere-initramfs-virt" | awk '{print $1}')
config_sha256=$(shasum -a 256 "$output/config-6.18.35-0-virt" | awk '{print $1}')
system_map_sha256=$(shasum -a 256 "$output/System.map-6.18.35-0-virt" | awk '{print $1}')
guest_init_sha256=$(shasum -a 256 "$output/overlay/init" | awk '{print $1}')
guest_init_source_sha256=$(shasum -a 256 "$source_dir/guest/init" | awk '{print $1}')
capability_probe_sha256=$(shasum -a 256 "$output/overlay/whoathere/capability-probe" | awk '{print $1}')
capability_probe_source_sha256=$(shasum -a 256 "$source_dir/guest/capability_probe.c" | awk '{print $1}')
process_sensor_probe_sha256=$(shasum -a 256 "$output/overlay/whoathere/process-sensor-probe" | awk '{print $1}')
process_sensor_probe_source_sha256=$(shasum -a 256 "$source_dir/guest/process_sensor_probe.c" | awk '{print $1}')
process_fixture_child_sha256=$(shasum -a 256 "$output/overlay/whoathere/process-fixture-child" | awk '{print $1}')
process_fixture_child_source_sha256=$(shasum -a 256 "$source_dir/guest/process_fixture_child.c" | awk '{print $1}')
canonical_newc_source_sha256=$(shasum -a 256 "$source_dir/tools/canonical_newc.c" | awk '{print $1}')
overlay_cpio_sha256=$(shasum -a 256 "$output/whoathere-overlay.cpio" | awk '{print $1}')
overlay_cpio_gzip_sha256=$(shasum -a 256 "$output/whoathere-overlay.cpio.gz" | awk '{print $1}')

manifest="$output/manifest.json"
tmp_manifest="$manifest.tmp.$$"
cat > "$tmp_manifest" <<EOF
{"architecture":"aarch64","base_initramfs_sha256":"sha256:$base_initramfs_sha256","builder_source_sha256":"sha256:$builder_source_sha256","canonical_newc_source_sha256":"sha256:$canonical_newc_source_sha256","capability_probe_sha256":"sha256:$capability_probe_sha256","capability_probe_source_sha256":"sha256:$capability_probe_source_sha256","config_sha256":"sha256:$config_sha256","external_network":"no_external_route","guest_init_sha256":"sha256:$guest_init_sha256","guest_init_source_sha256":"sha256:$guest_init_source_sha256","image_state":"candidate_unqualified","kernel_btf_sha256":"sha256:$expected_kernel_btf_sha256","kernel_extraction":"gzip_payload_from_pinned_pe_efi_kernel","kernel_gzip_payload_offset":"$kernel_gzip_payload_offset","kernel_image_sha256":"sha256:$kernel_image_sha256","kernel_release":"6.18.35-0-virt","overlay_cpio_gzip_sha256":"sha256:$overlay_cpio_gzip_sha256","overlay_cpio_sha256":"sha256:$overlay_cpio_sha256","process_fixture_child_sha256":"sha256:$process_fixture_child_sha256","process_fixture_child_source_sha256":"sha256:$process_fixture_child_source_sha256","process_sensor_probe_sha256":"sha256:$process_sensor_probe_sha256","process_sensor_probe_source_sha256":"sha256:$process_sensor_probe_source_sha256","schema_version":"whoathere.linux_vz_inert_image_manifest.v5","source_iso_sha256":"sha256:$actual_iso_sha256","source_kernel_pe_sha256":"sha256:$source_kernel_pe_sha256","source_url":"https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/alpine-virt-3.24.1-aarch64.iso","sync_back_policy":"structurally_absent","system_map_sha256":"sha256:$system_map_sha256","whoathere_initramfs_sha256":"sha256:$combined_initramfs_sha256","zig_version":"$zig_version"}
EOF
mv "$tmp_manifest" "$manifest"
tmp_manifest=

if [ -e "$final_output" ] || [ -L "$final_output" ]; then
    echo "output path appeared during build" >&2
    exit 73
fi
mv "$work_output" "$final_output"
work_output=
echo "$final_output/manifest.json"
