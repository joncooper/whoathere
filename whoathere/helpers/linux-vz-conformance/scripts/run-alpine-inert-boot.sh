#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 /absolute/path/alpine-virt-3.24.1-aarch64.iso /absolute/image-dir /absolute/new-run-dir" >&2
    exit 64
fi

iso=$1
image=$2
run_dir=$3
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
helpers_dir=$(CDPATH= cd -- "$source_dir/.." && pwd)
helper_dir="$helpers_dir/macos-vm-helper"

for path in "$iso" "$image" "$run_dir"; do
    case "$path" in
        /*) ;;
        *) echo "all paths must be absolute" >&2; exit 64 ;;
    esac
done
if [ -e "$run_dir" ]; then
    echo "run directory must not already exist: $run_dir" >&2
    exit 73
fi

"$script_dir/verify-alpine-inert-image.sh" "$iso" "$image" >/dev/null
mkdir -p "$run_dir"

host_architecture=$(uname -m)
macos_product_version=$(sw_vers -productVersion)
macos_build=$(sw_vers -buildVersion)
virtualization_supported=false
if [ "$(sysctl -n kern.hv_support 2>/dev/null || true)" = "1" ]; then
    virtualization_supported=true
fi
jq -ncS \
    --arg host_architecture "$host_architecture" \
    --arg macos_product_version "$macos_product_version" \
    --arg macos_build "$macos_build" \
    --argjson virtualization_supported "$virtualization_supported" \
    '{external_route:false,host_architecture:$host_architecture,macos_build:$macos_build,macos_product_version:$macos_product_version,package_execution:false,schema_version:"whoathere.linux_vz_inert_host_preflight.v1",sync_back:false,virtualization_supported:$virtualization_supported}' \
    > "$run_dir/host-preflight.json"

if [ "$virtualization_supported" != true ]; then
    cat "$run_dir/host-preflight.json"
    echo "Virtualization.framework hardware support is unavailable" >&2
    exit 69
fi

swift build \
    --package-path "$helper_dir" \
    --product whoathere-linux-vz-conformance
helper_bin_dir=$(swift build --package-path "$helper_dir" --show-bin-path)
helper="$helper_bin_dir/whoathere-linux-vz-conformance"
"$helper_dir/scripts/sign-local-helper.sh" "$helper" >/dev/null
codesign --verify --strict "$helper"

expected_kernel=$(jq -er '.kernel_sha256' "$image/manifest.json")
expected_initramfs=$(jq -er '.whoathere_initramfs_sha256' "$image/manifest.json")

result_tmp="$run_dir/.boot-result.json.tmp.$$"
cleanup() {
    rm -f "$result_tmp"
}
trap cleanup EXIT HUP INT TERM

if "$helper" \
    --kernel "$image/vmlinuz-virt" \
    --initramfs "$image/whoathere-initramfs-virt" \
    --expected-kernel-sha256 "$expected_kernel" \
    --expected-initramfs-sha256 "$expected_initramfs" \
    --serial-log "$run_dir/serial.log" \
    --timeout-seconds 30 \
    > "$result_tmp"
then
    status=0
else
    status=$?
fi
mv "$result_tmp" "$run_dir/boot-result.json"
result_tmp=

canonical_result="$run_dir/.canonical-result.json.tmp.$$"
jq -cS . "$run_dir/boot-result.json" > "$canonical_result"
if ! cmp -s "$canonical_result" "$run_dir/boot-result.json"; then
    rm -f "$canonical_result"
    echo "boot result was not canonical JSON" >&2
    exit 65
fi
rm -f "$canonical_result"

if [ "$status" -eq 0 ]; then
    actual_kernel=$(jq -er '.kernel_sha256' "$run_dir/boot-result.json")
    actual_initramfs=$(jq -er '.initramfs_sha256' "$run_dir/boot-result.json")
    if [ "$actual_kernel" != "$expected_kernel" ] || [ "$actual_initramfs" != "$expected_initramfs" ]; then
        echo "boot result image digest mismatch" >&2
        exit 65
    fi
fi

cat "$run_dir/boot-result.json"
exit "$status"
