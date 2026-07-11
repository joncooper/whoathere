#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
    echo "usage: $0" >&2
    exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
table="$source_dir/guest/fixture_cases.def"
inspector_source="$source_dir/tools/fixture_contract_inspector.c"

for command in jq shasum file sort; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command missing: $command" >&2
        exit 69
    fi
done
zig=$(command -v zig || true)
native_cc=$(xcrun --find clang 2>/dev/null || true)
native_sdk=$(xcrun --show-sdk-path 2>/dev/null || true)
if [ -z "$zig" ] || [ ! -x "$zig" ] || \
   [ -z "$native_cc" ] || [ ! -x "$native_cc" ] || \
   [ -z "$native_sdk" ] || [ ! -d "$native_sdk" ]; then
    echo "Zig and Xcode Clang are required" >&2
    exit 69
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-fixture-contract.XXXXXX")
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM
export ZIG_GLOBAL_CACHE_DIR="$work/zig-global-cache"
export ZIG_LOCAL_CACHE_DIR="$work/zig-local-cache"

"$native_cc" \
    -Wall \
    -Wextra \
    -Werror \
    -fno-ident \
    -O2 \
    -isysroot "$native_sdk" \
    -I "$source_dir/guest" \
    -o "$work/fixture-contract-native" \
    "$inspector_source"

build_linux_contract() {
    destination=$1
    "$zig" cc \
        -Wall \
        -Wextra \
        -Werror \
        -fno-ident \
        -target aarch64-linux-musl \
        -O2 \
        -static \
        -s \
        -Wl,--build-id=none \
        -I "$source_dir/guest" \
        -o "$destination" \
        "$inspector_source"
}

build_linux_contract "$work/fixture-contract-linux-1"
build_linux_contract "$work/fixture-contract-linux-2"
if ! cmp -s "$work/fixture-contract-linux-1" "$work/fixture-contract-linux-2"; then
    echo "aarch64 fixture contract build is not deterministic" >&2
    exit 65
fi

"$work/fixture-contract-native" --list > "$work/cases"
case_count=$(wc -l < "$work/cases" | tr -d ' ')
unique_case_count=$(sort -u "$work/cases" | wc -l | tr -d ' ')
if [ "$case_count" != 38 ] || [ "$unique_case_count" != 38 ]; then
    echo "fixture contract must list exactly 38 unique cases" >&2
    exit 65
fi

while IFS= read -r fixture_case; do
    "$work/fixture-contract-native" --describe "$fixture_case" > "$work/description"
    jq -cS . "$work/description" > "$work/canonical-description"
    if ! cmp -s "$work/description" "$work/canonical-description"; then
        echo "noncanonical fixture description: $fixture_case" >&2
        exit 65
    fi
    expected_keys='["action","case","expected_terminal","external_route","family","network_policy","operation","package_execution","schema_version","sync_back","trigger_owner"]'
    if [ "$(jq -c 'keys' "$work/description")" != "$expected_keys" ] || \
       [ "$(jq -r '.schema_version' "$work/description")" != whoathere.linux_vz_inert_fixture_contract.v1 ] || \
       [ "$(jq -r '.case' "$work/description")" != "$fixture_case" ] || \
       [ "$(jq -r '.operation' "$work/description")" != describe_only ] || \
       [ "$(jq -r '.external_route' "$work/description")" != false ] || \
       [ "$(jq -r '.package_execution' "$work/description")" != false ] || \
       [ "$(jq -r '.sync_back' "$work/description")" != false ]; then
        echo "unsafe or rebound fixture description: $fixture_case" >&2
        exit 65
    fi
    for required_string in action expected_terminal family network_policy trigger_owner; do
        if [ -z "$(jq -r --arg field "$required_string" '.[$field]' "$work/description")" ]; then
            echo "empty fixture description field: $fixture_case/$required_string" >&2
            exit 65
        fi
    done
done < "$work/cases"

for rejected in unknown_case --execute; do
    if "$work/fixture-contract-native" --describe "$rejected" >/dev/null 2>&1; then
        echo "unknown fixture case accepted: $rejected" >&2
        exit 65
    fi
done
if "$work/fixture-contract-native" --execute kernel_config_and_btf >/dev/null 2>&1; then
    echo "fixture inspector accepted execution" >&2
    exit 65
fi

binary_description=$(file "$work/fixture-contract-linux-1")
case "$binary_description" in
    *"ARM aarch64"*"statically linked"*"stripped"*) ;;
    *) echo "fixture contract is not a stripped static aarch64 Linux executable" >&2; exit 65 ;;
esac

table_sha256=$(shasum -a 256 "$table" | awk '{print $1}')
source_sha256=$(shasum -a 256 "$inspector_source" | awk '{print $1}')
binary_sha256=$(shasum -a 256 "$work/fixture-contract-linux-1" | awk '{print $1}')
jq -ncS \
    --arg table_sha256 "sha256:$table_sha256" \
    --arg source_sha256 "sha256:$source_sha256" \
    --arg binary_sha256 "sha256:$binary_sha256" \
    '{aarch64_binary_sha256:$binary_sha256,case_count:38,external_route:false,operation:"describe_only",package_execution:false,schema_version:"whoathere.linux_vz_inert_fixture_contract_verification.v1",source_sha256:$source_sha256,sync_back:false,table_sha256:$table_sha256}'
