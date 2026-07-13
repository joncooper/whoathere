#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /absolute/new-input-directory" >&2
    exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/runtime-inputs-common.sh"

final_output=$1
runtime_require_absolute_path "$final_output"
runtime_validate_lock
for command in awk cmp curl find shasum; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command missing: $command" >&2
        exit 69
    fi
done
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
cleanup() {
    if [ -n "$work_output" ]; then
        rm -rf "$work_output"
    fi
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work_output/minirootfs" "$work_output/runtime-apks" "$work_output/build-apks"
while IFS="$(printf '\t')" read -r role expected_sha256 url; do
    case "$role" in
        \#*) continue ;;
    esac
    directory=$(runtime_role_directory "$role")
    filename=${url##*/}
    destination="$work_output/$directory/$filename"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$destination" "$url"
    actual_sha256=$(shasum -a 256 "$destination" | awk '{print $1}')
    if [ "$actual_sha256" != "$expected_sha256" ]; then
        echo "downloaded runtime input SHA-256 mismatch: $filename" >&2
        exit 65
    fi
done < "$runtime_input_lock"
cp "$runtime_input_lock" "$work_output/runtime-inputs.lock"
runtime_verify_inputs "$work_output"
if [ -e "$final_output" ] || [ -L "$final_output" ]; then
    echo "output path appeared during acquisition" >&2
    exit 73
fi
mv "$work_output" "$final_output"
work_output=
printf '%s\n' "$final_output"
