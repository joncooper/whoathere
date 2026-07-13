#!/bin/sh

runtime_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
runtime_source_dir=$(CDPATH= cd -- "$runtime_script_dir/.." && pwd)
runtime_input_lock="$runtime_source_dir/config/runtime-inputs.lock"
runtime_container_digest=sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
runtime_container_image="alpine@$runtime_container_digest"
runtime_container_arm64_image_id=sha256:1991bd789d7184290c3cce84fd6af068b8b745e9bddf178661ce7f5ecf68135c
runtime_reproducible_epoch=1783900800
runtime_rootfs_uuid=57484f41-5448-4552-5254-554e54494d45

runtime_require_absolute_path() {
    case "$1" in
        /*) ;;
        *) echo "path must be absolute: $1" >&2; exit 64 ;;
    esac
}

runtime_validate_lock() {
    if [ ! -f "$runtime_input_lock" ] || [ -L "$runtime_input_lock" ]; then
        echo "runtime input lock must be a regular non-symlink file" >&2
        exit 66
    fi
    awk -F '\t' '
        NR == 1 {
            if ($0 != "# whoathere.linux_vz_package_runtime_inputs.v1") exit 1
            next
        }
        NF != 3 { exit 1 }
        $1 != "minirootfs" && $1 != "runtime_apk" && $1 != "build_apk" { exit 1 }
        length($2) != 64 || $2 !~ /^[0-9a-f]+$/ { exit 1 }
        $3 !~ /^https:\/\/dl-cdn\.alpinelinux\.org\/alpine\/v3\.24\// { exit 1 }
        seen_url[$3]++ && $1 != "build_apk" { exit 1 }
        $1 == "minirootfs" { minirootfs++ }
        $1 == "runtime_apk" { runtime++ }
        $1 == "build_apk" { build++ }
        END {
            if (NR != 59 || minirootfs != 1 || runtime != 38 || build != 19) exit 1
        }
    ' "$runtime_input_lock" || {
        echo "runtime input lock is invalid" >&2
        exit 65
    }
}

runtime_role_directory() {
    case "$1" in
        minirootfs) printf '%s\n' minirootfs ;;
        runtime_apk) printf '%s\n' runtime-apks ;;
        build_apk) printf '%s\n' build-apks ;;
        *) return 1 ;;
    esac
}

runtime_verify_inputs() {
    input_dir=$1
    runtime_require_absolute_path "$input_dir"
    runtime_validate_lock
    if [ ! -d "$input_dir" ] || [ -L "$input_dir" ]; then
        echo "runtime input directory must be a non-symlink directory" >&2
        exit 66
    fi
    if [ ! -f "$input_dir/runtime-inputs.lock" ] || [ -L "$input_dir/runtime-inputs.lock" ] || \
       ! cmp -s "$runtime_input_lock" "$input_dir/runtime-inputs.lock"
    then
        echo "runtime input directory has the wrong lock file" >&2
        exit 65
    fi
    expected_count=1
    while IFS="$(printf '\t')" read -r role expected_sha256 url; do
        case "$role" in
            \#*) continue ;;
        esac
        directory=$(runtime_role_directory "$role")
        filename=${url##*/}
        case "$filename" in
            ""|.*|*[!A-Za-z0-9._+-]*)
                echo "unsafe runtime input filename in lock" >&2
                exit 65
                ;;
        esac
        path="$input_dir/$directory/$filename"
        if [ ! -f "$path" ] || [ -L "$path" ]; then
            echo "required runtime input missing: $directory/$filename" >&2
            exit 66
        fi
        actual_sha256=$(shasum -a 256 "$path" | awk '{print $1}')
        if [ "$actual_sha256" != "$expected_sha256" ]; then
            echo "runtime input SHA-256 mismatch: $directory/$filename" >&2
            exit 65
        fi
        expected_count=$((expected_count + 1))
    done < "$runtime_input_lock"
    if [ -n "$(find "$input_dir" -type l -print -quit)" ]; then
        echo "runtime input directory contains a symlink" >&2
        exit 65
    fi
    actual_count=$(find "$input_dir" -type f | wc -l | tr -d ' ')
    if [ "$actual_count" != "$expected_count" ]; then
        echo "runtime input directory contains unexpected files" >&2
        exit 65
    fi
}

runtime_verify_container_image() {
    details=$(docker image inspect "$runtime_container_image" \
        --format '{{.Id}} {{.Architecture}} {{.Os}} {{join .RepoDigests " "}}' 2>/dev/null) || {
        echo "pinned Alpine build container is not present locally" >&2
        exit 69
    }
    case "$details" in
        "$runtime_container_arm64_image_id arm64 linux "*"alpine@$runtime_container_digest"*) ;;
        *) echo "pinned Alpine build container identity mismatch" >&2; exit 65 ;;
    esac
}
