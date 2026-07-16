#!/bin/sh
set -eu
umask 077

if [ "$#" -ne 5 ]; then
    echo "usage: $0 /absolute/base-initramfs /absolute/runtime-manifest.json /absolute/execution-bundle-directory /absolute/guest-ed25519.seed /absolute/new-output-directory" >&2
    exit 64
fi

base_initramfs=$1
runtime_manifest=$2
bundle_dir=$3
guest_seed=$4
final_output=$5
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
init_template="$source_dir/execution/guest/init.template"
launcher_source="$source_dir/execution/tools/execution_descriptor_launcher.c"
newc_source="$source_dir/execution/tools/canonical_execution_bundle_newc.c"

for path in "$base_initramfs" "$runtime_manifest" "$bundle_dir" "$guest_seed" "$final_output"; do
    case "$path" in
        /*) ;;
        *) echo "all input and output paths must be absolute" >&2; exit 64 ;;
    esac
done
for path in "$base_initramfs" "$runtime_manifest" "$guest_seed" \
    "$init_template" "$launcher_source" "$newc_source"
do
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        echo "execution image input must be a regular non-symlink file: $path" >&2
        exit 66
    fi
done
if [ ! -d "$bundle_dir" ] || [ -L "$bundle_dir" ]; then
    echo "execution bundle must be a non-symlink directory" >&2
    exit 66
fi
if [ "$(stat -f '%Lp' "$bundle_dir")" -ne 700 ]; then
    echo "execution bundle directory must have mode 0700" >&2
    exit 65
fi
if [ "$(stat -f '%z' "$guest_seed")" -ne 32 ]; then
    echo "guest signing seed must contain exactly 32 bytes" >&2
    exit 65
fi
if [ -e "$final_output" ] || [ -L "$final_output" ]; then
    echo "output path must not already exist" >&2
    exit 73
fi
for command in awk cmp file grep gzip jq sed shasum stat xcrun zig; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command missing: $command" >&2
        exit 69
    fi
done

bundle_manifest="$bundle_dir/bundle-manifest.json"
backend_identity="$bundle_dir/backend-identity.json"
qualified_backend="$bundle_dir/qualified-backend.json"
authority_request="$bundle_dir/package-authority-request.json"
execution_grant="$bundle_dir/execution-grant.json"
artifact="$bundle_dir/artifact.bin"
scenario_plan="$bundle_dir/scenario-plan.json"
scenario_template="$bundle_dir/scenario-template.json"
guest_public_key="$bundle_dir/guest-ed25519-public-key.bin"
host_public_key="$bundle_dir/host-ed25519-public-key.bin"
grant_public_key="$bundle_dir/grant-issuer-ed25519-public-key.bin"
qualification_record="$bundle_dir/execution-runtime-qualification-record.json"
clone_binding="$bundle_dir/runtime-clone-binding.json"
for path in "$bundle_manifest" "$backend_identity" "$qualified_backend" \
    "$authority_request" "$execution_grant" "$artifact" "$scenario_plan" \
    "$scenario_template" "$guest_public_key" "$host_public_key" \
    "$grant_public_key" "$qualification_record" "$clone_binding"
do
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        echo "execution bundle omitted a regular input: $path" >&2
        exit 66
    fi
done
for key in "$guest_public_key" "$host_public_key" "$grant_public_key"; do
    if [ "$(stat -f '%z' "$key")" -ne 32 ]; then
        echo "execution bundle public key has the wrong length" >&2
        exit 65
    fi
done

canonical_runtime=$(mktemp "${TMPDIR:-/tmp}/whoathere-runtime-manifest.XXXXXX")
canonical_bundle=$(mktemp "${TMPDIR:-/tmp}/whoathere-execution-bundle.XXXXXX")
canonical_request=$(mktemp "${TMPDIR:-/tmp}/whoathere-authority-request.XXXXXX")
canonical_grant=$(mktemp "${TMPDIR:-/tmp}/whoathere-execution-grant.XXXXXX")
canonical_clone=$(mktemp "${TMPDIR:-/tmp}/whoathere-clone-binding.XXXXXX")
cleanup_canonical() {
    rm -f "$canonical_runtime" "$canonical_bundle" "$canonical_request" \
        "$canonical_grant" "$canonical_clone"
}
trap cleanup_canonical EXIT HUP INT TERM
jq -cS . "$runtime_manifest" > "$canonical_runtime"
jq -cjS . "$bundle_manifest" > "$canonical_bundle"
jq -cjS . "$authority_request" > "$canonical_request"
jq -cjS . "$execution_grant" > "$canonical_grant"
jq -cjS . "$clone_binding" > "$canonical_clone"
for pair in \
    "$canonical_runtime:$runtime_manifest" \
    "$canonical_bundle:$bundle_manifest" \
    "$canonical_request:$authority_request" \
    "$canonical_grant:$execution_grant" \
    "$canonical_clone:$clone_binding"
do
    canonical=${pair%%:*}
    source=${pair#*:}
    if ! cmp -s "$canonical" "$source"; then
        echo "execution JSON input is not canonical JSON: $source" >&2
        exit 65
    fi
done

if [ "$(jq -er '.schema_version' "$runtime_manifest")" != \
     whoathere.linux_vz_package_execution_runtime_manifest.v1 ] || \
   [ "$(jq -er '.candidate_runtime_qualification' "$runtime_manifest")" != required ] || \
   [ "$(jq -er '.package_execution' "$runtime_manifest")" != false ] || \
   [ "$(jq -er '.sync_back' "$runtime_manifest")" != false ]
then
    echo "execution runtime manifest policy is invalid" >&2
    exit 65
fi
bundle_schema=$(jq -er '.schema_version | select(type == "string")' "$bundle_manifest")
case "$bundle_schema" in
    whoathere.linux_vz_inert_npm_execution_bundle.v1)
        bundle_environment=$(jq -er '.environment | select(type == "string")' \
            "$bundle_manifest")
        case "$bundle_environment" in
            ci_false|ci_true) ;;
            *) echo "execution bundle environment is invalid" >&2; exit 65 ;;
        esac
        if jq -e 'has("scenario_index")' "$bundle_manifest" >/dev/null; then
            echo "npm execution bundle contains a wheel selector" >&2
            exit 65
        fi
        expected_artifact_kind=npm_tarball
        ;;
    whoathere.linux_vz_inert_wheel_execution_bundle.v1)
        bundle_scenario_index=$(jq -er \
            '.scenario_index | select(type == "string")' "$bundle_manifest")
        if ! printf '%s\n' "$bundle_scenario_index" | grep -Eq '^(0|[1-9][0-9]*)$'; then
            echo "execution bundle scenario index is invalid" >&2
            exit 65
        fi
        if jq -e 'has("environment")' "$bundle_manifest" >/dev/null; then
            echo "wheel execution bundle contains an npm selector" >&2
            exit 65
        fi
        expected_artifact_kind=pypi_wheel
        ;;
    *)
        echo "execution bundle schema is invalid" >&2
        exit 65
        ;;
esac
if [ "$(jq -er '.execution_authority_issued' "$bundle_manifest")" != true ] || \
   [ "$(jq -er '.attempt_limit' "$bundle_manifest")" != 1 ] || \
   [ "$(jq -er '.public_network_route_present' "$bundle_manifest")" != false ] || \
   [ "$(jq -er '.sync_back' "$bundle_manifest")" != false ]
then
    echo "execution bundle policy is invalid" >&2
    exit 65
fi

digest() {
    printf 'sha256:%s\n' "$(shasum -a 256 "$1" | awk '{print $1}')"
}
require_digest() {
    path=$1
    expected=$2
    actual=$(digest "$path")
    if [ "$actual" != "$expected" ]; then
        echo "execution bundle digest mismatch: $path" >&2
        exit 65
    fi
}
valid_digest() {
    printf '%s\n' "$1" | grep -Eq '^sha256:[0-9a-f]{64}$'
}

runtime_sha256=$(jq -er '.package_runner_sha256' "$runtime_manifest")
rootfs_sha256=$(jq -er '.rootfs_sha256' "$runtime_manifest")
rootfs_byte_length=$(jq -er '.rootfs_byte_length' "$runtime_manifest")
node_sha256=$(jq -er '.node_executable_sha256' "$runtime_manifest")
npm_cli_sha256=$(jq -er '.npm_cli_sha256' "$runtime_manifest")
python_sha256=$(jq -er '.python_executable_sha256' "$runtime_manifest")
pip_entrypoint_sha256=$(jq -er '.pip_entrypoint_sha256' "$runtime_manifest")
runtime_manifest_sha256=$(digest "$runtime_manifest")
bundle_manifest_sha256=$(digest "$bundle_manifest")
backend_identity_sha256=$(digest "$backend_identity")
qualified_backend_sha256=$(digest "$qualified_backend")
authority_request_sha256=$(digest "$authority_request")
execution_grant_sha256=$(digest "$execution_grant")
artifact_sha256=$(digest "$artifact")
scenario_plan_sha256=$(digest "$scenario_plan")
scenario_template_sha256=$(digest "$scenario_template")
guest_public_key_sha256=$(digest "$guest_public_key")
host_public_key_sha256=$(digest "$host_public_key")
grant_public_key_sha256=$(digest "$grant_public_key")
qualification_record_sha256=$(digest "$qualification_record")
clone_binding_sha256=$(digest "$clone_binding")
for value in "$runtime_sha256" "$rootfs_sha256" "$node_sha256" "$npm_cli_sha256" \
    "$python_sha256" "$pip_entrypoint_sha256" "$runtime_manifest_sha256" \
    "$bundle_manifest_sha256" "$backend_identity_sha256" "$qualified_backend_sha256" \
    "$authority_request_sha256" "$execution_grant_sha256" "$artifact_sha256" \
    "$scenario_plan_sha256" "$scenario_template_sha256" "$guest_public_key_sha256" \
    "$host_public_key_sha256" "$grant_public_key_sha256" \
    "$qualification_record_sha256" "$clone_binding_sha256"
do
    valid_digest "$value" || { echo "execution digest is invalid" >&2; exit 65; }
done

require_digest "$artifact" "$(jq -er '.artifact_sha256' "$bundle_manifest")"
require_digest "$scenario_plan" "$(jq -er '.scenario_plan_sha256' "$bundle_manifest")"
require_digest "$scenario_template" "$(jq -er '.scenario_template_sha256' "$bundle_manifest")"
require_digest "$authority_request" \
    "$(jq -er '.package_authority_request_sha256' "$bundle_manifest")"
require_digest "$execution_grant" "$(jq -er '.execution_grant_sha256' "$bundle_manifest")"
require_digest "$qualification_record" \
    "$(jq -er '.execution_runtime_qualification_record_sha256' "$bundle_manifest")"
require_digest "$qualified_backend" \
    "$(jq -er '.qualified_telemetry_backend_sha256' "$bundle_manifest")"
require_digest "$guest_public_key" \
    "$(jq -er '.guest_evidence_public_key_sha256' "$bundle_manifest")"
require_digest "$host_public_key" \
    "$(jq -er '.host_evidence_public_key_sha256' "$bundle_manifest")"
require_digest "$grant_public_key" \
    "$(jq -er '.execution_grant_issuer_public_key_sha256' "$bundle_manifest")"
require_digest "$clone_binding" "$(jq -er '.clone_binding_sha256' "$bundle_manifest")"
require_digest "$backend_identity" "$(jq -er '.backend_identity_sha256' "$authority_request")"

if [ "$(jq -er '.artifact_sha256' "$authority_request")" != "$artifact_sha256" ] || \
   [ "$(jq -er '.artifact_kind' "$authority_request")" != "$expected_artifact_kind" ] || \
   [ "$(jq -er '.scenario_plan_sha256' "$authority_request")" != "$scenario_plan_sha256" ] || \
   [ "$(jq -er '.scenario_template_sha256' "$authority_request")" != "$scenario_template_sha256" ] || \
   [ "$(jq -er '.candidate_runtime_rootfs_sha256' "$authority_request")" != "$rootfs_sha256" ] || \
   [ "$(jq -er '.candidate_runtime_manifest_sha256' "$authority_request")" != "$runtime_manifest_sha256" ] || \
   [ "$(jq -er '.candidate_package_runner_sha256' "$authority_request")" != "$runtime_sha256" ] || \
   [ "$(jq -er '.clone_binding_sha256' "$authority_request")" != "$clone_binding_sha256" ] || \
   [ "$(jq -er '.package_execution_permitted' "$authority_request")" != false ] || \
   [ "$(jq -er '.sync_back_policy' "$authority_request")" != structurally_absent ]
then
    echo "authority request is not bound to the exact execution inputs" >&2
    exit 65
fi
if [ "$(jq -er '.package_authority_request_sha256' "$execution_grant")" != "$authority_request_sha256" ] || \
   [ "$(jq -er '.artifact_sha256' "$execution_grant")" != "$artifact_sha256" ] || \
   [ "$(jq -er '.execution_runtime_rootfs_sha256' "$execution_grant")" != "$rootfs_sha256" ] || \
   [ "$(jq -er '.execution_runtime_manifest_sha256' "$execution_grant")" != "$runtime_manifest_sha256" ] || \
   [ "$(jq -er '.package_execution_runner_sha256' "$execution_grant")" != "$runtime_sha256" ] || \
   [ "$(jq -er '.clone_binding_sha256' "$execution_grant")" != "$clone_binding_sha256" ] || \
   [ "$(jq -er '.attempt_limit' "$execution_grant")" != 1 ] || \
   [ "$(jq -er '.package_execution_permitted' "$execution_grant")" != true ] || \
   [ "$(jq -er '.public_network_route_present' "$execution_grant")" != false ] || \
   [ "$(jq -er '.sync_back_policy' "$execution_grant")" != structurally_absent ]
then
    echo "execution grant is not bound to the exact execution inputs" >&2
    exit 65
fi
if [ "$(jq -er '.base_rootfs_sha256' "$clone_binding")" != "$rootfs_sha256" ] || \
   [ "$(jq -er '.initial_rootfs_sha256' "$clone_binding")" != "$rootfs_sha256" ]
then
    echo "runtime clone binding is not bound to the qualified rootfs" >&2
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
build_root=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-execution-runtime-image.XXXXXX")
ZIG_GLOBAL_CACHE_DIR="$build_root/zig-global-cache"
ZIG_LOCAL_CACHE_DIR="$build_root/zig-local-cache"
export ZIG_GLOBAL_CACHE_DIR ZIG_LOCAL_CACHE_DIR
cleanup() {
    rm -rf "$build_root"
    if [ -n "$work_output" ]; then
        rm -rf "$work_output"
    fi
    cleanup_canonical
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$work_output/overlay/whoathere/inputs"

sed \
    -e "s|__WHOATHERE_RUNTIME_SHA256__|$runtime_sha256|g" \
    -e "s|__WHOATHERE_ROOTFS_SHA256__|$rootfs_sha256|g" \
    -e "s|__WHOATHERE_RUNTIME_MANIFEST_SHA256__|$runtime_manifest_sha256|g" \
    -e "s|__WHOATHERE_NODE_SHA256__|$node_sha256|g" \
    -e "s|__WHOATHERE_NPM_CLI_SHA256__|$npm_cli_sha256|g" \
    -e "s|__WHOATHERE_PYTHON_SHA256__|$python_sha256|g" \
    -e "s|__WHOATHERE_PIP_ENTRYPOINT_SHA256__|$pip_entrypoint_sha256|g" \
    -e "s|__WHOATHERE_BUNDLE_MANIFEST_SHA256__|$bundle_manifest_sha256|g" \
    -e "s|__WHOATHERE_BACKEND_IDENTITY_SHA256__|$backend_identity_sha256|g" \
    -e "s|__WHOATHERE_QUALIFIED_BACKEND_SHA256__|$qualified_backend_sha256|g" \
    -e "s|__WHOATHERE_AUTHORITY_REQUEST_SHA256__|$authority_request_sha256|g" \
    -e "s|__WHOATHERE_EXECUTION_GRANT_SHA256__|$execution_grant_sha256|g" \
    -e "s|__WHOATHERE_ARTIFACT_SHA256__|$artifact_sha256|g" \
    -e "s|__WHOATHERE_SCENARIO_PLAN_SHA256__|$scenario_plan_sha256|g" \
    -e "s|__WHOATHERE_SCENARIO_TEMPLATE_SHA256__|$scenario_template_sha256|g" \
    -e "s|__WHOATHERE_GUEST_PUBLIC_KEY_SHA256__|$guest_public_key_sha256|g" \
    -e "s|__WHOATHERE_HOST_PUBLIC_KEY_SHA256__|$host_public_key_sha256|g" \
    -e "s|__WHOATHERE_GRANT_PUBLIC_KEY_SHA256__|$grant_public_key_sha256|g" \
    -e "s|__WHOATHERE_QUALIFICATION_RECORD_SHA256__|$qualification_record_sha256|g" \
    -e "s|__WHOATHERE_CLONE_BINDING_SHA256__|$clone_binding_sha256|g" \
    "$init_template" > "$work_output/overlay/init"
if grep -q '__WHOATHERE_' "$work_output/overlay/init"; then
    echo "execution init substitution was incomplete" >&2
    exit 65
fi

zig cc -target aarch64-linux-musl -static -O2 -Wall -Wextra -Werror -fno-ident -s \
    -o "$work_output/overlay/whoathere/execution-descriptor-launcher" "$launcher_source"
case "$(file "$work_output/overlay/whoathere/execution-descriptor-launcher")" in
    *"ELF 64-bit"*"ARM aarch64"*"statically linked"*"stripped"*) ;;
    *) echo "execution descriptor launcher build is invalid" >&2; exit 65 ;;
esac
cp "$runtime_manifest" "$work_output/overlay/whoathere/execution-runtime-manifest.json"
cp "$guest_seed" "$work_output/overlay/whoathere/guest-ed25519.seed"
cp "$bundle_manifest" "$work_output/overlay/whoathere/inputs/bundle-manifest.json"
cp "$backend_identity" "$work_output/overlay/whoathere/inputs/backend-identity.json"
cp "$qualified_backend" "$work_output/overlay/whoathere/inputs/qualified-backend.json"
cp "$authority_request" "$work_output/overlay/whoathere/inputs/package-authority-request.json"
cp "$execution_grant" "$work_output/overlay/whoathere/inputs/execution-grant.json"
cp "$artifact" "$work_output/overlay/whoathere/inputs/artifact.bin"
cp "$scenario_plan" "$work_output/overlay/whoathere/inputs/scenario-plan.json"
cp "$scenario_template" "$work_output/overlay/whoathere/inputs/scenario-template.json"
cp "$guest_public_key" "$work_output/overlay/whoathere/inputs/guest-ed25519-public-key.bin"
cp "$host_public_key" "$work_output/overlay/whoathere/inputs/host-ed25519-public-key.bin"
cp "$grant_public_key" \
    "$work_output/overlay/whoathere/inputs/grant-issuer-ed25519-public-key.bin"
cp "$qualification_record" \
    "$work_output/overlay/whoathere/inputs/execution-runtime-qualification-record.json"
cp "$clone_binding" "$work_output/overlay/whoathere/inputs/runtime-clone-binding.json"
chmod 0755 "$work_output/overlay/init"
chmod 0711 "$work_output/overlay/whoathere" "$work_output/overlay/whoathere/inputs"
chmod 0500 "$work_output/overlay/whoathere/execution-descriptor-launcher"
chmod 0400 "$work_output/overlay/whoathere/guest-ed25519.seed"
chmod 0444 "$work_output/overlay/whoathere/execution-runtime-manifest.json" \
    "$work_output"/overlay/whoathere/inputs/*

native_cc=$(xcrun --find clang)
native_sdk=$(xcrun --show-sdk-path)
"$native_cc" -O2 -Wall -Wextra -Werror -fno-ident -isysroot "$native_sdk" \
    -o "$build_root/canonical-execution-bundle-newc" "$newc_source"
overlay="$work_output/whoathere-package-execution-overlay.cpio"
"$build_root/canonical-execution-bundle-newc" \
    "$overlay" \
    "$work_output/overlay/init" \
    "$work_output/overlay/whoathere/execution-descriptor-launcher" \
    "$work_output/overlay/whoathere/execution-runtime-manifest.json" \
    "$work_output/overlay/whoathere/guest-ed25519.seed" \
    "$work_output/overlay/whoathere/inputs/bundle-manifest.json" \
    "$work_output/overlay/whoathere/inputs/backend-identity.json" \
    "$work_output/overlay/whoathere/inputs/qualified-backend.json" \
    "$work_output/overlay/whoathere/inputs/package-authority-request.json" \
    "$work_output/overlay/whoathere/inputs/execution-grant.json" \
    "$work_output/overlay/whoathere/inputs/artifact.bin" \
    "$work_output/overlay/whoathere/inputs/scenario-plan.json" \
    "$work_output/overlay/whoathere/inputs/scenario-template.json" \
    "$work_output/overlay/whoathere/inputs/guest-ed25519-public-key.bin" \
    "$work_output/overlay/whoathere/inputs/host-ed25519-public-key.bin" \
    "$work_output/overlay/whoathere/inputs/grant-issuer-ed25519-public-key.bin" \
    "$work_output/overlay/whoathere/inputs/execution-runtime-qualification-record.json" \
    "$work_output/overlay/whoathere/inputs/runtime-clone-binding.json"
overlay_gzip="$overlay.gz"
gzip -n -9 -c "$overlay" > "$overlay_gzip"
final_initramfs="$work_output/whoathere-package-execution-initramfs-virt"
cp "$base_initramfs" "$final_initramfs"
chmod 0600 "$final_initramfs"
/bin/cat "$overlay_gzip" >> "$final_initramfs"
chmod 0600 "$overlay" "$overlay_gzip" "$final_initramfs"

base_initramfs_sha256=$(digest "$base_initramfs")
init_sha256=$(digest "$work_output/overlay/init")
init_source_sha256=$(digest "$init_template")
launcher_sha256=$(digest "$work_output/overlay/whoathere/execution-descriptor-launcher")
launcher_source_sha256=$(digest "$launcher_source")
newc_source_sha256=$(digest "$newc_source")
builder_source_sha256=$(digest "$script_dir/build-execution-runtime-execution-initramfs.sh")
overlay_sha256=$(digest "$overlay")
overlay_gzip_sha256=$(digest "$overlay_gzip")
final_initramfs_sha256=$(digest "$final_initramfs")
issued_at=$(jq -er '.issued_at_unix_seconds' "$bundle_manifest")
expires_at=$(jq -er '.expires_at_unix_seconds' "$bundle_manifest")

jq -ncS \
    --arg artifact_sha256 "$artifact_sha256" \
    --arg authority_request_sha256 "$authority_request_sha256" \
    --arg backend_identity_sha256 "$backend_identity_sha256" \
    --arg base_initramfs_sha256 "$base_initramfs_sha256" \
    --arg builder_source_sha256 "$builder_source_sha256" \
    --arg bundle_manifest_sha256 "$bundle_manifest_sha256" \
    --arg clone_binding_sha256 "$clone_binding_sha256" \
    --arg execution_grant_sha256 "$execution_grant_sha256" \
    --arg expires_at "$expires_at" \
    --arg final_initramfs_sha256 "$final_initramfs_sha256" \
    --arg guest_public_key_sha256 "$guest_public_key_sha256" \
    --arg host_public_key_sha256 "$host_public_key_sha256" \
    --arg init_sha256 "$init_sha256" \
    --arg init_source_sha256 "$init_source_sha256" \
    --arg issued_at "$issued_at" \
    --arg launcher_sha256 "$launcher_sha256" \
    --arg launcher_source_sha256 "$launcher_source_sha256" \
    --arg newc_source_sha256 "$newc_source_sha256" \
    --arg overlay_gzip_sha256 "$overlay_gzip_sha256" \
    --arg overlay_sha256 "$overlay_sha256" \
    --arg qualification_record_sha256 "$qualification_record_sha256" \
    --arg qualified_backend_sha256 "$qualified_backend_sha256" \
    --arg rootfs_byte_length "$rootfs_byte_length" \
    --arg rootfs_sha256 "$rootfs_sha256" \
    --arg runtime_manifest_sha256 "$runtime_manifest_sha256" \
    --arg runtime_sha256 "$runtime_sha256" \
    --arg scenario_plan_sha256 "$scenario_plan_sha256" \
    --arg scenario_template_sha256 "$scenario_template_sha256" \
    '{architecture:"aarch64",artifact_sha256:$artifact_sha256,authority_request_sha256:$authority_request_sha256,backend_identity_sha256:$backend_identity_sha256,base_initramfs_sha256:$base_initramfs_sha256,builder_source_sha256:$builder_source_sha256,bundle_manifest_sha256:$bundle_manifest_sha256,candidate_runtime_manifest_sha256:$runtime_manifest_sha256,candidate_runtime_rootfs_byte_length:$rootfs_byte_length,candidate_runtime_rootfs_sha256:$rootfs_sha256,clone_binding_sha256:$clone_binding_sha256,execution_authority_issued:true,execution_descriptor_launcher_sha256:$launcher_sha256,execution_descriptor_launcher_source_sha256:$launcher_source_sha256,execution_grant_expires_at_unix_seconds:$expires_at,execution_grant_issued_at_unix_seconds:$issued_at,execution_grant_sha256:$execution_grant_sha256,execution_init_sha256:$init_sha256,execution_init_source_sha256:$init_source_sha256,execution_initramfs_sha256:$final_initramfs_sha256,execution_overlay_cpio_gzip_sha256:$overlay_gzip_sha256,execution_overlay_cpio_sha256:$overlay_sha256,external_network:"host_raw_frame_sinkhole_no_external_route",guest_evidence_public_key_sha256:$guest_public_key_sha256,host_evidence_public_key_sha256:$host_public_key_sha256,package_execution:true,package_execution_runtime_sha256:$runtime_sha256,qualification_record_sha256:$qualification_record_sha256,qualified_telemetry_backend_sha256:$qualified_backend_sha256,rootfs_attachment:"disposable_clone_virtio_block_read_only",scenario_plan_sha256:$scenario_plan_sha256,scenario_template_sha256:$scenario_template_sha256,schema_version:"whoathere.linux_vz_package_execution_image_manifest.v1",sync_back:false,writer_source_sha256:$newc_source_sha256}' \
    > "$work_output/manifest.json"
chmod 0600 "$work_output/manifest.json"
rm -f "$work_output/overlay/whoathere/guest-ed25519.seed"

if [ -e "$final_output" ] || [ -L "$final_output" ]; then
    echo "output path appeared during build" >&2
    exit 73
fi
mv "$work_output" "$final_output"
work_output=
printf '%s\n' "$final_output/manifest.json"
