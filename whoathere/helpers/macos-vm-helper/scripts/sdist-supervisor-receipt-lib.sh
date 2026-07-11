#!/bin/sh

whoathere_render_sdist_supervisor_receipt() {
  [ "$#" -eq 15 ] || return 64
  BASE_GENERATION_ID_VALUE=$1
  CLONE_IMPLEMENTATION_SHA256_VALUE=$2
  CPU_COUNT_VALUE=$3
  GUEST_AUTH_PUBLIC_KEY_SHA256_VALUE=$4
  GUEST_PROTOCOL_SHA256_VALUE=$5
  GUEST_SUPERVISOR_SHA256_VALUE=$6
  MEMORY_MIB_VALUE=$7
  PACKAGE_GID_VALUE=$8
  PACKAGE_UID_VALUE=$9
  shift 9
  PACKAGE_USERNAME_VALUE=$1
  PIP_CLI_SHA256_VALUE=$2
  PIP_VERSION_VALUE=$3
  PYTHON_EXECUTABLE_SHA256_VALUE=$4
  PYTHON_VERSION_VALUE=$5
  RUNNER_CONFIGURATION_SHA256_VALUE=$6

  printf '%s' "{\"base_generation_id\":\"$BASE_GENERATION_ID_VALUE\",\"build_closure_materialization_enabled\":false,\"clone_implementation_sha256\":\"$CLONE_IMPLEMENTATION_SHA256_VALUE\",\"cpu_count\":\"$CPU_COUNT_VALUE\",\"guest_auth_public_key_sha256\":\"$GUEST_AUTH_PUBLIC_KEY_SHA256_VALUE\",\"guest_protocol_sha256\":\"$GUEST_PROTOCOL_SHA256_VALUE\",\"guest_supervisor_sha256\":\"$GUEST_SUPERVISOR_SHA256_VALUE\",\"memory_mib\":\"$MEMORY_MIB_VALUE\",\"package_execution_enabled\":false,\"package_gid\":\"$PACKAGE_GID_VALUE\",\"package_uid\":\"$PACKAGE_UID_VALUE\",\"package_username\":\"$PACKAGE_USERNAME_VALUE\",\"pip_cli_sha256\":\"$PIP_CLI_SHA256_VALUE\",\"pip_version\":\"$PIP_VERSION_VALUE\",\"public_resolution_enabled\":false,\"python_executable_sha256\":\"$PYTHON_EXECUTABLE_SHA256_VALUE\",\"python_version\":\"$PYTHON_VERSION_VALUE\",\"runner_configuration_sha256\":\"$RUNNER_CONFIGURATION_SHA256_VALUE\",\"schema_version\":\"whoathere.sdist_supervisor_provisioning.v1\",\"sdist_vsock_port\":\"47081\",\"sync_back_enabled\":false}"
}
