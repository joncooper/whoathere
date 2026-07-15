import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func executionRuntimeManifestDecodesExactNonAuthorizingCandidate() throws {
    let fixture = try executionRuntimeManifestFixture()
    let parsed = try decodeLinuxVzPackageExecutionRuntimeManifest(fixture.data)
    #expect(parsed.manifestSHA256 == sha256(fixture.data))
    #expect(parsed.rootfsSHA256 == sha256(fixture.rootfs))
    #expect(parsed.rootfsByteLength == UInt64(fixture.rootfs.count))
    #expect(parsed.packageRunnerSHA256 == sha256(fixture.runner))
    #expect(parsed.packageRunnerByteLength == UInt64(fixture.runner.count))
    #expect(parsed.packageUID == 65_534)
    #expect(parsed.packageGID == 65_534)
    #expect(parsed.physicalQualificationRequired)
    #expect(!parsed.executionAuthorityPermitted)
    #expect(!parsed.packageExecutionPermitted)
    #expect(!parsed.syncBackPermitted)
}

@Test func executionRuntimeManifestRejectsAuthorityRebindingAndNoncanonicalBytes() throws {
    let fixture = try executionRuntimeManifestFixture()
    var authority = fixture.value
    authority["package_execution_authority"] = "available"
    #expect(throws: LinuxVzPackageExecutionRuntimeManifestError.invalidSchema) {
        try decodeLinuxVzPackageExecutionRuntimeManifest(
            try executionRuntimeManifestData(authority)
        )
    }
    var digestAlias = fixture.value
    digestAlias["package_runner_sha256"] = digestAlias["rootfs_sha256"]
    #expect(throws: LinuxVzPackageExecutionRuntimeManifestError.invalidBinding) {
        try decodeLinuxVzPackageExecutionRuntimeManifest(
            try executionRuntimeManifestData(digestAlias)
        )
    }
    #expect(throws: LinuxVzPackageExecutionRuntimeManifestError.nonCanonical) {
        try decodeLinuxVzPackageExecutionRuntimeManifest(Data(fixture.data.dropLast()))
    }
}

struct ExecutionRuntimeManifestFixture {
    let data: Data
    let value: [String: Any]
    let rootfs: Data
    let runner: Data
}

func executionRuntimeManifestFixture() throws -> ExecutionRuntimeManifestFixture {
    let rootfs = Data("execution runtime rootfs".utf8)
    let runner = Data("fixed root coordinator".utf8)
    let value: [String: Any] = [
        "alpine_release": "3.24.1",
        "architecture": "aarch64",
        "builder_source_sha256": sha256(Data("outer builder".utf8)),
        "candidate_runtime_qualification": "required",
        "cargo_lock_sha256": sha256(Data("cargo lock".utf8)),
        "container_builder_source_sha256": sha256(Data("container builder".utf8)),
        "external_network": "structurally_absent",
        "image_state": "candidate_exact_bytes_not_yet_execution_qualified",
        "node_executable_sha256": sha256(Data("node executable".utf8)),
        "node_version": "v24.17.0",
        "npm_cli_sha256": sha256(Data("npm cli".utf8)),
        "npm_version": "11.12.1",
        "package_execution": false,
        "package_execution_authority":
            "structurally_unavailable_until_verified_qualification_and_signed_one_use_grant",
        "package_gid": "65534",
        "package_runner_byte_length": String(runner.count),
        "package_runner_mode": "fixed_root_coordinator_authenticated_evidence_v1",
        "package_runner_path": "/whoathere/package-root-runtime",
        "package_runner_sha256": sha256(runner),
        "package_uid": "65534",
        "pip_entrypoint_sha256": sha256(Data("pip entrypoint".utf8)),
        "pip_version": "26.1.2",
        "python_executable_sha256": sha256(Data("python executable".utf8)),
        "python_version": "3.14.5",
        "reproducible_epoch": "1783900800",
        "rootfs_byte_length": String(rootfs.count),
        "rootfs_format": "raw_ext2_block_image_v1",
        "rootfs_sha256": sha256(rootfs),
        "rootfs_tar_byte_length": "4096",
        "rootfs_tar_sha256": sha256(Data("rootfs tar".utf8)),
        "rootfs_uuid": "57484f41-5448-4552-5254-554e54494d45",
        "runtime_common_source_sha256": sha256(Data("runtime common source".utf8)),
        "runtime_container_arm64_image_id":
            "sha256:1991bd789d7184290c3cce84fd6af068b8b745e9bddf178661ce7f5ecf68135c",
        "runtime_container_digest":
            "sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
        "runtime_inputs_lock_sha256": sha256(Data("runtime inputs".utf8)),
        "runtime_source_closure_sha256": sha256(Data("runtime sources".utf8)),
        "schema_version": linuxVzPackageExecutionRuntimeManifestSchemaV1,
        "source_minirootfs_sha256":
            "sha256:f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259",
        "sync_back": false,
        "workspace_manifest_sha256": sha256(Data("workspace manifest".utf8)),
    ]
    return ExecutionRuntimeManifestFixture(
        data: try executionRuntimeManifestData(value),
        value: value,
        rootfs: rootfs,
        runner: runner
    )
}

func executionRuntimeManifestData(_ value: [String: Any]) throws -> Data {
    var data = try canonicalJSONData(value)
    data.append(0x0a)
    return data
}
