import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzPackageRuntimeManifestDecodesExactNonAuthorizingCandidate() throws {
    let fixture = try linuxVzPackageRuntimeManifestFixture()
    let parsed = try decodeLinuxVzPackageRuntimeManifest(fixture.data)
    #expect(parsed.manifestSHA256 == sha256(fixture.data))
    #expect(parsed.rootfsSHA256 == sha256(fixture.rootfs))
    #expect(parsed.rootfsByteLength == UInt64(fixture.rootfs.count))
    #expect(parsed.packageRunnerSHA256 == sha256(fixture.runner))
    #expect(parsed.packageUID == 65_534)
    #expect(parsed.packageGID == 65_534)
    #expect(parsed.runtimeQualificationPermitted)
    #expect(!parsed.packageExecutionPermitted)
    #expect(!parsed.syncBackPermitted)
}

@Test func linuxVzPackageRuntimeManifestRejectsRebindingAndNoncanonicalBytes() throws {
    let fixture = try linuxVzPackageRuntimeManifestFixture()
    var rebound = fixture.value
    rebound["package_execution"] = true
    #expect(throws: LinuxVzPackageRuntimeManifestError.invalidSchema) {
        try decodeLinuxVzPackageRuntimeManifest(try linuxVzRuntimeManifestData(rebound))
    }
    var runnerRebound = fixture.value
    runnerRebound["package_runner_sha256"] = runnerRebound["rootfs_sha256"]
    #expect(throws: LinuxVzPackageRuntimeManifestError.invalidBinding) {
        try decodeLinuxVzPackageRuntimeManifest(try linuxVzRuntimeManifestData(runnerRebound))
    }
    #expect(throws: LinuxVzPackageRuntimeManifestError.nonCanonical) {
        try decodeLinuxVzPackageRuntimeManifest(Data(fixture.data.dropLast()))
    }
}

struct LinuxVzPackageRuntimeManifestFixture {
    let data: Data
    let value: [String: Any]
    let rootfs: Data
    let runner: Data
}

func linuxVzPackageRuntimeManifestFixture(
    rootfs: Data = Data("inert rootfs".utf8),
    runner: Data = Data("non-executing package probe".utf8)
) throws -> LinuxVzPackageRuntimeManifestFixture {
    let value: [String: Any] = [
        "alpine_release": "3.24.1",
        "architecture": "aarch64",
        "builder_source_sha256": sha256(Data("outer builder".utf8)),
        "candidate_runtime_qualification": "required",
        "container_builder_source_sha256": sha256(Data("container builder".utf8)),
        "external_network": "structurally_absent",
        "image_state": "candidate_exact_bytes_not_yet_independently_qualified",
        "node_executable_sha256": sha256(Data("node".utf8)),
        "node_version": "v24.17.0",
        "npm_cli_sha256": sha256(Data("npm".utf8)),
        "npm_version": "11.12.1",
        "package_execution": false,
        "package_gid": "65534",
        "package_runner_mode": "nonexecuting_runtime_probe_only",
        "package_runner_sha256": sha256(runner),
        "package_uid": "65534",
        "pip_entrypoint_sha256": sha256(Data("pip".utf8)),
        "pip_version": "26.1.2",
        "python_executable_sha256": sha256(Data("python".utf8)),
        "python_version": "3.14.5",
        "reproducible_epoch": "1783900800",
        "rootfs_byte_length": String(rootfs.count),
        "rootfs_format": "raw_ext2_block_image_v1",
        "rootfs_sha256": sha256(rootfs),
        "rootfs_tar_byte_length": "4096",
        "rootfs_tar_sha256": sha256(Data("rootfs archive".utf8)),
        "rootfs_uuid": "57484f41-5448-4552-5254-554e54494d45",
        "runtime_container_arm64_image_id":
            "sha256:1991bd789d7184290c3cce84fd6af068b8b745e9bddf178661ce7f5ecf68135c",
        "runtime_container_digest":
            "sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
        "runtime_inputs_lock_sha256": sha256(Data("runtime lock".utf8)),
        "runtime_probe_source_sha256": sha256(Data("probe source".utf8)),
        "schema_version": linuxVzPackageRuntimeManifestSchemaV1,
        "source_minirootfs_sha256":
            "sha256:f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259",
        "sync_back": false,
        "zig_version": "0.15.2"
    ]
    return LinuxVzPackageRuntimeManifestFixture(
        data: try linuxVzRuntimeManifestData(value),
        value: value,
        rootfs: rootfs,
        runner: runner
    )
}

private func linuxVzRuntimeManifestData(_ value: [String: Any]) throws -> Data {
    var data = try canonicalJSONData(value)
    data.append(0x0a)
    return data
}
