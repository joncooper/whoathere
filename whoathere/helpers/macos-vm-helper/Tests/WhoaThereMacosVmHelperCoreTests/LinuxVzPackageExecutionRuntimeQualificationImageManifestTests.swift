import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func executionRuntimeQualificationImageManifestBindsExactCandidate() throws {
    let fixture = try executionRuntimeManifestFixture()
    let runtime = try decodeLinuxVzPackageExecutionRuntimeManifest(fixture.data)
    let guestKeySHA256 = sha256(Data("guest evidence public key".utf8))
    let data = try executionRuntimeQualificationImageManifestFixture(
        runtime: runtime,
        guestKeySHA256: guestKeySHA256
    )
    let parsed = try decodeLinuxVzPackageExecutionRuntimeQualificationImageManifest(
        data,
        runtimeManifest: runtime,
        expectedGuestEvidencePublicKeySHA256: guestKeySHA256
    )
    #expect(parsed.manifestSHA256 == sha256(data))
    #expect(parsed.runtimeRootfsSHA256 == runtime.rootfsSHA256)
    #expect(parsed.runtimeRootfsByteLength == runtime.rootfsByteLength)
    #expect(parsed.packageRunnerSHA256 == runtime.packageRunnerSHA256)
    #expect(parsed.guestEvidencePublicKeySHA256 == guestKeySHA256)
    #expect(!parsed.executionAuthorityIssued)
    #expect(!parsed.packageExecutionObserved)
    #expect(!parsed.syncBackPermitted)
}

@Test func executionRuntimeQualificationImageManifestRejectsRebindingAndAuthority() throws {
    let fixture = try executionRuntimeManifestFixture()
    let runtime = try decodeLinuxVzPackageExecutionRuntimeManifest(fixture.data)
    let guestKeySHA256 = sha256(Data("guest evidence public key".utf8))
    let data = try executionRuntimeQualificationImageManifestFixture(
        runtime: runtime,
        guestKeySHA256: guestKeySHA256
    )
    var value = try #require(
        JSONSerialization.jsonObject(with: data) as? [String: Any]
    )
    value["execution_authority_issued"] = true
    #expect(
        throws: LinuxVzPackageExecutionRuntimeQualificationImageManifestError.invalidSchema
    ) {
        try decodeLinuxVzPackageExecutionRuntimeQualificationImageManifest(
            try executionRuntimeQualificationImageManifestData(value),
            runtimeManifest: runtime,
            expectedGuestEvidencePublicKeySHA256: guestKeySHA256
        )
    }
    value["execution_authority_issued"] = false
    value["candidate_runtime_rootfs_sha256"] = sha256(Data("other rootfs".utf8))
    #expect(
        throws: LinuxVzPackageExecutionRuntimeQualificationImageManifestError.invalidBinding
    ) {
        try decodeLinuxVzPackageExecutionRuntimeQualificationImageManifest(
            try executionRuntimeQualificationImageManifestData(value),
            runtimeManifest: runtime,
            expectedGuestEvidencePublicKeySHA256: guestKeySHA256
        )
    }
    #expect(
        throws: LinuxVzPackageExecutionRuntimeQualificationImageManifestError.nonCanonical
    ) {
        try decodeLinuxVzPackageExecutionRuntimeQualificationImageManifest(
            Data(data.dropLast()),
            runtimeManifest: runtime,
            expectedGuestEvidencePublicKeySHA256: guestKeySHA256
        )
    }
}

func executionRuntimeQualificationImageManifestFixture(
    runtime: ParsedLinuxVzPackageExecutionRuntimeManifest,
    guestKeySHA256: String
) throws -> Data {
    try executionRuntimeQualificationImageManifestData([
        "architecture": "aarch64",
        "base_initramfs_sha256": sha256(Data("base initramfs".utf8)),
        "builder_source_sha256": sha256(Data("qualification builder".utf8)),
        "candidate_runtime_manifest_sha256": runtime.manifestSHA256,
        "candidate_runtime_rootfs_byte_length": String(runtime.rootfsByteLength),
        "candidate_runtime_rootfs_sha256": runtime.rootfsSHA256,
        "execution_authority_issued": false,
        "external_network": "host_raw_frame_sinkhole_no_external_route",
        "guest_evidence_public_key_sha256": guestKeySHA256,
        "node_executable_sha256": runtime.nodeExecutableSHA256,
        "npm_cli_sha256": runtime.npmCLISHA256,
        "package_execution": false,
        "package_execution_runtime_sha256": runtime.packageRunnerSHA256,
        "pip_entrypoint_sha256": runtime.pipEntrypointSHA256,
        "python_executable_sha256": runtime.pythonExecutableSHA256,
        "qualification_init_sha256": sha256(Data("qualification init".utf8)),
        "qualification_init_source_sha256": sha256(Data("init source".utf8)),
        "qualification_initramfs_sha256": sha256(Data("final initramfs".utf8)),
        "qualification_operation":
            "fixed_root_coordinator_custody_probe_from_exact_read_only_rootfs",
        "qualification_overlay_cpio_gzip_sha256": sha256(Data("overlay gzip".utf8)),
        "qualification_overlay_cpio_sha256": sha256(Data("overlay cpio".utf8)),
        "rootfs_attachment": "virtio_block_read_only",
        "schema_version":
            linuxVzPackageExecutionRuntimeQualificationImageManifestSchemaV1,
        "sync_back": false,
        "writer_source_sha256": sha256(Data("newc writer".utf8)),
    ])
}

func executionRuntimeQualificationImageManifestData(_ value: [String: Any]) throws -> Data {
    var data = try canonicalJSONData(value)
    data.append(0x0a)
    return data
}
