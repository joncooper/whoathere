import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private let runtimeDigest = "sha256:" + String(repeating: "11", count: 32)
private let runtimeKeyDigest = "sha256:" + String(repeating: "22", count: 32)

@Test func executionRuntimeQualificationEvidenceBindsExactRuntimeKeyAndCustody() throws {
    let serial = try executionRuntimeSerial()
    let evidence = try decodeLinuxVzPackageExecutionRuntimeQualificationEvidenceV1(
        serial,
        expectedRuntimeSHA256: runtimeDigest,
        expectedPublicKeySHA256: runtimeKeyDigest
    )
    #expect(evidence.runtimeSHA256 == runtimeDigest)
    #expect(evidence.publicKeySHA256 == runtimeKeyDigest)
    #expect(evidence.servicePID == 100)
    #expect(evidence.runnerPID == 101)
    #expect(evidence.openDescriptorCount == 4)
    #expect(evidence.threadCount == 1)
    #expect(linuxVzPackageExecutionRuntimeQualificationMissingMarkersV1(serial).isEmpty)
    #expect(!linuxVzPackageExecutionRuntimeQualificationFailurePresentV1(serial))
}

@Test func executionRuntimeQualificationEvidenceRejectsAuthorityAndCapabilityUpgrades() throws {
    for (key, value) in [
        ("execution_authority_issued", true as Any),
        ("package_execution", true as Any),
        ("sync_back", true as Any),
        ("runner_effective_capabilities", "0000000000080000" as Any),
    ] {
        let serial = try executionRuntimeSerial(overrides: [key: value])
        #expect(throws: LinuxVzPackageExecutionRuntimeQualificationEvidenceError.invalidSchema) {
            try decodeLinuxVzPackageExecutionRuntimeQualificationEvidenceV1(
                serial,
                expectedRuntimeSHA256: runtimeDigest,
                expectedPublicKeySHA256: runtimeKeyDigest
            )
        }
    }
}

@Test func executionRuntimeQualificationEvidenceRejectsDuplicateAndReportsFailure() throws {
    let serial = try executionRuntimeSerial()
    #expect(throws: LinuxVzPackageExecutionRuntimeQualificationEvidenceError.duplicate) {
        try decodeLinuxVzPackageExecutionRuntimeQualificationEvidenceV1(
            serial + serial,
            expectedRuntimeSHA256: runtimeDigest,
            expectedPublicKeySHA256: runtimeKeyDigest
        )
    }
    let failed = serial + Data(
        "WHOATHERE_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_FAILED reason=test\n".utf8
    )
    #expect(linuxVzPackageExecutionRuntimeQualificationFailurePresentV1(failed))
}

private func executionRuntimeSerial(overrides: [String: Any] = [:]) throws -> Data {
    var payload: [String: Any] = [
        "schema_version": linuxVzPackageExecutionRuntimeQualificationEvidenceSchemaV1,
        "runtime_sha256": runtimeDigest,
        "seed_public_key_sha256": runtimeKeyDigest,
        "service_pid": "100",
        "runner_pid": "101",
        "runner_thread_count": "1",
        "runner_open_descriptor_count": "4",
        "runner_unexpected_descriptor_count": "0",
        "runner_inheritable_capabilities": "0000000000000000",
        "runner_permitted_capabilities": "000001fffff7ffff",
        "runner_effective_capabilities": "000001fffff7ffff",
        "runner_bounding_capabilities": "000001fffff7ffff",
        "runner_ambient_capabilities": "0000000000000000",
        "runner_exit_status": "0",
        "seed_byte_length": "32",
        "root_credentials_verified": true,
        "tracer_absent": true,
        "no_new_privileges": true,
        "ptrace_capability_present": false,
        "runner_self_dumpable": false,
        "service_dumpable": false,
        "runner_parent_death_signal_sigkill": true,
        "runner_seed_descriptor_closed": true,
        "runner_control_release_bound": true,
        "seed_read_after_runner_boundary_verification": true,
        "seed_pipe_exact_eof": true,
        "fixed_execution_entrypoint_measured": true,
        "coordinator_split_exercised": true,
        "execution_grant_consumed": false,
        "execution_request_consumed": false,
        "execution_authority_issued": false,
        "package_execution": false,
        "sync_back": false,
    ]
    for (key, value) in overrides { payload[key] = value }
    let canonical = try canonicalJSONData(payload)
    var lines = linuxVzPackageExecutionRuntimeQualificationRequiredMarkersV1
    lines.insert(
        linuxVzPackageExecutionRuntimeQualificationEvidenceSerialPrefixV1
            + String(decoding: canonical, as: UTF8.self),
        at: 3
    )
    return Data((lines.joined(separator: "\n") + "\n").utf8)
}
