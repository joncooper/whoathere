import Foundation
@testable import WhoaThereMacosVmHelperCore
import Testing

private let coordinatorProbeSHA256 =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
private let coordinatorPublicKeySHA256 =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222"

@Test func packageRootCoordinatorEvidenceBindsCustodyAndSafetyState() throws {
    let serial = try rootCoordinatorSerial(value: rootCoordinatorValue())
    let evidence = try decodeLinuxVzPackageRootCoordinatorEvidenceV1(
        serial,
        expectedProbeSHA256: coordinatorProbeSHA256,
        expectedPublicKeySHA256: coordinatorPublicKeySHA256
    )
    #expect(evidence.probeSHA256 == coordinatorProbeSHA256)
    #expect(evidence.publicKeySHA256 == coordinatorPublicKeySHA256)
    #expect(evidence.servicePID == 41)
    #expect(evidence.runnerPID == 42)
    #expect(evidence.threadCount == 1)
    #expect(evidence.openDescriptorCount == 4)
    #expect(evidence.ambientCapabilities == 0)
    #expect(evidence.effectiveCapabilities & (UInt64(1) << 19) == 0)
    #expect(linuxVzPackageRootCoordinatorMissingMarkersV1(serial).isEmpty)
    #expect(!linuxVzPackageRootCoordinatorFailurePresentV1(serial))
}

@Test func packageRootCoordinatorEvidenceRejectsPrivilegeAndPolicyUpgrades() throws {
    for mutation in ["ptrace", "package", "descriptor", "seed_order"] {
        var value = rootCoordinatorValue()
        switch mutation {
        case "ptrace": value["effective_capabilities"] = "0000000000080000"
        case "package": value["package_execution"] = true
        case "descriptor": value["open_descriptor_count"] = "5"
        default: value["seed_read_after_runner_boundary_verification"] = false
        }
        #expect(throws: LinuxVzPackageRootCoordinatorEvidenceError.invalidSchema) {
            try decodeLinuxVzPackageRootCoordinatorEvidenceV1(
                rootCoordinatorSerial(value: value),
                expectedProbeSHA256: coordinatorProbeSHA256,
                expectedPublicKeySHA256: coordinatorPublicKeySHA256
            )
        }
    }
}

@Test func packageRootCoordinatorEvidenceRejectsDuplicateAndReportsFailure() throws {
    let serial = try rootCoordinatorSerial(value: rootCoordinatorValue())
    #expect(throws: LinuxVzPackageRootCoordinatorEvidenceError.duplicate) {
        try decodeLinuxVzPackageRootCoordinatorEvidenceV1(
            serial + serial,
            expectedProbeSHA256: coordinatorProbeSHA256,
            expectedPublicKeySHA256: coordinatorPublicKeySHA256
        )
    }
    let failed = serial + Data("WHOATHERE_PACKAGE_ROOT_COORDINATOR_FAILED reason=test\n".utf8)
    #expect(linuxVzPackageRootCoordinatorFailurePresentV1(failed))
}

private func rootCoordinatorValue() -> [String: Any] {
    [
        "ambient_capabilities": "0000000000000000",
        "bounding_capabilities": "000001fffff7ffff",
        "effective_capabilities": "000001fffff7ffff",
        "inheritable_capabilities": "0000000000000000",
        "malware_execution": false,
        "no_new_privileges": true,
        "open_descriptor_count": "4",
        "package_execution": false,
        "permitted_capabilities": "000001fffff7ffff",
        "probe_sha256": coordinatorProbeSHA256,
        "ptrace_capability_present": false,
        "root_credentials_verified": true,
        "runner_control_release_bound": true,
        "runner_exit_status": "0",
        "runner_parent_death_signal_sigkill": true,
        "runner_pid": "42",
        "runner_self_dumpable": false,
        "runner_seed_descriptor_closed": true,
        "runner_thread_count": "1",
        "schema_version": linuxVzPackageRootCoordinatorEvidenceSchemaV1,
        "seed_byte_length": "32",
        "seed_pipe_exact_eof": true,
        "seed_public_key_sha256": coordinatorPublicKeySHA256,
        "seed_read_after_runner_boundary_verification": true,
        "service_dumpable": false,
        "service_pid": "41",
        "sync_back": false,
        "tracer_absent": true,
        "unexpected_descriptor_count": "0",
    ]
}

private func rootCoordinatorSerial(value: [String: Any]) throws -> Data {
    var lines = linuxVzPackageRootCoordinatorRequiredMarkersV1
    let payload = try canonicalJSONData(value)
    lines.insert(
        linuxVzPackageRootCoordinatorEvidenceSerialPrefixV1
            + String(decoding: payload, as: UTF8.self),
        at: lines.count - 4
    )
    return Data((lines.joined(separator: "\n") + "\n").utf8)
}
