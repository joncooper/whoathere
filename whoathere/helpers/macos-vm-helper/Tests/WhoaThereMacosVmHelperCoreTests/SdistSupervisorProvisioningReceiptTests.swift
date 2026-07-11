import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func sdistProvisioningReceiptBindsMeasuredRuntimeAndDisabledCapabilities() throws {
    let publicKey = Data(repeating: 17, count: 32)
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "install_derived_wheel"],
        scenarioIndex: 91,
        guestAuthPublicKeySHA256: sha256(publicKey)
    )
    let identity = try beginSdistSubmission(
        from: sdistFileHandle(fixture.frame)
    ).prelude.backendIdentity
    let receipt = try sdistProvisioningReceiptFixture(
        identity: identity, guestAuthPublicKey: publicKey
    )
    let observation = try verifySdistSupervisorProvisioningReceipt(
        receipt, identity: identity, guestAuthPublicKey: publicKey
    )
    #expect(observation.sdistVSOCKPort == 47_081)
    #expect(!observation.packageExecutionEnabled)
    #expect(!observation.syncBackEnabled)
    #expect(!observation.buildClosureMaterializationEnabled)
    #expect(!observation.publicResolutionEnabled)
}

@Test func sdistProvisioningReceiptRejectsCrossDomainAndEnabledCapabilities() throws {
    let publicKey = Data(repeating: 18, count: 32)
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "inspect_derived_wheel"],
        scenarioIndex: 92,
        guestAuthPublicKeySHA256: sha256(publicKey)
    )
    let identity = try beginSdistSubmission(
        from: sdistFileHandle(fixture.frame)
    ).prelude.backendIdentity
    let canonical = try sdistProvisioningReceiptFixture(
        identity: identity, guestAuthPublicKey: publicKey
    )
    var enabled = try #require(
        JSONSerialization.jsonObject(with: canonical) as? [String: Any]
    )
    for field in [
        "package_execution_enabled", "sync_back_enabled",
        "build_closure_materialization_enabled", "public_resolution_enabled"
    ] {
        var changed = enabled
        changed[field] = true
        #expect(throws: ArtifactRunLifecycleError.sdistProvisioningReceiptInvalid) {
            try verifySdistSupervisorProvisioningReceipt(
                canonicalJSONData(changed), identity: identity, guestAuthPublicKey: publicKey
            )
        }
    }
    enabled["schema_version"] = wheelSupervisorProvisioningReceiptSchemaV1
    #expect(throws: ArtifactRunLifecycleError.sdistProvisioningReceiptInvalid) {
        try verifySdistSupervisorProvisioningReceipt(
            canonicalJSONData(enabled), identity: identity, guestAuthPublicKey: publicKey
        )
    }
}

func sdistProvisioningReceiptFixture(
    identity: SdistRunBackendIdentity,
    guestAuthPublicKey: Data
) throws -> Data {
    #expect(sha256(guestAuthPublicKey) == identity.guestAuthPublicKeySHA256)
    return try canonicalJSONData([
        "schema_version": sdistSupervisorProvisioningReceiptSchemaV1,
        "base_generation_id": identity.baseGenerationID,
        "guest_supervisor_sha256": identity.guestSupervisorSHA256,
        "guest_auth_public_key_sha256": identity.guestAuthPublicKeySHA256,
        "runner_configuration_sha256": identity.runnerConfigurationSHA256,
        "python_executable_sha256": identity.pythonExecutableSHA256,
        "python_version": identity.pythonVersion,
        "pip_cli_sha256": identity.pipCLISHA256,
        "pip_version": identity.pipVersion,
        "clone_implementation_sha256": identity.cloneImplementationSHA256,
        "guest_protocol_sha256": identity.guestProtocolSHA256,
        "cpu_count": String(identity.cpuCount),
        "memory_mib": String(identity.memoryMiB),
        "package_uid": String(identity.packageUID),
        "package_gid": String(identity.packageGID),
        "package_username": identity.packageUsername,
        "sdist_vsock_port": String(sdistGuestVSOCKPortV1),
        "package_execution_enabled": false,
        "sync_back_enabled": false,
        "build_closure_materialization_enabled": false,
        "public_resolution_enabled": false
    ])
}
