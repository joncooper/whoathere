import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzRuntimeQualificationRequestMatchesRustAndNeverAuthorizes() throws {
    let request = linuxVzRuntimeQualificationRequestFixture()
    let data = try canonicalJSONData(request)
    let parsed = try decodeLinuxVzPackageRuntimeQualificationRequest(data)

    #expect(parsed.requestSHA256 == sha256(data))
    #expect(
        parsed.requestSHA256
            == "sha256:08cf56cbf44a30bd906efa2fcb72383fe2145a709ffe505cb376f4ddf83d1e0d"
    )
    #expect(parsed.candidateRuntimeRootfsByteLength == 42)
    #expect(parsed.packageUID == 499)
    #expect(parsed.packageGID == 499)
    #expect(parsed.expectedProbeReportSHA256 == sha256(linuxVzPackageRuntimeProbeReportV1))
    #expect(parsed.fixedNonexecutingProbePermitted)
    #expect(!parsed.packageExecutionAuthorityPermitted)
    #expect(!parsed.syncBackPermitted)

    var elevated = request
    elevated["execution_authority_issued"] = true
    #expect(throws: LinuxVzPackageRuntimeQualificationRequestError.invalidSchema) {
        try decodeLinuxVzPackageRuntimeQualificationRequest(try canonicalJSONData(elevated))
    }
    var packageExecution = request
    packageExecution["package_execution_permitted"] = true
    #expect(throws: LinuxVzPackageRuntimeQualificationRequestError.invalidSchema) {
        try decodeLinuxVzPackageRuntimeQualificationRequest(try canonicalJSONData(packageExecution))
    }
    var wrongProbe = request
    wrongProbe["expected_probe_report_sha256"] = sha256(Data("different probe".utf8))
    #expect(throws: LinuxVzPackageRuntimeQualificationRequestError.invalidBinding) {
        try decodeLinuxVzPackageRuntimeQualificationRequest(try canonicalJSONData(wrongProbe))
    }
    var reusedClone = request
    reusedClone["clone_binding_sha256"] = request["candidate_runtime_rootfs_sha256"]
    #expect(throws: LinuxVzPackageRuntimeQualificationRequestError.invalidBinding) {
        try decodeLinuxVzPackageRuntimeQualificationRequest(try canonicalJSONData(reusedClone))
    }
    var duplicateImage = request
    duplicateImage["runtime_qualification_guest_agent_sha256"] =
        request["runtime_qualification_initramfs_sha256"]
    #expect(throws: LinuxVzPackageRuntimeQualificationRequestError.invalidBinding) {
        try decodeLinuxVzPackageRuntimeQualificationRequest(try canonicalJSONData(duplicateImage))
    }
    var unknown = request
    unknown["execution_capability"] = false
    #expect(throws: LinuxVzPackageRuntimeQualificationRequestError.invalidSchema) {
        try decodeLinuxVzPackageRuntimeQualificationRequest(try canonicalJSONData(unknown))
    }
    var noncanonical = Data(" ".utf8)
    noncanonical.append(data)
    #expect(throws: LinuxVzPackageRuntimeQualificationRequestError.nonCanonical) {
        try decodeLinuxVzPackageRuntimeQualificationRequest(noncanonical)
    }
}

@Test func linuxVzRuntimeQualificationRequestRejectsOpenEndedPoliciesAndRootIdentity() throws {
    let request = linuxVzRuntimeQualificationRequestFixture()
    for (key, replacement) in [
        ("operation", "package_install"),
        ("storage_policy", "reuse_writable_clone"),
        ("network_policy", "nat"),
        ("directory_share_policy", "read_only_host_share"),
        ("package_runner_argument", "--runtime-probe")
    ] {
        var changed = request
        changed[key] = replacement
        #expect(throws: LinuxVzPackageRuntimeQualificationRequestError.invalidSchema) {
            try decodeLinuxVzPackageRuntimeQualificationRequest(try canonicalJSONData(changed))
        }
    }
    var root = request
    root["package_uid"] = "0"
    #expect(throws: LinuxVzPackageRuntimeQualificationRequestError.invalidSchema) {
        try decodeLinuxVzPackageRuntimeQualificationRequest(try canonicalJSONData(root))
    }
}

private func linuxVzRuntimeQualificationRequestFixture() -> [String: Any] {
    [
        "schema_version": linuxVzPackageRuntimeQualificationRequestSchemaV1,
        "operation": "fixed_nonexecuting_probe",
        "qualified_telemetry_backend_sha256":
            "sha256:455c3566f07451d9a763ba594652938aced20bd8f90eb7c712995a8e13e91c1a",
        "backend_identity_sha256":
            "sha256:bc1dfc5ea76df97efa623cc00dbd70f96eab0de4d4d12066a6298aa20f15c3f8",
        "telemetry_requirements_sha256":
            "sha256:3ff8c862243232fbc48ec91d5926e587bf9817f678853d02d9730cde2c464946",
        "conformance_evidence_set_sha256":
            "sha256:249510d5b10b7f0e30d8f3555cddbf7ff4796495db2eefb9222441876dae5069",
        "kernel_image_sha256": qualificationDigest("inert kernel image"),
        "qualified_initramfs_sha256": qualificationDigest("inert initramfs"),
        "qualified_guest_signer_sha256": qualificationDigest("inert guest sensor"),
        "qualified_protected_sensor_sha256": qualificationDigest("inert guest bpf bundle"),
        "guest_evidence_public_key_sha256":
            "sha256:a3c761e56d55f45e06a31c3c7e32f79cfba417d3e2e2397767ef5a453f35ffe7",
        "host_evidence_public_key_sha256":
            "sha256:2d3bb9ef976d407955e4188df05c25f511cd1fe3c85fe70fc221c4d8f8e66261",
        "runtime_qualification_initramfs_sha256": qualificationDigest(
            "inert runtime qualification initramfs bytes"
        ),
        "runtime_qualification_guest_agent_sha256": qualificationDigest(
            "inert runtime qualification guest agent bytes"
        ),
        "runtime_qualification_guest_init_sha256": qualificationDigest(
            "inert runtime qualification guest init bytes"
        ),
        "runtime_qualification_module_bundle_sha256": qualificationDigest(
            "inert runtime qualification module bundle bytes"
        ),
        "candidate_runtime_rootfs_sha256": qualificationDigest(
            "inert qualification candidate rootfs bytes"
        ),
        "candidate_runtime_rootfs_byte_length": "42",
        "candidate_runtime_manifest_sha256": qualificationDigest(
            "{\"schema_version\":\"whoathere.inert_candidate_runtime_manifest.v1\"}"
        ),
        "candidate_package_runner_sha256": qualificationDigest(
            "inert qualification package runner bytes"
        ),
        "expected_probe_report_sha256": sha256(linuxVzPackageRuntimeProbeReportV1),
        "protected_sensor_case": "fork_exec_exit",
        "package_runner_argument": "fork_exec_exit",
        "request_challenge_sha256":
            "sha256:c26edab346b2cb9d2adbd8e2bd76677bdf39d7f60fc0aa83cdcebc442804bf2c",
        "clone_binding_sha256": qualificationDigest("unique qualification rootfs clone"),
        "package_uid": "499",
        "package_gid": "499",
        "storage_policy": "one_unique_writable_clone_destroy_after_vm_stop",
        "network_policy": "host_raw_frame_sinkhole_no_external_route",
        "directory_share_policy": "structurally_absent",
        "public_resolver_reachable": false,
        "nonexecuting_probe_permitted": true,
        "execution_authority_issued": false,
        "package_execution_permitted": false,
        "sync_back_policy": "structurally_absent"
    ]
}

private func qualificationDigest(_ text: String) -> String {
    sha256(Data(text.utf8))
}
