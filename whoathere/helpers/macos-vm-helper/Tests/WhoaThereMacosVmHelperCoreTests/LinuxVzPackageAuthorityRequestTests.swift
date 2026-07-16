import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzPackageAuthorityRequestIsCanonicalBoundAndNeverAuthorizing() throws {
    let scenarioKind: [String: Any] = [
        "kind": "npm_local_tarball_install",
        "environment": "ci_false"
    ]
    let request = linuxVzPackageAuthorityRequestFixture(scenarioKind: scenarioKind)
    let data = try canonicalJSONData(request)
    let parsed = try decodeLinuxVzPackageAuthorityRequest(data)
    #expect(parsed.requestSHA256 == sha256(data))
    #expect(parsed.artifactKind == "npm_tarball")
    #expect(parsed.candidateRuntimeQualificationPermitted)
    #expect(!parsed.packageExecutionAuthorityPermitted)
    #expect(!parsed.syncBackPermitted)

    var elevated = request
    elevated["execution_authority_issued"] = true
    #expect(throws: LinuxVzPackageAuthorityRequestError.invalidSchema) {
        try decodeLinuxVzPackageAuthorityRequest(try canonicalJSONData(elevated))
    }
    var packageExecution = request
    packageExecution["package_execution_permitted"] = true
    #expect(throws: LinuxVzPackageAuthorityRequestError.invalidSchema) {
        try decodeLinuxVzPackageAuthorityRequest(try canonicalJSONData(packageExecution))
    }
    var macos = request
    macos["runtime_target"] = "macos_arm64"
    #expect(throws: LinuxVzPackageAuthorityRequestError.invalidSchema) {
        try decodeLinuxVzPackageAuthorityRequest(try canonicalJSONData(macos))
    }
    var wrongKind = request
    wrongKind["artifact_kind"] = "pypi_wheel"
    #expect(throws: LinuxVzPackageAuthorityRequestError.invalidSchema) {
        try decodeLinuxVzPackageAuthorityRequest(try canonicalJSONData(wrongKind))
    }
    var kindRebound = request
    kindRebound["scenario_kind_sha256"] = sha256(Data("rebound kind".utf8))
    #expect(throws: LinuxVzPackageAuthorityRequestError.invalidSchema) {
        try decodeLinuxVzPackageAuthorityRequest(try canonicalJSONData(kindRebound))
    }
    var cloneReused = request
    cloneReused["clone_binding_sha256"] = request["request_challenge_sha256"]
    #expect(throws: LinuxVzPackageAuthorityRequestError.invalidBinding) {
        try decodeLinuxVzPackageAuthorityRequest(try canonicalJSONData(cloneReused))
    }
    var unknown = request
    unknown["sync_back"] = false
    #expect(throws: LinuxVzPackageAuthorityRequestError.invalidSchema) {
        try decodeLinuxVzPackageAuthorityRequest(try canonicalJSONData(unknown))
    }
    var noncanonical = Data(" ".utf8)
    noncanonical.append(data)
    #expect(throws: LinuxVzPackageAuthorityRequestError.nonCanonical) {
        try decodeLinuxVzPackageAuthorityRequest(noncanonical)
    }
}

@Test func linuxVzPackageAuthorityRequestAcceptsClosedWheelAndSdistKinds() throws {
    let wheelKinds: [[String: Any]] = [
        ["kind": "install_exact_wheel"],
        ["kind": "fresh_interpreter_pth", "pth_file_ids": [sha256(Data("pth".utf8))]],
        [
            "kind": "console_entry_point", "command_name": "wheel-tool",
            "module": "wheel_fixture.cli", "callable": "main",
            "target_sha256": sha256(Data("wheel_fixture.cli:main".utf8)),
            "argument_profile": "installed_generated_wrapper_help"
        ],
        [
            "kind": "console_entry_point", "command_name": "wheel-tool",
            "module": "wheel_fixture.cli", "callable": "main",
            "target_sha256": sha256(Data("wheel_fixture.cli:main".utf8)),
            "argument_profile": "installed_generated_wrapper_no_arguments"
        ],
        ["kind": "import_root", "module": "wheel_fixture"]
    ]
    for scenarioKind in wheelKinds {
        var request = linuxVzPackageAuthorityRequestFixture(scenarioKind: scenarioKind)
        request["artifact_kind"] = "pypi_wheel"
        _ = try decodeLinuxVzPackageAuthorityRequest(try canonicalJSONData(request))
    }

    let sdistKinds: [[String: Any]] = [
        [
            "kind": "build_exact_sdist", "build_mode": "pep517",
            "build_backend": "setuptools.build_meta", "backend_paths": [],
            "build_requires_sha256": sha256(Data("requirements".utf8))
        ],
        ["kind": "inspect_derived_wheel"],
        ["kind": "install_derived_wheel"],
        ["kind": "import_root", "module": "sdist_fixture"]
    ]
    for scenarioKind in sdistKinds {
        var request = linuxVzPackageAuthorityRequestFixture(scenarioKind: scenarioKind)
        request["artifact_kind"] = "pypi_sdist"
        _ = try decodeLinuxVzPackageAuthorityRequest(try canonicalJSONData(request))
    }
}

private func linuxVzPackageAuthorityRequestFixture(
    scenarioKind: [String: Any]
) -> [String: Any] {
    [
        "schema_version": linuxVzPackageAuthorityRequestSchemaV1,
        "artifact_kind": "npm_tarball",
        "artifact_sha256": sha256(Data("artifact".utf8)),
        "artifact_byte_length": "4096",
        "envelope_sha256": sha256(Data("envelope".utf8)),
        "manifest_sha256": sha256(Data("manifest".utf8)),
        "scenario_plan_sha256": sha256(Data("plan".utf8)),
        "scenario_plan_id": "linux-vz-plan",
        "scenario_template_sha256": sha256(Data("template".utf8)),
        "scenario_id": "linux-vz-scenario",
        "scenario_kind": scenarioKind,
        "scenario_kind_sha256": sha256(try! canonicalJSONData(scenarioKind)),
        "scenario_policy_sha256": sha256(Data("policy".utf8)),
        "dependency_closure_sha256": sha256(Data("closure".utf8)),
        "runtime_target": "linux_arm64",
        "runtime_profile_sha256": sha256(Data("runtime profile".utf8)),
        "candidate_runtime_qualification_state":
            "candidate_exact_bytes_not_yet_independently_qualified",
        "candidate_runtime_rootfs_sha256": sha256(Data("rootfs".utf8)),
        "candidate_runtime_rootfs_byte_length": "1048576",
        "candidate_runtime_manifest_sha256": sha256(Data("runtime manifest".utf8)),
        "candidate_package_runner_sha256": sha256(Data("package runner".utf8)),
        "qualified_telemetry_backend_sha256": sha256(Data("qualified backend".utf8)),
        "backend_identity_sha256": sha256(Data("backend identity".utf8)),
        "telemetry_requirements_sha256": sha256(Data("telemetry requirements".utf8)),
        "conformance_evidence_set_sha256": sha256(Data("conformance set".utf8)),
        "request_challenge_sha256": sha256(Data("request challenge".utf8)),
        "clone_binding_sha256": sha256(Data("clone binding".utf8)),
        "artifact_transport": "digest_checked_bounded_raw_bytes",
        "network_policy": "no_network_device",
        "package_privilege": "dedicated_unprivileged_uid_gid",
        "clone_disposition": "destroy_clone",
        "execution_eligibility":
            "independent_runtime_qualification_then_one_use_execution_grant",
        "execution_authority_issued": false,
        "package_execution_permitted": false,
        "sync_back_policy": "structurally_absent"
    ]
}
