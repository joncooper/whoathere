import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func wheelRunUsesDistinctAuthorityBoundNoSyncOptions() throws {
    let parsed = try parseHelperInvocation([
        "wheel-run",
        "--state-dir", "/tmp/whoathere-wheel-runs",
        "--authority-id", "wheel-authority-1",
        "--execute",
        "--json"
    ])
    guard case .wheelRun(let options) = parsed else {
        Issue.record("expected wheel-run invocation")
        return
    }
    #expect(options.stateDir == "/tmp/whoathere-wheel-runs")
    #expect(options.authorityID == "wheel-authority-1")
    #expect(options.execute)
    #expect(options.json)

    #expect(throws: ArgumentError.valueRequired("--authority-id")) {
        _ = try parseHelperInvocation(["wheel-run", "--execute"])
    }
    for forbidden in ["--sync-back", "--tool=pip", "--", "--project-payload-path=/tmp/x"] {
        do {
            _ = try parseHelperInvocation([
                "wheel-run", "--authority-id", "wheel-authority-1", forbidden
            ])
            Issue.record("expected wheel-run flag rejection: \(forbidden)")
        } catch let error as ArgumentError {
            let expected = forbidden.split(separator: "=", maxSplits: 1).first.map(String.init)
                ?? forbidden
            #expect(error == .unknownFlag(expected))
        }
    }
}

@Test func strictWheelSubmissionParserAcceptsEveryTypedScenarioVariant() throws {
    let scenarios: [[String: Any]] = [
        ["kind": "install_exact_wheel"],
        [
            "kind": "fresh_interpreter_pth",
            "pth_file_ids": [sha256(Data("pth file".utf8))]
        ],
        ["kind": "import_root", "module": "wheel_fixture"],
        [
            "kind": "console_entry_point",
            "command_name": "wheel-tool",
            "module": "wheel_fixture.cli",
            "callable": "main",
            "target_sha256": sha256(Data("wheel_fixture.cli:main".utf8)),
            "argument_profile": "installed_generated_wrapper_help"
        ],
        [
            "kind": "console_entry_point",
            "command_name": "wheel-tool",
            "module": "wheel_fixture.cli",
            "callable": "main",
            "target_sha256": sha256(Data("wheel_fixture.cli:main".utf8)),
            "argument_profile": "installed_generated_wrapper_no_arguments"
        ]
    ]
    for (index, scenario) in scenarios.enumerated() {
        let fixture = try wheelSubmissionFixture(scenario: scenario, scenarioIndex: index)
        let observation = try inspectWheelSubmission(from: wheelFileHandle(fixture.frame))
        #expect(observation.runSpecSHA256 == fixture.runSpecSHA256)
        #expect(observation.templateSHA256 == fixture.templateSHA256)
        #expect(observation.challengeBindingSHA256 == fixture.challengeBindingSHA256)
        #expect(observation.executionBindingSHA256 == fixture.executionBindingSHA256)
        #expect(observation.artifactSHA256 == fixture.artifactSHA256)
        #expect(observation.artifactByteLength == UInt64(fixture.artifact.count))
        #expect(observation.scenarioID == "wheel-scenario-\(index)")
        #expect(observation.scenarioKind == scenario["kind"] as? String)
        #expect(observation.backendIdentity.packageUsername == "_whoatherepkg")
        #expect(observation.backendIdentity.packageUID == 499)
        #expect(observation.backendIdentity.packageGID == 499)
        #expect(observation.backendIdentity.pythonVersion == "3.12.13")
        #expect(observation.backendIdentity.pipVersion == "26.1.2")
    }
}

@Test func wheelExecutionBindingMatchesTheRustGolden() {
    let challenge = sha256(Data("wheel challenge".utf8))
    let runSpec = sha256(Data("wheel run spec".utf8))
    #expect(
        challenge
            == "sha256:b1ab8715aa7684198e18b8edf39eda977c1ed27ea8ef39d3bbed8289e6fbcae2"
    )
    #expect(
        runSpec
            == "sha256:6ed9490f306948340b695150470fee00b434f28442914867c0750b067abf228e"
    )
    let binding = sha256(
        Data("whoathere.macos_wheel_submission_execution_binding.v1\0\(challenge)\0\(runSpec)".utf8)
    )
    #expect(
        binding
            == "sha256:fc895a01869db614532cae70220cdafe0eec5a6682b8197dcc6bab91fc04ef33"
    )
}

@Test func wheelSubmissionPreludeStreamsExactBytesOnlyOnce() throws {
    let fixture = try wheelSubmissionFixture(
        scenario: ["kind": "import_root", "module": "wheel_fixture"],
        scenarioIndex: 1
    )
    let reader = try beginWheelSubmission(from: wheelFileHandle(fixture.frame))
    #expect(reader.prelude.runSpecSHA256 == fixture.runSpecSHA256)
    #expect(reader.prelude.artifactSHA256 == fixture.artifactSHA256)
    #expect(reader.prelude.scenarioKind == "import_root")
    var forwarded = Data()
    let observation = try reader.consumeArtifact { forwarded.append($0) }
    #expect(forwarded == fixture.artifact)
    #expect(observation.executionBindingSHA256 == fixture.executionBindingSHA256)
    #expect(throws: ArtifactRunProtocolError.trailingData) {
        try reader.consumeArtifact()
    }
    let authorityBound = try inspectWheelSubmission(
        from: wheelFileHandle(fixture.frame),
        expectedChallengeBindingSHA256: fixture.challengeBindingSHA256
    )
    #expect(authorityBound.challengeBindingSHA256 == fixture.challengeBindingSHA256)
    #expect(throws: ArtifactRunProtocolError.bindingMismatch) {
        try inspectWheelSubmission(
            from: wheelFileHandle(fixture.frame),
            expectedChallengeBindingSHA256: sha256(Data("wrong expected challenge".utf8))
        )
    }
}

@Test func npmAndWheelFramesAreMutuallyRejected() throws {
    let wheel = try wheelSubmissionFixture(
        scenario: ["kind": "install_exact_wheel"], scenarioIndex: 1
    )
    #expect(throws: ArtifactRunProtocolError.invalidMagic) {
        try inspectArtifactSubmission(from: wheelFileHandle(wheel.frame))
    }
    let npm = try artifactSubmissionFixture()
    #expect(throws: ArtifactRunProtocolError.invalidMagic) {
        try inspectWheelSubmission(from: wheelFileHandle(npm.frame))
    }
}

@Test func wheelSubmissionRejectsCorruptionRebindingAndCrossSchemaContent() throws {
    let fixture = try wheelSubmissionFixture(
        scenario: ["kind": "import_root", "module": "wheel_fixture"],
        scenarioIndex: 1
    )

    var truncated = fixture.frame
    truncated.removeLast()
    #expect(throws: ArtifactRunProtocolError.truncated) {
        try inspectWheelSubmission(from: wheelFileHandle(truncated))
    }
    var trailing = fixture.frame
    trailing.append(0)
    #expect(throws: ArtifactRunProtocolError.trailingData) {
        try inspectWheelSubmission(from: wheelFileHandle(trailing))
    }
    var mutated = fixture.frame
    mutated[mutated.index(before: mutated.endIndex)] ^= 1
    #expect(throws: ArtifactRunProtocolError.artifactDigestMismatch) {
        try inspectWheelSubmission(from: wheelFileHandle(mutated))
    }

    var unknown = fixture.header
    unknown["sync_back"] = false
    #expect(throws: ArtifactRunProtocolError.headerInvalid) {
        try inspectWheelSubmission(
            from: wheelFileHandle(try rebuildWheelFrame(fixture, header: unknown))
        )
    }

    var wrongDomain = fixture.header
    let wrongExecution = sha256(
        Data("whoathere.macos_artifact_submission_execution_binding.v1\0\(fixture.challengeBindingSHA256)\0\(fixture.runSpecSHA256)".utf8)
    )
    wrongDomain["execution_binding_sha256"] = wrongExecution
    #expect(throws: ArtifactRunProtocolError.bindingMismatch) {
        try inspectWheelSubmission(
            from: wheelFileHandle(try rebuildWheelFrame(fixture, header: wrongDomain))
        )
    }

    var crossSchema = fixture.header
    var crossRunSpec = try #require(crossSchema["run_spec"] as? [String: Any])
    crossRunSpec["schema_version"] = "whoathere.macos_artifact_run_spec.v1"
    try rebindWheelHeader(
        &crossSchema, runSpec: crossRunSpec, challenge: fixture.challengeBindingSHA256
    )
    #expect(throws: ArtifactRunProtocolError.runSpecInvalid) {
        try inspectWheelSubmission(
            from: wheelFileHandle(try rebuildWheelFrame(fixture, header: crossSchema))
        )
    }

    var wrongAccount = fixture.header
    var accountRunSpec = try #require(wrongAccount["run_spec"] as? [String: Any])
    var backend = try #require(accountRunSpec["backend_identity"] as? [String: Any])
    backend["package_username"] = "admin"
    accountRunSpec["backend_identity"] = backend
    try rebindWheelHeader(
        &wrongAccount, runSpec: accountRunSpec, challenge: fixture.challengeBindingSHA256
    )
    #expect(throws: ArtifactRunProtocolError.runSpecInvalid) {
        try inspectWheelSubmission(
            from: wheelFileHandle(try rebuildWheelFrame(fixture, header: wrongAccount))
        )
    }

    var invalidTrigger = fixture.header
    var triggerRunSpec = try #require(invalidTrigger["run_spec"] as? [String: Any])
    var template = try #require(triggerRunSpec["template"] as? [String: Any])
    template["scenario_kind"] = ["kind": "import_root", "module": "../../escape"]
    triggerRunSpec["template"] = template
    triggerRunSpec["template_sha256"] = sha256(try canonicalJSONData(template))
    try rebindWheelHeader(
        &invalidTrigger, runSpec: triggerRunSpec, challenge: fixture.challengeBindingSHA256
    )
    #expect(throws: ArtifactRunProtocolError.templateInvalid) {
        try inspectWheelSubmission(
            from: wheelFileHandle(try rebuildWheelFrame(fixture, header: invalidTrigger))
        )
    }
}

struct WheelSubmissionFixture {
    let frame: Data
    let header: [String: Any]
    let artifact: Data
    let artifactSHA256: String
    let templateSHA256: String
    let runSpecSHA256: String
    let challengeBindingSHA256: String
    let executionBindingSHA256: String
}

func wheelSubmissionFixture(
    scenario: [String: Any],
    scenarioIndex: Int,
    guestAuthPublicKeySHA256: String? = nil,
    postProvisioningReceiptSHA256: String? = nil
) throws -> WheelSubmissionFixture {
    let artifact = Data([0x50, 0x4b, 0x03, 0x04, 0x57, 0x48, 0x4f, 0x41])
    let artifactSHA256 = sha256(artifact)
    let envelopeSHA256 = sha256(Data("wheel envelope".utf8))
    let manifestSHA256 = sha256(Data("wheel manifest".utf8))
    let pythonSHA256 = sha256(Data("python executable".utf8))
    let pipSHA256 = sha256(Data("pip cli".utf8))
    let commandTemplateSHA256 = sha256(
        Data("whoathere.python_wheel_offline_probe.fixed_runner.v1".utf8)
    )
    let runtimeProfile: [String: Any] = [
        "schema_version": "whoathere.wheel_runtime_profile.v1",
        "profile_id": "macos-arm64-python312-pip26-inert",
        "target_os": "macos",
        "target_arch": "arm64",
        "python_version": "3.12.13",
        "python_executable_sha256": pythonSHA256,
        "pip_version": "26.1.2",
        "pip_cli_sha256": pipSHA256,
        "command_template_sha256": commandTemplateSHA256
    ]
    let runtimeProfileSHA256 = sha256(try canonicalJSONData(runtimeProfile))
    let closure: [String: Any] = [
        "schema_version": "whoathere.empty_dependency_closure.v1",
        "manifest_sha256": manifestSHA256,
        "dependency_declarations": [Any]()
    ]
    let closureSHA256 = sha256(try canonicalJSONData(closure))
    let template: [String: Any] = [
        "schema_version": "whoathere.wheel_scenario_template.v1",
        "canonicalization": "rfc8785.jcs.v1",
        "compiler_id": "whoathere.dependency_free_wheel_scenario_compiler.v1",
        "identity": [
            "job_id": "wheel-job-\(scenarioIndex)",
            "run_id": "wheel-run-\(scenarioIndex)",
            "evidence_id": "wheel-evidence-\(scenarioIndex)",
            "scenario_id": "wheel-scenario-\(scenarioIndex)"
        ],
        "subject": [
            "artifact_sha256": artifactSHA256,
            "envelope_sha256": envelopeSHA256,
            "manifest_sha256": manifestSHA256,
            "cas_object_key": "blobs/sha256/" + artifactSHA256.dropFirst(7)
        ],
        "package": [
            "ecosystem": "pypi",
            "display_name": "swift-wheel-fixture",
            "normalized_name": "swift-wheel-fixture",
            "version": "1.0.0"
        ],
        "artifact_byte_length": UInt64(artifact.count),
        "policy_sha256": sha256(Data("wheel policy".utf8)),
        "runtime_profile": [
            "profile_id": "macos-arm64-python312-pip26-inert",
            "profile_sha256": runtimeProfileSHA256,
            "target_os": "macos",
            "target_arch": "arm64",
            "python_version": "3.12.13",
            "python_executable_sha256": pythonSHA256,
            "pip_version": "26.1.2",
            "pip_cli_sha256": pipSHA256,
            "command_template_sha256": commandTemplateSHA256
        ],
        "dependency_closure": [
            "kind": "empty",
            "declaration_set_sha256": closureSHA256
        ],
        "scenario_kind": scenario,
        "install_environment": "fresh_virtual_environment",
        "resolver_policy": "no_index_no_dependencies",
        "interpreter_policy": "fresh_interpreter_per_probe",
        "target_os": "macos",
        "target_arch": "arm64",
        "transport": "digest_checked_bounded_raw_bytes",
        "network_policy": "no_network_device",
        "package_privilege": "dedicated_unprivileged_uid_gid",
        "clone_disposition": "destroy_clone",
        "limits": [
            "max_artifact_bytes": UInt64(64 * 1024 * 1024),
            "wall_clock_millis": UInt64(120_000),
            "max_stdout_bytes": UInt64(1024 * 1024),
            "max_stderr_bytes": UInt64(1024 * 1024),
            "max_processes": UInt64(256),
            "max_open_files": UInt64(1024),
            "max_observed_file_events": UInt64(65_536)
        ],
        "required_evidence": [
            "artifact_transport", "guest_artifact_rehash", "process_credentials",
            "process_lifecycle", "listener_inventory", "sensor_health", "no_network_device",
            "vm_stop", "channel_closure", "clone_destruction"
        ]
    ]
    let templateSHA256 = sha256(try canonicalJSONData(template))
    let guestProtocolSHA256 = sha256(Data("whoathere.wheel_artifact_scenario.v1".utf8))
    let runSpec: [String: Any] = [
        "schema_version": "whoathere.macos_wheel_run_spec.v1",
        "canonicalization": "rfc8785.jcs.v1",
        "template": template,
        "template_sha256": templateSHA256,
        "backend_identity": [
            "base_generation_id": "wheel-base-generation-inert-v1",
            "base_disk_sha256": sha256(Data("wheel base disk".utf8)),
            "base_auxiliary_storage_sha256": sha256(Data("wheel base aux".utf8)),
            "hardware_model_sha256": sha256(Data("hardware model".utf8)),
            "machine_identifier_sha256": sha256(Data("machine identifier".utf8)),
            "cpu_count": UInt64(4),
            "memory_mib": UInt64(6_144),
            "post_provisioning_receipt_sha256": postProvisioningReceiptSHA256
                ?? sha256(Data("wheel receipt".utf8)),
            "helper_sha256": sha256(Data("helper".utf8)),
            "guest_supervisor_sha256": sha256(Data("wheel supervisor".utf8)),
            "guest_auth_public_key_sha256": guestAuthPublicKeySHA256
                ?? sha256(Data("wheel public key".utf8)),
            "runner_configuration_sha256": sha256(Data("wheel runner".utf8)),
            "package_username": "_whoatherepkg",
            "package_uid": UInt64(499),
            "package_gid": UInt64(499),
            "python_version": "3.12.13",
            "python_executable_sha256": pythonSHA256,
            "pip_version": "26.1.2",
            "pip_cli_sha256": pipSHA256,
            "clone_implementation_sha256": sha256(
                Data("whoathere.swift.fclonefileat.direct.v1".utf8)
            ),
            "guest_protocol_sha256": guestProtocolSHA256
        ],
        "clone_policy": "apfs_clone_required_no_copy_fallback",
        "network_configuration": "zero_network_devices",
        "reuse_policy": "one_boot_one_scenario_destroy_clone",
        "guest_protocol": "whoathere.wheel_artifact_scenario.v1"
    ]
    let runSpecSHA256 = sha256(try canonicalJSONData(runSpec))
    let challenge = sha256(Data("wheel challenge".utf8))
    let execution = sha256(
        Data("whoathere.macos_wheel_submission_execution_binding.v1\0\(challenge)\0\(runSpecSHA256)".utf8)
    )
    let header: [String: Any] = [
        "schema_version": "whoathere.macos_wheel_submission_header.v1",
        "run_spec": runSpec,
        "run_spec_sha256": runSpecSHA256,
        "challenge_binding_sha256": challenge,
        "execution_binding_sha256": execution,
        "artifact_sha256": artifactSHA256,
        "artifact_byte_length": UInt64(artifact.count),
        "artifact_transport_ceiling": UInt64(64 * 1024 * 1024)
    ]
    let frame = try encodeWheelFixtureFrame(header: header, artifact: artifact, digest: artifactSHA256)
    return WheelSubmissionFixture(
        frame: frame,
        header: header,
        artifact: artifact,
        artifactSHA256: artifactSHA256,
        templateSHA256: templateSHA256,
        runSpecSHA256: runSpecSHA256,
        challengeBindingSHA256: challenge,
        executionBindingSHA256: execution
    )
}

private func rebindWheelHeader(
    _ header: inout [String: Any],
    runSpec: [String: Any],
    challenge: String
) throws {
    let runSpecSHA256 = sha256(try canonicalJSONData(runSpec))
    header["run_spec"] = runSpec
    header["run_spec_sha256"] = runSpecSHA256
    header["execution_binding_sha256"] = sha256(
        Data("whoathere.macos_wheel_submission_execution_binding.v1\0\(challenge)\0\(runSpecSHA256)".utf8)
    )
}

private func rebuildWheelFrame(
    _ fixture: WheelSubmissionFixture,
    header: [String: Any]
) throws -> Data {
    try encodeWheelFixtureFrame(
        header: header,
        artifact: fixture.artifact,
        digest: fixture.artifactSHA256
    )
}

private func encodeWheelFixtureFrame(
    header: [String: Any],
    artifact: Data,
    digest: String
) throws -> Data {
    let headerData = try canonicalJSONData(header)
    var frame = Data()
    frame.append(wheelSubmissionMagicV1)
    wheelAppendBigEndian(wheelSubmissionVersionV1, to: &frame)
    wheelAppendBigEndian(wheelSubmissionFrameTypeV1, to: &frame)
    wheelAppendBigEndian(UInt32(headerData.count), to: &frame)
    wheelAppendBigEndian(UInt64(artifact.count), to: &frame)
    frame.append(try wheelFixtureRawDigest(digest))
    frame.append(headerData)
    frame.append(artifact)
    return frame
}

private func wheelFileHandle(_ data: Data) -> FileHandle {
    let pipe = Pipe()
    pipe.fileHandleForWriting.write(data)
    try? pipe.fileHandleForWriting.close()
    return pipe.fileHandleForReading
}

private func wheelAppendBigEndian(_ value: UInt16, to data: inout Data) {
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func wheelAppendBigEndian(_ value: UInt32, to data: inout Data) {
    for shift in stride(from: 24, through: 0, by: -8) {
        data.append(UInt8((value >> UInt32(shift)) & 0xff))
    }
}

private func wheelAppendBigEndian(_ value: UInt64, to data: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}

private func wheelFixtureRawDigest(_ value: String) throws -> Data {
    let hex = value.dropFirst(7)
    var result = Data()
    var index = hex.startIndex
    for _ in 0..<32 {
        let next = hex.index(index, offsetBy: 2)
        result.append(try #require(UInt8(hex[index..<next], radix: 16)))
        index = next
    }
    return result
}
