import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func sdistRunUsesDistinctDigestBoundNoSyncOptions() throws {
    let recordSHA256 = sha256(Data("sdist authority record".utf8))
    let parsed = try parseHelperInvocation([
        "sdist-run",
        "--state-dir", "/tmp/whoathere-sdist-runs",
        "--authority-id", "sdist-authority-" + String(repeating: "a", count: 64),
        "--authority-record-sha256", recordSHA256,
        "--build-closure-fd", "3",
        "--execute",
        "--json"
    ])
    guard case .sdistRun(let options) = parsed else {
        Issue.record("expected sdist-run invocation")
        return
    }
    #expect(options.stateDir == "/tmp/whoathere-sdist-runs")
    #expect(options.authorityRecordSHA256 == recordSHA256)
    #expect(options.buildClosureFD == 3)
    #expect(options.execute)
    #expect(options.json)

    #expect(throws: ArgumentError.valueRequired("--authority-id")) {
        _ = try parseHelperInvocation([
            "sdist-run", "--authority-record-sha256", recordSHA256,
            "--build-closure-fd", "3", "--execute"
        ])
    }
    #expect(throws: ArgumentError.valueRequired("--authority-record-sha256")) {
        _ = try parseHelperInvocation([
            "sdist-run",
            "--authority-id", "sdist-authority-" + String(repeating: "a", count: 64),
            "--build-closure-fd", "3",
            "--execute"
        ])
    }
    #expect(throws: ArgumentError.valueRequired("--build-closure-fd")) {
        _ = try parseHelperInvocation([
            "sdist-run",
            "--authority-id", "sdist-authority-" + String(repeating: "a", count: 64),
            "--authority-record-sha256", recordSHA256,
            "--execute"
        ])
    }
    #expect(throws: ArgumentError.invalidInteger("--build-closure-fd")) {
        _ = try parseHelperInvocation([
            "sdist-run",
            "--authority-id", "sdist-authority-" + String(repeating: "a", count: 64),
            "--authority-record-sha256", recordSHA256,
            "--build-closure-fd", "4"
        ])
    }
    for forbidden in ["--sync-back", "--tool=pip", "--", "--project-payload-path=/tmp/x"] {
        #expect(throws: ArgumentError.self) {
            _ = try parseHelperInvocation([
                "sdist-run",
                "--authority-id", "sdist-authority-" + String(repeating: "a", count: 64),
                "--authority-record-sha256", recordSHA256,
                "--build-closure-fd", "3",
                forbidden
            ])
        }
    }
}

@Test func strictSdistSubmissionParserAcceptsEveryTypedScenarioVariant() throws {
    let declaration = sha256(Data("setuptools>=75".utf8))
    let scenarios: [[String: Any]] = [
        [
            "kind": "build_exact_sdist",
            "build_mode": "pep517",
            "build_backend": "setuptools.build_meta:__legacy__",
            "backend_paths": ["build_backend"],
            "build_requires_sha256": declaration
        ],
        [
            "kind": "build_exact_sdist",
            "build_mode": "legacy_setup_py",
            "build_backend": NSNull(),
            "backend_paths": [String](),
            "build_requires_sha256": declaration
        ],
        ["kind": "inspect_derived_wheel"],
        ["kind": "install_derived_wheel"],
        ["kind": "import_root", "module": "swift_sdist_fixture"]
    ]
    for (index, scenario) in scenarios.enumerated() {
        let fixture = try sdistSubmissionFixture(
            scenario: scenario,
            scenarioIndex: index,
            declarationSetSHA256: declaration
        )
        let observation = try inspectSdistSubmission(from: sdistFileHandle(fixture.frame))
        #expect(observation.runSpecSHA256 == fixture.runSpecSHA256)
        #expect(observation.templateSHA256 == fixture.templateSHA256)
        #expect(observation.buildClosureSHA256 == fixture.buildClosureSHA256)
        #expect(observation.challengeBindingSHA256 == fixture.challengeBindingSHA256)
        #expect(observation.executionBindingSHA256 == fixture.executionBindingSHA256)
        #expect(observation.artifactSHA256 == fixture.artifactSHA256)
        #expect(observation.artifactByteLength == UInt64(fixture.artifact.count))
        #expect(observation.scenarioID == "sdist-scenario-\(index)")
        #expect(observation.scenarioKind == scenario["kind"] as? String)
        #expect(observation.backendIdentity.packageUsername == "_whoatherepkg")
        #expect(observation.backendIdentity.packageUID == 499)
        #expect(observation.backendIdentity.packageGID == 499)
        #expect(observation.backendIdentity.pythonVersion == "3.12.13")
        #expect(observation.backendIdentity.pipVersion == "26.1.2")
    }
}

@Test func sdistSubmissionPreludeLeavesArtifactUnreadAndStreamsItOnlyOnce() throws {
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "import_root", "module": "swift_sdist_fixture"],
        scenarioIndex: 7
    )
    let reader = try beginSdistSubmission(from: sdistFileHandle(fixture.frame))
    #expect(reader.prelude.runSpecSHA256 == fixture.runSpecSHA256)
    #expect(reader.prelude.buildClosureSHA256 == fixture.buildClosureSHA256)
    #expect(reader.prelude.artifactSHA256 == fixture.artifactSHA256)
    #expect(reader.prelude.scenarioKind == "import_root")
    var forwarded = Data()
    let observation = try reader.consumeArtifact { forwarded.append($0) }
    #expect(forwarded == fixture.artifact)
    #expect(observation.executionBindingSHA256 == fixture.executionBindingSHA256)
    #expect(throws: ArtifactRunProtocolError.trailingData) {
        try reader.consumeArtifact()
    }
    let authorityBound = try inspectSdistSubmission(
        from: sdistFileHandle(fixture.frame),
        expectedChallengeBindingSHA256: fixture.challengeBindingSHA256
    )
    #expect(authorityBound.challengeBindingSHA256 == fixture.challengeBindingSHA256)
    #expect(throws: ArtifactRunProtocolError.bindingMismatch) {
        try inspectSdistSubmission(
            from: sdistFileHandle(fixture.frame),
            expectedChallengeBindingSHA256: sha256(Data("wrong challenge".utf8))
        )
    }
}

@Test func npmWheelAndSdistSubmissionDomainsAreMutuallyRejected() throws {
    let sdist = try sdistSubmissionFixture(
        scenario: ["kind": "install_derived_wheel"], scenarioIndex: 1
    )
    #expect(throws: ArtifactRunProtocolError.invalidMagic) {
        try inspectArtifactSubmission(from: sdistFileHandle(sdist.frame))
    }
    #expect(throws: ArtifactRunProtocolError.invalidMagic) {
        try inspectWheelSubmission(from: sdistFileHandle(sdist.frame))
    }
    let wheel = try wheelSubmissionFixture(
        scenario: ["kind": "install_exact_wheel"], scenarioIndex: 1
    )
    #expect(throws: ArtifactRunProtocolError.invalidMagic) {
        try inspectSdistSubmission(from: sdistFileHandle(wheel.frame))
    }
    let npm = try artifactSubmissionFixture()
    #expect(throws: ArtifactRunProtocolError.invalidMagic) {
        try inspectSdistSubmission(from: sdistFileHandle(npm.frame))
    }
}

@Test func sdistSubmissionRejectsCorruptionRebindingAndClosureSubstitution() throws {
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "import_root", "module": "swift_sdist_fixture"],
        scenarioIndex: 3
    )

    var truncated = fixture.frame
    truncated.removeLast()
    #expect(throws: ArtifactRunProtocolError.truncated) {
        try inspectSdistSubmission(from: sdistFileHandle(truncated))
    }
    var trailing = fixture.frame
    trailing.append(0)
    #expect(throws: ArtifactRunProtocolError.trailingData) {
        try inspectSdistSubmission(from: sdistFileHandle(trailing))
    }
    var mutated = fixture.frame
    mutated[mutated.index(before: mutated.endIndex)] ^= 1
    #expect(throws: ArtifactRunProtocolError.artifactDigestMismatch) {
        try inspectSdistSubmission(from: sdistFileHandle(mutated))
    }

    var unknown = fixture.header
    unknown["sync_back"] = false
    #expect(throws: ArtifactRunProtocolError.headerInvalid) {
        try inspectSdistSubmission(
            from: sdistFileHandle(try rebuildSdistFrame(fixture, header: unknown))
        )
    }

    var wrongHeaderClosure = fixture.header
    wrongHeaderClosure["build_closure_sha256"] = sha256(Data("other closure".utf8))
    #expect(throws: ArtifactRunProtocolError.bindingMismatch) {
        try inspectSdistSubmission(
            from: sdistFileHandle(try rebuildSdistFrame(fixture, header: wrongHeaderClosure))
        )
    }

    var wrongRunClosure = fixture.header
    var closureRunSpec = try #require(wrongRunClosure["run_spec"] as? [String: Any])
    closureRunSpec["build_closure_sha256"] = sha256(Data("rebound closure".utf8))
    try rebindSdistHeader(
        &wrongRunClosure,
        runSpec: closureRunSpec,
        challenge: fixture.challengeBindingSHA256
    )
    wrongRunClosure["build_closure_sha256"] = closureRunSpec["build_closure_sha256"]
    #expect(throws: ArtifactRunProtocolError.runSpecInvalid) {
        try inspectSdistSubmission(
            from: sdistFileHandle(try rebuildSdistFrame(fixture, header: wrongRunClosure))
        )
    }

    var invalidClosure = fixture.header
    var invalidRunSpec = try #require(invalidClosure["run_spec"] as? [String: Any])
    var template = try #require(invalidRunSpec["template"] as? [String: Any])
    var closure = try #require(template["build_closure"] as? [String: Any])
    closure["closure_sha256"] = sha256(Data("forged closure digest".utf8))
    template["build_closure"] = closure
    invalidRunSpec["template"] = template
    invalidRunSpec["template_sha256"] = sha256(try canonicalJSONData(template))
    invalidRunSpec["build_closure_sha256"] = closure["closure_sha256"]
    try rebindSdistHeader(
        &invalidClosure,
        runSpec: invalidRunSpec,
        challenge: fixture.challengeBindingSHA256
    )
    invalidClosure["build_closure_sha256"] = closure["closure_sha256"]
    #expect(throws: ArtifactRunProtocolError.templateInvalid) {
        try inspectSdistSubmission(
            from: sdistFileHandle(try rebuildSdistFrame(fixture, header: invalidClosure))
        )
    }

    var crossSchema = fixture.header
    var crossRunSpec = try #require(crossSchema["run_spec"] as? [String: Any])
    crossRunSpec["schema_version"] = "whoathere.macos_wheel_run_spec.v1"
    try rebindSdistHeader(
        &crossSchema, runSpec: crossRunSpec, challenge: fixture.challengeBindingSHA256
    )
    #expect(throws: ArtifactRunProtocolError.runSpecInvalid) {
        try inspectSdistSubmission(
            from: sdistFileHandle(try rebuildSdistFrame(fixture, header: crossSchema))
        )
    }
}

@Test func sdistSubmissionRejectsUnsafeClosureArtifactNamesFormatsAndDuplicates() throws {
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "install_derived_wheel"], scenarioIndex: 11
    )
    let mutations: [(inout [[String: Any]]) -> Void] = [
        { $0[0]["artifact_filename"] = "../setuptools-75.0.0-py3-none-any.whl" },
        { $0[0]["artifact_filename"] = "nested\\setuptools-75.0.0-py3-none-any.whl" },
        { $0[0]["artifact_filename"] = "wheel-75.0.0-py3-none-any.whl" },
        { $0[0]["artifact_filename"] = "setuptools-74.0.0-py3-none-any.whl" },
        { $0[0]["artifact_filename"] = "setuptools-75.0.0-py3-none.whl" },
        { $0[0]["artifact_filename"] = "setuptools-75.0.0-build-py3-none-any.whl" },
        { $0[0]["artifact_filename"] = "setuptools-75.0.0-py3..py4-none-any.whl" },
        { $0[0]["artifact_format"] = "sdist" },
        {
            var duplicate = $0[0]
            duplicate["artifact_sha256"] = sha256(Data("duplicate name bytes".utf8))
            duplicate["artifact_byte_length"] = UInt64(20)
            $0.append(duplicate)
            $0.sort {
                (try? canonicalJSONData($0))?.lexicographicallyPrecedes(
                    (try? canonicalJSONData($1)) ?? Data()
                ) ?? false
            }
        }
    ]
    for mutate in mutations {
        var header = fixture.header
        var runSpec = try #require(header["run_spec"] as? [String: Any])
        var template = try #require(runSpec["template"] as? [String: Any])
        var closure = try #require(template["build_closure"] as? [String: Any])
        var artifacts = try #require(closure["artifacts"] as? [[String: Any]])
        mutate(&artifacts)
        closure["artifacts"] = artifacts
        let digestWire: [String: Any] = [
            "schema_version": "whoathere.sdist_build_closure.v1",
            "declaration_set_sha256": closure["declaration_set_sha256"] as Any,
            "artifacts": artifacts,
            "resolver_policy": "no_index_fixed_closure_only"
        ]
        let closureSHA256 = sha256(try canonicalJSONData(digestWire))
        closure["closure_sha256"] = closureSHA256
        template["build_closure"] = closure
        runSpec["template"] = template
        runSpec["template_sha256"] = sha256(try canonicalJSONData(template))
        runSpec["build_closure_sha256"] = closureSHA256
        try rebindSdistHeader(
            &header, runSpec: runSpec, challenge: fixture.challengeBindingSHA256
        )
        header["build_closure_sha256"] = closureSHA256
        #expect(throws: ArtifactRunProtocolError.templateInvalid) {
            try inspectSdistSubmission(
                from: sdistFileHandle(try rebuildSdistFrame(fixture, header: header))
            )
        }
    }
}

struct SdistSubmissionFixture {
    let frame: Data
    let header: [String: Any]
    let artifact: Data
    let artifactSHA256: String
    let templateSHA256: String
    let buildClosureSHA256: String
    let runSpecSHA256: String
    let challengeBindingSHA256: String
    let executionBindingSHA256: String
}

func sdistSubmissionFixture(
    scenario: [String: Any],
    scenarioIndex: Int,
    declarationSetSHA256: String? = nil,
    guestAuthPublicKeySHA256: String? = nil,
    postProvisioningReceiptSHA256: String? = nil
) throws -> SdistSubmissionFixture {
    let artifact = Data([0x1f, 0x8b, 0x08, 0x00, 0x53, 0x44, 0x49, 0x53, 0x54])
    let artifactSHA256 = sha256(artifact)
    let envelopeSHA256 = sha256(Data("sdist envelope".utf8))
    let manifestSHA256 = sha256(Data("sdist manifest".utf8))
    let pythonSHA256 = sha256(Data("python executable".utf8))
    let pipSHA256 = sha256(Data("pip cli".utf8))
    let commandTemplateSHA256 = sha256(
        Data("whoathere.python_sdist_offline_build.fixed_runner.v1".utf8)
    )
    let runtimeProfile: [String: Any] = [
        "schema_version": "whoathere.sdist_runtime_profile.v1",
        "profile_id": "macos-arm64-python312-pip26-sdist-inert",
        "target_os": "macos",
        "target_arch": "arm64",
        "python_version": "3.12.13",
        "python_executable_sha256": pythonSHA256,
        "pip_version": "26.1.2",
        "pip_cli_sha256": pipSHA256,
        "command_template_sha256": commandTemplateSHA256
    ]
    let runtimeProfileSHA256 = sha256(try canonicalJSONData(runtimeProfile))
    let declaration = declarationSetSHA256 ?? sha256(Data("setuptools>=75".utf8))
    let closureArtifactBytes = sdistBuildClosureArtifactBytes()
    let closureArtifacts: [[String: Any]] = [[
        "normalized_name": "setuptools",
        "version": "75.0.0",
        "artifact_filename": "setuptools-75.0.0-py3-none-any.whl",
        "artifact_format": "wheel",
        "artifact_sha256": sha256(closureArtifactBytes),
        "artifact_byte_length": UInt64(closureArtifactBytes.count)
    ]]
    let closureDigestWire: [String: Any] = [
        "schema_version": "whoathere.sdist_build_closure.v1",
        "declaration_set_sha256": declaration,
        "artifacts": closureArtifacts,
        "resolver_policy": "no_index_fixed_closure_only"
    ]
    let buildClosureSHA256 = sha256(try canonicalJSONData(closureDigestWire))
    let buildClosure: [String: Any] = [
        "schema_version": "whoathere.sdist_build_closure.v1",
        "declaration_set_sha256": declaration,
        "artifacts": closureArtifacts,
        "closure_sha256": buildClosureSHA256
    ]
    let template: [String: Any] = [
        "schema_version": "whoathere.sdist_scenario_template.v1",
        "canonicalization": "rfc8785.jcs.v1",
        "compiler_id": "whoathere.sdist_scenario_compiler.v1",
        "identity": [
            "job_id": "sdist-job-\(scenarioIndex)",
            "run_id": "sdist-run-\(scenarioIndex)",
            "evidence_id": "sdist-evidence-\(scenarioIndex)",
            "scenario_id": "sdist-scenario-\(scenarioIndex)"
        ],
        "subject": [
            "artifact_sha256": artifactSHA256,
            "envelope_sha256": envelopeSHA256,
            "manifest_sha256": manifestSHA256,
            "cas_object_key": "blobs/sha256/" + artifactSHA256.dropFirst(7)
        ],
        "package": [
            "ecosystem": "pypi",
            "display_name": "swift-sdist-fixture",
            "normalized_name": "swift-sdist-fixture",
            "version": "1.0.0"
        ],
        "canonical_package_root": "swift-sdist-fixture-1.0.0",
        "artifact_byte_length": UInt64(artifact.count),
        "policy_sha256": sha256(Data("sdist policy".utf8)),
        "runtime_profile": [
            "profile_id": "macos-arm64-python312-pip26-sdist-inert",
            "profile_sha256": runtimeProfileSHA256,
            "target_os": "macos",
            "target_arch": "arm64",
            "python_version": "3.12.13",
            "python_executable_sha256": pythonSHA256,
            "pip_version": "26.1.2",
            "pip_cli_sha256": pipSHA256,
            "command_template_sha256": commandTemplateSHA256
        ],
        "build_closure": buildClosure,
        "scenario_kind": scenario,
        "build_environment": "fresh_isolated_virtual_environment",
        "resolver_policy": "no_index_fixed_closure_only",
        "dynamic_build_requirements_policy": "deny_outside_fixed_closure",
        "derived_wheel_policy": "rehash_validate_fresh_scenario_no_host_copy",
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
            "vm_stop", "channel_closure", "clone_destruction", "build_closure_identity",
            "derived_artifact_digest", "derived_artifact_validation", "build_environment_teardown"
        ]
    ]
    let templateSHA256 = sha256(try canonicalJSONData(template))
    let guestProtocolSHA256 = sha256(Data("whoathere.sdist_artifact_scenario.v1".utf8))
    let runSpec: [String: Any] = [
        "schema_version": "whoathere.macos_sdist_run_spec.v1",
        "canonicalization": "rfc8785.jcs.v1",
        "template": template,
        "template_sha256": templateSHA256,
        "build_closure_sha256": buildClosureSHA256,
        "backend_identity": [
            "base_generation_id": "sdist-base-generation-inert-v1",
            "base_disk_sha256": sha256(Data("sdist base disk".utf8)),
            "base_auxiliary_storage_sha256": sha256(Data("sdist base aux".utf8)),
            "hardware_model_sha256": sha256(Data("hardware model".utf8)),
            "machine_identifier_sha256": sha256(Data("machine identifier".utf8)),
            "cpu_count": UInt64(4),
            "memory_mib": UInt64(6_144),
            "post_provisioning_receipt_sha256": postProvisioningReceiptSHA256
                ?? sha256(Data("sdist receipt".utf8)),
            "helper_sha256": sha256(Data("helper".utf8)),
            "guest_supervisor_sha256": sha256(Data("sdist supervisor".utf8)),
            "guest_auth_public_key_sha256": guestAuthPublicKeySHA256
                ?? sha256(Data("sdist public key".utf8)),
            "runner_configuration_sha256": sha256(Data("sdist runner".utf8)),
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
        "guest_protocol": "whoathere.sdist_artifact_scenario.v1"
    ]
    let runSpecSHA256 = sha256(try canonicalJSONData(runSpec))
    let challenge = sha256(Data("sdist challenge".utf8))
    let execution = sha256(
        Data("whoathere.macos_sdist_submission_execution_binding.v1\0\(challenge)\0\(runSpecSHA256)".utf8)
    )
    let header: [String: Any] = [
        "schema_version": "whoathere.macos_sdist_submission_header.v1",
        "run_spec": runSpec,
        "run_spec_sha256": runSpecSHA256,
        "challenge_binding_sha256": challenge,
        "execution_binding_sha256": execution,
        "artifact_sha256": artifactSHA256,
        "artifact_byte_length": UInt64(artifact.count),
        "build_closure_sha256": buildClosureSHA256,
        "artifact_transport_ceiling": UInt64(64 * 1024 * 1024)
    ]
    let frame = try encodeSdistFixtureFrame(
        header: header, artifact: artifact, digest: artifactSHA256
    )
    return SdistSubmissionFixture(
        frame: frame,
        header: header,
        artifact: artifact,
        artifactSHA256: artifactSHA256,
        templateSHA256: templateSHA256,
        buildClosureSHA256: buildClosureSHA256,
        runSpecSHA256: runSpecSHA256,
        challengeBindingSHA256: challenge,
        executionBindingSHA256: execution
    )
}

func sdistBuildClosureArtifactBytes() -> Data {
    Data(repeating: 0x5a, count: 4_096)
}

func rebindSdistHeader(
    _ header: inout [String: Any],
    runSpec: [String: Any],
    challenge: String
) throws {
    let runSpecSHA256 = sha256(try canonicalJSONData(runSpec))
    header["run_spec"] = runSpec
    header["run_spec_sha256"] = runSpecSHA256
    header["execution_binding_sha256"] = sha256(
        Data("whoathere.macos_sdist_submission_execution_binding.v1\0\(challenge)\0\(runSpecSHA256)".utf8)
    )
}

func rebuildSdistFrame(
    _ fixture: SdistSubmissionFixture,
    header: [String: Any]
) throws -> Data {
    try encodeSdistFixtureFrame(
        header: header, artifact: fixture.artifact, digest: fixture.artifactSHA256
    )
}

func sdistFileHandle(_ data: Data) -> FileHandle {
    let pipe = Pipe()
    pipe.fileHandleForWriting.write(data)
    try? pipe.fileHandleForWriting.close()
    return pipe.fileHandleForReading
}

private func encodeSdistFixtureFrame(
    header: [String: Any],
    artifact: Data,
    digest: String
) throws -> Data {
    let headerData = try canonicalJSONData(header)
    var frame = Data()
    frame.append(sdistSubmissionMagicV1)
    sdistAppendBigEndian(sdistSubmissionVersionV1, to: &frame)
    sdistAppendBigEndian(sdistSubmissionFrameTypeV1, to: &frame)
    sdistAppendBigEndian(UInt32(headerData.count), to: &frame)
    sdistAppendBigEndian(UInt64(artifact.count), to: &frame)
    frame.append(try sdistFixtureRawDigest(digest))
    frame.append(headerData)
    frame.append(artifact)
    return frame
}

private func sdistAppendBigEndian(_ value: UInt16, to data: inout Data) {
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func sdistAppendBigEndian(_ value: UInt32, to data: inout Data) {
    for shift in stride(from: 24, through: 0, by: -8) {
        data.append(UInt8((value >> UInt32(shift)) & 0xff))
    }
}

private func sdistAppendBigEndian(_ value: UInt64, to data: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}

private func sdistFixtureRawDigest(_ value: String) throws -> Data {
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
