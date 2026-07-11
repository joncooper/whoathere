import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func artifactRunUsesASeparateNoSyncOptionType() throws {
    let parsed = try parseHelperInvocation([
        "artifact-run",
        "--state-dir", "/tmp/whoathere-artifact-runs",
        "--execute",
        "--json"
    ])
    guard case .artifactRun(let options) = parsed else {
        Issue.record("expected artifact-run invocation")
        return
    }
    #expect(options.stateDir == "/tmp/whoathere-artifact-runs")
    #expect(options.execute)
    #expect(options.json)

    for forbidden in ["--sync-back", "--tool=npm", "--", "--project-payload-path=/tmp/x"] {
        do {
            _ = try parseHelperInvocation(["artifact-run", forbidden])
            Issue.record("expected artifact-run flag rejection: \(forbidden)")
        } catch let error as ArgumentError {
            let expected = forbidden.split(separator: "=", maxSplits: 1).first.map(String.init)
                ?? forbidden
            #expect(error == .unknownFlag(expected))
        }
    }
}

@Test func strictArtifactSubmissionParserAcceptsBoundCanonicalFrame() throws {
    let fixture = try artifactSubmissionFixture()
    let observation = try inspectArtifactSubmission(from: fileHandle(fixture.frame))
    #expect(observation.runSpecSHA256 == fixture.runSpecSHA256)
    #expect(observation.templateSHA256 == fixture.templateSHA256)
    #expect(observation.challengeBindingSHA256 == fixture.challengeBindingSHA256)
    #expect(observation.executionBindingSHA256 == fixture.executionBindingSHA256)
    #expect(observation.artifactSHA256 == fixture.artifactSHA256)
    #expect(observation.artifactByteLength == UInt64(fixture.artifact.count))
    #expect(observation.scenarioID == "scenario-ci-false")
    #expect(observation.environment == "ci_false")
    #expect(observation.backendIdentity.cpuCount == 4)
    #expect(observation.backendIdentity.memoryMiB == 6_144)
    #expect(observation.backendIdentity.hardwareModelSHA256 == sha256(Data("hardware model".utf8)))
    #expect(
        observation.backendIdentity.machineIdentifierSHA256
            == sha256(Data("machine identifier".utf8))
    )
}

@Test func artifactSubmissionParserRejectsCorruptionAndExposesChallengeAuthorityBoundary() throws {
    let fixture = try artifactSubmissionFixture()

    var truncated = fixture.frame
    truncated.removeLast()
    #expect(throws: ArtifactRunProtocolError.truncated) {
        try inspectArtifactSubmission(from: fileHandle(truncated))
    }

    var trailing = fixture.frame
    trailing.append(0)
    #expect(throws: ArtifactRunProtocolError.trailingData) {
        try inspectArtifactSubmission(from: fileHandle(trailing))
    }

    var mutated = fixture.frame
    mutated[mutated.index(before: mutated.endIndex)] ^= 1
    #expect(throws: ArtifactRunProtocolError.artifactDigestMismatch) {
        try inspectArtifactSubmission(from: fileHandle(mutated))
    }

    var unknownHeader = fixture.header
    unknownHeader["sync_back"] = false
    let unknown = try rebuild(fixture, header: unknownHeader)
    #expect(throws: ArtifactRunProtocolError.headerInvalid) {
        try inspectArtifactSubmission(from: fileHandle(unknown))
    }

    var reboundHeader = fixture.header
    let forgedChallenge = sha256(Data("forged challenge".utf8))
    reboundHeader["challenge_binding_sha256"] = forgedChallenge
    reboundHeader["execution_binding_sha256"] = sha256(
        Data("whoathere.macos_artifact_submission_execution_binding.v1\0\(forgedChallenge)\0\(fixture.runSpecSHA256)".utf8)
    )
    let rebound = try rebuild(fixture, header: reboundHeader)
    let observation = try inspectArtifactSubmission(from: fileHandle(rebound))
    #expect(observation.challengeBindingSHA256 == forgedChallenge)
    #expect(observation.executionBindingSHA256 != fixture.executionBindingSHA256)
    // The parser proves internal binding. A later authenticated authority must
    // compare it with the pre-issued expected challenge before execution.
}

private struct ArtifactSubmissionFixture {
    let frame: Data
    let header: [String: Any]
    let artifact: Data
    let artifactSHA256: String
    let templateSHA256: String
    let runSpecSHA256: String
    let challengeBindingSHA256: String
    let executionBindingSHA256: String
}

private func artifactSubmissionFixture() throws -> ArtifactSubmissionFixture {
    let artifact = Data([0x1f, 0x8b, 0x08, 0x00, 0x57, 0x48, 0x4f, 0x41])
    let artifactSHA256 = sha256(artifact)
    let envelopeSHA256 = sha256(Data("envelope".utf8))
    let manifestSHA256 = sha256(Data("manifest".utf8))
    let nodeSHA256 = sha256(Data("node executable".utf8))
    let npmSHA256 = sha256(Data("npm cli".utf8))
    let commandTemplateSHA256 = sha256(
        Data("whoathere.npm_local_tarball_install.fixed_argv.v1".utf8)
    )
    let runtimeProfile: [String: Any] = [
        "schema_version": "whoathere.npm_runtime_profile.v1",
        "profile_id": "macos-arm64-node22-npm11-inert",
        "target_os": "macos",
        "target_arch": "arm64",
        "node_version": "22.17.0",
        "node_executable_sha256": nodeSHA256,
        "npm_version": "11.18.0",
        "npm_cli_sha256": npmSHA256,
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
        "schema_version": "whoathere.artifact_scenario_template.v1",
        "canonicalization": "rfc8785.jcs.v1",
        "compiler_id": "whoathere.dependency_free_npm_scenario_compiler.v1",
        "identity": [
            "job_id": "job-ci-false",
            "run_id": "run-ci-false",
            "evidence_id": "evidence-ci-false",
            "scenario_id": "scenario-ci-false"
        ],
        "subject": [
            "artifact_sha256": artifactSHA256,
            "envelope_sha256": envelopeSHA256,
            "manifest_sha256": manifestSHA256,
            "cas_object_key": "blobs/sha256/" + artifactSHA256.dropFirst(7)
        ],
        "package": [
            "ecosystem": "npm",
            "display_name": "swift-parser-fixture",
            "normalized_name": "swift-parser-fixture",
            "version": "1.0.0"
        ],
        "artifact_byte_length": UInt64(artifact.count),
        "policy_sha256": sha256(Data("policy".utf8)),
        "runtime_profile": [
            "profile_id": "macos-arm64-node22-npm11-inert",
            "profile_sha256": runtimeProfileSHA256,
            "target_os": "macos",
            "target_arch": "arm64",
            "node_version": "22.17.0",
            "node_executable_sha256": nodeSHA256,
            "npm_version": "11.18.0",
            "npm_cli_sha256": npmSHA256,
            "command_template_sha256": commandTemplateSHA256
        ],
        "dependency_closure": [
            "kind": "empty",
            "declaration_set_sha256": closureSHA256
        ],
        "scenario_kind": [
            "kind": "npm_local_tarball_install",
            "environment": "ci_false"
        ],
        "lifecycle_hooks": [[
            "hook": "postinstall",
            "command_sha256": sha256(Data("node post.js".utf8))
        ]],
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
    let guestProtocolSHA256 = sha256(Data("whoathere.artifact_scenario.v1".utf8))
    let runSpec: [String: Any] = [
        "schema_version": "whoathere.macos_artifact_run_spec.v1",
        "canonicalization": "rfc8785.jcs.v1",
        "template": template,
        "template_sha256": templateSHA256,
        "backend_identity": [
            "base_generation_id": "base-generation-inert-v1",
            "base_disk_sha256": sha256(Data("base disk".utf8)),
            "base_auxiliary_storage_sha256": sha256(Data("base aux".utf8)),
            "hardware_model_sha256": sha256(Data("hardware model".utf8)),
            "machine_identifier_sha256": sha256(Data("machine identifier".utf8)),
            "cpu_count": UInt64(4),
            "memory_mib": UInt64(6_144),
            "post_provisioning_receipt_sha256": sha256(Data("receipt".utf8)),
            "helper_sha256": sha256(Data("helper".utf8)),
            "guest_supervisor_sha256": sha256(Data("supervisor".utf8)),
            "runner_configuration_sha256": sha256(Data("runner".utf8)),
            "node_version": "22.17.0",
            "node_executable_sha256": nodeSHA256,
            "npm_version": "11.18.0",
            "npm_cli_sha256": npmSHA256,
            "clone_implementation_sha256": sha256(Data("clone".utf8)),
            "guest_protocol_sha256": guestProtocolSHA256
        ],
        "clone_policy": "apfs_clone_required_no_copy_fallback",
        "network_configuration": "zero_network_devices",
        "reuse_policy": "one_boot_one_scenario_destroy_clone",
        "guest_protocol": "whoathere.artifact_scenario.v1"
    ]
    let runSpecSHA256 = sha256(try canonicalJSONData(runSpec))
    let challenge = sha256(Data("challenge".utf8))
    let execution = sha256(
        Data("whoathere.macos_artifact_submission_execution_binding.v1\0\(challenge)\0\(runSpecSHA256)".utf8)
    )
    let header: [String: Any] = [
        "schema_version": "whoathere.macos_artifact_submission_header.v1",
        "run_spec": runSpec,
        "run_spec_sha256": runSpecSHA256,
        "challenge_binding_sha256": challenge,
        "execution_binding_sha256": execution,
        "artifact_sha256": artifactSHA256,
        "artifact_byte_length": UInt64(artifact.count),
        "artifact_transport_ceiling": UInt64(64 * 1024 * 1024)
    ]
    let headerData = try canonicalJSONData(header)
    var frame = Data()
    frame.append(artifactSubmissionMagicV1)
    appendBigEndian(artifactSubmissionVersionV1, to: &frame)
    appendBigEndian(artifactSubmissionFrameTypeV1, to: &frame)
    appendBigEndian(UInt32(headerData.count), to: &frame)
    appendBigEndian(UInt64(artifact.count), to: &frame)
    frame.append(try rawDigest(artifactSHA256))
    frame.append(headerData)
    frame.append(artifact)
    return ArtifactSubmissionFixture(
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

private func rebuild(
    _ fixture: ArtifactSubmissionFixture,
    header: [String: Any]
) throws -> Data {
    let headerData = try canonicalJSONData(header)
    var frame = Data()
    frame.append(artifactSubmissionMagicV1)
    appendBigEndian(artifactSubmissionVersionV1, to: &frame)
    appendBigEndian(artifactSubmissionFrameTypeV1, to: &frame)
    appendBigEndian(UInt32(headerData.count), to: &frame)
    appendBigEndian(UInt64(fixture.artifact.count), to: &frame)
    frame.append(try rawDigest(fixture.artifactSHA256))
    frame.append(headerData)
    frame.append(fixture.artifact)
    return frame
}

private func fileHandle(_ data: Data) -> FileHandle {
    let pipe = Pipe()
    pipe.fileHandleForWriting.write(data)
    try? pipe.fileHandleForWriting.close()
    return pipe.fileHandleForReading
}

private func appendBigEndian(_ value: UInt16, to data: inout Data) {
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func appendBigEndian(_ value: UInt32, to data: inout Data) {
    for shift in stride(from: 24, through: 0, by: -8) {
        data.append(UInt8((value >> UInt32(shift)) & 0xff))
    }
}

private func appendBigEndian(_ value: UInt64, to data: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}

private func rawDigest(_ value: String) throws -> Data {
    let hex = value.dropFirst(7)
    var data = Data()
    var index = hex.startIndex
    for _ in 0..<32 {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<next], radix: 16) else {
            throw ArtifactRunProtocolError.headerInvalid
        }
        data.append(byte)
        index = next
    }
    return data
}
