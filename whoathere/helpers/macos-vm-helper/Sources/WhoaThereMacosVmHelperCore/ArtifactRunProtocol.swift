import CoreFoundation
import CryptoKit
import Foundation

public let artifactSubmissionMagicV1 = Data("WHOAART1".utf8)
public let artifactSubmissionVersionV1: UInt16 = 1
public let artifactSubmissionFrameTypeV1: UInt16 = 1
public let artifactSubmissionPrefixBytesV1 = 56
public let maximumArtifactSubmissionHeaderBytesV1 = 576 * 1024
public let maximumArtifactSubmissionBytesV1: UInt64 = 64 * 1024 * 1024

public enum ArtifactRunProtocolError: Error, Equatable, CustomStringConvertible {
    case truncated
    case trailingData
    case invalidMagic
    case unsupportedVersion
    case unsupportedFrameType
    case headerLimitExceeded
    case artifactLimitExceeded
    case headerInvalid
    case runSpecInvalid
    case templateInvalid
    case bindingMismatch
    case artifactDigestMismatch
    case inputReadFailed

    public var description: String {
        switch self {
        case .truncated: return "artifact_run_submission_truncated"
        case .trailingData: return "artifact_run_submission_trailing_data"
        case .invalidMagic: return "artifact_run_submission_magic_invalid"
        case .unsupportedVersion: return "artifact_run_submission_version_unsupported"
        case .unsupportedFrameType: return "artifact_run_submission_frame_type_unsupported"
        case .headerLimitExceeded: return "artifact_run_submission_header_limit_exceeded"
        case .artifactLimitExceeded: return "artifact_run_submission_artifact_limit_exceeded"
        case .headerInvalid: return "artifact_run_submission_header_invalid"
        case .runSpecInvalid: return "artifact_run_submission_run_spec_invalid"
        case .templateInvalid: return "artifact_run_submission_template_invalid"
        case .bindingMismatch: return "artifact_run_submission_binding_mismatch"
        case .artifactDigestMismatch: return "artifact_run_submission_artifact_digest_mismatch"
        case .inputReadFailed: return "artifact_run_submission_input_read_failed"
        }
    }
}

public struct ArtifactRunTransportObservation: Equatable, Sendable {
    public let runSpecSHA256: String
    public let templateSHA256: String
    public let challengeBindingSHA256: String
    public let executionBindingSHA256: String
    public let artifactSHA256: String
    public let artifactByteLength: UInt64
    public let headerByteLength: UInt32
    public let scenarioID: String
    public let environment: String
    public let backendIdentity: ArtifactRunBackendIdentity

    public init(
        runSpecSHA256: String,
        templateSHA256: String,
        challengeBindingSHA256: String,
        executionBindingSHA256: String,
        artifactSHA256: String,
        artifactByteLength: UInt64,
        headerByteLength: UInt32,
        scenarioID: String,
        environment: String,
        backendIdentity: ArtifactRunBackendIdentity
    ) {
        self.runSpecSHA256 = runSpecSHA256
        self.templateSHA256 = templateSHA256
        self.challengeBindingSHA256 = challengeBindingSHA256
        self.executionBindingSHA256 = executionBindingSHA256
        self.artifactSHA256 = artifactSHA256
        self.artifactByteLength = artifactByteLength
        self.headerByteLength = headerByteLength
        self.scenarioID = scenarioID
        self.environment = environment
        self.backendIdentity = backendIdentity
    }
}

public struct ArtifactRunBackendIdentity: Equatable, Sendable {
    public let baseGenerationID: String
    public let baseDiskSHA256: String
    public let baseAuxiliaryStorageSHA256: String
    public let hardwareModelSHA256: String
    public let machineIdentifierSHA256: String
    public let cpuCount: UInt16
    public let memoryMiB: UInt64
    public let postProvisioningReceiptSHA256: String
    public let helperSHA256: String
    public let guestSupervisorSHA256: String
    public let guestAuthPublicKeySHA256: String
    public let runnerConfigurationSHA256: String
    public let packageUID: UInt32
    public let packageGID: UInt32
    public let nodeVersion: String
    public let nodeExecutableSHA256: String
    public let npmVersion: String
    public let npmCLISHA256: String
    public let cloneImplementationSHA256: String
    public let guestProtocolSHA256: String
}

public struct ArtifactRunSubmissionPrelude: Equatable, Sendable {
    public let runSpecSHA256: String
    public let templateSHA256: String
    public let challengeBindingSHA256: String
    public let executionBindingSHA256: String
    public let artifactSHA256: String
    public let artifactByteLength: UInt64
    public let headerByteLength: UInt32
    public let scenarioID: String
    public let environment: String
    public let backendIdentity: ArtifactRunBackendIdentity
}

public final class ArtifactRunSubmissionReader {
    public let prelude: ArtifactRunSubmissionPrelude

    private let handle: FileHandle
    let expectedArtifactDigest: Data
    let canonicalHeaderData: Data
    private var consumed = false

    fileprivate init(
        handle: FileHandle,
        expectedArtifactDigest: Data,
        canonicalHeaderData: Data,
        prelude: ArtifactRunSubmissionPrelude
    ) {
        self.handle = handle
        self.expectedArtifactDigest = expectedArtifactDigest
        self.canonicalHeaderData = canonicalHeaderData
        self.prelude = prelude
    }

    public func consumeArtifact(
        chunkSink: (Data) throws -> Void = { _ in }
    ) throws -> ArtifactRunTransportObservation {
        guard !consumed else {
            throw ArtifactRunProtocolError.trailingData
        }
        consumed = true
        var remaining = prelude.artifactByteLength
        var artifactHasher = SHA256()
        while remaining > 0 {
            let requested = Int(min(remaining, 64 * 1024))
            let chunk = try readExactly(handle, count: requested)
            artifactHasher.update(data: chunk)
            try chunkSink(chunk)
            remaining -= UInt64(chunk.count)
        }
        let observedDigest = Data(artifactHasher.finalize())
        guard observedDigest == expectedArtifactDigest else {
            throw ArtifactRunProtocolError.artifactDigestMismatch
        }
        do {
            if let trailing = try handle.read(upToCount: 1), !trailing.isEmpty {
                throw ArtifactRunProtocolError.trailingData
            }
        } catch let error as ArtifactRunProtocolError {
            throw error
        } catch {
            throw ArtifactRunProtocolError.inputReadFailed
        }
        return ArtifactRunTransportObservation(
            runSpecSHA256: prelude.runSpecSHA256,
            templateSHA256: prelude.templateSHA256,
            challengeBindingSHA256: prelude.challengeBindingSHA256,
            executionBindingSHA256: prelude.executionBindingSHA256,
            artifactSHA256: prelude.artifactSHA256,
            artifactByteLength: prelude.artifactByteLength,
            headerByteLength: prelude.headerByteLength,
            scenarioID: prelude.scenarioID,
            environment: prelude.environment,
            backendIdentity: prelude.backendIdentity
        )
    }
}

public func inspectArtifactSubmission(
    from handle: FileHandle
) throws -> ArtifactRunTransportObservation {
    try beginArtifactSubmission(from: handle).consumeArtifact()
}

public func beginArtifactSubmission(
    from handle: FileHandle
) throws -> ArtifactRunSubmissionReader {
    let prefix = try readExactly(handle, count: artifactSubmissionPrefixBytesV1)
    guard prefix.prefix(8) == artifactSubmissionMagicV1 else {
        throw ArtifactRunProtocolError.invalidMagic
    }
    guard uint16(prefix, at: 8) == artifactSubmissionVersionV1 else {
        throw ArtifactRunProtocolError.unsupportedVersion
    }
    guard uint16(prefix, at: 10) == artifactSubmissionFrameTypeV1 else {
        throw ArtifactRunProtocolError.unsupportedFrameType
    }
    let headerLength = uint32(prefix, at: 12)
    guard headerLength > 0, headerLength <= maximumArtifactSubmissionHeaderBytesV1 else {
        throw ArtifactRunProtocolError.headerLimitExceeded
    }
    let artifactLength = uint64(prefix, at: 16)
    guard artifactLength > 0, artifactLength <= maximumArtifactSubmissionBytesV1 else {
        throw ArtifactRunProtocolError.artifactLimitExceeded
    }
    let prefixDigest = Data(prefix[24..<56])
    let headerData = try readExactly(handle, count: Int(headerLength))
    let validated = try validateArtifactHeader(
        headerData,
        prefixArtifactLength: artifactLength,
        prefixArtifactDigest: prefixDigest
    )
    let prelude = ArtifactRunSubmissionPrelude(
        runSpecSHA256: validated.runSpecSHA256,
        templateSHA256: validated.templateSHA256,
        challengeBindingSHA256: validated.challengeBindingSHA256,
        executionBindingSHA256: validated.executionBindingSHA256,
        artifactSHA256: validated.artifactSHA256,
        artifactByteLength: artifactLength,
        headerByteLength: headerLength,
        scenarioID: validated.scenarioID,
        environment: validated.environment,
        backendIdentity: validated.backendIdentity
    )
    return ArtifactRunSubmissionReader(
        handle: handle,
        expectedArtifactDigest: prefixDigest,
        canonicalHeaderData: headerData,
        prelude: prelude
    )
}

private struct ValidatedHeader {
    let runSpecSHA256: String
    let templateSHA256: String
    let challengeBindingSHA256: String
    let executionBindingSHA256: String
    let artifactSHA256: String
    let scenarioID: String
    let environment: String
    let backendIdentity: ArtifactRunBackendIdentity
}

private func validateArtifactHeader(
    _ data: Data,
    prefixArtifactLength: UInt64,
    prefixArtifactDigest: Data
) throws -> ValidatedHeader {
    let object: Any
    do {
        object = try JSONSerialization.jsonObject(with: data)
    } catch {
        throw ArtifactRunProtocolError.headerInvalid
    }
    guard let header = object as? [String: Any],
          try canonicalJSONData(header) == data else {
        throw ArtifactRunProtocolError.headerInvalid
    }
    try requireExactKeys(header, [
        "artifact_byte_length", "artifact_sha256", "artifact_transport_ceiling",
        "challenge_binding_sha256", "execution_binding_sha256", "run_spec",
        "run_spec_sha256", "schema_version"
    ], error: .headerInvalid)
    guard try string(header, "schema_version", error: .headerInvalid)
            == "whoathere.macos_artifact_submission_header.v1",
          try integer(header, "artifact_byte_length", error: .headerInvalid)
            == prefixArtifactLength,
          try integer(header, "artifact_transport_ceiling", error: .headerInvalid)
            == maximumArtifactSubmissionBytesV1 else {
        throw ArtifactRunProtocolError.headerInvalid
    }
    let artifactSHA256 = try digest(header, "artifact_sha256", error: .headerInvalid)
    guard try rawDigest(artifactSHA256) == prefixArtifactDigest else {
        throw ArtifactRunProtocolError.artifactDigestMismatch
    }
    let challenge = try digest(header, "challenge_binding_sha256", error: .headerInvalid)
    let execution = try digest(header, "execution_binding_sha256", error: .headerInvalid)
    let runSpecSHA256 = try digest(header, "run_spec_sha256", error: .headerInvalid)
    guard let runSpec = header["run_spec"] as? [String: Any] else {
        throw ArtifactRunProtocolError.runSpecInvalid
    }
    let runSpecData = try canonicalJSONData(runSpec)
    guard sha256(runSpecData) == runSpecSHA256 else {
        throw ArtifactRunProtocolError.runSpecInvalid
    }
    let expectedExecution = sha256(
        Data("whoathere.macos_artifact_submission_execution_binding.v1\0\(challenge)\0\(runSpecSHA256)".utf8)
    )
    guard execution == expectedExecution else {
        throw ArtifactRunProtocolError.bindingMismatch
    }
    let runSpecFields = try validateRunSpec(runSpec)
    guard runSpecFields.artifactSHA256 == artifactSHA256,
          runSpecFields.artifactByteLength == prefixArtifactLength else {
        throw ArtifactRunProtocolError.artifactDigestMismatch
    }
    return ValidatedHeader(
        runSpecSHA256: runSpecSHA256,
        templateSHA256: runSpecFields.templateSHA256,
        challengeBindingSHA256: challenge,
        executionBindingSHA256: execution,
        artifactSHA256: artifactSHA256,
        scenarioID: runSpecFields.scenarioID,
        environment: runSpecFields.environment,
        backendIdentity: runSpecFields.backendIdentity
    )
}

private struct ValidatedRunSpec {
    let templateSHA256: String
    let artifactSHA256: String
    let artifactByteLength: UInt64
    let scenarioID: String
    let environment: String
    let backendIdentity: ArtifactRunBackendIdentity
}

private func validateRunSpec(_ runSpec: [String: Any]) throws -> ValidatedRunSpec {
    try requireExactKeys(runSpec, [
        "backend_identity", "canonicalization", "clone_policy", "guest_protocol",
        "network_configuration", "reuse_policy", "schema_version", "template",
        "template_sha256"
    ], error: .runSpecInvalid)
    guard try string(runSpec, "schema_version", error: .runSpecInvalid)
            == "whoathere.macos_artifact_run_spec.v1",
          try string(runSpec, "canonicalization", error: .runSpecInvalid) == "rfc8785.jcs.v1",
          try string(runSpec, "clone_policy", error: .runSpecInvalid)
            == "apfs_clone_required_no_copy_fallback",
          try string(runSpec, "network_configuration", error: .runSpecInvalid)
            == "zero_network_devices",
          try string(runSpec, "reuse_policy", error: .runSpecInvalid)
            == "one_boot_one_scenario_destroy_clone",
          try string(runSpec, "guest_protocol", error: .runSpecInvalid)
            == "whoathere.artifact_scenario.v1",
          let template = runSpec["template"] as? [String: Any],
          let backend = runSpec["backend_identity"] as? [String: Any] else {
        throw ArtifactRunProtocolError.runSpecInvalid
    }
    let templateSHA256 = try digest(runSpec, "template_sha256", error: .runSpecInvalid)
    guard sha256(try canonicalJSONData(template)) == templateSHA256 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let templateFields = try validateTemplate(template)
    let backendIdentity = try validateBackend(backend, template: templateFields)
    return ValidatedRunSpec(
        templateSHA256: templateSHA256,
        artifactSHA256: templateFields.artifactSHA256,
        artifactByteLength: templateFields.artifactByteLength,
        scenarioID: templateFields.scenarioID,
        environment: templateFields.environment,
        backendIdentity: backendIdentity
    )
}

private struct ValidatedTemplate {
    let artifactSHA256: String
    let manifestSHA256: String
    let artifactByteLength: UInt64
    let scenarioID: String
    let environment: String
    let nodeVersion: String
    let nodeSHA256: String
    let npmVersion: String
    let npmSHA256: String
}

private func validateTemplate(_ template: [String: Any]) throws -> ValidatedTemplate {
    try requireExactKeys(template, [
        "artifact_byte_length", "canonicalization", "clone_disposition", "compiler_id",
        "dependency_closure", "identity", "lifecycle_hooks", "limits", "network_policy",
        "package", "package_privilege", "policy_sha256", "required_evidence",
        "runtime_profile", "scenario_kind", "schema_version", "subject", "target_arch",
        "target_os", "transport"
    ], error: .templateInvalid)
    guard try string(template, "schema_version", error: .templateInvalid)
            == "whoathere.artifact_scenario_template.v1",
          try string(template, "canonicalization", error: .templateInvalid) == "rfc8785.jcs.v1",
          try string(template, "compiler_id", error: .templateInvalid)
            == "whoathere.dependency_free_npm_scenario_compiler.v1",
          try string(template, "target_os", error: .templateInvalid) == "macos",
          try string(template, "target_arch", error: .templateInvalid) == "arm64",
          try string(template, "transport", error: .templateInvalid)
            == "digest_checked_bounded_raw_bytes",
          try string(template, "network_policy", error: .templateInvalid) == "no_network_device",
          try string(template, "package_privilege", error: .templateInvalid)
            == "dedicated_unprivileged_uid_gid",
          try string(template, "clone_disposition", error: .templateInvalid) == "destroy_clone",
          let identity = template["identity"] as? [String: Any],
          let subject = template["subject"] as? [String: Any],
          let package = template["package"] as? [String: Any],
          let runtime = template["runtime_profile"] as? [String: Any],
          let closure = template["dependency_closure"] as? [String: Any],
          let scenario = template["scenario_kind"] as? [String: Any],
          let hooks = template["lifecycle_hooks"] as? [Any],
          let limits = template["limits"] as? [String: Any],
          let evidence = template["required_evidence"] as? [String] else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    _ = try digest(template, "policy_sha256", error: .templateInvalid)
    try validateIdentity(identity)
    let scenarioID = try string(identity, "scenario_id", error: .templateInvalid)
    let (artifactSHA256, manifestSHA256) = try validateSubject(subject)
    try validatePackage(package)
    let runtimeFields = try validateRuntime(runtime)
    try validateClosure(closure, manifestSHA256: manifestSHA256)
    let environment = try validateScenario(scenario)
    try validateHooks(hooks)
    try validateLimits(limits)
    guard evidence == [
        "artifact_transport", "guest_artifact_rehash", "process_credentials",
        "process_lifecycle", "listener_inventory", "sensor_health", "no_network_device",
        "vm_stop", "channel_closure", "clone_destruction"
    ] else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    return ValidatedTemplate(
        artifactSHA256: artifactSHA256,
        manifestSHA256: manifestSHA256,
        artifactByteLength: try integer(template, "artifact_byte_length", error: .templateInvalid),
        scenarioID: scenarioID,
        environment: environment,
        nodeVersion: runtimeFields.nodeVersion,
        nodeSHA256: runtimeFields.nodeSHA256,
        npmVersion: runtimeFields.npmVersion,
        npmSHA256: runtimeFields.npmSHA256
    )
}

private func validateIdentity(_ value: [String: Any]) throws {
    try requireExactKeys(value, ["evidence_id", "job_id", "run_id", "scenario_id"], error: .templateInvalid)
    for key in ["evidence_id", "job_id", "run_id", "scenario_id"] {
        guard validIdentity(try string(value, key, error: .templateInvalid)) else {
            throw ArtifactRunProtocolError.templateInvalid
        }
    }
}

private func validateSubject(_ value: [String: Any]) throws -> (String, String) {
    try requireExactKeys(value, ["artifact_sha256", "cas_object_key", "envelope_sha256", "manifest_sha256"], error: .templateInvalid)
    let artifact = try digest(value, "artifact_sha256", error: .templateInvalid)
    let manifest = try digest(value, "manifest_sha256", error: .templateInvalid)
    _ = try digest(value, "envelope_sha256", error: .templateInvalid)
    let expectedKey = "blobs/sha256/" + artifact.dropFirst("sha256:".count)
    guard try string(value, "cas_object_key", error: .templateInvalid) == expectedKey else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    return (artifact, manifest)
}

private func validatePackage(_ value: [String: Any]) throws {
    try requireExactKeys(value, ["display_name", "ecosystem", "normalized_name", "version"], error: .templateInvalid)
    guard try string(value, "ecosystem", error: .templateInvalid) == "npm" else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    for key in ["display_name", "normalized_name", "version"] {
        let text = try string(value, key, error: .templateInvalid)
        guard !text.isEmpty, text.utf8.count <= 256, !text.unicodeScalars.contains(where: { $0.value < 0x20 }) else {
            throw ArtifactRunProtocolError.templateInvalid
        }
    }
}

private struct RuntimeFields {
    let nodeVersion: String
    let nodeSHA256: String
    let npmVersion: String
    let npmSHA256: String
}

private func validateRuntime(_ value: [String: Any]) throws -> RuntimeFields {
    try requireExactKeys(value, [
        "command_template_sha256", "node_executable_sha256", "node_version", "npm_cli_sha256",
        "npm_version", "profile_id", "profile_sha256", "target_arch", "target_os"
    ], error: .templateInvalid)
    guard try string(value, "target_os", error: .templateInvalid) == "macos",
          try string(value, "target_arch", error: .templateInvalid) == "arm64" else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let commandDigest = try digest(value, "command_template_sha256", error: .templateInvalid)
    guard commandDigest == sha256(Data("whoathere.npm_local_tarball_install.fixed_argv.v1".utf8)) else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let nodeVersion = try string(value, "node_version", error: .templateInvalid)
    let npmVersion = try string(value, "npm_version", error: .templateInvalid)
    let nodeDigest = try digest(value, "node_executable_sha256", error: .templateInvalid)
    let npmDigest = try digest(value, "npm_cli_sha256", error: .templateInvalid)
    let profile: [String: Any] = [
        "schema_version": "whoathere.npm_runtime_profile.v1",
        "profile_id": try string(value, "profile_id", error: .templateInvalid),
        "target_os": "macos",
        "target_arch": "arm64",
        "node_version": nodeVersion,
        "node_executable_sha256": nodeDigest,
        "npm_version": npmVersion,
        "npm_cli_sha256": npmDigest,
        "command_template_sha256": commandDigest
    ]
    let expectedProfileSHA256 = sha256(try canonicalJSONData(profile))
    let observedProfileSHA256 = try digest(value, "profile_sha256", error: .templateInvalid)
    guard expectedProfileSHA256 == observedProfileSHA256 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    return RuntimeFields(
        nodeVersion: nodeVersion,
        nodeSHA256: nodeDigest,
        npmVersion: npmVersion,
        npmSHA256: npmDigest
    )
}

private func validateClosure(_ value: [String: Any], manifestSHA256: String) throws {
    try requireExactKeys(value, ["declaration_set_sha256", "kind"], error: .templateInvalid)
    guard try string(value, "kind", error: .templateInvalid) == "empty" else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let closure: [String: Any] = [
        "schema_version": "whoathere.empty_dependency_closure.v1",
        "manifest_sha256": manifestSHA256,
        "dependency_declarations": []
    ]
    let expectedClosureSHA256 = sha256(try canonicalJSONData(closure))
    let observedClosureSHA256 = try digest(
        value,
        "declaration_set_sha256",
        error: .templateInvalid
    )
    guard expectedClosureSHA256 == observedClosureSHA256 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
}

private func validateScenario(_ value: [String: Any]) throws -> String {
    try requireExactKeys(value, ["environment", "kind"], error: .templateInvalid)
    let environment = try string(value, "environment", error: .templateInvalid)
    guard try string(value, "kind", error: .templateInvalid) == "npm_local_tarball_install",
          ["ci_false", "ci_true"].contains(environment) else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    return environment
}

private func validateHooks(_ values: [Any]) throws {
    let order = ["preinstall": 0, "install": 1, "postinstall": 2]
    var previous = -1
    for raw in values {
        guard let value = raw as? [String: Any] else {
            throw ArtifactRunProtocolError.templateInvalid
        }
        try requireExactKeys(value, ["command_sha256", "hook"], error: .templateInvalid)
        let hook = try string(value, "hook", error: .templateInvalid)
        guard let rank = order[hook], rank > previous else {
            throw ArtifactRunProtocolError.templateInvalid
        }
        _ = try digest(value, "command_sha256", error: .templateInvalid)
        previous = rank
    }
}

private func validateLimits(_ value: [String: Any]) throws {
    let keys = [
        "max_artifact_bytes", "max_observed_file_events", "max_open_files", "max_processes",
        "max_stderr_bytes", "max_stdout_bytes", "wall_clock_millis"
    ]
    try requireExactKeys(value, keys, error: .templateInvalid)
    for key in keys {
        guard try integer(value, key, error: .templateInvalid) > 0 else {
            throw ArtifactRunProtocolError.templateInvalid
        }
    }
    guard try integer(value, "max_artifact_bytes", error: .templateInvalid)
            <= maximumArtifactSubmissionBytesV1 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
}

private func validateBackend(
    _ backend: [String: Any],
    template: ValidatedTemplate
) throws -> ArtifactRunBackendIdentity {
    try requireExactKeys(backend, [
        "base_auxiliary_storage_sha256", "base_disk_sha256", "base_generation_id",
        "clone_implementation_sha256", "cpu_count", "guest_auth_public_key_sha256",
        "guest_protocol_sha256", "guest_supervisor_sha256", "hardware_model_sha256", "helper_sha256",
        "machine_identifier_sha256", "memory_mib", "node_executable_sha256", "node_version",
        "npm_cli_sha256", "npm_version", "package_gid", "package_uid",
        "post_provisioning_receipt_sha256", "runner_configuration_sha256"
    ], error: .runSpecInvalid)
    let baseGenerationID = try string(backend, "base_generation_id", error: .runSpecInvalid)
    let cpuCount = try integer(backend, "cpu_count", error: .runSpecInvalid)
    let memoryMiB = try integer(backend, "memory_mib", error: .runSpecInvalid)
    let packageUID = try integer(backend, "package_uid", error: .runSpecInvalid)
    let packageGID = try integer(backend, "package_gid", error: .runSpecInvalid)
    let nodeVersion = try string(backend, "node_version", error: .runSpecInvalid)
    let nodeSHA256 = try digest(backend, "node_executable_sha256", error: .runSpecInvalid)
    let npmVersion = try string(backend, "npm_version", error: .runSpecInvalid)
    let npmSHA256 = try digest(backend, "npm_cli_sha256", error: .runSpecInvalid)
    let guestProtocolSHA256 = try digest(backend, "guest_protocol_sha256", error: .runSpecInvalid)
    guard validIdentity(baseGenerationID),
          cpuCount > 0, cpuCount <= UInt16.max,
          memoryMiB >= 1_024, memoryMiB <= 1_048_576,
          packageUID > 0, packageUID <= UInt32.max,
          packageGID > 0, packageGID <= UInt32.max,
          nodeVersion == template.nodeVersion,
          nodeSHA256 == template.nodeSHA256,
          npmVersion == template.npmVersion,
          npmSHA256 == template.npmSHA256,
          guestProtocolSHA256
            == sha256(Data("whoathere.artifact_scenario.v1".utf8)) else {
        throw ArtifactRunProtocolError.runSpecInvalid
    }
    return ArtifactRunBackendIdentity(
        baseGenerationID: baseGenerationID,
        baseDiskSHA256: try digest(backend, "base_disk_sha256", error: .runSpecInvalid),
        baseAuxiliaryStorageSHA256: try digest(
            backend, "base_auxiliary_storage_sha256", error: .runSpecInvalid
        ),
        hardwareModelSHA256: try digest(backend, "hardware_model_sha256", error: .runSpecInvalid),
        machineIdentifierSHA256: try digest(
            backend, "machine_identifier_sha256", error: .runSpecInvalid
        ),
        cpuCount: UInt16(cpuCount),
        memoryMiB: memoryMiB,
        postProvisioningReceiptSHA256: try digest(
            backend, "post_provisioning_receipt_sha256", error: .runSpecInvalid
        ),
        helperSHA256: try digest(backend, "helper_sha256", error: .runSpecInvalid),
        guestSupervisorSHA256: try digest(
            backend, "guest_supervisor_sha256", error: .runSpecInvalid
        ),
        guestAuthPublicKeySHA256: try digest(
            backend, "guest_auth_public_key_sha256", error: .runSpecInvalid
        ),
        runnerConfigurationSHA256: try digest(
            backend, "runner_configuration_sha256", error: .runSpecInvalid
        ),
        packageUID: UInt32(packageUID),
        packageGID: UInt32(packageGID),
        nodeVersion: nodeVersion,
        nodeExecutableSHA256: nodeSHA256,
        npmVersion: npmVersion,
        npmCLISHA256: npmSHA256,
        cloneImplementationSHA256: try digest(
            backend, "clone_implementation_sha256", error: .runSpecInvalid
        ),
        guestProtocolSHA256: guestProtocolSHA256
    )
}

private func readExactly(_ handle: FileHandle, count: Int) throws -> Data {
    var result = Data()
    result.reserveCapacity(count)
    do {
        while result.count < count {
            let requested = min(64 * 1024, count - result.count)
            guard let chunk = try handle.read(upToCount: requested), !chunk.isEmpty else {
                throw ArtifactRunProtocolError.truncated
            }
            result.append(chunk)
        }
    } catch let error as ArtifactRunProtocolError {
        throw error
    } catch {
        throw ArtifactRunProtocolError.inputReadFailed
    }
    return result
}

private func uint16(_ data: Data, at offset: Int) -> UInt16 {
    data[offset..<offset + 2].reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
}

private func uint32(_ data: Data, at offset: Int) -> UInt32 {
    data[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
}

private func uint64(_ data: Data, at offset: Int) -> UInt64 {
    data[offset..<offset + 8].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
}

private func requireExactKeys(
    _ object: [String: Any],
    _ keys: [String],
    error: ArtifactRunProtocolError
) throws {
    guard Set(object.keys) == Set(keys) else {
        throw error
    }
}

private func string(
    _ object: [String: Any],
    _ key: String,
    error: ArtifactRunProtocolError
) throws -> String {
    guard let value = object[key] as? String else {
        throw error
    }
    return value
}

private func integer(
    _ object: [String: Any],
    _ key: String,
    error: ArtifactRunProtocolError
) throws -> UInt64 {
    guard let number = object[key] as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID(),
          !CFNumberIsFloatType(number),
          number.int64Value >= 0 else {
        throw error
    }
    return number.uint64Value
}

private func digest(
    _ object: [String: Any],
    _ key: String,
    error: ArtifactRunProtocolError
) throws -> String {
    let value = try string(object, key, error: error)
    guard validDigest(value) else {
        throw error
    }
    return value
}

private func validDigest(_ value: String) -> Bool {
    guard value.utf8.count == 71, value.hasPrefix("sha256:") else {
        return false
    }
    return value.dropFirst(7).utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }
}

private func rawDigest(_ value: String) throws -> Data {
    guard validDigest(value) else {
        throw ArtifactRunProtocolError.headerInvalid
    }
    let hex = value.dropFirst(7)
    var result = Data()
    result.reserveCapacity(32)
    var index = hex.startIndex
    for _ in 0..<32 {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<next], radix: 16) else {
            throw ArtifactRunProtocolError.headerInvalid
        }
        result.append(byte)
        index = next
    }
    return result
}

private func validIdentity(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 128, value.unicodeScalars.allSatisfy({ $0.isASCII }) else {
        return false
    }
    return value.utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
            || [46, 95, 45, 58, 64].contains(byte)
    }
}

func sha256(_ data: Data) -> String {
    "sha256:" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func canonicalJSONData(_ value: Any) throws -> Data {
    var output = ""
    try appendCanonicalJSON(value, to: &output)
    guard let data = output.data(using: .utf8) else {
        throw ArtifactRunProtocolError.headerInvalid
    }
    return data
}

private func appendCanonicalJSON(_ value: Any, to output: inout String) throws {
    switch value {
    case let object as [String: Any]:
        output.append("{")
        for (index, key) in object.keys.sorted().enumerated() {
            if index > 0 { output.append(",") }
            appendJSONString(key, to: &output)
            output.append(":")
            guard let nested = object[key] else {
                throw ArtifactRunProtocolError.headerInvalid
            }
            try appendCanonicalJSON(nested, to: &output)
        }
        output.append("}")
    case let array as [Any]:
        output.append("[")
        for (index, nested) in array.enumerated() {
            if index > 0 { output.append(",") }
            try appendCanonicalJSON(nested, to: &output)
        }
        output.append("]")
    case let text as String:
        appendJSONString(text, to: &output)
    case is NSNull:
        output.append("null")
    case let number as NSNumber:
        if CFGetTypeID(number) == CFBooleanGetTypeID() {
            output.append(number.boolValue ? "true" : "false")
        } else {
            guard !CFNumberIsFloatType(number), number.int64Value >= 0 else {
                throw ArtifactRunProtocolError.headerInvalid
            }
            output.append(String(number.uint64Value))
        }
    default:
        throw ArtifactRunProtocolError.headerInvalid
    }
}

private func appendJSONString(_ value: String, to output: inout String) {
    output.append("\"")
    for scalar in value.unicodeScalars {
        switch scalar.value {
        case 0x08: output.append("\\b")
        case 0x09: output.append("\\t")
        case 0x0a: output.append("\\n")
        case 0x0c: output.append("\\f")
        case 0x0d: output.append("\\r")
        case 0x22: output.append("\\\"")
        case 0x5c: output.append("\\\\")
        case 0x00...0x1f: output.append(String(format: "\\u%04x", scalar.value))
        default: output.unicodeScalars.append(scalar)
        }
    }
    output.append("\"")
}
