import CoreFoundation
import CryptoKit
import Foundation

public let wheelSubmissionMagicV1 = Data("WHOAWHE1".utf8)
public let wheelSubmissionVersionV1: UInt16 = 1
public let wheelSubmissionFrameTypeV1: UInt16 = 1
public let wheelSubmissionPrefixBytesV1 = 56
public let maximumWheelSubmissionHeaderBytesV1 = 576 * 1024
public let maximumWheelSubmissionBytesV1: UInt64 = 64 * 1024 * 1024

public struct WheelRunBackendIdentity: Equatable, Sendable {
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
    public let packageUsername: String
    public let packageUID: UInt32
    public let packageGID: UInt32
    public let pythonVersion: String
    public let pythonExecutableSHA256: String
    public let pipVersion: String
    public let pipCLISHA256: String
    public let cloneImplementationSHA256: String
    public let guestProtocolSHA256: String
}

public struct WheelRunSubmissionPrelude: Equatable, Sendable {
    public let runSpecSHA256: String
    public let templateSHA256: String
    public let challengeBindingSHA256: String
    public let executionBindingSHA256: String
    public let artifactSHA256: String
    public let artifactByteLength: UInt64
    public let headerByteLength: UInt32
    public let scenarioID: String
    public let scenarioKind: String
    public let backendIdentity: WheelRunBackendIdentity
}

public struct WheelRunTransportObservation: Equatable, Sendable {
    public let runSpecSHA256: String
    public let templateSHA256: String
    public let challengeBindingSHA256: String
    public let executionBindingSHA256: String
    public let artifactSHA256: String
    public let artifactByteLength: UInt64
    public let headerByteLength: UInt32
    public let scenarioID: String
    public let scenarioKind: String
    public let backendIdentity: WheelRunBackendIdentity
}

public final class WheelRunSubmissionReader {
    public let prelude: WheelRunSubmissionPrelude

    private let handle: FileHandle
    let expectedArtifactDigest: Data
    let canonicalHeaderData: Data
    private var consumed = false

    fileprivate init(
        handle: FileHandle,
        expectedArtifactDigest: Data,
        canonicalHeaderData: Data,
        prelude: WheelRunSubmissionPrelude
    ) {
        self.handle = handle
        self.expectedArtifactDigest = expectedArtifactDigest
        self.canonicalHeaderData = canonicalHeaderData
        self.prelude = prelude
    }

    public func consumeArtifact(
        chunkSink: (Data) throws -> Void = { _ in }
    ) throws -> WheelRunTransportObservation {
        guard !consumed else {
            throw ArtifactRunProtocolError.trailingData
        }
        consumed = true
        var remaining = prelude.artifactByteLength
        var hasher = SHA256()
        while remaining > 0 {
            let requested = Int(min(remaining, 64 * 1024))
            let chunk = try wheelReadExactly(handle, count: requested)
            hasher.update(data: chunk)
            try chunkSink(chunk)
            remaining -= UInt64(chunk.count)
        }
        guard Data(hasher.finalize()) == expectedArtifactDigest else {
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
        return WheelRunTransportObservation(
            runSpecSHA256: prelude.runSpecSHA256,
            templateSHA256: prelude.templateSHA256,
            challengeBindingSHA256: prelude.challengeBindingSHA256,
            executionBindingSHA256: prelude.executionBindingSHA256,
            artifactSHA256: prelude.artifactSHA256,
            artifactByteLength: prelude.artifactByteLength,
            headerByteLength: prelude.headerByteLength,
            scenarioID: prelude.scenarioID,
            scenarioKind: prelude.scenarioKind,
            backendIdentity: prelude.backendIdentity
        )
    }
}

public func inspectWheelSubmission(
    from handle: FileHandle,
    expectedChallengeBindingSHA256: String? = nil
) throws -> WheelRunTransportObservation {
    try beginWheelSubmission(
        from: handle,
        expectedChallengeBindingSHA256: expectedChallengeBindingSHA256
    ).consumeArtifact()
}

public func beginWheelSubmission(
    from handle: FileHandle,
    expectedChallengeBindingSHA256: String? = nil
) throws -> WheelRunSubmissionReader {
    let prefix = try wheelReadExactly(handle, count: wheelSubmissionPrefixBytesV1)
    guard prefix.prefix(8) == wheelSubmissionMagicV1 else {
        throw ArtifactRunProtocolError.invalidMagic
    }
    guard wheelUInt16(prefix, at: 8) == wheelSubmissionVersionV1 else {
        throw ArtifactRunProtocolError.unsupportedVersion
    }
    guard wheelUInt16(prefix, at: 10) == wheelSubmissionFrameTypeV1 else {
        throw ArtifactRunProtocolError.unsupportedFrameType
    }
    let headerLength = wheelUInt32(prefix, at: 12)
    guard headerLength > 0, headerLength <= maximumWheelSubmissionHeaderBytesV1 else {
        throw ArtifactRunProtocolError.headerLimitExceeded
    }
    let artifactLength = wheelUInt64(prefix, at: 16)
    guard artifactLength > 0, artifactLength <= maximumWheelSubmissionBytesV1 else {
        throw ArtifactRunProtocolError.artifactLimitExceeded
    }
    let prefixDigest = Data(prefix[24..<56])
    let headerData = try wheelReadExactly(handle, count: Int(headerLength))
    let validated = try validateWheelHeader(
        headerData,
        prefixArtifactLength: artifactLength,
        prefixArtifactDigest: prefixDigest,
        expectedChallengeBindingSHA256: expectedChallengeBindingSHA256
    )
    let prelude = WheelRunSubmissionPrelude(
        runSpecSHA256: validated.runSpecSHA256,
        templateSHA256: validated.templateSHA256,
        challengeBindingSHA256: validated.challengeBindingSHA256,
        executionBindingSHA256: validated.executionBindingSHA256,
        artifactSHA256: validated.artifactSHA256,
        artifactByteLength: artifactLength,
        headerByteLength: headerLength,
        scenarioID: validated.scenarioID,
        scenarioKind: validated.scenarioKind,
        backendIdentity: validated.backendIdentity
    )
    return WheelRunSubmissionReader(
        handle: handle,
        expectedArtifactDigest: prefixDigest,
        canonicalHeaderData: headerData,
        prelude: prelude
    )
}

private struct ValidatedWheelHeader {
    let runSpecSHA256: String
    let templateSHA256: String
    let challengeBindingSHA256: String
    let executionBindingSHA256: String
    let artifactSHA256: String
    let scenarioID: String
    let scenarioKind: String
    let backendIdentity: WheelRunBackendIdentity
}

private func validateWheelHeader(
    _ data: Data,
    prefixArtifactLength: UInt64,
    prefixArtifactDigest: Data,
    expectedChallengeBindingSHA256: String?
) throws -> ValidatedWheelHeader {
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
    try wheelRequireExactKeys(header, [
        "artifact_byte_length", "artifact_sha256", "artifact_transport_ceiling",
        "challenge_binding_sha256", "execution_binding_sha256", "run_spec",
        "run_spec_sha256", "schema_version"
    ], error: .headerInvalid)
    guard try wheelString(header, "schema_version", error: .headerInvalid)
            == "whoathere.macos_wheel_submission_header.v1",
          try wheelInteger(header, "artifact_byte_length", error: .headerInvalid)
            == prefixArtifactLength,
          try wheelInteger(header, "artifact_transport_ceiling", error: .headerInvalid)
            == maximumWheelSubmissionBytesV1 else {
        throw ArtifactRunProtocolError.headerInvalid
    }
    let artifactSHA256 = try wheelDigest(header, "artifact_sha256", error: .headerInvalid)
    guard try wheelRawDigest(artifactSHA256) == prefixArtifactDigest else {
        throw ArtifactRunProtocolError.artifactDigestMismatch
    }
    let challenge = try wheelDigest(header, "challenge_binding_sha256", error: .headerInvalid)
    if let expectedChallengeBindingSHA256 {
        guard wheelValidDigest(expectedChallengeBindingSHA256),
              challenge == expectedChallengeBindingSHA256 else {
            throw ArtifactRunProtocolError.bindingMismatch
        }
    }
    let execution = try wheelDigest(header, "execution_binding_sha256", error: .headerInvalid)
    let runSpecSHA256 = try wheelDigest(header, "run_spec_sha256", error: .headerInvalid)
    guard let runSpec = header["run_spec"] as? [String: Any] else {
        throw ArtifactRunProtocolError.runSpecInvalid
    }
    guard sha256(try canonicalJSONData(runSpec)) == runSpecSHA256 else {
        throw ArtifactRunProtocolError.runSpecInvalid
    }
    let expectedExecution = sha256(
        Data("whoathere.macos_wheel_submission_execution_binding.v1\0\(challenge)\0\(runSpecSHA256)".utf8)
    )
    guard execution == expectedExecution else {
        throw ArtifactRunProtocolError.bindingMismatch
    }
    let fields = try validateWheelRunSpec(runSpec)
    guard fields.artifactSHA256 == artifactSHA256,
          fields.artifactByteLength == prefixArtifactLength else {
        throw ArtifactRunProtocolError.artifactDigestMismatch
    }
    return ValidatedWheelHeader(
        runSpecSHA256: runSpecSHA256,
        templateSHA256: fields.templateSHA256,
        challengeBindingSHA256: challenge,
        executionBindingSHA256: execution,
        artifactSHA256: artifactSHA256,
        scenarioID: fields.scenarioID,
        scenarioKind: fields.scenarioKind,
        backendIdentity: fields.backendIdentity
    )
}

private struct ValidatedWheelRunSpec {
    let templateSHA256: String
    let artifactSHA256: String
    let artifactByteLength: UInt64
    let scenarioID: String
    let scenarioKind: String
    let backendIdentity: WheelRunBackendIdentity
}

private func validateWheelRunSpec(_ runSpec: [String: Any]) throws -> ValidatedWheelRunSpec {
    try wheelRequireExactKeys(runSpec, [
        "backend_identity", "canonicalization", "clone_policy", "guest_protocol",
        "network_configuration", "reuse_policy", "schema_version", "template",
        "template_sha256"
    ], error: .runSpecInvalid)
    guard try wheelString(runSpec, "schema_version", error: .runSpecInvalid)
            == "whoathere.macos_wheel_run_spec.v1",
          try wheelString(runSpec, "canonicalization", error: .runSpecInvalid) == "rfc8785.jcs.v1",
          try wheelString(runSpec, "clone_policy", error: .runSpecInvalid)
            == "apfs_clone_required_no_copy_fallback",
          try wheelString(runSpec, "network_configuration", error: .runSpecInvalid)
            == "zero_network_devices",
          try wheelString(runSpec, "reuse_policy", error: .runSpecInvalid)
            == "one_boot_one_scenario_destroy_clone",
          try wheelString(runSpec, "guest_protocol", error: .runSpecInvalid)
            == "whoathere.wheel_artifact_scenario.v1",
          let template = runSpec["template"] as? [String: Any],
          let backend = runSpec["backend_identity"] as? [String: Any] else {
        throw ArtifactRunProtocolError.runSpecInvalid
    }
    let templateSHA256 = try wheelDigest(runSpec, "template_sha256", error: .runSpecInvalid)
    guard sha256(try canonicalJSONData(template)) == templateSHA256 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let templateFields = try validateWheelTemplate(template)
    let backendIdentity = try validateWheelBackend(backend, template: templateFields)
    return ValidatedWheelRunSpec(
        templateSHA256: templateSHA256,
        artifactSHA256: templateFields.artifactSHA256,
        artifactByteLength: templateFields.artifactByteLength,
        scenarioID: templateFields.scenarioID,
        scenarioKind: templateFields.scenarioKind,
        backendIdentity: backendIdentity
    )
}

private struct ValidatedWheelTemplate {
    let artifactSHA256: String
    let manifestSHA256: String
    let artifactByteLength: UInt64
    let scenarioID: String
    let scenarioKind: String
    let pythonVersion: String
    let pythonSHA256: String
    let pipVersion: String
    let pipSHA256: String
}

private func validateWheelTemplate(_ template: [String: Any]) throws -> ValidatedWheelTemplate {
    try wheelRequireExactKeys(template, [
        "artifact_byte_length", "canonicalization", "clone_disposition", "compiler_id",
        "dependency_closure", "identity", "install_environment", "interpreter_policy",
        "limits", "network_policy", "package", "package_privilege", "policy_sha256",
        "required_evidence", "resolver_policy", "runtime_profile", "scenario_kind",
        "schema_version", "subject", "target_arch", "target_os", "transport"
    ], error: .templateInvalid)
    guard try wheelString(template, "schema_version", error: .templateInvalid)
            == "whoathere.wheel_scenario_template.v1",
          try wheelString(template, "canonicalization", error: .templateInvalid) == "rfc8785.jcs.v1",
          try wheelString(template, "compiler_id", error: .templateInvalid)
            == "whoathere.dependency_free_wheel_scenario_compiler.v1",
          try wheelString(template, "install_environment", error: .templateInvalid)
            == "fresh_virtual_environment",
          try wheelString(template, "resolver_policy", error: .templateInvalid)
            == "no_index_no_dependencies",
          try wheelString(template, "interpreter_policy", error: .templateInvalid)
            == "fresh_interpreter_per_probe",
          try wheelString(template, "target_os", error: .templateInvalid) == "macos",
          try wheelString(template, "target_arch", error: .templateInvalid) == "arm64",
          try wheelString(template, "transport", error: .templateInvalid)
            == "digest_checked_bounded_raw_bytes",
          try wheelString(template, "network_policy", error: .templateInvalid) == "no_network_device",
          try wheelString(template, "package_privilege", error: .templateInvalid)
            == "dedicated_unprivileged_uid_gid",
          try wheelString(template, "clone_disposition", error: .templateInvalid) == "destroy_clone",
          let identity = template["identity"] as? [String: Any],
          let subject = template["subject"] as? [String: Any],
          let package = template["package"] as? [String: Any],
          let runtime = template["runtime_profile"] as? [String: Any],
          let closure = template["dependency_closure"] as? [String: Any],
          let scenario = template["scenario_kind"] as? [String: Any],
          let limits = template["limits"] as? [String: Any],
          let evidence = template["required_evidence"] as? [String] else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    _ = try wheelDigest(template, "policy_sha256", error: .templateInvalid)
    try validateWheelIdentity(identity)
    let scenarioID = try wheelString(identity, "scenario_id", error: .templateInvalid)
    let (artifactSHA256, manifestSHA256) = try validateWheelSubject(subject)
    try validateWheelPackage(package)
    let runtimeFields = try validateWheelRuntime(runtime)
    try validateWheelClosure(closure, manifestSHA256: manifestSHA256)
    let scenarioKind = try validateWheelScenario(scenario)
    try validateWheelLimits(limits)
    guard evidence == [
        "artifact_transport", "guest_artifact_rehash", "process_credentials",
        "process_lifecycle", "listener_inventory", "sensor_health", "no_network_device",
        "vm_stop", "channel_closure", "clone_destruction"
    ] else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let artifactByteLength = try wheelInteger(
        template, "artifact_byte_length", error: .templateInvalid
    )
    guard artifactByteLength > 0, artifactByteLength <= maximumWheelSubmissionBytesV1 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    return ValidatedWheelTemplate(
        artifactSHA256: artifactSHA256,
        manifestSHA256: manifestSHA256,
        artifactByteLength: artifactByteLength,
        scenarioID: scenarioID,
        scenarioKind: scenarioKind,
        pythonVersion: runtimeFields.pythonVersion,
        pythonSHA256: runtimeFields.pythonSHA256,
        pipVersion: runtimeFields.pipVersion,
        pipSHA256: runtimeFields.pipSHA256
    )
}

private func validateWheelIdentity(_ value: [String: Any]) throws {
    try wheelRequireExactKeys(
        value, ["evidence_id", "job_id", "run_id", "scenario_id"], error: .templateInvalid
    )
    for key in ["evidence_id", "job_id", "run_id", "scenario_id"] {
        guard wheelValidIdentity(try wheelString(value, key, error: .templateInvalid)) else {
            throw ArtifactRunProtocolError.templateInvalid
        }
    }
}

private func validateWheelSubject(_ value: [String: Any]) throws -> (String, String) {
    try wheelRequireExactKeys(
        value,
        ["artifact_sha256", "cas_object_key", "envelope_sha256", "manifest_sha256"],
        error: .templateInvalid
    )
    let artifact = try wheelDigest(value, "artifact_sha256", error: .templateInvalid)
    let manifest = try wheelDigest(value, "manifest_sha256", error: .templateInvalid)
    _ = try wheelDigest(value, "envelope_sha256", error: .templateInvalid)
    let expectedKey = "blobs/sha256/" + artifact.dropFirst("sha256:".count)
    guard try wheelString(value, "cas_object_key", error: .templateInvalid) == expectedKey else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    return (artifact, manifest)
}

private func validateWheelPackage(_ value: [String: Any]) throws {
    try wheelRequireExactKeys(
        value, ["display_name", "ecosystem", "normalized_name", "version"], error: .templateInvalid
    )
    guard try wheelString(value, "ecosystem", error: .templateInvalid) == "pypi" else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    for key in ["display_name", "normalized_name", "version"] {
        let text = try wheelString(value, key, error: .templateInvalid)
        guard !text.isEmpty, text.utf8.count <= 256, text.unicodeScalars.allSatisfy({ $0.isASCII && $0.value >= 0x20 }) else {
            throw ArtifactRunProtocolError.templateInvalid
        }
    }
}

private struct WheelRuntimeFields {
    let pythonVersion: String
    let pythonSHA256: String
    let pipVersion: String
    let pipSHA256: String
}

private func validateWheelRuntime(_ value: [String: Any]) throws -> WheelRuntimeFields {
    try wheelRequireExactKeys(value, [
        "command_template_sha256", "pip_cli_sha256", "pip_version", "profile_id",
        "profile_sha256", "python_executable_sha256", "python_version", "target_arch",
        "target_os"
    ], error: .templateInvalid)
    guard try wheelString(value, "target_os", error: .templateInvalid) == "macos",
          try wheelString(value, "target_arch", error: .templateInvalid) == "arm64" else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let commandDigest = try wheelDigest(
        value, "command_template_sha256", error: .templateInvalid
    )
    guard commandDigest
            == sha256(Data("whoathere.python_wheel_offline_probe.fixed_runner.v1".utf8)) else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let pythonVersion = try wheelString(value, "python_version", error: .templateInvalid)
    let pipVersion = try wheelString(value, "pip_version", error: .templateInvalid)
    guard wheelValidVersion(pythonVersion), wheelValidVersion(pipVersion) else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let pythonDigest = try wheelDigest(
        value, "python_executable_sha256", error: .templateInvalid
    )
    let pipDigest = try wheelDigest(value, "pip_cli_sha256", error: .templateInvalid)
    let profile: [String: Any] = [
        "schema_version": "whoathere.wheel_runtime_profile.v1",
        "profile_id": try wheelString(value, "profile_id", error: .templateInvalid),
        "target_os": "macos",
        "target_arch": "arm64",
        "python_version": pythonVersion,
        "python_executable_sha256": pythonDigest,
        "pip_version": pipVersion,
        "pip_cli_sha256": pipDigest,
        "command_template_sha256": commandDigest
    ]
    let observedProfileSHA256 = try wheelDigest(
        value, "profile_sha256", error: .templateInvalid
    )
    guard sha256(try canonicalJSONData(profile)) == observedProfileSHA256 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    return WheelRuntimeFields(
        pythonVersion: pythonVersion,
        pythonSHA256: pythonDigest,
        pipVersion: pipVersion,
        pipSHA256: pipDigest
    )
}

private func validateWheelClosure(_ value: [String: Any], manifestSHA256: String) throws {
    try wheelRequireExactKeys(value, ["declaration_set_sha256", "kind"], error: .templateInvalid)
    guard try wheelString(value, "kind", error: .templateInvalid) == "empty" else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let closure: [String: Any] = [
        "schema_version": "whoathere.empty_dependency_closure.v1",
        "manifest_sha256": manifestSHA256,
        "dependency_declarations": []
    ]
    let observedClosureSHA256 = try wheelDigest(
        value, "declaration_set_sha256", error: .templateInvalid
    )
    guard sha256(try canonicalJSONData(closure)) == observedClosureSHA256 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
}

private func validateWheelScenario(_ value: [String: Any]) throws -> String {
    let kind = try wheelString(value, "kind", error: .templateInvalid)
    switch kind {
    case "install_exact_wheel":
        try wheelRequireExactKeys(value, ["kind"], error: .templateInvalid)
    case "fresh_interpreter_pth":
        try wheelRequireExactKeys(value, ["kind", "pth_file_ids"], error: .templateInvalid)
        guard let ids = value["pth_file_ids"] as? [String], !ids.isEmpty,
              ids == ids.sorted(), Set(ids).count == ids.count,
              ids.allSatisfy(wheelValidDigest) else {
            throw ArtifactRunProtocolError.templateInvalid
        }
    case "import_root":
        try wheelRequireExactKeys(value, ["kind", "module"], error: .templateInvalid)
        guard wheelValidPythonTarget(try wheelString(value, "module", error: .templateInvalid)) else {
            throw ArtifactRunProtocolError.templateInvalid
        }
    case "console_entry_point":
        try wheelRequireExactKeys(value, [
            "argument_profile", "callable", "command_name", "kind", "module", "target_sha256"
        ], error: .templateInvalid)
        let commandName = try wheelString(value, "command_name", error: .templateInvalid)
        let module = try wheelString(value, "module", error: .templateInvalid)
        let callable = try wheelString(value, "callable", error: .templateInvalid)
        guard wheelValidConsoleName(commandName), wheelValidPythonTarget(module),
              wheelValidPythonTarget(callable),
              [
                  "installed_generated_wrapper_help",
                  "installed_generated_wrapper_no_arguments"
              ].contains(
                  try wheelString(value, "argument_profile", error: .templateInvalid)
              ),
              try wheelDigest(value, "target_sha256", error: .templateInvalid)
                == sha256(Data("\(module):\(callable)".utf8)) else {
            throw ArtifactRunProtocolError.templateInvalid
        }
    default:
        throw ArtifactRunProtocolError.templateInvalid
    }
    return kind
}

private func validateWheelLimits(_ value: [String: Any]) throws {
    let keys = [
        "max_artifact_bytes", "max_observed_file_events", "max_open_files", "max_processes",
        "max_stderr_bytes", "max_stdout_bytes", "wall_clock_millis"
    ]
    try wheelRequireExactKeys(value, keys, error: .templateInvalid)
    let artifact = try wheelInteger(value, "max_artifact_bytes", error: .templateInvalid)
    let wall = try wheelInteger(value, "wall_clock_millis", error: .templateInvalid)
    let stdout = try wheelInteger(value, "max_stdout_bytes", error: .templateInvalid)
    let stderr = try wheelInteger(value, "max_stderr_bytes", error: .templateInvalid)
    let processes = try wheelInteger(value, "max_processes", error: .templateInvalid)
    let openFiles = try wheelInteger(value, "max_open_files", error: .templateInvalid)
    let events = try wheelInteger(value, "max_observed_file_events", error: .templateInvalid)
    guard artifact > 0, artifact <= maximumWheelSubmissionBytesV1,
          wall >= 1_000, wall <= 900_000,
          stdout > 0, stdout <= 16 * 1024 * 1024,
          stderr > 0, stderr <= 16 * 1024 * 1024,
          processes >= 1, processes <= 4_096,
          openFiles >= 16, openFiles <= 65_536,
          events > 0, events <= 1_000_000 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
}

private func validateWheelBackend(
    _ backend: [String: Any],
    template: ValidatedWheelTemplate
) throws -> WheelRunBackendIdentity {
    try wheelRequireExactKeys(backend, [
        "base_auxiliary_storage_sha256", "base_disk_sha256", "base_generation_id",
        "clone_implementation_sha256", "cpu_count", "guest_auth_public_key_sha256",
        "guest_protocol_sha256", "guest_supervisor_sha256", "hardware_model_sha256", "helper_sha256",
        "machine_identifier_sha256", "memory_mib", "package_gid", "package_uid",
        "package_username", "pip_cli_sha256", "pip_version", "post_provisioning_receipt_sha256",
        "python_executable_sha256", "python_version", "runner_configuration_sha256"
    ], error: .runSpecInvalid)
    let baseGenerationID = try wheelString(backend, "base_generation_id", error: .runSpecInvalid)
    let cpuCount = try wheelInteger(backend, "cpu_count", error: .runSpecInvalid)
    let memoryMiB = try wheelInteger(backend, "memory_mib", error: .runSpecInvalid)
    let packageUID = try wheelInteger(backend, "package_uid", error: .runSpecInvalid)
    let packageGID = try wheelInteger(backend, "package_gid", error: .runSpecInvalid)
    let packageUsername = try wheelString(backend, "package_username", error: .runSpecInvalid)
    let pythonVersion = try wheelString(backend, "python_version", error: .runSpecInvalid)
    let pythonSHA256 = try wheelDigest(
        backend, "python_executable_sha256", error: .runSpecInvalid
    )
    let pipVersion = try wheelString(backend, "pip_version", error: .runSpecInvalid)
    let pipSHA256 = try wheelDigest(backend, "pip_cli_sha256", error: .runSpecInvalid)
    let guestProtocolSHA256 = try wheelDigest(
        backend, "guest_protocol_sha256", error: .runSpecInvalid
    )
    guard wheelValidIdentity(baseGenerationID),
          cpuCount > 0, cpuCount <= UInt16.max,
          memoryMiB >= 1_024, memoryMiB <= 1_048_576,
          packageUsername == "_whoatherepkg",
          packageUID > 0, packageUID <= UInt32.max,
          packageGID > 0, packageGID <= UInt32.max,
          pythonVersion == template.pythonVersion,
          pythonSHA256 == template.pythonSHA256,
          pipVersion == template.pipVersion,
          pipSHA256 == template.pipSHA256,
          guestProtocolSHA256
            == sha256(Data("whoathere.wheel_artifact_scenario.v1".utf8)) else {
        throw ArtifactRunProtocolError.runSpecInvalid
    }
    return WheelRunBackendIdentity(
        baseGenerationID: baseGenerationID,
        baseDiskSHA256: try wheelDigest(backend, "base_disk_sha256", error: .runSpecInvalid),
        baseAuxiliaryStorageSHA256: try wheelDigest(
            backend, "base_auxiliary_storage_sha256", error: .runSpecInvalid
        ),
        hardwareModelSHA256: try wheelDigest(
            backend, "hardware_model_sha256", error: .runSpecInvalid
        ),
        machineIdentifierSHA256: try wheelDigest(
            backend, "machine_identifier_sha256", error: .runSpecInvalid
        ),
        cpuCount: UInt16(cpuCount),
        memoryMiB: memoryMiB,
        postProvisioningReceiptSHA256: try wheelDigest(
            backend, "post_provisioning_receipt_sha256", error: .runSpecInvalid
        ),
        helperSHA256: try wheelDigest(backend, "helper_sha256", error: .runSpecInvalid),
        guestSupervisorSHA256: try wheelDigest(
            backend, "guest_supervisor_sha256", error: .runSpecInvalid
        ),
        guestAuthPublicKeySHA256: try wheelDigest(
            backend, "guest_auth_public_key_sha256", error: .runSpecInvalid
        ),
        runnerConfigurationSHA256: try wheelDigest(
            backend, "runner_configuration_sha256", error: .runSpecInvalid
        ),
        packageUsername: packageUsername,
        packageUID: UInt32(packageUID),
        packageGID: UInt32(packageGID),
        pythonVersion: pythonVersion,
        pythonExecutableSHA256: pythonSHA256,
        pipVersion: pipVersion,
        pipCLISHA256: pipSHA256,
        cloneImplementationSHA256: try wheelDigest(
            backend, "clone_implementation_sha256", error: .runSpecInvalid
        ),
        guestProtocolSHA256: guestProtocolSHA256
    )
}

private func wheelReadExactly(_ handle: FileHandle, count: Int) throws -> Data {
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

private func wheelUInt16(_ data: Data, at offset: Int) -> UInt16 {
    data[offset..<offset + 2].reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
}

private func wheelUInt32(_ data: Data, at offset: Int) -> UInt32 {
    data[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
}

private func wheelUInt64(_ data: Data, at offset: Int) -> UInt64 {
    data[offset..<offset + 8].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
}

private func wheelRequireExactKeys(
    _ object: [String: Any],
    _ keys: [String],
    error: ArtifactRunProtocolError
) throws {
    guard Set(object.keys) == Set(keys) else {
        throw error
    }
}

private func wheelString(
    _ object: [String: Any],
    _ key: String,
    error: ArtifactRunProtocolError
) throws -> String {
    guard let value = object[key] as? String else {
        throw error
    }
    return value
}

private func wheelInteger(
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

private func wheelDigest(
    _ object: [String: Any],
    _ key: String,
    error: ArtifactRunProtocolError
) throws -> String {
    let value = try wheelString(object, key, error: error)
    guard wheelValidDigest(value) else {
        throw error
    }
    return value
}

private func wheelValidDigest(_ value: String) -> Bool {
    guard value.utf8.count == 71, value.hasPrefix("sha256:") else {
        return false
    }
    return value.dropFirst(7).utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }
}

private func wheelRawDigest(_ value: String) throws -> Data {
    guard wheelValidDigest(value) else {
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

private func wheelValidIdentity(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 128,
          value.unicodeScalars.allSatisfy({ $0.isASCII }) else {
        return false
    }
    return value.utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
            || [46, 95, 45, 58, 64].contains(byte)
    }
}

private func wheelValidVersion(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 64,
          value.unicodeScalars.allSatisfy({ $0.isASCII }) else {
        return false
    }
    return value.utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
            || [46, 95, 45, 43].contains(byte)
    }
}

private func wheelValidPythonTarget(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 256,
          value.unicodeScalars.allSatisfy({ $0.isASCII }) else {
        return false
    }
    return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { component in
        guard let first = component.utf8.first,
              (first == 95 || (first >= 65 && first <= 90) || (first >= 97 && first <= 122)) else {
            return false
        }
        return component.utf8.allSatisfy { byte in
            byte == 95 || (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
                || (byte >= 97 && byte <= 122)
        }
    }
}

private func wheelValidConsoleName(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 128, !value.hasPrefix("-"),
          value.unicodeScalars.allSatisfy({ $0.isASCII }) else {
        return false
    }
    return value.utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
            || [46, 95, 45].contains(byte)
    }
}
