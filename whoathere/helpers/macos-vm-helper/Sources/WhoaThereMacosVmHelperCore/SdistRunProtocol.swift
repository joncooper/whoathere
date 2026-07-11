import CoreFoundation
import CryptoKit
import Darwin
import Foundation

public let sdistSubmissionMagicV1 = Data("WHOASDI1".utf8)
public let sdistSubmissionVersionV1: UInt16 = 1
public let sdistSubmissionFrameTypeV1: UInt16 = 1
public let sdistSubmissionPrefixBytesV1 = 56
public let maximumSdistSubmissionHeaderBytesV1 = 576 * 1024
public let maximumSdistSubmissionBytesV1: UInt64 = 64 * 1024 * 1024

public struct SdistRunBackendIdentity: Equatable, Sendable {
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

public struct SdistRunSubmissionPrelude: Equatable, Sendable {
    public let runSpecSHA256: String
    public let templateSHA256: String
    public let buildClosureSHA256: String
    public let buildClosure: SdistBuildClosureManifest
    public let challengeBindingSHA256: String
    public let executionBindingSHA256: String
    public let artifactSHA256: String
    public let artifactByteLength: UInt64
    public let headerByteLength: UInt32
    public let scenarioID: String
    public let scenarioKind: String
    public let backendIdentity: SdistRunBackendIdentity
}

public struct SdistBuildClosureArtifact: Comparable, Equatable, Sendable {
    public let normalizedName: String
    public let version: String
    public let artifactFilename: String
    public let artifactFormat: String
    public let artifactSHA256: String
    public let artifactByteLength: UInt64

    public static func < (lhs: Self, rhs: Self) -> Bool {
        if lhs.normalizedName != rhs.normalizedName {
            return lhs.normalizedName < rhs.normalizedName
        }
        if lhs.version != rhs.version { return lhs.version < rhs.version }
        if lhs.artifactFilename != rhs.artifactFilename {
            return lhs.artifactFilename < rhs.artifactFilename
        }
        if lhs.artifactFormat != rhs.artifactFormat {
            return lhs.artifactFormat < rhs.artifactFormat
        }
        if lhs.artifactSHA256 != rhs.artifactSHA256 {
            return lhs.artifactSHA256 < rhs.artifactSHA256
        }
        return lhs.artifactByteLength < rhs.artifactByteLength
    }
}

public struct SdistBuildClosureManifest: Equatable, Sendable {
    public let declarationSetSHA256: String
    public let closureSHA256: String
    public let artifacts: [SdistBuildClosureArtifact]
    public let canonicalJSON: Data

    public var payloadByteLength: UInt64 {
        artifacts.reduce(UInt64(0)) { $0 + $1.artifactByteLength }
    }
}

public struct SdistRunTransportObservation: Equatable, Sendable {
    public let runSpecSHA256: String
    public let templateSHA256: String
    public let buildClosureSHA256: String
    public let challengeBindingSHA256: String
    public let executionBindingSHA256: String
    public let artifactSHA256: String
    public let artifactByteLength: UInt64
    public let headerByteLength: UInt32
    public let scenarioID: String
    public let scenarioKind: String
    public let backendIdentity: SdistRunBackendIdentity
}

/// Holds an already-validated sdist header while leaving the exact artifact body unread.
/// Callers can therefore burn launch authority before accepting any package-controlled bytes.
public final class SdistRunSubmissionReader {
    public let prelude: SdistRunSubmissionPrelude

    private let handle: FileHandle
    private let cancellation: SdistRunCancellationState?
    let expectedArtifactDigest: Data
    let canonicalHeaderData: Data
    private var consumed = false

    fileprivate init(
        handle: FileHandle,
        cancellation: SdistRunCancellationState?,
        expectedArtifactDigest: Data,
        canonicalHeaderData: Data,
        prelude: SdistRunSubmissionPrelude
    ) {
        self.handle = handle
        self.cancellation = cancellation
        self.expectedArtifactDigest = expectedArtifactDigest
        self.canonicalHeaderData = canonicalHeaderData
        self.prelude = prelude
    }

    public func consumeArtifact(
        chunkSink: (Data) throws -> Void = { _ in }
    ) throws -> SdistRunTransportObservation {
        guard !consumed else {
            throw ArtifactRunProtocolError.trailingData
        }
        consumed = true
        var remaining = prelude.artifactByteLength
        var hasher = SHA256()
        while remaining > 0 {
            let requested = Int(min(remaining, 64 * 1024))
            let chunk = try sdistReadExactly(
                handle,
                count: requested,
                cancellation: cancellation
            )
            hasher.update(data: chunk)
            try chunkSink(chunk)
            remaining -= UInt64(chunk.count)
        }
        guard Data(hasher.finalize()) == expectedArtifactDigest else {
            throw ArtifactRunProtocolError.artifactDigestMismatch
        }
        do {
            try sdistWaitUntilReadable(handle, cancellation: cancellation)
            if let trailing = try handle.read(upToCount: 1), !trailing.isEmpty {
                throw ArtifactRunProtocolError.trailingData
            }
        } catch let error as ArtifactRunProtocolError {
            throw error
        } catch {
            try cancellation?.throwIfRequested()
            throw ArtifactRunProtocolError.inputReadFailed
        }
        return SdistRunTransportObservation(
            runSpecSHA256: prelude.runSpecSHA256,
            templateSHA256: prelude.templateSHA256,
            buildClosureSHA256: prelude.buildClosureSHA256,
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

public func inspectSdistSubmission(
    from handle: FileHandle,
    expectedChallengeBindingSHA256: String? = nil
) throws -> SdistRunTransportObservation {
    try beginSdistSubmission(
        from: handle,
        expectedChallengeBindingSHA256: expectedChallengeBindingSHA256
    ).consumeArtifact()
}

public func beginSdistSubmission(
    from handle: FileHandle,
    expectedChallengeBindingSHA256: String? = nil,
    cancellation: SdistRunCancellationState? = nil
) throws -> SdistRunSubmissionReader {
    let prefix = try sdistReadExactly(
        handle,
        count: sdistSubmissionPrefixBytesV1,
        cancellation: cancellation
    )
    guard prefix.prefix(8) == sdistSubmissionMagicV1 else {
        throw ArtifactRunProtocolError.invalidMagic
    }
    guard sdistUInt16(prefix, at: 8) == sdistSubmissionVersionV1 else {
        throw ArtifactRunProtocolError.unsupportedVersion
    }
    guard sdistUInt16(prefix, at: 10) == sdistSubmissionFrameTypeV1 else {
        throw ArtifactRunProtocolError.unsupportedFrameType
    }
    let headerLength = sdistUInt32(prefix, at: 12)
    guard headerLength > 0, headerLength <= maximumSdistSubmissionHeaderBytesV1 else {
        throw ArtifactRunProtocolError.headerLimitExceeded
    }
    let artifactLength = sdistUInt64(prefix, at: 16)
    guard artifactLength > 0, artifactLength <= maximumSdistSubmissionBytesV1 else {
        throw ArtifactRunProtocolError.artifactLimitExceeded
    }
    let prefixDigest = Data(prefix[24..<56])
    let headerData = try sdistReadExactly(
        handle,
        count: Int(headerLength),
        cancellation: cancellation
    )
    let validated = try validateSdistHeader(
        headerData,
        prefixArtifactLength: artifactLength,
        prefixArtifactDigest: prefixDigest,
        expectedChallengeBindingSHA256: expectedChallengeBindingSHA256
    )
    let prelude = SdistRunSubmissionPrelude(
        runSpecSHA256: validated.runSpecSHA256,
        templateSHA256: validated.templateSHA256,
        buildClosureSHA256: validated.buildClosureSHA256,
        buildClosure: validated.buildClosure,
        challengeBindingSHA256: validated.challengeBindingSHA256,
        executionBindingSHA256: validated.executionBindingSHA256,
        artifactSHA256: validated.artifactSHA256,
        artifactByteLength: artifactLength,
        headerByteLength: headerLength,
        scenarioID: validated.scenarioID,
        scenarioKind: validated.scenarioKind,
        backendIdentity: validated.backendIdentity
    )
    return SdistRunSubmissionReader(
        handle: handle,
        cancellation: cancellation,
        expectedArtifactDigest: prefixDigest,
        canonicalHeaderData: headerData,
        prelude: prelude
    )
}

private struct ValidatedSdistHeader {
    let runSpecSHA256: String
    let templateSHA256: String
    let buildClosureSHA256: String
    let buildClosure: SdistBuildClosureManifest
    let challengeBindingSHA256: String
    let executionBindingSHA256: String
    let artifactSHA256: String
    let scenarioID: String
    let scenarioKind: String
    let backendIdentity: SdistRunBackendIdentity
}

private func validateSdistHeader(
    _ data: Data,
    prefixArtifactLength: UInt64,
    prefixArtifactDigest: Data,
    expectedChallengeBindingSHA256: String?
) throws -> ValidatedSdistHeader {
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
    try sdistRequireExactKeys(header, [
        "artifact_byte_length", "artifact_sha256", "artifact_transport_ceiling",
        "build_closure_sha256", "challenge_binding_sha256", "execution_binding_sha256",
        "run_spec", "run_spec_sha256", "schema_version"
    ], error: .headerInvalid)
    guard try sdistString(header, "schema_version", error: .headerInvalid)
            == "whoathere.macos_sdist_submission_header.v1",
          try sdistInteger(header, "artifact_byte_length", error: .headerInvalid)
            == prefixArtifactLength,
          try sdistInteger(header, "artifact_transport_ceiling", error: .headerInvalid)
            == maximumSdistSubmissionBytesV1 else {
        throw ArtifactRunProtocolError.headerInvalid
    }
    let artifactSHA256 = try sdistDigest(header, "artifact_sha256", error: .headerInvalid)
    guard try sdistRawDigest(artifactSHA256) == prefixArtifactDigest else {
        throw ArtifactRunProtocolError.artifactDigestMismatch
    }
    let challenge = try sdistDigest(header, "challenge_binding_sha256", error: .headerInvalid)
    if let expectedChallengeBindingSHA256 {
        guard sdistValidDigest(expectedChallengeBindingSHA256),
              challenge == expectedChallengeBindingSHA256 else {
            throw ArtifactRunProtocolError.bindingMismatch
        }
    }
    let execution = try sdistDigest(header, "execution_binding_sha256", error: .headerInvalid)
    let runSpecSHA256 = try sdistDigest(header, "run_spec_sha256", error: .headerInvalid)
    let headerClosure = try sdistDigest(header, "build_closure_sha256", error: .headerInvalid)
    guard let runSpec = header["run_spec"] as? [String: Any] else {
        throw ArtifactRunProtocolError.runSpecInvalid
    }
    guard sha256(try canonicalJSONData(runSpec)) == runSpecSHA256 else {
        throw ArtifactRunProtocolError.runSpecInvalid
    }
    let expectedExecution = sha256(
        Data("whoathere.macos_sdist_submission_execution_binding.v1\0\(challenge)\0\(runSpecSHA256)".utf8)
    )
    guard execution == expectedExecution else {
        throw ArtifactRunProtocolError.bindingMismatch
    }
    let fields = try validateSdistRunSpec(runSpec)
    guard fields.artifactSHA256 == artifactSHA256,
          fields.artifactByteLength == prefixArtifactLength else {
        throw ArtifactRunProtocolError.artifactDigestMismatch
    }
    guard fields.buildClosureSHA256 == headerClosure else {
        throw ArtifactRunProtocolError.bindingMismatch
    }
    return ValidatedSdistHeader(
        runSpecSHA256: runSpecSHA256,
        templateSHA256: fields.templateSHA256,
        buildClosureSHA256: fields.buildClosureSHA256,
        buildClosure: fields.buildClosure,
        challengeBindingSHA256: challenge,
        executionBindingSHA256: execution,
        artifactSHA256: artifactSHA256,
        scenarioID: fields.scenarioID,
        scenarioKind: fields.scenarioKind,
        backendIdentity: fields.backendIdentity
    )
}

private struct ValidatedSdistRunSpec {
    let templateSHA256: String
    let buildClosureSHA256: String
    let buildClosure: SdistBuildClosureManifest
    let artifactSHA256: String
    let artifactByteLength: UInt64
    let scenarioID: String
    let scenarioKind: String
    let backendIdentity: SdistRunBackendIdentity
}

private func validateSdistRunSpec(_ runSpec: [String: Any]) throws -> ValidatedSdistRunSpec {
    try sdistRequireExactKeys(runSpec, [
        "backend_identity", "build_closure_sha256", "canonicalization", "clone_policy",
        "guest_protocol", "network_configuration", "reuse_policy", "schema_version",
        "template", "template_sha256"
    ], error: .runSpecInvalid)
    guard try sdistString(runSpec, "schema_version", error: .runSpecInvalid)
            == "whoathere.macos_sdist_run_spec.v1",
          try sdistString(runSpec, "canonicalization", error: .runSpecInvalid)
            == "rfc8785.jcs.v1",
          try sdistString(runSpec, "clone_policy", error: .runSpecInvalid)
            == "apfs_clone_required_no_copy_fallback",
          try sdistString(runSpec, "network_configuration", error: .runSpecInvalid)
            == "zero_network_devices",
          try sdistString(runSpec, "reuse_policy", error: .runSpecInvalid)
            == "one_boot_one_scenario_destroy_clone",
          try sdistString(runSpec, "guest_protocol", error: .runSpecInvalid)
            == "whoathere.sdist_artifact_scenario.v1",
          let template = runSpec["template"] as? [String: Any],
          let backend = runSpec["backend_identity"] as? [String: Any] else {
        throw ArtifactRunProtocolError.runSpecInvalid
    }
    let templateSHA256 = try sdistDigest(runSpec, "template_sha256", error: .runSpecInvalid)
    guard sha256(try canonicalJSONData(template)) == templateSHA256 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let runSpecClosure = try sdistDigest(
        runSpec, "build_closure_sha256", error: .runSpecInvalid
    )
    let templateFields = try validateSdistTemplate(template)
    guard runSpecClosure == templateFields.buildClosureSHA256 else {
        throw ArtifactRunProtocolError.runSpecInvalid
    }
    let backendIdentity = try validateSdistBackend(backend, template: templateFields)
    return ValidatedSdistRunSpec(
        templateSHA256: templateSHA256,
        buildClosureSHA256: runSpecClosure,
        buildClosure: templateFields.buildClosure,
        artifactSHA256: templateFields.artifactSHA256,
        artifactByteLength: templateFields.artifactByteLength,
        scenarioID: templateFields.scenarioID,
        scenarioKind: templateFields.scenarioKind,
        backendIdentity: backendIdentity
    )
}

private struct ValidatedSdistTemplate {
    let artifactSHA256: String
    let artifactByteLength: UInt64
    let scenarioID: String
    let scenarioKind: String
    let pythonVersion: String
    let pythonSHA256: String
    let pipVersion: String
    let pipSHA256: String
    let buildClosureSHA256: String
    let buildClosure: SdistBuildClosureManifest
}

private func validateSdistTemplate(_ template: [String: Any]) throws -> ValidatedSdistTemplate {
    try sdistRequireExactKeys(template, [
        "artifact_byte_length", "build_closure", "build_environment", "canonical_package_root",
        "canonicalization", "clone_disposition", "compiler_id", "derived_wheel_policy",
        "dynamic_build_requirements_policy", "identity", "interpreter_policy", "limits",
        "network_policy", "package", "package_privilege", "policy_sha256", "required_evidence",
        "resolver_policy", "runtime_profile", "scenario_kind", "schema_version", "subject",
        "target_arch", "target_os", "transport"
    ], error: .templateInvalid)
    guard try sdistString(template, "schema_version", error: .templateInvalid)
            == "whoathere.sdist_scenario_template.v1",
          try sdistString(template, "canonicalization", error: .templateInvalid)
            == "rfc8785.jcs.v1",
          try sdistString(template, "compiler_id", error: .templateInvalid)
            == "whoathere.sdist_scenario_compiler.v1",
          try sdistString(template, "build_environment", error: .templateInvalid)
            == "fresh_isolated_virtual_environment",
          try sdistString(template, "resolver_policy", error: .templateInvalid)
            == "no_index_fixed_closure_only",
          try sdistString(template, "dynamic_build_requirements_policy", error: .templateInvalid)
            == "deny_outside_fixed_closure",
          try sdistString(template, "derived_wheel_policy", error: .templateInvalid)
            == "rehash_validate_fresh_scenario_no_host_copy",
          try sdistString(template, "interpreter_policy", error: .templateInvalid)
            == "fresh_interpreter_per_probe",
          try sdistString(template, "target_os", error: .templateInvalid) == "macos",
          try sdistString(template, "target_arch", error: .templateInvalid) == "arm64",
          try sdistString(template, "transport", error: .templateInvalid)
            == "digest_checked_bounded_raw_bytes",
          try sdistString(template, "network_policy", error: .templateInvalid)
            == "no_network_device",
          try sdistString(template, "package_privilege", error: .templateInvalid)
            == "dedicated_unprivileged_uid_gid",
          try sdistString(template, "clone_disposition", error: .templateInvalid)
            == "destroy_clone",
          let identity = template["identity"] as? [String: Any],
          let subject = template["subject"] as? [String: Any],
          let package = template["package"] as? [String: Any],
          let runtime = template["runtime_profile"] as? [String: Any],
          let closure = template["build_closure"] as? [String: Any],
          let scenario = template["scenario_kind"] as? [String: Any],
          let limits = template["limits"] as? [String: Any],
          let evidence = template["required_evidence"] as? [String] else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    _ = try sdistDigest(template, "policy_sha256", error: .templateInvalid)
    try validateSdistIdentity(identity)
    let scenarioID = try sdistString(identity, "scenario_id", error: .templateInvalid)
    let artifactSHA256 = try validateSdistSubject(subject)
    try validateSdistPackage(package)
    try validateSdistPackageRoot(
        try sdistString(template, "canonical_package_root", error: .templateInvalid)
    )
    let runtimeFields = try validateSdistRuntime(runtime)
    let closureFields = try validateSdistClosure(closure)
    let scenarioKind = try validateSdistScenario(
        scenario, declarationSetSHA256: closureFields.declarationSetSHA256
    )
    try validateSdistLimits(limits)
    guard evidence == [
        "artifact_transport", "guest_artifact_rehash", "process_credentials",
        "process_lifecycle", "listener_inventory", "sensor_health", "no_network_device",
        "vm_stop", "channel_closure", "clone_destruction", "build_closure_identity",
        "derived_artifact_digest", "derived_artifact_validation", "build_environment_teardown"
    ] else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let artifactByteLength = try sdistInteger(
        template, "artifact_byte_length", error: .templateInvalid
    )
    guard artifactByteLength > 0, artifactByteLength <= maximumSdistSubmissionBytesV1 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    return ValidatedSdistTemplate(
        artifactSHA256: artifactSHA256,
        artifactByteLength: artifactByteLength,
        scenarioID: scenarioID,
        scenarioKind: scenarioKind,
        pythonVersion: runtimeFields.pythonVersion,
        pythonSHA256: runtimeFields.pythonSHA256,
        pipVersion: runtimeFields.pipVersion,
        pipSHA256: runtimeFields.pipSHA256,
        buildClosureSHA256: closureFields.closureSHA256,
        buildClosure: closureFields.manifest
    )
}

private func validateSdistIdentity(_ value: [String: Any]) throws {
    try sdistRequireExactKeys(
        value, ["evidence_id", "job_id", "run_id", "scenario_id"], error: .templateInvalid
    )
    for key in ["evidence_id", "job_id", "run_id", "scenario_id"] {
        guard sdistValidIdentity(try sdistString(value, key, error: .templateInvalid)) else {
            throw ArtifactRunProtocolError.templateInvalid
        }
    }
}

private func validateSdistSubject(_ value: [String: Any]) throws -> String {
    try sdistRequireExactKeys(
        value,
        ["artifact_sha256", "cas_object_key", "envelope_sha256", "manifest_sha256"],
        error: .templateInvalid
    )
    let artifact = try sdistDigest(value, "artifact_sha256", error: .templateInvalid)
    _ = try sdistDigest(value, "envelope_sha256", error: .templateInvalid)
    _ = try sdistDigest(value, "manifest_sha256", error: .templateInvalid)
    let expectedKey = "blobs/sha256/" + artifact.dropFirst("sha256:".count)
    guard try sdistString(value, "cas_object_key", error: .templateInvalid) == expectedKey else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    return artifact
}

private func validateSdistPackage(_ value: [String: Any]) throws {
    try sdistRequireExactKeys(
        value, ["display_name", "ecosystem", "normalized_name", "version"],
        error: .templateInvalid
    )
    guard try sdistString(value, "ecosystem", error: .templateInvalid) == "pypi" else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    for key in ["display_name", "normalized_name", "version"] {
        guard sdistValidPackageText(try sdistString(value, key, error: .templateInvalid)) else {
            throw ArtifactRunProtocolError.templateInvalid
        }
    }
}

private func validateSdistPackageRoot(_ value: String) throws {
    guard !value.isEmpty, value.utf8.count <= 256,
          value.unicodeScalars.allSatisfy({ $0.isASCII }),
          !value.contains("/"), value != ".", value != ".." else {
        throw ArtifactRunProtocolError.templateInvalid
    }
}

private struct SdistRuntimeFields {
    let pythonVersion: String
    let pythonSHA256: String
    let pipVersion: String
    let pipSHA256: String
}

private func validateSdistRuntime(_ value: [String: Any]) throws -> SdistRuntimeFields {
    try sdistRequireExactKeys(value, [
        "command_template_sha256", "pip_cli_sha256", "pip_version", "profile_id",
        "profile_sha256", "python_executable_sha256", "python_version", "target_arch",
        "target_os"
    ], error: .templateInvalid)
    guard try sdistString(value, "target_os", error: .templateInvalid) == "macos",
          try sdistString(value, "target_arch", error: .templateInvalid) == "arm64" else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let commandDigest = try sdistDigest(
        value, "command_template_sha256", error: .templateInvalid
    )
    guard commandDigest
            == sha256(Data("whoathere.python_sdist_offline_build.fixed_runner.v1".utf8)) else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let profileID = try sdistString(value, "profile_id", error: .templateInvalid)
    let pythonVersion = try sdistString(value, "python_version", error: .templateInvalid)
    let pipVersion = try sdistString(value, "pip_version", error: .templateInvalid)
    guard sdistValidIdentity(profileID), sdistValidVersion(pythonVersion),
          sdistValidVersion(pipVersion) else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let pythonDigest = try sdistDigest(
        value, "python_executable_sha256", error: .templateInvalid
    )
    let pipDigest = try sdistDigest(value, "pip_cli_sha256", error: .templateInvalid)
    let profile: [String: Any] = [
        "schema_version": "whoathere.sdist_runtime_profile.v1",
        "profile_id": profileID,
        "target_os": "macos",
        "target_arch": "arm64",
        "python_version": pythonVersion,
        "python_executable_sha256": pythonDigest,
        "pip_version": pipVersion,
        "pip_cli_sha256": pipDigest,
        "command_template_sha256": commandDigest
    ]
    let observedProfileSHA256 = try sdistDigest(
        value, "profile_sha256", error: .templateInvalid
    )
    guard sha256(try canonicalJSONData(profile)) == observedProfileSHA256 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    return SdistRuntimeFields(
        pythonVersion: pythonVersion,
        pythonSHA256: pythonDigest,
        pipVersion: pipVersion,
        pipSHA256: pipDigest
    )
}

private struct SdistClosureFields {
    let declarationSetSHA256: String
    let closureSHA256: String
    let manifest: SdistBuildClosureManifest
}

private func validateSdistClosure(_ value: [String: Any]) throws -> SdistClosureFields {
    try sdistRequireExactKeys(value, [
        "artifacts", "closure_sha256", "declaration_set_sha256", "schema_version"
    ], error: .templateInvalid)
    guard try sdistString(value, "schema_version", error: .templateInvalid)
            == "whoathere.sdist_build_closure.v1",
          let artifacts = value["artifacts"] as? [Any],
          artifacts.count <= maximumSdistBuildClosureArtifactsV1 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    let declaration = try sdistDigest(
        value, "declaration_set_sha256", error: .templateInvalid
    )
    let observedClosure = try sdistDigest(value, "closure_sha256", error: .templateInvalid)
    var previous: SdistBuildClosureArtifact?
    var validatedArtifacts: [SdistBuildClosureArtifact] = []
    var artifactFilenames = Set<String>()
    for raw in artifacts {
        guard let artifact = raw as? [String: Any] else {
            throw ArtifactRunProtocolError.templateInvalid
        }
        try sdistRequireExactKeys(artifact, [
            "artifact_byte_length", "artifact_filename", "artifact_format", "artifact_sha256",
            "normalized_name", "version"
        ], error: .templateInvalid)
        let normalizedName = try sdistString(
            artifact, "normalized_name", error: .templateInvalid
        )
        let version = try sdistString(artifact, "version", error: .templateInvalid)
        let filename = try sdistString(
            artifact, "artifact_filename", error: .templateInvalid
        )
        let format = try sdistString(artifact, "artifact_format", error: .templateInvalid)
        let digest = try sdistDigest(artifact, "artifact_sha256", error: .templateInvalid)
        let length = try sdistInteger(
            artifact, "artifact_byte_length", error: .templateInvalid
        )
        guard sdistNormalizeBuildName(normalizedName) == normalizedName,
              sdistValidVersion(version), format == "wheel",
              sdistValidClosureWheelFilename(
                  normalizedName: normalizedName,
                  version: version,
                  filename: filename
              ), artifactFilenames.insert(filename).inserted, length > 0,
              length <= maximumSdistSubmissionBytesV1 else {
            throw ArtifactRunProtocolError.templateInvalid
        }
        let item = SdistBuildClosureArtifact(
            normalizedName: normalizedName,
            version: version,
            artifactFilename: filename,
            artifactFormat: format,
            artifactSHA256: digest,
            artifactByteLength: length
        )
        if let previous, !(previous < item) {
            throw ArtifactRunProtocolError.templateInvalid
        }
        previous = item
        validatedArtifacts.append(item)
    }
    let digestWire: [String: Any] = [
        "schema_version": "whoathere.sdist_build_closure.v1",
        "declaration_set_sha256": declaration,
        "artifacts": artifacts,
        "resolver_policy": "no_index_fixed_closure_only"
    ]
    guard sha256(try canonicalJSONData(digestWire)) == observedClosure else {
        throw ArtifactRunProtocolError.templateInvalid
    }
    return SdistClosureFields(
        declarationSetSHA256: declaration,
        closureSHA256: observedClosure,
        manifest: SdistBuildClosureManifest(
            declarationSetSHA256: declaration,
            closureSHA256: observedClosure,
            artifacts: validatedArtifacts,
            canonicalJSON: try canonicalJSONData(value)
        )
    )
}

private func sdistValidClosureWheelFilename(
    normalizedName: String,
    version: String,
    filename: String
) -> Bool {
    guard !filename.isEmpty, filename.utf8.count <= 255,
          filename.unicodeScalars.allSatisfy({ $0.isASCII }),
          !filename.contains("/"), !filename.contains("\\"),
          filename.hasSuffix(".whl"),
          filename.utf8.allSatisfy({
              ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                || ($0 >= 97 && $0 <= 122) || [46, 95, 45].contains($0)
          }) else {
        return false
    }
    let distribution = normalizedName.replacingOccurrences(of: "-", with: "_")
    let prefix = "\(distribution)-\(version)-"
    guard filename.hasPrefix(prefix) else { return false }
    let tagStart = filename.index(filename.startIndex, offsetBy: prefix.count)
    let tagEnd = filename.index(filename.endIndex, offsetBy: -4)
    guard tagStart < tagEnd else { return false }
    let tags = filename[tagStart..<tagEnd].split(separator: "-", omittingEmptySubsequences: false)
    guard tags.count == 3 || tags.count == 4 else { return false }
    if tags.count == 4 {
        guard let first = tags[0].utf8.first, first >= 48, first <= 57,
              tags[0].utf8.allSatisfy({
                  ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                    || ($0 >= 97 && $0 <= 122) || $0 == 95
              }) else {
            return false
        }
    }
    return tags.suffix(3).allSatisfy { tag in
        tag.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { component in
            !component.isEmpty && component.utf8.allSatisfy {
                ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                    || ($0 >= 97 && $0 <= 122) || $0 == 95
            }
        }
    }
}

private func validateSdistScenario(
    _ value: [String: Any],
    declarationSetSHA256: String
) throws -> String {
    let kind = try sdistString(value, "kind", error: .templateInvalid)
    switch kind {
    case "build_exact_sdist":
        try sdistRequireExactKeys(value, [
            "backend_paths", "build_backend", "build_mode", "build_requires_sha256", "kind"
        ], error: .templateInvalid)
        guard let paths = value["backend_paths"] as? [String],
              paths == paths.sorted(), Set(paths).count == paths.count,
              paths.allSatisfy(sdistValidBackendPath),
              try sdistDigest(value, "build_requires_sha256", error: .templateInvalid)
                == declarationSetSHA256 else {
            throw ArtifactRunProtocolError.templateInvalid
        }
        let mode = try sdistString(value, "build_mode", error: .templateInvalid)
        if mode == "pep517" {
            guard let backend = value["build_backend"] as? String,
                  sdistValidBackendTarget(backend) else {
                throw ArtifactRunProtocolError.templateInvalid
            }
        } else if mode == "legacy_setup_py" {
            guard value["build_backend"] is NSNull, paths.isEmpty else {
                throw ArtifactRunProtocolError.templateInvalid
            }
        } else {
            throw ArtifactRunProtocolError.templateInvalid
        }
    case "inspect_derived_wheel", "install_derived_wheel":
        try sdistRequireExactKeys(value, ["kind"], error: .templateInvalid)
    case "import_root":
        try sdistRequireExactKeys(value, ["kind", "module"], error: .templateInvalid)
        guard sdistValidPythonTarget(
            try sdistString(value, "module", error: .templateInvalid)
        ) else {
            throw ArtifactRunProtocolError.templateInvalid
        }
    default:
        throw ArtifactRunProtocolError.templateInvalid
    }
    return kind
}

private func validateSdistLimits(_ value: [String: Any]) throws {
    try sdistRequireExactKeys(value, [
        "max_artifact_bytes", "max_observed_file_events", "max_open_files", "max_processes",
        "max_stderr_bytes", "max_stdout_bytes", "wall_clock_millis"
    ], error: .templateInvalid)
    let artifact = try sdistInteger(value, "max_artifact_bytes", error: .templateInvalid)
    let wall = try sdistInteger(value, "wall_clock_millis", error: .templateInvalid)
    let stdout = try sdistInteger(value, "max_stdout_bytes", error: .templateInvalid)
    let stderr = try sdistInteger(value, "max_stderr_bytes", error: .templateInvalid)
    let processes = try sdistInteger(value, "max_processes", error: .templateInvalid)
    let openFiles = try sdistInteger(value, "max_open_files", error: .templateInvalid)
    let events = try sdistInteger(value, "max_observed_file_events", error: .templateInvalid)
    guard artifact > 0, artifact <= maximumSdistSubmissionBytesV1,
          wall >= 1_000, wall <= 900_000,
          stdout > 0, stdout <= 16 * 1024 * 1024,
          stderr > 0, stderr <= 16 * 1024 * 1024,
          processes >= 1, processes <= 4_096,
          openFiles >= 16, openFiles <= 65_536,
          events > 0, events <= 1_000_000 else {
        throw ArtifactRunProtocolError.templateInvalid
    }
}

private func validateSdistBackend(
    _ backend: [String: Any],
    template: ValidatedSdistTemplate
) throws -> SdistRunBackendIdentity {
    try sdistRequireExactKeys(backend, [
        "base_auxiliary_storage_sha256", "base_disk_sha256", "base_generation_id",
        "clone_implementation_sha256", "cpu_count", "guest_auth_public_key_sha256",
        "guest_protocol_sha256", "guest_supervisor_sha256", "hardware_model_sha256",
        "helper_sha256", "machine_identifier_sha256", "memory_mib", "package_gid",
        "package_uid", "package_username", "pip_cli_sha256", "pip_version",
        "post_provisioning_receipt_sha256", "python_executable_sha256", "python_version",
        "runner_configuration_sha256"
    ], error: .runSpecInvalid)
    let baseGenerationID = try sdistString(
        backend, "base_generation_id", error: .runSpecInvalid
    )
    let cpuCount = try sdistInteger(backend, "cpu_count", error: .runSpecInvalid)
    let memoryMiB = try sdistInteger(backend, "memory_mib", error: .runSpecInvalid)
    let packageUID = try sdistInteger(backend, "package_uid", error: .runSpecInvalid)
    let packageGID = try sdistInteger(backend, "package_gid", error: .runSpecInvalid)
    let packageUsername = try sdistString(
        backend, "package_username", error: .runSpecInvalid
    )
    let pythonVersion = try sdistString(backend, "python_version", error: .runSpecInvalid)
    let pythonSHA256 = try sdistDigest(
        backend, "python_executable_sha256", error: .runSpecInvalid
    )
    let pipVersion = try sdistString(backend, "pip_version", error: .runSpecInvalid)
    let pipSHA256 = try sdistDigest(backend, "pip_cli_sha256", error: .runSpecInvalid)
    let guestProtocolSHA256 = try sdistDigest(
        backend, "guest_protocol_sha256", error: .runSpecInvalid
    )
    guard sdistValidIdentity(baseGenerationID),
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
            == sha256(Data("whoathere.sdist_artifact_scenario.v1".utf8)) else {
        throw ArtifactRunProtocolError.runSpecInvalid
    }
    return SdistRunBackendIdentity(
        baseGenerationID: baseGenerationID,
        baseDiskSHA256: try sdistDigest(backend, "base_disk_sha256", error: .runSpecInvalid),
        baseAuxiliaryStorageSHA256: try sdistDigest(
            backend, "base_auxiliary_storage_sha256", error: .runSpecInvalid
        ),
        hardwareModelSHA256: try sdistDigest(
            backend, "hardware_model_sha256", error: .runSpecInvalid
        ),
        machineIdentifierSHA256: try sdistDigest(
            backend, "machine_identifier_sha256", error: .runSpecInvalid
        ),
        cpuCount: UInt16(cpuCount),
        memoryMiB: memoryMiB,
        postProvisioningReceiptSHA256: try sdistDigest(
            backend, "post_provisioning_receipt_sha256", error: .runSpecInvalid
        ),
        helperSHA256: try sdistDigest(backend, "helper_sha256", error: .runSpecInvalid),
        guestSupervisorSHA256: try sdistDigest(
            backend, "guest_supervisor_sha256", error: .runSpecInvalid
        ),
        guestAuthPublicKeySHA256: try sdistDigest(
            backend, "guest_auth_public_key_sha256", error: .runSpecInvalid
        ),
        runnerConfigurationSHA256: try sdistDigest(
            backend, "runner_configuration_sha256", error: .runSpecInvalid
        ),
        packageUsername: packageUsername,
        packageUID: UInt32(packageUID),
        packageGID: UInt32(packageGID),
        pythonVersion: pythonVersion,
        pythonExecutableSHA256: pythonSHA256,
        pipVersion: pipVersion,
        pipCLISHA256: pipSHA256,
        cloneImplementationSHA256: try sdistDigest(
            backend, "clone_implementation_sha256", error: .runSpecInvalid
        ),
        guestProtocolSHA256: guestProtocolSHA256
    )
}

private func sdistReadExactly(
    _ handle: FileHandle,
    count: Int,
    cancellation: SdistRunCancellationState?
) throws -> Data {
    var result = Data()
    result.reserveCapacity(count)
    do {
        while result.count < count {
            try sdistWaitUntilReadable(handle, cancellation: cancellation)
            let requested = min(64 * 1024, count - result.count)
            guard let chunk = try handle.read(upToCount: requested), !chunk.isEmpty else {
                throw ArtifactRunProtocolError.truncated
            }
            result.append(chunk)
        }
    } catch let error as ArtifactRunProtocolError {
        throw error
    } catch {
        try cancellation?.throwIfRequested()
        throw ArtifactRunProtocolError.inputReadFailed
    }
    return result
}

private func sdistWaitUntilReadable(
    _ handle: FileHandle,
    cancellation: SdistRunCancellationState?
) throws {
    guard let cancellation else { return }
    let descriptor = handle.fileDescriptor
    guard descriptor >= 0 else { throw ArtifactRunProtocolError.inputReadFailed }
    while true {
        try cancellation.throwIfRequested()
        var item = pollfd(
            fd: descriptor,
            events: Int16(POLLIN | POLLHUP),
            revents: 0
        )
        let result = Darwin.poll(&item, 1, 100)
        if result > 0 {
            try cancellation.throwIfRequested()
            guard item.revents & Int16(POLLNVAL) == 0 else {
                throw ArtifactRunProtocolError.inputReadFailed
            }
            return
        }
        if result == 0 { continue }
        if errno == EINTR { continue }
        try cancellation.throwIfRequested()
        throw ArtifactRunProtocolError.inputReadFailed
    }
}

private func sdistUInt16(_ data: Data, at offset: Int) -> UInt16 {
    data[offset..<offset + 2].reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
}

private func sdistUInt32(_ data: Data, at offset: Int) -> UInt32 {
    data[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
}

private func sdistUInt64(_ data: Data, at offset: Int) -> UInt64 {
    data[offset..<offset + 8].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
}

private func sdistRequireExactKeys(
    _ object: [String: Any],
    _ keys: [String],
    error: ArtifactRunProtocolError
) throws {
    guard Set(object.keys) == Set(keys) else { throw error }
}

private func sdistString(
    _ object: [String: Any],
    _ key: String,
    error: ArtifactRunProtocolError
) throws -> String {
    guard let value = object[key] as? String else { throw error }
    return value
}

private func sdistInteger(
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

private func sdistDigest(
    _ object: [String: Any],
    _ key: String,
    error: ArtifactRunProtocolError
) throws -> String {
    let value = try sdistString(object, key, error: error)
    guard sdistValidDigest(value) else { throw error }
    return value
}

private func sdistValidDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
}

private func sdistRawDigest(_ value: String) throws -> Data {
    guard sdistValidDigest(value) else { throw ArtifactRunProtocolError.headerInvalid }
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

private func sdistValidIdentity(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 128,
          value.unicodeScalars.allSatisfy({ $0.isASCII }) else {
        return false
    }
    return value.utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
            || (byte >= 97 && byte <= 122) || [46, 95, 45, 58, 64].contains(byte)
    }
}

private func sdistValidVersion(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 64,
          value.unicodeScalars.allSatisfy({ $0.isASCII }) else {
        return false
    }
    return value.utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
            || (byte >= 97 && byte <= 122) || [46, 95, 45, 43].contains(byte)
    }
}

private func sdistValidPackageText(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 256
        && value.unicodeScalars.allSatisfy {
            $0.isASCII && $0.value >= 0x20 && $0.value != 0x7f
        }
}

private func sdistNormalizeBuildName(_ value: String) -> String? {
    guard !value.isEmpty, value.utf8.count <= 128,
          value.unicodeScalars.allSatisfy({ $0.isASCII }),
          value.utf8.allSatisfy({ byte in
              (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
                  || (byte >= 97 && byte <= 122) || [45, 95, 46].contains(byte)
          }) else {
        return nil
    }
    var output = ""
    var separator = false
    for byte in value.utf8 {
        if [45, 95, 46].contains(byte) {
            if !separator && !output.isEmpty { output.append("-") }
            separator = true
        } else {
            output.append(Character(UnicodeScalar(byte >= 65 && byte <= 90 ? byte + 32 : byte)))
            separator = false
        }
    }
    while output.hasSuffix("-") { output.removeLast() }
    return output.isEmpty ? nil : output
}

private func sdistValidPythonTarget(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 256,
          value.unicodeScalars.allSatisfy({ $0.isASCII }) else {
        return false
    }
    return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { component in
        guard let first = component.utf8.first,
              first == 95 || (first >= 65 && first <= 90)
                || (first >= 97 && first <= 122) else {
            return false
        }
        return component.utf8.allSatisfy { byte in
            byte == 95 || (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
                || (byte >= 97 && byte <= 122)
        }
    }
}

private func sdistValidBackendTarget(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 256,
          value.unicodeScalars.allSatisfy({ $0.isASCII }) else {
        return false
    }
    let pieces = value.split(separator: ":", omittingEmptySubsequences: false)
    guard pieces.count <= 2, pieces.allSatisfy({ sdistValidPythonTarget(String($0)) }) else {
        return false
    }
    return true
}

private func sdistValidBackendPath(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 512,
          value.unicodeScalars.allSatisfy({ $0.isASCII }),
          !value.hasPrefix("/"), !value.hasSuffix("/") else {
        return false
    }
    return !value.split(separator: "/", omittingEmptySubsequences: false).contains { component in
        component.isEmpty || component == "." || component == ".."
    }
}
