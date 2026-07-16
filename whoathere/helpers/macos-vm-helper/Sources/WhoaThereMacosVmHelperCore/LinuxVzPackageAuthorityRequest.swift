import Foundation

public let linuxVzPackageAuthorityRequestSchemaV1 =
    "whoathere.macos_linux_vz_package_authority_request.v1"
public let maximumLinuxVzPackageAuthorityRequestBytesV1 = 64 * 1024

public enum LinuxVzPackageAuthorityRequestError: Error, Equatable,
    CustomStringConvertible {
    case empty
    case limitExceeded
    case invalidSchema
    case invalidBinding
    case nonCanonical

    public var description: String {
        switch self {
        case .empty: return "linux_vz_package_authority_request_empty"
        case .limitExceeded: return "linux_vz_package_authority_request_limit_exceeded"
        case .invalidSchema: return "linux_vz_package_authority_request_schema_invalid"
        case .invalidBinding: return "linux_vz_package_authority_request_binding_invalid"
        case .nonCanonical: return "linux_vz_package_authority_request_noncanonical"
        }
    }
}

public struct ParsedLinuxVzPackageAuthorityRequest: Equatable, Sendable {
    public let canonicalJSON: Data
    public let requestSHA256: String
    public let artifactKind: String
    public let artifactSHA256: String
    public let scenarioPlanSHA256: String
    public let scenarioTemplateSHA256: String
    public let runtimeProfileSHA256: String
    public let qualifiedTelemetryBackendSHA256: String
    public let requestChallengeSHA256: String
    public let cloneBindingSHA256: String

    public var candidateRuntimeQualificationPermitted: Bool { true }
    public var packageExecutionAuthorityPermitted: Bool { false }
    public var syncBackPermitted: Bool { false }
}

public func decodeLinuxVzPackageAuthorityRequest(
    _ data: Data
) throws -> ParsedLinuxVzPackageAuthorityRequest {
    guard !data.isEmpty else { throw LinuxVzPackageAuthorityRequestError.empty }
    guard data.count <= maximumLinuxVzPackageAuthorityRequestBytesV1 else {
        throw LinuxVzPackageAuthorityRequestError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzPackageAuthorityRequestError.invalidSchema
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzPackageAuthorityRequestError.nonCanonical
    }
    let expectedKeys = Set([
        "schema_version", "artifact_kind", "artifact_sha256", "artifact_byte_length",
        "envelope_sha256", "manifest_sha256", "scenario_plan_sha256",
        "scenario_plan_id", "scenario_template_sha256", "scenario_id", "scenario_kind",
        "scenario_kind_sha256", "scenario_policy_sha256", "dependency_closure_sha256",
        "runtime_target", "runtime_profile_sha256", "candidate_runtime_qualification_state",
        "candidate_runtime_rootfs_sha256", "candidate_runtime_rootfs_byte_length",
        "candidate_runtime_manifest_sha256", "candidate_package_runner_sha256",
        "qualified_telemetry_backend_sha256", "backend_identity_sha256",
        "telemetry_requirements_sha256", "conformance_evidence_set_sha256",
        "request_challenge_sha256", "clone_binding_sha256", "artifact_transport",
        "network_policy", "package_privilege", "clone_disposition", "execution_eligibility",
        "execution_authority_issued", "package_execution_permitted", "sync_back_policy"
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String == linuxVzPackageAuthorityRequestSchemaV1,
          let artifactKind = value["artifact_kind"] as? String,
          ["npm_tarball", "pypi_wheel", "pypi_sdist"].contains(artifactKind),
          let artifactByteLengthText = value["artifact_byte_length"] as? String,
          let artifactByteLength = linuxVzPackageAuthorityUInt64(artifactByteLengthText),
          artifactByteLength <= 64 * 1024 * 1024,
          let rootfsByteLengthText = value["candidate_runtime_rootfs_byte_length"] as? String,
          let rootfsByteLength = linuxVzPackageAuthorityUInt64(rootfsByteLengthText),
          rootfsByteLength <= 64 * 1024 * 1024 * 1024,
          let planID = value["scenario_plan_id"] as? String,
          let scenarioID = value["scenario_id"] as? String,
          linuxVzPackageAuthorityValidIdentity(planID),
          linuxVzPackageAuthorityValidIdentity(scenarioID),
          value["runtime_target"] as? String == "linux_arm64",
          value["candidate_runtime_qualification_state"] as? String
            == "candidate_exact_bytes_not_yet_independently_qualified",
          value["artifact_transport"] as? String == "digest_checked_bounded_raw_bytes",
          value["network_policy"] as? String == "no_network_device",
          value["package_privilege"] as? String == "dedicated_unprivileged_uid_gid",
          value["clone_disposition"] as? String == "destroy_clone",
          value["execution_eligibility"] as? String
            == "independent_runtime_qualification_then_one_use_execution_grant",
          value["execution_authority_issued"] as? Bool == false,
          value["package_execution_permitted"] as? Bool == false,
          value["sync_back_policy"] as? String == "structurally_absent",
          let scenarioKind = value["scenario_kind"] as? [String: Any],
          linuxVzPackageAuthorityValidScenarioKind(scenarioKind, artifactKind: artifactKind),
          let scenarioKindSHA256 = value["scenario_kind_sha256"] as? String,
          linuxVzPackageAuthorityValidDigest(scenarioKindSHA256),
          sha256(try canonicalJSONData(scenarioKind)) == scenarioKindSHA256 else {
        throw LinuxVzPackageAuthorityRequestError.invalidSchema
    }

    let digestKeys = [
        "artifact_sha256", "envelope_sha256", "manifest_sha256", "scenario_plan_sha256",
        "scenario_template_sha256", "scenario_kind_sha256", "scenario_policy_sha256",
        "dependency_closure_sha256", "runtime_profile_sha256",
        "candidate_runtime_rootfs_sha256", "candidate_runtime_manifest_sha256",
        "candidate_package_runner_sha256", "qualified_telemetry_backend_sha256",
        "backend_identity_sha256", "telemetry_requirements_sha256",
        "conformance_evidence_set_sha256", "request_challenge_sha256", "clone_binding_sha256"
    ]
    var digests: [String: String] = [:]
    for key in digestKeys {
        guard let digest = value[key] as? String,
              linuxVzPackageAuthorityValidDigest(digest) else {
            throw LinuxVzPackageAuthorityRequestError.invalidBinding
        }
        digests[key] = digest
    }
    let emptySHA256 = sha256(Data())
    let rootfsSHA256 = digests["candidate_runtime_rootfs_sha256"]!
    let manifestSHA256 = digests["candidate_runtime_manifest_sha256"]!
    let runnerSHA256 = digests["candidate_package_runner_sha256"]!
    guard ![rootfsSHA256, manifestSHA256, runnerSHA256].contains(emptySHA256),
          Set([rootfsSHA256, manifestSHA256, runnerSHA256]).count == 3,
          digests["request_challenge_sha256"] != digests["clone_binding_sha256"] else {
        throw LinuxVzPackageAuthorityRequestError.invalidBinding
    }

    return ParsedLinuxVzPackageAuthorityRequest(
        canonicalJSON: data,
        requestSHA256: sha256(data),
        artifactKind: artifactKind,
        artifactSHA256: digests["artifact_sha256"]!,
        scenarioPlanSHA256: digests["scenario_plan_sha256"]!,
        scenarioTemplateSHA256: digests["scenario_template_sha256"]!,
        runtimeProfileSHA256: digests["runtime_profile_sha256"]!,
        qualifiedTelemetryBackendSHA256: digests["qualified_telemetry_backend_sha256"]!,
        requestChallengeSHA256: digests["request_challenge_sha256"]!,
        cloneBindingSHA256: digests["clone_binding_sha256"]!
    )
}

private func linuxVzPackageAuthorityValidScenarioKind(
    _ value: [String: Any],
    artifactKind: String
) -> Bool {
    guard let kind = value["kind"] as? String else { return false }
    switch (artifactKind, kind) {
    case ("npm_tarball", "npm_local_tarball_install"):
        return Set(value.keys) == Set(["kind", "environment"])
            && ["ci_false", "ci_true"].contains(value["environment"] as? String)
    case ("pypi_wheel", "install_exact_wheel"):
        return Set(value.keys) == Set(["kind"])
    case ("pypi_wheel", "fresh_interpreter_pth"):
        guard Set(value.keys) == Set(["kind", "pth_file_ids"]),
              let identifiers = value["pth_file_ids"] as? [String], !identifiers.isEmpty,
              identifiers.allSatisfy(linuxVzPackageAuthorityValidDigest) else { return false }
        return identifiers == identifiers.sorted() && Set(identifiers).count == identifiers.count
    case ("pypi_wheel", "console_entry_point"):
        return Set(value.keys) == Set([
            "kind", "command_name", "module", "callable", "target_sha256", "argument_profile"
        ])
            && linuxVzPackageAuthorityValidText(value["command_name"] as? String)
            && linuxVzPackageAuthorityValidText(value["module"] as? String)
            && linuxVzPackageAuthorityValidText(value["callable"] as? String)
            && linuxVzPackageAuthorityValidDigest(value["target_sha256"] as? String)
            && [
                "installed_generated_wrapper_help",
                "installed_generated_wrapper_no_arguments"
            ].contains(value["argument_profile"] as? String)
    case ("pypi_sdist", "build_exact_sdist"):
        guard Set(value.keys) == Set([
            "kind", "build_mode", "build_backend", "backend_paths", "build_requires_sha256"
        ]),
        let mode = value["build_mode"] as? String,
        ["pep517", "legacy_setup_py"].contains(mode),
        let paths = value["backend_paths"] as? [String],
        paths == paths.sorted(), Set(paths).count == paths.count,
        paths.allSatisfy({ linuxVzPackageAuthorityValidText($0) }),
        linuxVzPackageAuthorityValidDigest(value["build_requires_sha256"] as? String) else {
            return false
        }
        if mode == "pep517" {
            return linuxVzPackageAuthorityValidText(value["build_backend"] as? String)
        }
        return value["build_backend"] is NSNull && paths.isEmpty
    case ("pypi_sdist", "inspect_derived_wheel"),
         ("pypi_sdist", "install_derived_wheel"):
        return Set(value.keys) == Set(["kind"])
    case ("pypi_wheel", "import_root"), ("pypi_sdist", "import_root"):
        return Set(value.keys) == Set(["kind", "module"])
            && linuxVzPackageAuthorityValidText(value["module"] as? String)
    default:
        return false
    }
}

private func linuxVzPackageAuthorityValidDigest(_ value: String?) -> Bool {
    guard let value else { return false }
    return value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
}

private func linuxVzPackageAuthorityValidIdentity(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 128 && value.utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
            || (byte >= 97 && byte <= 122) || [45, 46, 95].contains(byte)
    }
}

private func linuxVzPackageAuthorityValidText(_ value: String?) -> Bool {
    guard let value, !value.isEmpty, value.utf8.count <= 256 else { return false }
    return value.unicodeScalars.allSatisfy {
        $0.isASCII && $0.value >= 0x20 && $0.value != 0x7f
    }
}

private func linuxVzPackageAuthorityUInt64(_ value: String) -> UInt64? {
    guard !value.isEmpty, value.utf8.count <= 20,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = UInt64(value), parsed > 0 else {
        return nil
    }
    return parsed
}
