import Foundation

public let linuxVzQualifiedTelemetryBackendSchemaV1 =
    "whoathere.macos_linux_vz_qualified_telemetry_backend.v1"

public enum LinuxVzTelemetryQualificationRecordError: Error, Equatable,
    CustomStringConvertible {
    case empty
    case limitExceeded
    case invalidSchema
    case invalidBackend
    case incompleteMatrix
    case reusedIdentity
    case nonCanonical

    public var description: String {
        switch self {
        case .empty: return "linux_vz_telemetry_qualification_record_empty"
        case .limitExceeded: return "linux_vz_telemetry_qualification_record_limit_exceeded"
        case .invalidSchema: return "linux_vz_telemetry_qualification_record_schema_invalid"
        case .invalidBackend: return "linux_vz_telemetry_qualification_record_backend_invalid"
        case .incompleteMatrix: return "linux_vz_telemetry_qualification_record_matrix_incomplete"
        case .reusedIdentity: return "linux_vz_telemetry_qualification_record_identity_reused"
        case .nonCanonical: return "linux_vz_telemetry_qualification_record_noncanonical"
        }
    }
}

public struct ParsedLinuxVzTelemetryQualificationRecord: Equatable, Sendable {
    public let canonicalJSON: Data
    public let recordSHA256: String
    public let backendIdentitySHA256: String
    public let telemetryRequirementsSHA256: String
    public let conformanceEvidenceSetSHA256: String
    public let caseCount: Int

    // Parsing a record is not receipt re-verification and cannot construct authority.
    public var executionAuthorityRequestPermitted: Bool { false }
    public var packageExecutionAuthorityPermitted: Bool { false }
    public var syncBackPermitted: Bool { false }
}

public func decodeLinuxVzTelemetryQualificationRecord(
    _ data: Data
) throws -> ParsedLinuxVzTelemetryQualificationRecord {
    guard !data.isEmpty else { throw LinuxVzTelemetryQualificationRecordError.empty }
    guard data.count <= maximumLinuxVzTelemetryConformanceEvidenceBytesV1 else {
        throw LinuxVzTelemetryQualificationRecordError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzTelemetryQualificationRecordError.invalidSchema
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzTelemetryQualificationRecordError.nonCanonical
    }
    guard Set(value.keys) == Set([
        "schema_version", "qualification_state", "backend_identity",
        "backend_identity_sha256", "telemetry_requirements_sha256", "conformance_cases",
        "conformance_case_count", "conformance_evidence_set_sha256", "clone_policy",
        "execution_eligibility", "execution_authority_issued", "sync_back_policy"
    ]),
    value["schema_version"] as? String == linuxVzQualifiedTelemetryBackendSchemaV1,
    value["qualification_state"] as? String
        == "complete_inert_conformance_matrix_verified",
    value["conformance_case_count"] as? String == "38",
    value["clone_policy"] as? String == "one_unique_clone_per_case_destroyed",
    value["execution_eligibility"] as? String
        == "typed_package_scenario_authority_request_only",
    value["execution_authority_issued"] as? Bool == false,
    value["sync_back_policy"] as? String == "structurally_absent",
    let backendValue = value["backend_identity"] as? [String: Any],
    let backendSHA256 = value["backend_identity_sha256"] as? String,
    let requirementsSHA256 = value["telemetry_requirements_sha256"] as? String,
    let evidenceSetSHA256 = value["conformance_evidence_set_sha256"] as? String,
    [backendSHA256, requirementsSHA256, evidenceSetSHA256]
        .allSatisfy(linuxVzEvidenceValidDigest),
    let cases = value["conformance_cases"] as? [[String: Any]] else {
        throw LinuxVzTelemetryQualificationRecordError.invalidSchema
    }
    let backendData = try canonicalJSONData(backendValue)
    guard sha256(backendData) == backendSHA256,
          let backend = try? decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
              backendData,
              expectedTelemetryRequirementsSHA256: requirementsSHA256
          ),
          backend.identitySHA256 == backendSHA256,
          !backend.executionAuthorityPermitted else {
        throw LinuxVzTelemetryQualificationRecordError.invalidBackend
    }
    let expectedCases = linuxVzAllTelemetryConformanceCasesV1()
    guard cases.count == expectedCases.count else {
        throw LinuxVzTelemetryQualificationRecordError.incompleteMatrix
    }
    var challenges = Set<String>()
    var runSpecs = Set<String>()
    var clones = Set<String>()
    for (index, item) in cases.enumerated() {
        guard Set(item.keys) == Set([
            "fixture_case", "challenge_sha256", "run_spec_sha256", "clone_binding_sha256",
            "guest_receipt_present"
        ]),
        item["fixture_case"] as? String == expectedCases[index],
        let challenge = item["challenge_sha256"] as? String,
        let runSpec = item["run_spec_sha256"] as? String,
        let clone = item["clone_binding_sha256"] as? String,
        [challenge, runSpec, clone].allSatisfy(linuxVzEvidenceValidDigest),
        let guestPresent = item["guest_receipt_present"] as? Bool else {
            throw LinuxVzTelemetryQualificationRecordError.incompleteMatrix
        }
        let fixtureCase = expectedCases[index]
        if fixtureCase == "guest_sensor_death" && guestPresent {
            throw LinuxVzTelemetryQualificationRecordError.incompleteMatrix
        }
        if !["guest_sensor_death", "channel_interruption", "vm_stop"].contains(fixtureCase),
           !guestPresent {
            throw LinuxVzTelemetryQualificationRecordError.incompleteMatrix
        }
        guard challenges.insert(challenge).inserted,
              runSpecs.insert(runSpec).inserted,
              clones.insert(clone).inserted else {
            throw LinuxVzTelemetryQualificationRecordError.reusedIdentity
        }
    }
    guard sha256(try canonicalJSONData(cases)) == evidenceSetSHA256 else {
        throw LinuxVzTelemetryQualificationRecordError.incompleteMatrix
    }
    return ParsedLinuxVzTelemetryQualificationRecord(
        canonicalJSON: data,
        recordSHA256: sha256(data),
        backendIdentitySHA256: backendSHA256,
        telemetryRequirementsSHA256: requirementsSHA256,
        conformanceEvidenceSetSHA256: evidenceSetSHA256,
        caseCount: cases.count
    )
}
