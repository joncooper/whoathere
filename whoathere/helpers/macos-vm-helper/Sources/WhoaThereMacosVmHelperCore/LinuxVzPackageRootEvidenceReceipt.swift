import CryptoKit
import Foundation

public let linuxVzPackageRootEvidenceReceiptSchemaV2 =
  "whoathere.linux_vz_package_root_evidence_receipt.v2"
public let maximumLinuxVzPackageRootEvidenceReceiptBytesV2 = 256 * 1024
public let maximumLinuxVzPackageRootEvidencePayloadBytesV2 = 16 * 1024 * 1024
public let maximumLinuxVzPackageRootEvidenceReceiptLifetimeSecondsV2: UInt64 = 10 * 60

private let linuxVzPackageRootEvidenceReceiptSignatureDomainV2 = Data(
  "whoathere.linux_vz_package_root_evidence_receipt.signature.v2\0".utf8
)

public enum LinuxVzPackageRootEvidenceReceiptError: Error, Equatable,
  CustomStringConvertible
{
  case empty
  case limitExceeded
  case invalidExpectedBinding
  case invalidReceipt
  case nonCanonical
  case publicKeyMismatch
  case signatureFailed
  case bindingMismatch
  case invalidCoverage
  case invalidTime

  public var description: String {
    switch self {
    case .empty: return "linux_vz_package_root_evidence_receipt_empty"
    case .limitExceeded: return "linux_vz_package_root_evidence_receipt_limit_exceeded"
    case .invalidExpectedBinding:
      return "linux_vz_package_root_evidence_receipt_expected_binding_invalid"
    case .invalidReceipt: return "linux_vz_package_root_evidence_receipt_invalid"
    case .nonCanonical: return "linux_vz_package_root_evidence_receipt_noncanonical"
    case .publicKeyMismatch:
      return "linux_vz_package_root_evidence_receipt_public_key_mismatch"
    case .signatureFailed:
      return "linux_vz_package_root_evidence_receipt_signature_failed"
    case .bindingMismatch:
      return "linux_vz_package_root_evidence_receipt_binding_mismatch"
    case .invalidCoverage:
      return "linux_vz_package_root_evidence_receipt_coverage_invalid"
    case .invalidTime: return "linux_vz_package_root_evidence_receipt_time_invalid"
    }
  }
}

/// Host-authoritative digest bindings. The guest cannot select the expected value for any field.
public enum LinuxVzPackageRootEvidenceDigestFieldV2: String, CaseIterable, Hashable,
  Sendable
{
  case artifactSHA256 = "artifact_sha256"
  case packageAuthorityRequestSHA256 = "package_authority_request_sha256"
  case executionGrantSHA256 = "execution_grant_sha256"
  case executionRuntimeQualificationRecordSHA256 =
    "execution_runtime_qualification_record_sha256"
  case scenarioPlanSHA256 = "scenario_plan_sha256"
  case scenarioTemplateSHA256 = "scenario_template_sha256"
  case scenarioKindSHA256 = "scenario_kind_sha256"
  case scenarioPolicySHA256 = "scenario_policy_sha256"
  case dependencyClosureSHA256 = "dependency_closure_sha256"
  case runtimeProfileSHA256 = "runtime_profile_sha256"
  case executionRuntimeRootfsSHA256 = "execution_runtime_rootfs_sha256"
  case executionRuntimeManifestSHA256 = "execution_runtime_manifest_sha256"
  case packageExecutionRunnerSHA256 = "package_execution_runner_sha256"
  case qualifiedTelemetryBackendSHA256 = "qualified_telemetry_backend_sha256"
  case requestChallengeSHA256 = "request_challenge_sha256"
  case grantChallengeSHA256 = "grant_challenge_sha256"
  case attemptBindingSHA256 = "attempt_binding_sha256"
  case cloneBindingSHA256 = "clone_binding_sha256"
  case sensorSessionChallengeSHA256 = "sensor_session_challenge_sha256"
  case guestEvidenceSignerSHA256 = "guest_evidence_signer_sha256"
  case protectedSensorBundleSHA256 = "protected_sensor_bundle_sha256"
  case sensorConfigurationSHA256 = "sensor_configuration_sha256"
  case launchContractSHA256 = "launch_contract_sha256"
  case processPlanSHA256 = "process_plan_sha256"
}

/// Host-authoritative numeric bindings. Values are encoded as canonical decimal strings on wire.
public enum LinuxVzPackageRootEvidenceNumericFieldV2: String, CaseIterable, Hashable,
  Sendable
{
  case artifactByteLength = "artifact_byte_length"
  case executionGrantIssuedAt = "execution_grant_issued_at_unix_seconds"
  case executionGrantVerifiedAt = "execution_grant_verified_at_unix_seconds"
  case executionGrantExpiresAt = "execution_grant_expires_at_unix_seconds"
  case actionIndex = "action_index"
  case cgroupID = "cgroup_id"
  case rootRunnerPID = "root_runner_pid"
  case leaderPID = "leader_pid"
  case processStartedMonotonicNanoseconds = "process_started_monotonic_nanoseconds"
  case processEndedMonotonicNanoseconds = "process_ended_monotonic_nanoseconds"
  case leaderSupervisorWaitStatus = "leader_supervisor_wait_status"
  case heartbeatCount = "heartbeat_count"
  case processSourceEventCount = "process_source_event_count"
  case processObservationCount = "process_observation_count"
  case fileEventCount = "file_event_count"
  case fileChangeCount = "file_change_count"
  case networkEventCount = "network_event_count"
  case egressEventCount = "egress_event_count"
  case egressDroppedEventCount = "egress_dropped_event_count"
  case egressDiscardedRecordCount = "egress_discarded_record_count"
}

/// Coverage is expected independently by the host and then checked for internal consistency.
public enum LinuxVzPackageRootEvidenceCoverageFieldV2: String, CaseIterable, Hashable,
  Sendable
{
  case egressPacket = "egress_packet_coverage_complete"
  case connectSendtoIntent = "connect_sendto_intent_coverage_complete"
  case guestIntent = "guest_intent_coverage_complete"
  case hostFrameCorrelation = "host_frame_correlation_complete"
  case dnsIntent = "dns_intent_coverage_complete"
  case httpObservation = "http_observation_complete"
  case compositeNetwork = "composite_network_coverage_complete"
  case fileDeclaredScope = "file_declared_scope_complete"
  case fileGlobalMount = "file_global_mount_coverage_complete"
  case evidence = "evidence_complete"
}

/// Exact host-side expectations for one already-authorized, one-attempt package action.
///
/// The three evidence payloads are supplied as exact canonical bytes so their hashes and lengths
/// are computed independently on the Mac. Counts and execution bindings must come from the host's
/// typed authority/grant/lifecycle state, not from the receipt being verified.
public struct LinuxVzPackageRootEvidenceReceiptExpectedBindingsV2: Equatable, Sendable {
  public let artifactKind: String
  public let digests: [LinuxVzPackageRootEvidenceDigestFieldV2: String]
  public let numerics: [LinuxVzPackageRootEvidenceNumericFieldV2: UInt64]
  public let cgroupName: String
  public let leaderTerminal: String
  public let leaderExitStatus: UInt8?
  public let leaderTerminationSignal: UInt8?
  public let coverage: [LinuxVzPackageRootEvidenceCoverageFieldV2: Bool]
  public let unobservedNetworkCapabilities: [String]
  public let processEvidence: Data
  public let fileEvidence: Data
  public let networkEvidence: Data

  public init(
    artifactKind: String,
    digests: [LinuxVzPackageRootEvidenceDigestFieldV2: String],
    numerics: [LinuxVzPackageRootEvidenceNumericFieldV2: UInt64],
    cgroupName: String,
    leaderTerminal: String,
    leaderExitStatus: UInt8?,
    leaderTerminationSignal: UInt8?,
    coverage: [LinuxVzPackageRootEvidenceCoverageFieldV2: Bool],
    unobservedNetworkCapabilities: [String],
    processEvidence: Data,
    fileEvidence: Data,
    networkEvidence: Data
  ) throws {
    guard ["npm_tarball", "pypi_wheel", "pypi_sdist"].contains(artifactKind),
      Set(digests.keys) == Set(LinuxVzPackageRootEvidenceDigestFieldV2.allCases),
      Set(numerics.keys) == Set(LinuxVzPackageRootEvidenceNumericFieldV2.allCases),
      Set(coverage.keys) == Set(LinuxVzPackageRootEvidenceCoverageFieldV2.allCases),
      !cgroupName.isEmpty,
      ["exited", "signaled"].contains(leaderTerminal),
      linuxVzPackageRootEvidenceTerminalIsValidV2(
        terminal: leaderTerminal,
        exitStatus: leaderExitStatus,
        terminationSignal: leaderTerminationSignal,
        waitStatus: numerics[.leaderSupervisorWaitStatus]
      ),
      digests.values.allSatisfy(linuxVzPackageRootEvidenceValidDigestV2),
      linuxVzPackageRootEvidenceCapabilitiesAreCanonicalV2(
        unobservedNetworkCapabilities
      ),
      linuxVzPackageRootEvidencePayloadIsCanonicalV2(processEvidence),
      linuxVzPackageRootEvidencePayloadIsCanonicalV2(fileEvidence),
      linuxVzPackageRootEvidencePayloadIsCanonicalV2(networkEvidence)
    else {
      throw LinuxVzPackageRootEvidenceReceiptError.invalidExpectedBinding
    }
    self.artifactKind = artifactKind
    self.digests = digests
    self.numerics = numerics
    self.cgroupName = cgroupName
    self.leaderTerminal = leaderTerminal
    self.leaderExitStatus = leaderExitStatus
    self.leaderTerminationSignal = leaderTerminationSignal
    self.coverage = coverage
    self.unobservedNetworkCapabilities = unobservedNetworkCapabilities
    self.processEvidence = processEvidence
    self.fileEvidence = fileEvidence
    self.networkEvidence = networkEvidence
  }
}

public struct VerifiedLinuxVzPackageRootEvidenceReceiptV2: Equatable, Sendable {
  public let receiptSHA256: String
  public let artifactSHA256: String
  public let packageAuthorityRequestSHA256: String
  public let executionGrantSHA256: String
  public let executionRuntimeRootfsSHA256: String
  public let executionRuntimeManifestSHA256: String
  public let packageExecutionRunnerSHA256: String
  public let cloneBindingSHA256: String
  public let sensorSessionChallengeSHA256: String
  public let guestEvidencePublicKeySHA256: String
  public let processEvidenceSHA256: String
  public let fileEvidenceSHA256: String
  public let networkEvidenceSHA256: String
  public let createdAtUnixSeconds: UInt64
  public let expiresAtUnixSeconds: UInt64
  public let evidenceComplete: Bool

  public var hostCompositionRequired: Bool { true }
  public var authoritativeVerdictPermitted: Bool { false }
  public var syncBackPermitted: Bool { false }
}

/// Independently verifies the protected guest's Rust-produced receipt using Foundation and
/// CryptoKit. It does not accept a Rust claims object or treat a valid guest signature as a final
/// verdict: host lifecycle composition is still mandatory.
public func verifyLinuxVzPackageRootEvidenceReceiptV2(
  _ receiptData: Data,
  expected: LinuxVzPackageRootEvidenceReceiptExpectedBindingsV2,
  guestVerifyingKey: Data,
  observedAtUnixSeconds: UInt64
) throws -> VerifiedLinuxVzPackageRootEvidenceReceiptV2 {
  guard !receiptData.isEmpty else { throw LinuxVzPackageRootEvidenceReceiptError.empty }
  guard receiptData.count <= maximumLinuxVzPackageRootEvidenceReceiptBytesV2 else {
    throw LinuxVzPackageRootEvidenceReceiptError.limitExceeded
  }
  guard let receipt = try? JSONSerialization.jsonObject(with: receiptData) as? [String: Any],
    Set(receipt.keys) == Set(["claims", "signature_ed25519_hex"]),
    let claims = receipt["claims"] as? [String: Any],
    Set(claims.keys) == linuxVzPackageRootEvidenceClaimKeysV2,
    let signatureHex = receipt["signature_ed25519_hex"] as? String
  else {
    throw LinuxVzPackageRootEvidenceReceiptError.invalidReceipt
  }
  guard try canonicalJSONData(receipt) == receiptData else {
    throw LinuxVzPackageRootEvidenceReceiptError.nonCanonical
  }
  let claimsData = try canonicalJSONData(claims)

  let expectedPublicKeySHA256 = sha256(guestVerifyingKey)
  guard guestVerifyingKey.count == 32,
    !guestVerifyingKey.allSatisfy({ $0 == 0 }),
    claims["guest_evidence_public_key_sha256"] as? String
      == expectedPublicKeySHA256,
    claims["key_id_sha256"] as? String == expectedPublicKeySHA256,
    let publicKey = try? Curve25519.Signing.PublicKey(
      rawRepresentation: guestVerifyingKey
    )
  else {
    throw LinuxVzPackageRootEvidenceReceiptError.publicKeyMismatch
  }
  guard
    let signature = linuxVzPackageRootEvidenceDecodeHexV2(
      signatureHex, byteCount: 64
    )
  else {
    throw LinuxVzPackageRootEvidenceReceiptError.nonCanonical
  }
  var signatureMessage = linuxVzPackageRootEvidenceReceiptSignatureDomainV2
  signatureMessage.append(claimsData)
  guard publicKey.isValidSignature(signature, for: signatureMessage) else {
    throw LinuxVzPackageRootEvidenceReceiptError.signatureFailed
  }

  guard claims["schema_version"] as? String == linuxVzPackageRootEvidenceReceiptSchemaV2,
    claims["authority"] as? String == "guest_protected_sensor",
    claims["artifact_kind"] as? String == expected.artifactKind,
    claims["cgroup_name"] as? String == expected.cgroupName,
    claims["leader_terminal"] as? String == expected.leaderTerminal
  else {
    throw LinuxVzPackageRootEvidenceReceiptError.bindingMismatch
  }
  for field in LinuxVzPackageRootEvidenceDigestFieldV2.allCases {
    guard claims[field.rawValue] as? String == expected.digests[field] else {
      throw LinuxVzPackageRootEvidenceReceiptError.bindingMismatch
    }
  }
  for field in LinuxVzPackageRootEvidenceNumericFieldV2.allCases {
    guard let value = expected.numerics[field],
      claims[field.rawValue] as? String == String(value)
    else {
      throw LinuxVzPackageRootEvidenceReceiptError.bindingMismatch
    }
  }
  for field in LinuxVzPackageRootEvidenceCoverageFieldV2.allCases {
    guard let value = expected.coverage[field],
      claims[field.rawValue] as? Bool == value
    else {
      throw LinuxVzPackageRootEvidenceReceiptError.bindingMismatch
    }
  }
  guard claims["process_evidence_sha256"] as? String == sha256(expected.processEvidence),
    claims["process_evidence_byte_length"] as? String
      == String(expected.processEvidence.count),
    claims["file_evidence_sha256"] as? String == sha256(expected.fileEvidence),
    claims["file_evidence_byte_length"] as? String
      == String(expected.fileEvidence.count),
    claims["network_evidence_sha256"] as? String == sha256(expected.networkEvidence),
    claims["network_evidence_byte_length"] as? String
      == String(expected.networkEvidence.count),
    claims["unobserved_network_capabilities"] as? [String]
      == expected.unobservedNetworkCapabilities,
    try linuxVzPackageRootEvidenceOptionalUInt8V2(
      claims["leader_exit_status"]
    ) == expected.leaderExitStatus,
    try linuxVzPackageRootEvidenceOptionalUInt8V2(
      claims["leader_termination_signal"]
    ) == expected.leaderTerminationSignal
  else {
    throw LinuxVzPackageRootEvidenceReceiptError.bindingMismatch
  }

  try linuxVzPackageRootEvidenceValidateStructureV2(
    claims,
    expected: expected,
    expectedPublicKeySHA256: expectedPublicKeySHA256,
    observedAtUnixSeconds: observedAtUnixSeconds
  )

  return VerifiedLinuxVzPackageRootEvidenceReceiptV2(
    receiptSHA256: sha256(receiptData),
    artifactSHA256: expected.digests[.artifactSHA256]!,
    packageAuthorityRequestSHA256: expected.digests[.packageAuthorityRequestSHA256]!,
    executionGrantSHA256: expected.digests[.executionGrantSHA256]!,
    executionRuntimeRootfsSHA256: expected.digests[.executionRuntimeRootfsSHA256]!,
    executionRuntimeManifestSHA256: expected.digests[.executionRuntimeManifestSHA256]!,
    packageExecutionRunnerSHA256: expected.digests[.packageExecutionRunnerSHA256]!,
    cloneBindingSHA256: expected.digests[.cloneBindingSHA256]!,
    sensorSessionChallengeSHA256: expected.digests[.sensorSessionChallengeSHA256]!,
    guestEvidencePublicKeySHA256: expectedPublicKeySHA256,
    processEvidenceSHA256: sha256(expected.processEvidence),
    fileEvidenceSHA256: sha256(expected.fileEvidence),
    networkEvidenceSHA256: sha256(expected.networkEvidence),
    createdAtUnixSeconds: try linuxVzPackageRootEvidenceUInt64V2(
      claims["created_at_unix_seconds"]
    ),
    expiresAtUnixSeconds: try linuxVzPackageRootEvidenceUInt64V2(
      claims["expires_at_unix_seconds"]
    ),
    evidenceComplete: expected.coverage[.evidence]!
  )
}

private func linuxVzPackageRootEvidenceValidateStructureV2(
  _ claims: [String: Any],
  expected: LinuxVzPackageRootEvidenceReceiptExpectedBindingsV2,
  expectedPublicKeySHA256: String,
  observedAtUnixSeconds: UInt64
) throws {
  let allDigestKeys =
    LinuxVzPackageRootEvidenceDigestFieldV2.allCases.map(\.rawValue) + [
      "guest_evidence_public_key_sha256", "process_evidence_sha256",
      "file_evidence_sha256", "network_evidence_sha256",
    ]
  let digests = try allDigestKeys.map { key -> String in
    guard let value = claims[key] as? String,
      linuxVzPackageRootEvidenceValidDigestV2(value),
      value != sha256(Data())
    else {
      throw LinuxVzPackageRootEvidenceReceiptError.invalidReceipt
    }
    return value
  }
  guard Set(digests).count == digests.count,
    claims["key_id_sha256"] as? String == expectedPublicKeySHA256
  else {
    throw LinuxVzPackageRootEvidenceReceiptError.invalidReceipt
  }

  let number = { (field: LinuxVzPackageRootEvidenceNumericFieldV2) -> UInt64 in
    expected.numerics[field]!
  }
  guard number(.artifactByteLength) > 0,
    number(.actionIndex) > 0,
    expected.cgroupName == "whoathere-package-action-\(number(.actionIndex))",
    number(.cgroupID) > 0,
    number(.rootRunnerPID) > 1,
    number(.rootRunnerPID) <= UInt64(UInt32.max),
    number(.leaderPID) > 1,
    number(.leaderPID) <= UInt64(UInt32.max),
    number(.rootRunnerPID) != number(.leaderPID),
    number(.processStartedMonotonicNanoseconds) > 0,
    number(.processEndedMonotonicNanoseconds)
      > number(.processStartedMonotonicNanoseconds),
    number(.leaderSupervisorWaitStatus) <= UInt64(UInt16.max),
    number(.heartbeatCount) >= 2,
    number(.processSourceEventCount) > 0,
    number(.processObservationCount) > 0,
    number(.processObservationCount) <= number(.processSourceEventCount),
    number(.executionGrantIssuedAt) > 0,
    number(.executionGrantVerifiedAt) >= number(.executionGrantIssuedAt),
    number(.executionGrantExpiresAt) > number(.executionGrantVerifiedAt),
    linuxVzPackageRootEvidenceTerminalIsValidV2(
      terminal: expected.leaderTerminal,
      exitStatus: expected.leaderExitStatus,
      terminationSignal: expected.leaderTerminationSignal,
      waitStatus: number(.leaderSupervisorWaitStatus)
    )
  else {
    throw LinuxVzPackageRootEvidenceReceiptError.bindingMismatch
  }

  guard claims["process_coverage_complete"] as? Bool == true,
    claims["evidence_truncated"] as? Bool == false,
    claims["dropped_event_count"] as? String == "0",
    claims["public_network_route_present"] as? Bool == false,
    claims["raw_arguments_captured"] as? Bool == false,
    claims["raw_exec_paths_captured"] as? Bool == false,
    claims["raw_file_paths_captured"] as? Bool == false,
    claims["raw_network_addresses_captured"] as? Bool == false,
    claims["package_uid"] as? String == "65534",
    claims["package_gid"] as? String == "65534",
    claims["sync_back"] as? Bool == false,
    claims["host_composition_required"] as? Bool == true,
    claims["vm_destruction_observed"] as? Bool == false,
    claims["authoritative_verdict_permitted"] as? Bool == false
  else {
    throw LinuxVzPackageRootEvidenceReceiptError.invalidReceipt
  }

  let coverage = { (field: LinuxVzPackageRootEvidenceCoverageFieldV2) -> Bool in
    expected.coverage[field]!
  }
  let expectedComposite =
    coverage(.guestIntent) && coverage(.hostFrameCorrelation)
    && coverage(.dnsIntent) && coverage(.httpObservation)
  let expectedComplete =
    coverage(.fileDeclaredScope) && coverage(.fileGlobalMount)
    && coverage(.compositeNetwork)
  guard coverage(.egressPacket),
    coverage(.connectSendtoIntent),
    number(.egressDroppedEventCount) == 0,
    number(.egressDiscardedRecordCount) == 0,
    coverage(.compositeNetwork) == expectedComposite,
    coverage(.evidence) == expectedComplete,
    coverage(.evidence)
      ? expected.unobservedNetworkCapabilities.isEmpty
      : !expected.unobservedNetworkCapabilities.isEmpty
  else {
    throw LinuxVzPackageRootEvidenceReceiptError.invalidCoverage
  }

  let createdAt = try linuxVzPackageRootEvidenceUInt64V2(
    claims["created_at_unix_seconds"]
  )
  let expiresAt = try linuxVzPackageRootEvidenceUInt64V2(
    claims["expires_at_unix_seconds"]
  )
  guard createdAt >= number(.executionGrantVerifiedAt),
    createdAt < number(.executionGrantExpiresAt),
    expiresAt > createdAt,
    expiresAt <= number(.executionGrantExpiresAt),
    expiresAt - createdAt <= maximumLinuxVzPackageRootEvidenceReceiptLifetimeSecondsV2,
    observedAtUnixSeconds >= createdAt,
    observedAtUnixSeconds < expiresAt
  else {
    throw LinuxVzPackageRootEvidenceReceiptError.invalidTime
  }
}

private let linuxVzPackageRootEvidenceClaimKeysV2 = Set([
  "schema_version", "authority", "artifact_kind", "artifact_sha256",
  "artifact_byte_length", "package_authority_request_sha256", "execution_grant_sha256",
  "execution_grant_issued_at_unix_seconds", "execution_grant_verified_at_unix_seconds",
  "execution_grant_expires_at_unix_seconds",
  "execution_runtime_qualification_record_sha256", "scenario_plan_sha256",
  "scenario_template_sha256", "scenario_kind_sha256", "scenario_policy_sha256",
  "dependency_closure_sha256", "runtime_profile_sha256",
  "execution_runtime_rootfs_sha256", "execution_runtime_manifest_sha256",
  "package_execution_runner_sha256", "qualified_telemetry_backend_sha256",
  "request_challenge_sha256", "grant_challenge_sha256", "attempt_binding_sha256",
  "clone_binding_sha256", "sensor_session_challenge_sha256",
  "guest_evidence_public_key_sha256", "guest_evidence_signer_sha256",
  "protected_sensor_bundle_sha256", "sensor_configuration_sha256",
  "launch_contract_sha256", "process_plan_sha256", "action_index", "cgroup_name",
  "cgroup_id", "root_runner_pid", "leader_pid",
  "process_started_monotonic_nanoseconds", "process_ended_monotonic_nanoseconds",
  "leader_supervisor_wait_status", "leader_terminal", "leader_exit_status",
  "leader_termination_signal", "heartbeat_count", "process_evidence_sha256",
  "process_evidence_byte_length", "process_source_event_count",
  "process_observation_count", "file_evidence_sha256", "file_evidence_byte_length",
  "file_event_count", "file_change_count", "network_evidence_sha256",
  "network_evidence_byte_length", "network_event_count", "egress_event_count",
  "egress_packet_coverage_complete", "egress_dropped_event_count",
  "egress_discarded_record_count", "connect_sendto_intent_coverage_complete",
  "guest_intent_coverage_complete", "host_frame_correlation_complete",
  "dns_intent_coverage_complete", "http_observation_complete",
  "composite_network_coverage_complete", "unobserved_network_capabilities",
  "process_coverage_complete", "file_declared_scope_complete",
  "file_global_mount_coverage_complete", "evidence_complete", "evidence_truncated",
  "dropped_event_count", "public_network_route_present", "raw_arguments_captured",
  "raw_exec_paths_captured", "raw_file_paths_captured",
  "raw_network_addresses_captured", "package_uid", "package_gid", "sync_back",
  "host_composition_required", "vm_destruction_observed",
  "authoritative_verdict_permitted", "key_id_sha256", "created_at_unix_seconds",
  "expires_at_unix_seconds",
])

private func linuxVzPackageRootEvidencePayloadIsCanonicalV2(_ data: Data) -> Bool {
  guard !data.isEmpty,
    data.count <= maximumLinuxVzPackageRootEvidencePayloadBytesV2,
    let value = try? JSONSerialization.jsonObject(with: data)
  else { return false }
  return (try? canonicalJSONData(value)) == data
}

private func linuxVzPackageRootEvidenceValidDigestV2(_ value: String) -> Bool {
  value.utf8.count == 71 && value.hasPrefix("sha256:")
    && value.dropFirst(7).utf8.allSatisfy {
      ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
    }
}

private func linuxVzPackageRootEvidenceCapabilitiesAreCanonicalV2(
  _ capabilities: [String]
) -> Bool {
  capabilities == capabilities.sorted() && Set(capabilities).count == capabilities.count
    && capabilities.allSatisfy { value in
      !value.isEmpty && value.utf8.count <= 128
        && value.utf8.allSatisfy { byte in
          (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
            || (byte >= 97 && byte <= 122) || [45, 46, 95].contains(byte)
        }
    }
}

private func linuxVzPackageRootEvidenceTerminalIsValidV2(
  terminal: String,
  exitStatus: UInt8?,
  terminationSignal: UInt8?,
  waitStatus: UInt64?
) -> Bool {
  guard let waitStatus, waitStatus <= UInt64(UInt16.max) else { return false }
  switch (terminal, exitStatus, terminationSignal) {
  case ("exited", let status?, nil):
    return waitStatus == UInt64(status) << 8
  case ("signaled", nil, let signal?) where signal >= 1 && signal <= 64:
    return waitStatus & 0xff00 == 0 && waitStatus & 0x007f == UInt64(signal)
  default:
    return false
  }
}

private func linuxVzPackageRootEvidenceUInt64V2(_ value: Any?) throws -> UInt64 {
  guard let text = value as? String,
    !text.isEmpty, text.utf8.count <= 20,
    text == "0" || !text.hasPrefix("0"),
    text.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
    let parsed = UInt64(text)
  else {
    throw LinuxVzPackageRootEvidenceReceiptError.invalidReceipt
  }
  return parsed
}

private func linuxVzPackageRootEvidenceOptionalUInt8V2(_ value: Any?) throws -> UInt8? {
  if value is NSNull { return nil }
  let parsed = try linuxVzPackageRootEvidenceUInt64V2(value)
  guard parsed <= UInt64(UInt8.max) else {
    throw LinuxVzPackageRootEvidenceReceiptError.invalidReceipt
  }
  return UInt8(parsed)
}

private func linuxVzPackageRootEvidenceDecodeHexV2(
  _ value: String,
  byteCount: Int
) -> Data? {
  guard value.utf8.count == byteCount * 2 else { return nil }
  var output = Data(capacity: byteCount)
  var index = value.startIndex
  for _ in 0..<byteCount {
    let next = value.index(index, offsetBy: 2)
    let pair = value[index..<next]
    guard
      pair.utf8.allSatisfy({ byte in
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
      }), let byte = UInt8(pair, radix: 16)
    else { return nil }
    output.append(byte)
    index = next
  }
  return output
}
