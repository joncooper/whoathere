import CryptoKit
import Foundation

public let linuxVzTelemetryConformanceChallengeSchemaV1 =
    "whoathere.macos_linux_vz_telemetry_conformance_challenge.v1"
public let maximumLinuxVzTelemetryConformanceEvidenceBytesV1 = 16 * 1024 * 1024
public let linuxVzTelemetryGuestReceiptSchemaV1 =
    "whoathere.macos_linux_vz_telemetry_guest_receipt.v1"
public let linuxVzTelemetryHostReceiptSchemaV1 =
    "whoathere.macos_linux_vz_telemetry_host_receipt.v1"

private let linuxVzGuestReceiptSignatureDomainDataV1 = Data(
    "whoathere.macos_linux_vz_telemetry_guest_receipt.signature.v1\0".utf8
)
private let linuxVzHostReceiptSignatureDomainDataV1 = Data(
    "whoathere.macos_linux_vz_telemetry_host_receipt.signature.v1\0".utf8
)

public enum LinuxVzTelemetryConformanceEvidenceError: Error, Equatable,
    CustomStringConvertible {
    case empty
    case limitExceeded
    case invalidSchema
    case invalidNonce
    case runSpecMismatch
    case backendMismatch
    case cloneMismatch
    case invalidReceipt
    case publicKeyMismatch
    case signatureFailed
    case nonCanonical

    public var description: String {
        switch self {
        case .empty: return "linux_vz_telemetry_evidence_empty"
        case .limitExceeded: return "linux_vz_telemetry_evidence_limit_exceeded"
        case .invalidSchema: return "linux_vz_telemetry_evidence_schema_invalid"
        case .invalidNonce: return "linux_vz_telemetry_evidence_nonce_invalid"
        case .runSpecMismatch: return "linux_vz_telemetry_evidence_run_spec_mismatch"
        case .backendMismatch: return "linux_vz_telemetry_evidence_backend_mismatch"
        case .cloneMismatch: return "linux_vz_telemetry_evidence_clone_mismatch"
        case .invalidReceipt: return "linux_vz_telemetry_evidence_receipt_invalid"
        case .publicKeyMismatch: return "linux_vz_telemetry_evidence_public_key_mismatch"
        case .signatureFailed: return "linux_vz_telemetry_evidence_signature_failed"
        case .nonCanonical: return "linux_vz_telemetry_evidence_noncanonical"
        }
    }
}

public struct LinuxVzTelemetryGuestObservationClaims: Equatable, Sendable {
    public let evidencePayloadSHA256: String
    public let evidenceByteLength: UInt64
    public let eventSequenceStart: UInt64
    public let eventSequenceEnd: UInt64
    public let eventCount: UInt64
    public let heartbeatCount: UInt64
    public let droppedEventCount: UInt64
    public let sensorHealthy: Bool
    public let evidenceTruncated: Bool
    public let descendantTeardownComplete: Bool
    public let observedTerminal: String

    public init(
        evidencePayloadSHA256: String,
        evidenceByteLength: UInt64,
        eventSequenceStart: UInt64,
        eventSequenceEnd: UInt64,
        eventCount: UInt64,
        heartbeatCount: UInt64,
        droppedEventCount: UInt64,
        sensorHealthy: Bool,
        evidenceTruncated: Bool,
        descendantTeardownComplete: Bool,
        observedTerminal: String
    ) {
        self.evidencePayloadSHA256 = evidencePayloadSHA256
        self.evidenceByteLength = evidenceByteLength
        self.eventSequenceStart = eventSequenceStart
        self.eventSequenceEnd = eventSequenceEnd
        self.eventCount = eventCount
        self.heartbeatCount = heartbeatCount
        self.droppedEventCount = droppedEventCount
        self.sensorHealthy = sensorHealthy
        self.evidenceTruncated = evidenceTruncated
        self.descendantTeardownComplete = descendantTeardownComplete
        self.observedTerminal = observedTerminal
    }
}

public struct LinuxVzTelemetryHostObservationClaims: Equatable, Sendable {
    public let evidencePayloadSHA256: String
    public let evidenceByteLength: UInt64
    public let eventSequenceStart: UInt64
    public let eventSequenceEnd: UInt64
    public let eventCount: UInt64
    public let heartbeatCount: UInt64
    public let droppedFrameCount: UInt64
    public let packetSensorHealthy: Bool
    public let evidenceTruncated: Bool
    public let guestChannelTerminated: Bool
    public let vmStarted: Bool
    public let vmStopped: Bool
    public let cloneDestroyed: Bool
    public let externalFramesForwarded: UInt64
    public let observedTerminal: String

    public init(
        evidencePayloadSHA256: String,
        evidenceByteLength: UInt64,
        eventSequenceStart: UInt64,
        eventSequenceEnd: UInt64,
        eventCount: UInt64,
        heartbeatCount: UInt64,
        droppedFrameCount: UInt64,
        packetSensorHealthy: Bool,
        evidenceTruncated: Bool,
        guestChannelTerminated: Bool,
        vmStarted: Bool,
        vmStopped: Bool,
        cloneDestroyed: Bool,
        externalFramesForwarded: UInt64,
        observedTerminal: String
    ) {
        self.evidencePayloadSHA256 = evidencePayloadSHA256
        self.evidenceByteLength = evidenceByteLength
        self.eventSequenceStart = eventSequenceStart
        self.eventSequenceEnd = eventSequenceEnd
        self.eventCount = eventCount
        self.heartbeatCount = heartbeatCount
        self.droppedFrameCount = droppedFrameCount
        self.packetSensorHealthy = packetSensorHealthy
        self.evidenceTruncated = evidenceTruncated
        self.guestChannelTerminated = guestChannelTerminated
        self.vmStarted = vmStarted
        self.vmStopped = vmStopped
        self.cloneDestroyed = cloneDestroyed
        self.externalFramesForwarded = externalFramesForwarded
        self.observedTerminal = observedTerminal
    }
}

public struct VerifiedLinuxVzTelemetryGuestReceipt: Equatable, Sendable {
    public let challengeSHA256: String
    public let observedSensors: [String]
    public let claims: LinuxVzTelemetryGuestObservationClaims
    public var packageExecutionAuthorityPermitted: Bool { false }
}

public struct VerifiedLinuxVzTelemetryHostReceipt: Equatable, Sendable {
    public let challengeSHA256: String
    public let observedSensors: [String]
    public let claims: LinuxVzTelemetryHostObservationClaims
    public var packageExecutionAuthorityPermitted: Bool { false }
}

public struct VerifiedLinuxVzObservationCompleteConformanceCase: Equatable, Sendable {
    public let challengeSHA256: String
    public let runSpecSHA256: String
    public let backendIdentitySHA256: String
    public let guestReceiptPresent: Bool
    public let hostReceiptPresent: Bool
    public var packageExecutionAuthorityPermitted: Bool { false }
}

public func signLinuxVzTelemetryHostReceipt(
    challenge: LinuxVzTelemetryConformanceChallenge,
    runSpec: LinuxVzTelemetryConformanceRunSpec,
    backend: UnqualifiedLinuxVzTelemetryBackendIdentity,
    claims: LinuxVzTelemetryHostObservationClaims,
    signingSeed: inout Data
) throws -> Data {
    defer {
        signingSeed.resetBytes(in: 0..<signingSeed.count)
    }
    guard signingSeed.count == 32,
          let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: signingSeed),
          sha256(privateKey.publicKey.rawRepresentation)
            == challenge.hostEvidencePublicKeySHA256 else {
        throw LinuxVzTelemetryConformanceEvidenceError.publicKeyMismatch
    }
    let unsigned = try linuxVzHostUnsignedReceipt(
        challenge: challenge,
        runSpec: runSpec,
        backend: backend,
        claims: claims
    )
    let unsignedData = try canonicalJSONData(unsigned)
    var message = Data()
    message.append(linuxVzHostReceiptSignatureDomainDataV1)
    message.append(challenge.canonicalJSON)
    message.append(0)
    message.append(unsignedData)
    let signature = try privateKey.signature(for: message)
    var receipt = unsigned
    receipt["signature_ed25519_hex"] = signature.map {
        String(format: "%02x", $0)
    }.joined()
    let data = try canonicalJSONData(receipt)
    guard data.count <= maximumLinuxVzTelemetryConformanceEvidenceBytesV1 else {
        throw LinuxVzTelemetryConformanceEvidenceError.limitExceeded
    }
    return data
}

public func verifyLinuxVzTelemetryGuestReceipt(
    _ data: Data,
    challenge: LinuxVzTelemetryConformanceChallenge,
    runSpec: LinuxVzTelemetryConformanceRunSpec,
    backend: UnqualifiedLinuxVzTelemetryBackendIdentity,
    verifyingKey: Data,
    expectedClaims: LinuxVzTelemetryGuestObservationClaims
) throws -> VerifiedLinuxVzTelemetryGuestReceipt {
    let unsigned = try linuxVzGuestUnsignedReceipt(
        challenge: challenge,
        runSpec: runSpec,
        backend: backend,
        claims: expectedClaims
    )
    try verifyLinuxVzSignedReceipt(
        data,
        expectedUnsigned: unsigned,
        challenge: challenge,
        verifyingKey: verifyingKey,
        expectedKeySHA256: challenge.guestEvidencePublicKeySHA256,
        signatureDomain: linuxVzGuestReceiptSignatureDomainDataV1
    )
    return VerifiedLinuxVzTelemetryGuestReceipt(
        challengeSHA256: challenge.challengeSHA256,
        observedSensors: linuxVzConformanceExpectedGuestSensors(runSpec),
        claims: expectedClaims
    )
}

public func verifyLinuxVzTelemetryHostReceipt(
    _ data: Data,
    challenge: LinuxVzTelemetryConformanceChallenge,
    runSpec: LinuxVzTelemetryConformanceRunSpec,
    backend: UnqualifiedLinuxVzTelemetryBackendIdentity,
    verifyingKey: Data,
    expectedClaims: LinuxVzTelemetryHostObservationClaims
) throws -> VerifiedLinuxVzTelemetryHostReceipt {
    let unsigned = try linuxVzHostUnsignedReceipt(
        challenge: challenge,
        runSpec: runSpec,
        backend: backend,
        claims: expectedClaims
    )
    try verifyLinuxVzSignedReceipt(
        data,
        expectedUnsigned: unsigned,
        challenge: challenge,
        verifyingKey: verifyingKey,
        expectedKeySHA256: challenge.hostEvidencePublicKeySHA256,
        signatureDomain: linuxVzHostReceiptSignatureDomainDataV1
    )
    return VerifiedLinuxVzTelemetryHostReceipt(
        challengeSHA256: challenge.challengeSHA256,
        observedSensors: linuxVzConformanceExpectedHostSensors(runSpec),
        claims: expectedClaims
    )
}

public func verifyLinuxVzObservationCompleteConformanceCase(
    challenge: LinuxVzTelemetryConformanceChallenge,
    runSpec: LinuxVzTelemetryConformanceRunSpec,
    backend: UnqualifiedLinuxVzTelemetryBackendIdentity,
    guest: VerifiedLinuxVzTelemetryGuestReceipt,
    host: VerifiedLinuxVzTelemetryHostReceipt
) throws -> VerifiedLinuxVzObservationCompleteConformanceCase {
    guard challenge.runSpecSHA256 == runSpec.runSpecSHA256,
          challenge.backendIdentitySHA256 == backend.identitySHA256,
          guest.challengeSHA256 == challenge.challengeSHA256,
          host.challengeSHA256 == challenge.challengeSHA256,
          !runSpec.packageExecutionAuthorityPermitted,
          !backend.executionAuthorityPermitted,
          !guest.packageExecutionAuthorityPermitted,
          !host.packageExecutionAuthorityPermitted,
          guest.claims.observedTerminal == runSpec.expectedTerminal,
          !guest.claims.evidenceTruncated,
          guest.claims.descendantTeardownComplete,
          host.claims.observedTerminal == runSpec.expectedTerminal,
          !host.claims.evidenceTruncated,
          host.claims.guestChannelTerminated,
          host.claims.vmStarted,
          host.claims.vmStopped,
          host.claims.cloneDestroyed,
          host.claims.externalFramesForwarded == 0 else {
        throw LinuxVzTelemetryConformanceEvidenceError.invalidReceipt
    }
    switch runSpec.expectedTerminal {
    case "observation_complete", "timeout_with_teardown",
         "access_denied_with_complete_evidence":
        guard guest.claims.sensorHealthy,
              guest.claims.droppedEventCount == 0,
              host.claims.packetSensorHealthy,
              host.claims.droppedFrameCount == 0 else {
            throw LinuxVzTelemetryConformanceEvidenceError.invalidReceipt
        }
    case "incomplete_on_injected_gap":
        guard guest.claims.sensorHealthy, host.claims.packetSensorHealthy else {
            throw LinuxVzTelemetryConformanceEvidenceError.invalidReceipt
        }
        let exactGap: Bool
        switch runSpec.fixtureCase {
        case "bpf_reservation_failure", "fanotify_queue_overflow":
            exactGap = guest.claims.droppedEventCount > 0
                && host.claims.droppedFrameCount == 0
        case "host_frame_overflow":
            exactGap = guest.claims.droppedEventCount == 0
                && host.claims.droppedFrameCount > 0
        default:
            exactGap = false
        }
        guard exactGap else {
            throw LinuxVzTelemetryConformanceEvidenceError.invalidReceipt
        }
    case "infrastructure_error_with_teardown":
        let exactHealth: Bool
        switch runSpec.fixtureCase {
        case "host_sensor_death":
            exactHealth = guest.claims.sensorHealthy && !host.claims.packetSensorHealthy
        case "channel_interruption", "vm_stop":
            exactHealth = guest.claims.sensorHealthy && host.claims.packetSensorHealthy
        default:
            exactHealth = false
        }
        guard exactHealth,
              guest.claims.droppedEventCount == 0,
              host.claims.droppedFrameCount == 0 else {
            throw LinuxVzTelemetryConformanceEvidenceError.invalidReceipt
        }
    default:
        throw LinuxVzTelemetryConformanceEvidenceError.invalidReceipt
    }
    return VerifiedLinuxVzObservationCompleteConformanceCase(
        challengeSHA256: challenge.challengeSHA256,
        runSpecSHA256: runSpec.runSpecSHA256,
        backendIdentitySHA256: backend.identitySHA256,
        guestReceiptPresent: true,
        hostReceiptPresent: true
    )
}

func linuxVzGuestUnsignedReceipt(
    challenge: LinuxVzTelemetryConformanceChallenge,
    runSpec: LinuxVzTelemetryConformanceRunSpec,
    backend: UnqualifiedLinuxVzTelemetryBackendIdentity,
    claims: LinuxVzTelemetryGuestObservationClaims
) throws -> [String: Any] {
    guard claims.evidenceByteLength > 0, claims.eventCount > 0, claims.heartbeatCount > 0,
          claims.eventSequenceEnd >= claims.eventSequenceStart,
          linuxVzEvidenceValidDigest(claims.evidencePayloadSHA256) else {
        throw LinuxVzTelemetryConformanceEvidenceError.invalidReceipt
    }
    try linuxVzValidateReceiptContext(challenge, runSpec, backend)
    return [
        "schema_version": linuxVzTelemetryGuestReceiptSchemaV1,
        "authority": "guest_protected_sensors",
        "challenge_sha256": challenge.challengeSHA256,
        "run_spec_sha256": runSpec.runSpecSHA256,
        "backend_identity_sha256": backend.identitySHA256,
        "telemetry_requirements_sha256": runSpec.telemetryRequirementsSHA256,
        "clone_binding_sha256": challenge.cloneBindingSHA256,
        "fixture": runSpec.fixture,
        "fixture_case": runSpec.fixtureCase,
        "fixture_binary_sha256": runSpec.fixtureBinarySHA256,
        "expected_terminal": runSpec.expectedTerminal,
        "observed_terminal": claims.observedTerminal,
        "observed_sensors": linuxVzConformanceExpectedGuestSensors(runSpec),
        "evidence_payload_sha256": claims.evidencePayloadSHA256,
        "evidence_byte_length": String(claims.evidenceByteLength),
        "event_sequence_start": String(claims.eventSequenceStart),
        "event_sequence_end": String(claims.eventSequenceEnd),
        "event_count": String(claims.eventCount),
        "heartbeat_count": String(claims.heartbeatCount),
        "dropped_event_count": String(claims.droppedEventCount),
        "sensor_healthy": claims.sensorHealthy,
        "evidence_truncated": claims.evidenceTruncated,
        "descendant_teardown_complete": claims.descendantTeardownComplete,
        "package_uid": String(backend.packageUID),
        "package_gid": String(backend.packageGID),
        "package_capabilities_present": false,
        "public_network_reachable": false,
        "package_execution": "disabled",
        "sync_back_policy": "structurally_absent"
    ]
}

func linuxVzHostUnsignedReceipt(
    challenge: LinuxVzTelemetryConformanceChallenge,
    runSpec: LinuxVzTelemetryConformanceRunSpec,
    backend: UnqualifiedLinuxVzTelemetryBackendIdentity,
    claims: LinuxVzTelemetryHostObservationClaims
) throws -> [String: Any] {
    guard claims.evidenceByteLength > 0, claims.eventCount > 0, claims.heartbeatCount > 0,
          claims.eventSequenceEnd >= claims.eventSequenceStart,
          linuxVzEvidenceValidDigest(claims.evidencePayloadSHA256) else {
        throw LinuxVzTelemetryConformanceEvidenceError.invalidReceipt
    }
    try linuxVzValidateReceiptContext(challenge, runSpec, backend)
    return [
        "schema_version": linuxVzTelemetryHostReceiptSchemaV1,
        "authority": "host_packet_and_vm_lifecycle",
        "challenge_sha256": challenge.challengeSHA256,
        "run_spec_sha256": runSpec.runSpecSHA256,
        "backend_identity_sha256": backend.identitySHA256,
        "telemetry_requirements_sha256": runSpec.telemetryRequirementsSHA256,
        "clone_binding_sha256": challenge.cloneBindingSHA256,
        "fixture": runSpec.fixture,
        "fixture_case": runSpec.fixtureCase,
        "fixture_binary_sha256": runSpec.fixtureBinarySHA256,
        "expected_terminal": runSpec.expectedTerminal,
        "observed_terminal": claims.observedTerminal,
        "observed_sensors": linuxVzConformanceExpectedHostSensors(runSpec),
        "evidence_payload_sha256": claims.evidencePayloadSHA256,
        "evidence_byte_length": String(claims.evidenceByteLength),
        "event_sequence_start": String(claims.eventSequenceStart),
        "event_sequence_end": String(claims.eventSequenceEnd),
        "event_count": String(claims.eventCount),
        "heartbeat_count": String(claims.heartbeatCount),
        "dropped_frame_count": String(claims.droppedFrameCount),
        "packet_sensor_healthy": claims.packetSensorHealthy,
        "evidence_truncated": claims.evidenceTruncated,
        "guest_channel_terminated": claims.guestChannelTerminated,
        "vm_started": claims.vmStarted,
        "vm_stopped": claims.vmStopped,
        "clone_destroyed": claims.cloneDestroyed,
        "external_frames_forwarded": String(claims.externalFramesForwarded),
        "public_network_route_present": false,
        "package_execution": "disabled",
        "sync_back_policy": "structurally_absent"
    ]
}

private func linuxVzValidateReceiptContext(
    _ challenge: LinuxVzTelemetryConformanceChallenge,
    _ runSpec: LinuxVzTelemetryConformanceRunSpec,
    _ backend: UnqualifiedLinuxVzTelemetryBackendIdentity
) throws {
    guard challenge.runSpecSHA256 == runSpec.runSpecSHA256 else {
        throw LinuxVzTelemetryConformanceEvidenceError.runSpecMismatch
    }
    guard challenge.backendIdentitySHA256 == backend.identitySHA256,
          runSpec.backendIdentitySHA256 == backend.identitySHA256,
          challenge.telemetryRequirementsSHA256 == backend.telemetryRequirementsSHA256,
          !runSpec.packageExecutionAuthorityPermitted,
          !backend.executionAuthorityPermitted else {
        throw LinuxVzTelemetryConformanceEvidenceError.backendMismatch
    }
}

private func verifyLinuxVzSignedReceipt(
    _ data: Data,
    expectedUnsigned: [String: Any],
    challenge: LinuxVzTelemetryConformanceChallenge,
    verifyingKey: Data,
    expectedKeySHA256: String,
    signatureDomain: Data
) throws {
    guard !data.isEmpty else { throw LinuxVzTelemetryConformanceEvidenceError.empty }
    guard data.count <= maximumLinuxVzTelemetryConformanceEvidenceBytesV1 else {
        throw LinuxVzTelemetryConformanceEvidenceError.limitExceeded
    }
    guard sha256(verifyingKey) == expectedKeySHA256,
          let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: verifyingKey) else {
        throw LinuxVzTelemetryConformanceEvidenceError.publicKeyMismatch
    }
    guard let receipt = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzTelemetryConformanceEvidenceError.invalidReceipt
    }
    guard try canonicalJSONData(receipt) == data else {
        throw LinuxVzTelemetryConformanceEvidenceError.nonCanonical
    }
    var unsigned = receipt
    guard let signatureHex = unsigned.removeValue(forKey: "signature_ed25519_hex") as? String,
          let signature = linuxVzEvidenceDecodeLowerHex(signatureHex, byteCount: 64),
          Set(unsigned.keys) == Set(expectedUnsigned.keys),
          try canonicalJSONData(unsigned) == canonicalJSONData(expectedUnsigned) else {
        throw LinuxVzTelemetryConformanceEvidenceError.invalidReceipt
    }
    let unsignedData = try canonicalJSONData(unsigned)
    var message = Data()
    message.append(signatureDomain)
    message.append(challenge.canonicalJSON)
    message.append(0)
    message.append(unsignedData)
    guard publicKey.isValidSignature(signature, for: message) else {
        throw LinuxVzTelemetryConformanceEvidenceError.signatureFailed
    }
}

public struct LinuxVzTelemetryConformanceChallenge: Equatable, Sendable {
    public let canonicalJSON: Data
    public let challengeSHA256: String
    public let runSpecSHA256: String
    public let backendIdentitySHA256: String
    public let telemetryRequirementsSHA256: String
    public let cloneBindingSHA256: String
    public let guestEvidencePublicKeySHA256: String
    public let hostEvidencePublicKeySHA256: String

    public var packageExecutionAuthorityPermitted: Bool { false }
}

public func decodeLinuxVzTelemetryConformanceChallenge(
    _ data: Data,
    expectedRunSpec: LinuxVzTelemetryConformanceRunSpec,
    expectedBackend: UnqualifiedLinuxVzTelemetryBackendIdentity
) throws -> LinuxVzTelemetryConformanceChallenge {
    guard !data.isEmpty else { throw LinuxVzTelemetryConformanceEvidenceError.empty }
    guard data.count <= maximumLinuxVzTelemetryConformanceEvidenceBytesV1 else {
        throw LinuxVzTelemetryConformanceEvidenceError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzTelemetryConformanceEvidenceError.invalidSchema
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzTelemetryConformanceEvidenceError.nonCanonical
    }
    guard Set(value.keys) == Set([
        "schema_version", "nonce_hex", "challenge_purpose", "run_spec_sha256",
        "backend_identity_sha256", "telemetry_requirements_sha256",
        "clone_binding_sha256", "guest_evidence_public_key_sha256",
        "host_evidence_public_key_sha256", "package_execution", "sync_back_policy"
    ]) else {
        throw LinuxVzTelemetryConformanceEvidenceError.invalidSchema
    }
    guard value["schema_version"] as? String == linuxVzTelemetryConformanceChallengeSchemaV1,
          value["challenge_purpose"] as? String
            == "trusted_inert_telemetry_conformance_only",
          value["package_execution"] as? String == "disabled",
          value["sync_back_policy"] as? String == "structurally_absent",
          let nonce = value["nonce_hex"] as? String,
          linuxVzEvidenceValidLowerHex(nonce, length: 64),
          let runSpecSHA256 = value["run_spec_sha256"] as? String,
          let backendSHA256 = value["backend_identity_sha256"] as? String,
          let requirementsSHA256 = value["telemetry_requirements_sha256"] as? String,
          let cloneSHA256 = value["clone_binding_sha256"] as? String,
          let guestKeySHA256 = value["guest_evidence_public_key_sha256"] as? String,
          let hostKeySHA256 = value["host_evidence_public_key_sha256"] as? String,
          [runSpecSHA256, backendSHA256, requirementsSHA256, cloneSHA256,
           guestKeySHA256, hostKeySHA256].allSatisfy(linuxVzEvidenceValidDigest) else {
        throw LinuxVzTelemetryConformanceEvidenceError.invalidSchema
    }
    guard runSpecSHA256 == expectedRunSpec.runSpecSHA256,
          !expectedRunSpec.packageExecutionAuthorityPermitted else {
        throw LinuxVzTelemetryConformanceEvidenceError.runSpecMismatch
    }
    guard backendSHA256 == expectedBackend.identitySHA256,
          backendSHA256 == expectedRunSpec.backendIdentitySHA256,
          requirementsSHA256 == expectedBackend.telemetryRequirementsSHA256,
          requirementsSHA256 == expectedRunSpec.telemetryRequirementsSHA256,
          guestKeySHA256 == expectedBackend.guestEvidencePublicKeySHA256,
          hostKeySHA256 == expectedBackend.hostEvidencePublicKeySHA256,
          !expectedBackend.executionAuthorityPermitted else {
        throw LinuxVzTelemetryConformanceEvidenceError.backendMismatch
    }
    return LinuxVzTelemetryConformanceChallenge(
        canonicalJSON: data,
        challengeSHA256: sha256(data),
        runSpecSHA256: runSpecSHA256,
        backendIdentitySHA256: backendSHA256,
        telemetryRequirementsSHA256: requirementsSHA256,
        cloneBindingSHA256: cloneSHA256,
        guestEvidencePublicKeySHA256: guestKeySHA256,
        hostEvidencePublicKeySHA256: hostKeySHA256
    )
}

func linuxVzEvidenceValidDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && linuxVzEvidenceValidLowerHex(String(value.dropFirst(7)), length: 64)
}

private func linuxVzEvidenceDecodeLowerHex(_ value: String, byteCount: Int) -> Data? {
    guard value.utf8.count == byteCount * 2 else { return nil }
    var data = Data(capacity: byteCount)
    var index = value.startIndex
    for _ in 0..<byteCount {
        let next = value.index(index, offsetBy: 2)
        guard let byte = UInt8(value[index..<next], radix: 16),
              value[index..<next].allSatisfy({ $0.isNumber || ("a"..."f").contains(String($0)) }) else {
            return nil
        }
        data.append(byte)
        index = next
    }
    return data
}

private func linuxVzEvidenceValidLowerHex(_ value: String, length: Int) -> Bool {
    value.utf8.count == length && value.utf8.allSatisfy {
        ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
    }
}
