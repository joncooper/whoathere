import CryptoKit
import Foundation
import Testing

@testable import WhoaThereMacosVmHelperCore

private let rootReceiptGoldenSignature =
  "053fa74681b22607ebc86a26d7341d07da26cb0b091f0a6c94683e09569740a2"
  + "f989a9a360ba134bf65bce99ab705553d66ca25eb88784fe94ae55a1e9a78701"
private let rustHostCompositeGoldenSignature =
  "4e92d17e8b04a52f53e5c0a92dd5664d55ba4ffe07edf16c9671ea58551bada0"
  + "7fd8400c08cc398a2340836e6aefdc213680f9fb67eb77422d585f48b55c190d"

@Test func linuxVzPackageEvidencePayloadLimitsMatchQualifiedHostContract() {
  #expect(maximumLinuxVzPackageRootRuntimeEvidenceFrameBytesV1 == 16 * 1024 * 1024)
  #expect(
    maximumLinuxVzPackageRootEvidencePayloadBytesV2
      == maximumLinuxVzPackageRootRuntimeEvidenceFrameBytesV1
  )
}

@Test func linuxVzPackageRootReceiptVerifiesRustCrossLanguageGolden() throws {
  let privateKey = try rootReceiptPrivateKey()
  let publicKey = privateKey.publicKey.rawRepresentation
  #expect(
    rootReceiptHex(publicKey)
      == "772c8a442b7db06e166cfbc1ccbcbcde6f3eba76a4e98ef3ffc519502237d6ef"
  )
  let claims = rootReceiptClaims(publicKeySHA256: sha256(publicKey))
  let claimsData = try canonicalJSONData(claims)
  #expect(
    sha256(claimsData)
      == "sha256:9c24aa8dd83ad562f72415d1c110bff61548412b2f18aedf75e182cc39d776f9"
  )
  let receipt = try canonicalJSONData([
    "claims": claims,
    "signature_ed25519_hex": rootReceiptGoldenSignature,
  ])
  #expect(
    sha256(receipt)
      == "sha256:dc91df448364fa0d8ddb2fb60d4f7c89027f3326d7ae9136a70bebaedc6d8a22"
  )
  let expected = try rootReceiptExpectedBindings()
  let verified = try verifyLinuxVzPackageRootEvidenceReceiptV2(
    receipt,
    expected: expected,
    guestVerifyingKey: publicKey,
    observedAtUnixSeconds: 1_750_000_001
  )
  #expect(verified.receiptSHA256 == sha256(receipt))
  #expect(verified.artifactSHA256 == rootReceiptDigest("artifact"))
  #expect(verified.executionGrantSHA256 == rootReceiptDigest("execution grant"))
  #expect(verified.processEvidenceSHA256 == sha256(rootReceiptProcessEvidence()))
  #expect(verified.fileEvidenceSHA256 == sha256(rootReceiptFileEvidence()))
  #expect(verified.networkEvidenceSHA256 == sha256(rootReceiptNetworkEvidence()))
  #expect(!verified.evidenceComplete)
  #expect(verified.hostCompositionRequired)
  #expect(!verified.authoritativeVerdictPermitted)
  #expect(!verified.syncBackPermitted)
}

@Test func linuxVzPackageRootReceiptRejectsRebindingKeyTimeAndCanonicalMutations() throws {
  let privateKey = try rootReceiptPrivateKey()
  let publicKey = privateKey.publicKey.rawRepresentation
  let receipt = try rootReceiptSigned(
    rootReceiptClaims(publicKeySHA256: sha256(publicKey)),
    privateKey: privateKey
  )

  let rebound = try rootReceiptExpectedBindings(
    networkEvidence: Data(#"{"type":"different-network"}"#.utf8)
  )
  #expect(throws: LinuxVzPackageRootEvidenceReceiptError.bindingMismatch) {
    try verifyLinuxVzPackageRootEvidenceReceiptV2(
      receipt,
      expected: rebound,
      guestVerifyingKey: publicKey,
      observedAtUnixSeconds: 1_750_000_001
    )
  }
  #expect(throws: LinuxVzPackageRootEvidenceReceiptError.publicKeyMismatch) {
    try verifyLinuxVzPackageRootEvidenceReceiptV2(
      receipt,
      expected: try rootReceiptExpectedBindings(),
      guestVerifyingKey: Data(repeating: 8, count: 32),
      observedAtUnixSeconds: 1_750_000_001
    )
  }
  #expect(throws: LinuxVzPackageRootEvidenceReceiptError.invalidTime) {
    try verifyLinuxVzPackageRootEvidenceReceiptV2(
      receipt,
      expected: try rootReceiptExpectedBindings(),
      guestVerifyingKey: publicKey,
      observedAtUnixSeconds: 1_750_000_301
    )
  }
  var nonCanonical = receipt
  nonCanonical.append(0x0a)
  #expect(throws: LinuxVzPackageRootEvidenceReceiptError.nonCanonical) {
    try verifyLinuxVzPackageRootEvidenceReceiptV2(
      nonCanonical,
      expected: try rootReceiptExpectedBindings(),
      guestVerifyingKey: publicKey,
      observedAtUnixSeconds: 1_750_000_001
    )
  }
  var signatureMutation = try #require(
    JSONSerialization.jsonObject(with: receipt) as? [String: Any]
  )
  signatureMutation["signature_ed25519_hex"] = String(repeating: "0", count: 128)
  #expect(throws: LinuxVzPackageRootEvidenceReceiptError.signatureFailed) {
    try verifyLinuxVzPackageRootEvidenceReceiptV2(
      try canonicalJSONData(signatureMutation),
      expected: try rootReceiptExpectedBindings(),
      guestVerifyingKey: publicKey,
      observedAtUnixSeconds: 1_750_000_001
    )
  }
}

@Test func linuxVzPackageRootReceiptRejectsSignedSafetyAndCoverageOverclaims() throws {
  let privateKey = try rootReceiptPrivateKey()
  let publicKey = privateKey.publicKey.rawRepresentation

  var unsafeClaims = rootReceiptClaims(publicKeySHA256: sha256(publicKey))
  unsafeClaims["sync_back"] = true
  let unsafeReceipt = try rootReceiptSigned(unsafeClaims, privateKey: privateKey)
  #expect(throws: LinuxVzPackageRootEvidenceReceiptError.invalidReceipt) {
    try verifyLinuxVzPackageRootEvidenceReceiptV2(
      unsafeReceipt,
      expected: try rootReceiptExpectedBindings(),
      guestVerifyingKey: publicKey,
      observedAtUnixSeconds: 1_750_000_001
    )
  }

  var coverageClaims = rootReceiptClaims(publicKeySHA256: sha256(publicKey))
  coverageClaims["evidence_complete"] = true
  let coverageReceipt = try rootReceiptSigned(coverageClaims, privateKey: privateKey)
  let overclaimedExpected = try rootReceiptExpectedBindings(evidenceComplete: true)
  #expect(throws: LinuxVzPackageRootEvidenceReceiptError.invalidCoverage) {
    try verifyLinuxVzPackageRootEvidenceReceiptV2(
      coverageReceipt,
      expected: overclaimedExpected,
      guestVerifyingKey: publicKey,
      observedAtUnixSeconds: 1_750_000_001
    )
  }

  var unknownClaims = rootReceiptClaims(publicKeySHA256: sha256(publicKey))
  unknownClaims["verdict"] = "clean"
  let unknownReceipt = try rootReceiptSigned(unknownClaims, privateKey: privateKey)
  #expect(throws: LinuxVzPackageRootEvidenceReceiptError.invalidReceipt) {
    try verifyLinuxVzPackageRootEvidenceReceiptV2(
      unknownReceipt,
      expected: try rootReceiptExpectedBindings(),
      guestVerifyingKey: publicKey,
      observedAtUnixSeconds: 1_750_000_001
    )
  }
}

@Test func linuxVzPackageHostCompositeBindsGuestHostAndClosedLifecycle() throws {
  let root = try rootReceiptVerifiedFixture()
  let hostNetwork = try rootReceiptHostNetworkEvidence(root.verified)
  let hostKey = try Curve25519.Signing.PrivateKey(
    rawRepresentation: Data(repeating: 44, count: 32)
  )
  let hostPublicKey = Data(hostKey.publicKey.rawRepresentation)
  let lifecycle = try rootReceiptHostLifecycle(
    root.verified,
    hostPublicKey: hostPublicKey
  )
  #expect(
    sha256(hostPublicKey)
      == lifecycle.hostEvidencePublicKeySHA256
  )
  let evidence = try makeLinuxVzPackageHostCompositeEvidenceV1(
    verifiedRootReceipt: root.verified,
    rootReceiptData: root.receipt,
    hostNetworkEvidence: hostNetwork,
    lifecycle: lifecycle
  )
  #expect(evidence.rootReceiptSHA256 == root.verified.receiptSHA256)
  #expect(evidence.hostNetworkEvidenceSHA256 == hostNetwork.payloadSHA256)
  #expect(
    evidence.evidenceSHA256
      == "sha256:ab65634f16bbdf22c57a4f5146fa5e7885720b9722b3a1b8cd1c2b65fb46c5ee"
  )
  #expect(evidence.lifecycleComplete)
  #expect(evidence.selectedHostCorrelationComplete)
  #expect(!evidence.broadHostNetworkCoverageComplete)
  #expect(!evidence.compositeEvidenceComplete)
  #expect(!evidence.authoritativeVerdictPermitted)
  #expect(!evidence.syncBackPermitted)
  let decoded = try decodeLinuxVzPackageHostCompositeEvidenceV1(
    evidence.canonicalJSON,
    verifiedRootReceipt: root.verified,
    rootReceiptData: root.receipt,
    hostNetworkEvidence: hostNetwork,
    lifecycle: lifecycle
  )
  #expect(decoded == evidence)

  var hostSeed = hostKey.rawRepresentation
  let receipt = try signLinuxVzPackageHostCompositeReceiptV1(
    evidence: evidence,
    lifecycle: lifecycle,
    createdAtUnixSeconds: 1_750_000_010,
    expiresAtUnixSeconds: 1_750_000_310,
    signingSeed: &hostSeed
  )
  #expect(hostSeed == Data(repeating: 0, count: 32))
  let receiptObject = try #require(
    JSONSerialization.jsonObject(with: receipt) as? [String: Any]
  )
  let verified = try verifyLinuxVzPackageHostCompositeReceiptV1(
    receipt,
    evidence: evidence,
    lifecycle: lifecycle,
    hostVerifyingKey: hostPublicKey,
    observedAtUnixSeconds: 1_750_000_010
  )
  #expect(verified.compositeEvidenceSHA256 == evidence.evidenceSHA256)
  #expect(verified.rootReceiptSHA256 == root.verified.receiptSHA256)
  #expect(verified.hostNetworkEvidenceSHA256 == hostNetwork.payloadSHA256)
  #expect(!verified.compositeEvidenceComplete)
  #expect(!verified.authoritativeVerdictPermitted)
  #expect(!verified.syncBackPermitted)

  var rustReceiptObject = receiptObject
  rustReceiptObject["signature_ed25519_hex"] = rustHostCompositeGoldenSignature
  let rustReceipt = try canonicalJSONData(rustReceiptObject)
  #expect(
    sha256(rustReceipt)
      == "sha256:6a45287c15812d0ad932e7558ae9c34cb4ade14bc81dbb052d23d2c952f173f0"
  )
  let rustVerified = try verifyLinuxVzPackageHostCompositeReceiptV1(
    rustReceipt,
    evidence: evidence,
    lifecycle: lifecycle,
    hostVerifyingKey: hostPublicKey,
    observedAtUnixSeconds: 1_750_000_010
  )
  #expect(rustVerified.compositeEvidenceSHA256 == evidence.evidenceSHA256)
}

@Test func linuxVzPackageHostCompositeFailsClosedOnLifecycleRebindingAndForgery() throws {
  let root = try rootReceiptVerifiedFixture()
  let hostNetwork = try rootReceiptHostNetworkEvidence(root.verified)
  let hostKey = try Curve25519.Signing.PrivateKey(
    rawRepresentation: Data(repeating: 44, count: 32)
  )
  let hostPublicKey = Data(hostKey.publicKey.rawRepresentation)
  let lifecycle = try rootReceiptHostLifecycle(
    root.verified,
    hostPublicKey: hostPublicKey
  )
  #expect(
    sha256(hostPublicKey)
      == lifecycle.hostEvidencePublicKeySHA256
  )
  let evidence = try makeLinuxVzPackageHostCompositeEvidenceV1(
    verifiedRootReceipt: root.verified,
    rootReceiptData: root.receipt,
    hostNetworkEvidence: hostNetwork,
    lifecycle: lifecycle
  )
  var hostSeed = hostKey.rawRepresentation
  let receipt = try signLinuxVzPackageHostCompositeReceiptV1(
    evidence: evidence,
    lifecycle: lifecycle,
    createdAtUnixSeconds: 1_750_000_010,
    expiresAtUnixSeconds: 1_750_000_310,
    signingSeed: &hostSeed
  )

  #expect(throws: LinuxVzPackageHostCompositeEvidenceError.invalidLifecycle) {
    _ = try LinuxVzPackageHostCompositeLifecycleV1(
      cloneBindingSHA256: root.verified.cloneBindingSHA256,
      executionRuntimeRootfsSHA256: root.verified.executionRuntimeRootfsSHA256,
      executionRuntimeManifestSHA256:
        root.verified.executionRuntimeManifestSHA256,
      packageExecutionRunnerSHA256: root.verified.packageExecutionRunnerSHA256,
      hostEvidencePublicKeySHA256: sha256(hostPublicKey),
      serialLogSHA256: rootReceiptDigest("host serial log"),
      restrictedEvidenceReferenceSHA256s: [
        rootReceiptDigest("restricted raw evidence reference")
      ],
      vmStarted: true,
      guestChannelTerminated: true,
      vmStopped: false,
      imageIdentityStable: true,
      cloneDestroyedAfterStop: true,
      externalFramesForwarded: 0
    )
  }
  #expect(throws: LinuxVzPackageHostCompositeEvidenceError.invalidBinding) {
    _ = try makeLinuxVzPackageHostCompositeEvidenceV1(
      verifiedRootReceipt: root.verified,
      rootReceiptData: Data(#"{"rebound":true}"#.utf8),
      hostNetworkEvidence: hostNetwork,
      lifecycle: lifecycle
    )
  }
  #expect(throws: LinuxVzPackageHostCompositeEvidenceError.publicKeyMismatch) {
    try verifyLinuxVzPackageHostCompositeReceiptV1(
      receipt,
      evidence: evidence,
      lifecycle: lifecycle,
      hostVerifyingKey: Data(repeating: 9, count: 32),
      observedAtUnixSeconds: 1_750_000_010
    )
  }
  #expect(throws: LinuxVzPackageHostCompositeEvidenceError.invalidTime) {
    try verifyLinuxVzPackageHostCompositeReceiptV1(
      receipt,
      evidence: evidence,
      lifecycle: lifecycle,
      hostVerifyingKey: hostPublicKey,
      observedAtUnixSeconds: 1_750_000_310
    )
  }
  var forged = try #require(
    JSONSerialization.jsonObject(with: receipt) as? [String: Any]
  )
  forged["signature_ed25519_hex"] = String(repeating: "0", count: 128)
  #expect(throws: LinuxVzPackageHostCompositeEvidenceError.signatureFailed) {
    try verifyLinuxVzPackageHostCompositeReceiptV1(
      try canonicalJSONData(forged),
      evidence: evidence,
      lifecycle: lifecycle,
      hostVerifyingKey: hostPublicKey,
      observedAtUnixSeconds: 1_750_000_010
    )
  }
}

private func rootReceiptPrivateKey() throws -> Curve25519.Signing.PrivateKey {
  try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 73, count: 32))
}

private func rootReceiptVerifiedFixture() throws -> (
  receipt: Data,
  verified: VerifiedLinuxVzPackageRootEvidenceReceiptV2
) {
  let privateKey = try rootReceiptPrivateKey()
  let publicKey = privateKey.publicKey.rawRepresentation
  let receipt = try canonicalJSONData([
    "claims": rootReceiptClaims(publicKeySHA256: sha256(publicKey)),
    "signature_ed25519_hex": rootReceiptGoldenSignature,
  ])
  let verified = try verifyLinuxVzPackageRootEvidenceReceiptV2(
    receipt,
    expected: try rootReceiptExpectedBindings(),
    guestVerifyingKey: publicKey,
    observedAtUnixSeconds: 1_750_000_001
  )
  return (receipt, verified)
}

private func rootReceiptHostNetworkEvidence(
  _ root: VerifiedLinuxVzPackageRootEvidenceReceiptV2
) throws -> LinuxVzPackageHostUDPSendtoEvidenceV1 {
  let destinationToken = rootReceiptDigest("host destination token")
  let correlation = rootReceiptDigest("host egress packet correlation")
  let frame = rootReceiptDigest("host frame")
  let expected = try LinuxVzPackageExpectedHostUDPSendtoV1(
    rootNetworkEvidenceSHA256: root.networkEvidenceSHA256,
    processEvidenceSHA256: root.processEvidenceSHA256,
    sensorSessionChallengeSHA256: root.sensorSessionChallengeSHA256,
    destinationTokenSHA256: destinationToken,
    egressPacketCorrelationSHA256: correlation,
    destinationClass: .documentation,
    destinationPort: 40_553,
    enterSourceSequence: 16,
    syscallResult: 16
  )
  let value: [String: Any] = [
    "binding": [
      "egress_packet_correlation_sha256": correlation,
      "process_evidence_sha256": root.processEvidenceSHA256,
      "root_network_evidence_sha256": root.networkEvidenceSHA256,
      "sensor_session_challenge_sha256": root.sensorSessionChallengeSHA256,
    ],
    "collector": [
      "dropped_frame_count": "0",
      "healthy": true,
      "ingress_frame_count": "1",
      "retained_frame_count": "1",
      "terminal": "drained_after_stop",
      "truncated_frame_count": "0",
    ],
    "coverage": [
      "broad_host_frame_coverage_complete": false,
      "correlated_transmitted_event_count": "1",
      "raw_addresses_serialized": false,
      "raw_frame_bytes_serialized": false,
      "selected_udp_sendto_correlation_complete": true,
      "unobserved_capabilities": [
        "ipv6_host_frames", "kernel_socket_buffer_drop_accounting",
        "non_udp_sendto_host_frames", "retransmission_and_multi_frame_events",
      ],
    ],
    "event": [
      "destination_class": "documentation",
      "destination_port": "40553",
      "destination_token_sha256": destinationToken,
      "enter_source_sequence": "16",
      "event_kind": "sendto",
      "frame_sha256": frame,
      "network_layer_correlation_sha256": correlation,
      "source_port": "49152",
      "syscall_result": "16",
      "transport": "udp",
      "transport_payload_byte_count": "16",
    ],
    "schema_version": linuxVzPackageHostUDPSendtoEvidenceSchemaV2,
  ]
  return try decodeLinuxVzPackageHostUDPSendtoEvidenceV1(
    canonicalJSONData(value), expected: expected
  )
}

private func rootReceiptHostLifecycle(
  _ root: VerifiedLinuxVzPackageRootEvidenceReceiptV2,
  hostPublicKey: Data
) throws -> LinuxVzPackageHostCompositeLifecycleV1 {
  try LinuxVzPackageHostCompositeLifecycleV1(
    cloneBindingSHA256: root.cloneBindingSHA256,
    executionRuntimeRootfsSHA256: root.executionRuntimeRootfsSHA256,
    executionRuntimeManifestSHA256: root.executionRuntimeManifestSHA256,
    packageExecutionRunnerSHA256: root.packageExecutionRunnerSHA256,
    hostEvidencePublicKeySHA256: sha256(hostPublicKey),
    serialLogSHA256: rootReceiptDigest("host serial log"),
    restrictedEvidenceReferenceSHA256s: [
      rootReceiptDigest("restricted raw evidence reference")
    ],
    vmStarted: true,
    guestChannelTerminated: true,
    vmStopped: true,
    imageIdentityStable: true,
    cloneDestroyedAfterStop: true,
    externalFramesForwarded: 0
  )
}

private func rootReceiptProcessEvidence() -> Data {
  Data(#"{"type":"process"}"#.utf8)
}

private func rootReceiptFileEvidence() -> Data {
  Data(#"{"type":"file"}"#.utf8)
}

private func rootReceiptNetworkEvidence() -> Data {
  Data(#"{"type":"network"}"#.utf8)
}

private func rootReceiptExpectedBindings(
  evidenceComplete: Bool = false,
  networkEvidence: Data = rootReceiptNetworkEvidence()
) throws -> LinuxVzPackageRootEvidenceReceiptExpectedBindingsV2 {
  let digests: [LinuxVzPackageRootEvidenceDigestFieldV2: String] = [
    .artifactSHA256: rootReceiptDigest("artifact"),
    .packageAuthorityRequestSHA256: rootReceiptDigest("authority request"),
    .executionGrantSHA256: rootReceiptDigest("execution grant"),
    .executionRuntimeQualificationRecordSHA256: rootReceiptDigest("qualification record"),
    .scenarioPlanSHA256: rootReceiptDigest("scenario plan"),
    .scenarioTemplateSHA256: rootReceiptDigest("scenario template"),
    .scenarioKindSHA256: rootReceiptDigest("scenario kind"),
    .scenarioPolicySHA256: rootReceiptDigest("scenario policy"),
    .dependencyClosureSHA256: rootReceiptDigest("dependency closure"),
    .runtimeProfileSHA256: rootReceiptDigest("runtime profile"),
    .executionRuntimeRootfsSHA256: rootReceiptDigest("runtime rootfs"),
    .executionRuntimeManifestSHA256: rootReceiptDigest("runtime manifest"),
    .packageExecutionRunnerSHA256: rootReceiptDigest("package runner"),
    .qualifiedTelemetryBackendSHA256: rootReceiptDigest("telemetry backend"),
    .requestChallengeSHA256: rootReceiptDigest("request challenge"),
    .grantChallengeSHA256: rootReceiptDigest("grant challenge"),
    .attemptBindingSHA256: rootReceiptDigest("attempt binding"),
    .cloneBindingSHA256: rootReceiptDigest("clone binding"),
    .sensorSessionChallengeSHA256: rootReceiptDigest("sensor session challenge"),
    .guestEvidenceSignerSHA256: rootReceiptDigest("guest evidence signer"),
    .protectedSensorBundleSHA256: rootReceiptDigest("protected sensor bundle"),
    .sensorConfigurationSHA256: rootReceiptDigest("sensor configuration"),
    .launchContractSHA256: rootReceiptDigest("launch contract"),
    .processPlanSHA256: rootReceiptDigest("process plan"),
  ]
  let numerics: [LinuxVzPackageRootEvidenceNumericFieldV2: UInt64] = [
    .artifactByteLength: 4_096,
    .executionGrantIssuedAt: 1_749_999_940,
    .executionGrantVerifiedAt: 1_750_000_000,
    .executionGrantExpiresAt: 1_750_000_361,
    .actionIndex: 1,
    .cgroupID: 9_001,
    .rootRunnerPID: 40,
    .leaderPID: 42,
    .processStartedMonotonicNanoseconds: 100,
    .processEndedMonotonicNanoseconds: 300,
    .leaderSupervisorWaitStatus: 0,
    .heartbeatCount: 2,
    .processSourceEventCount: 18,
    .processObservationCount: 10,
    .fileEventCount: 6,
    .fileChangeCount: 1,
    .networkEventCount: 2,
    .egressEventCount: 1,
    .egressDroppedEventCount: 0,
    .egressDiscardedRecordCount: 0,
  ]
  let coverage: [LinuxVzPackageRootEvidenceCoverageFieldV2: Bool] = [
    .egressPacket: true,
    .connectSendtoIntent: true,
    .guestIntent: false,
    .hostFrameCorrelation: false,
    .dnsIntent: false,
    .httpObservation: false,
    .compositeNetwork: false,
    .fileDeclaredScope: true,
    .fileGlobalMount: false,
    .evidence: evidenceComplete,
  ]
  return try LinuxVzPackageRootEvidenceReceiptExpectedBindingsV2(
    artifactKind: "npm_tarball",
    digests: digests,
    numerics: numerics,
    cgroupName: "whoathere-package-action-1",
    leaderTerminal: "exited",
    leaderExitStatus: 0,
    leaderTerminationSignal: nil,
    coverage: coverage,
    unobservedNetworkCapabilities: [
      "additional_network_syscalls", "dns_intent", "host_frame_correlation",
      "http_observation",
    ],
    processEvidence: rootReceiptProcessEvidence(),
    fileEvidence: rootReceiptFileEvidence(),
    networkEvidence: networkEvidence
  )
}

private func rootReceiptClaims(publicKeySHA256: String) -> [String: Any] {
  [
    "schema_version": linuxVzPackageRootEvidenceReceiptSchemaV2,
    "authority": "guest_protected_sensor",
    "artifact_kind": "npm_tarball",
    "artifact_sha256": rootReceiptDigest("artifact"),
    "artifact_byte_length": "4096",
    "package_authority_request_sha256": rootReceiptDigest("authority request"),
    "execution_grant_sha256": rootReceiptDigest("execution grant"),
    "execution_grant_issued_at_unix_seconds": "1749999940",
    "execution_grant_verified_at_unix_seconds": "1750000000",
    "execution_grant_expires_at_unix_seconds": "1750000361",
    "execution_runtime_qualification_record_sha256": rootReceiptDigest(
      "qualification record"
    ),
    "scenario_plan_sha256": rootReceiptDigest("scenario plan"),
    "scenario_template_sha256": rootReceiptDigest("scenario template"),
    "scenario_kind_sha256": rootReceiptDigest("scenario kind"),
    "scenario_policy_sha256": rootReceiptDigest("scenario policy"),
    "dependency_closure_sha256": rootReceiptDigest("dependency closure"),
    "runtime_profile_sha256": rootReceiptDigest("runtime profile"),
    "execution_runtime_rootfs_sha256": rootReceiptDigest("runtime rootfs"),
    "execution_runtime_manifest_sha256": rootReceiptDigest("runtime manifest"),
    "package_execution_runner_sha256": rootReceiptDigest("package runner"),
    "qualified_telemetry_backend_sha256": rootReceiptDigest("telemetry backend"),
    "request_challenge_sha256": rootReceiptDigest("request challenge"),
    "grant_challenge_sha256": rootReceiptDigest("grant challenge"),
    "attempt_binding_sha256": rootReceiptDigest("attempt binding"),
    "clone_binding_sha256": rootReceiptDigest("clone binding"),
    "sensor_session_challenge_sha256": rootReceiptDigest("sensor session challenge"),
    "guest_evidence_public_key_sha256": publicKeySHA256,
    "guest_evidence_signer_sha256": rootReceiptDigest("guest evidence signer"),
    "protected_sensor_bundle_sha256": rootReceiptDigest("protected sensor bundle"),
    "sensor_configuration_sha256": rootReceiptDigest("sensor configuration"),
    "launch_contract_sha256": rootReceiptDigest("launch contract"),
    "process_plan_sha256": rootReceiptDigest("process plan"),
    "action_index": "1",
    "cgroup_name": "whoathere-package-action-1",
    "cgroup_id": "9001",
    "root_runner_pid": "40",
    "leader_pid": "42",
    "process_started_monotonic_nanoseconds": "100",
    "process_ended_monotonic_nanoseconds": "300",
    "leader_supervisor_wait_status": "0",
    "leader_terminal": "exited",
    "leader_exit_status": "0",
    "leader_termination_signal": NSNull(),
    "heartbeat_count": "2",
    "process_evidence_sha256": sha256(rootReceiptProcessEvidence()),
    "process_evidence_byte_length": String(rootReceiptProcessEvidence().count),
    "process_source_event_count": "18",
    "process_observation_count": "10",
    "file_evidence_sha256": sha256(rootReceiptFileEvidence()),
    "file_evidence_byte_length": String(rootReceiptFileEvidence().count),
    "file_event_count": "6",
    "file_change_count": "1",
    "network_evidence_sha256": sha256(rootReceiptNetworkEvidence()),
    "network_evidence_byte_length": String(rootReceiptNetworkEvidence().count),
    "network_event_count": "2",
    "egress_event_count": "1",
    "egress_packet_coverage_complete": true,
    "egress_dropped_event_count": "0",
    "egress_discarded_record_count": "0",
    "connect_sendto_intent_coverage_complete": true,
    "guest_intent_coverage_complete": false,
    "host_frame_correlation_complete": false,
    "dns_intent_coverage_complete": false,
    "http_observation_complete": false,
    "composite_network_coverage_complete": false,
    "unobserved_network_capabilities": [
      "additional_network_syscalls", "dns_intent", "host_frame_correlation",
      "http_observation",
    ],
    "process_coverage_complete": true,
    "file_declared_scope_complete": true,
    "file_global_mount_coverage_complete": false,
    "evidence_complete": false,
    "evidence_truncated": false,
    "dropped_event_count": "0",
    "public_network_route_present": false,
    "raw_arguments_captured": false,
    "raw_exec_paths_captured": false,
    "raw_file_paths_captured": false,
    "raw_network_addresses_captured": false,
    "package_uid": "65534",
    "package_gid": "65534",
    "sync_back": false,
    "host_composition_required": true,
    "vm_destruction_observed": false,
    "authoritative_verdict_permitted": false,
    "key_id_sha256": publicKeySHA256,
    "created_at_unix_seconds": "1750000001",
    "expires_at_unix_seconds": "1750000301",
  ]
}

private func rootReceiptSigned(
  _ claims: [String: Any],
  privateKey: Curve25519.Signing.PrivateKey
) throws -> Data {
  let claimsData = try canonicalJSONData(claims)
  var message = Data(
    "whoathere.linux_vz_package_root_evidence_receipt.signature.v2\0".utf8
  )
  message.append(claimsData)
  return try canonicalJSONData([
    "claims": claims,
    "signature_ed25519_hex": rootReceiptHex(try privateKey.signature(for: message)),
  ])
}

private func rootReceiptDigest(_ label: String) -> String {
  sha256(Data(label.utf8))
}

private func rootReceiptHex(_ data: Data) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}
