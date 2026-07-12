import CryptoKit
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzConformanceRunSpecMatchesRustAndDisablesPackageExecution() throws {
    let fixture = try linuxVzConformanceFixture()
    let data = try canonicalJSONData(fixture)
    let spec = try decodeLinuxVzTelemetryConformanceRunSpec(data)
    #expect(
        spec.runSpecSHA256
            == "sha256:4fd12743b8a404e68e171058b13c4ae797d35548cad068fc6a08fd23c410bf4b"
    )
    #expect(spec.fixture == "network_intent")
    #expect(spec.fixtureCase == "dns_plaintext")
    #expect(spec.expectedTerminal == "observation_complete")
    #expect(spec.expectedSensors.count == 7)
    #expect(!spec.packageExecutionAuthorityPermitted)
}

@Test func linuxVzConformanceRunSpecAcceptsEveryClosedCaseExactly() throws {
    let base = try linuxVzConformanceFixture()
    let cases = linuxVzAllTelemetryConformanceCasesV1()
    #expect(cases.count == 38)
    #expect(Set(cases).count == cases.count)
    for fixtureCase in cases {
        let fixture = try #require(linuxVzConformanceFixture(fixtureCase))
        let expectedTerminal = try #require(
            linuxVzConformanceExpectedTerminal(fixtureCase)
        )
        let expectedSensors = try #require(linuxVzConformanceExpectedSensors(fixture))
        var value = base
        value["fixture_case"] = fixtureCase
        value["fixture"] = fixture
        value["expected_terminal"] = expectedTerminal
        value["expected_sensors"] = expectedSensors
        let decoded = try decodeLinuxVzTelemetryConformanceRunSpec(
            try canonicalJSONData(value)
        )
        #expect(decoded.fixtureCase == fixtureCase)
        #expect(decoded.expectedTerminal == expectedTerminal)
        #expect(!decoded.packageExecutionAuthorityPermitted)
    }
}

@Test func linuxVzConformanceChallengeMatchesRustAndRejectsRebinding() throws {
    let runValue = try linuxVzConformanceFixture(
        runID: "linux-vz-conformance-run-challenge-golden",
        evidenceID: "linux-vz-conformance-evidence-challenge-golden"
    )
    let runData = try canonicalJSONData(runValue)
    let runSpec = try decodeLinuxVzTelemetryConformanceRunSpec(runData)
    let backendValue = try #require(runValue["backend_identity"] as? [String: Any])
    let requirementsSHA256 = try #require(
        runValue["telemetry_requirements_sha256"] as? String
    )
    let backend = try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
        try canonicalJSONData(backendValue),
        expectedTelemetryRequirementsSHA256: requirementsSHA256
    )
    var challenge: [String: Any] = [
        "schema_version": linuxVzTelemetryConformanceChallengeSchemaV1,
        "nonce_hex": String(repeating: "42", count: 32),
        "challenge_purpose": "trusted_inert_telemetry_conformance_only",
        "run_spec_sha256": runSpec.runSpecSHA256,
        "backend_identity_sha256": backend.identitySHA256,
        "telemetry_requirements_sha256": requirementsSHA256,
        "clone_binding_sha256": sha256(Data("inert disposable clone binding".utf8)),
        "guest_evidence_public_key_sha256": backend.guestEvidencePublicKeySHA256,
        "host_evidence_public_key_sha256": backend.hostEvidencePublicKeySHA256,
        "package_execution": "disabled",
        "sync_back_policy": "structurally_absent"
    ]
    let data = try canonicalJSONData(challenge)
    let decoded = try decodeLinuxVzTelemetryConformanceChallenge(
        data,
        expectedRunSpec: runSpec,
        expectedBackend: backend
    )
    #expect(
        decoded.challengeSHA256
            == "sha256:28136636fa8be52022213f238b9a39b55c35a837eb8262552dc5eeae55400ff6"
    )
    #expect(!decoded.packageExecutionAuthorityPermitted)

    challenge["package_execution"] = "enabled"
    #expect(throws: LinuxVzTelemetryConformanceEvidenceError.invalidSchema) {
        try decodeLinuxVzTelemetryConformanceChallenge(
            try canonicalJSONData(challenge),
            expectedRunSpec: runSpec,
            expectedBackend: backend
        )
    }
}

@Test func linuxVzGuestAndHostReceiptsMatchRustSignaturesAndRejectCrossAuthority() throws {
    let guestSeed = Data(repeating: 0x11, count: 32)
    let hostSeed = Data(repeating: 0x22, count: 32)
    let guestPrivate = try Curve25519.Signing.PrivateKey(rawRepresentation: guestSeed)
    let hostPrivate = try Curve25519.Signing.PrivateKey(rawRepresentation: hostSeed)
    var runValue = try linuxVzConformanceFixture(
        runID: "linux-vz-conformance-run-receipt-golden",
        evidenceID: "linux-vz-conformance-evidence-receipt-golden"
    )
    var backendValue = try #require(runValue["backend_identity"] as? [String: Any])
    backendValue["guest_evidence_public_key_sha256"] = sha256(
        guestPrivate.publicKey.rawRepresentation
    )
    backendValue["host_evidence_public_key_sha256"] = sha256(
        hostPrivate.publicKey.rawRepresentation
    )
    runValue["backend_identity"] = backendValue
    runValue["backend_identity_sha256"] = sha256(try canonicalJSONData(backendValue))
    let runSpec = try decodeLinuxVzTelemetryConformanceRunSpec(
        try canonicalJSONData(runValue)
    )
    let requirementsSHA256 = try #require(
        runValue["telemetry_requirements_sha256"] as? String
    )
    let backend = try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
        try canonicalJSONData(backendValue),
        expectedTelemetryRequirementsSHA256: requirementsSHA256
    )
    #expect(
        backend.identitySHA256
            == "sha256:d189e21f9a0fd1277e552db580414b6b572cebe3ce795c0f0da1acce87116088"
    )
    #expect(
        runSpec.runSpecSHA256
            == "sha256:9c1db6610378d3c0533024f32acf4a656ed8c0ad3a158a0b9b856451f004db9d"
    )
    #expect(
        backend.guestEvidencePublicKeySHA256
            == "sha256:10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d"
    )
    #expect(
        backend.hostEvidencePublicKeySHA256
            == "sha256:1325b850c2871916eae203f0efc3c8987f64e5e3cdb27679e6d1fa97808357e6"
    )
    let challengeValue: [String: Any] = [
        "schema_version": linuxVzTelemetryConformanceChallengeSchemaV1,
        "nonce_hex": String(repeating: "33", count: 32),
        "challenge_purpose": "trusted_inert_telemetry_conformance_only",
        "run_spec_sha256": runSpec.runSpecSHA256,
        "backend_identity_sha256": backend.identitySHA256,
        "telemetry_requirements_sha256": requirementsSHA256,
        "clone_binding_sha256": sha256(Data("receipt disposable clone binding".utf8)),
        "guest_evidence_public_key_sha256": backend.guestEvidencePublicKeySHA256,
        "host_evidence_public_key_sha256": backend.hostEvidencePublicKeySHA256,
        "package_execution": "disabled",
        "sync_back_policy": "structurally_absent"
    ]
    let challenge = try decodeLinuxVzTelemetryConformanceChallenge(
        try canonicalJSONData(challengeValue),
        expectedRunSpec: runSpec,
        expectedBackend: backend
    )
    #expect(
        challenge.challengeSHA256
            == "sha256:2979ab81d5382b8fd89eaddf5b303c227b8d267890311d975dc9830a918408ec"
    )
    let guestClaims = LinuxVzTelemetryGuestObservationClaims(
        evidencePayloadSHA256: sha256(
            Data("canonical guest telemetry evidence payload".utf8)
        ),
        evidenceByteLength: 4096,
        eventSequenceStart: 10,
        eventSequenceEnd: 89,
        eventCount: 80,
        heartbeatCount: 4,
        droppedEventCount: 0,
        sensorHealthy: true,
        evidenceTruncated: false,
        descendantTeardownComplete: true,
        observedTerminal: "observation_complete"
    )
    let hostClaims = LinuxVzTelemetryHostObservationClaims(
        evidencePayloadSHA256: sha256(
            Data("canonical host telemetry evidence payload".utf8)
        ),
        evidenceByteLength: 2048,
        eventSequenceStart: 100,
        eventSequenceEnd: 139,
        eventCount: 40,
        heartbeatCount: 4,
        droppedFrameCount: 0,
        packetSensorHealthy: true,
        evidenceTruncated: false,
        guestChannelTerminated: true,
        vmStarted: true,
        vmStopped: true,
        cloneDestroyed: true,
        externalFramesForwarded: 0,
        observedTerminal: "observation_complete"
    )
    let guestUnsigned = try linuxVzGuestUnsignedReceipt(
        challenge: challenge,
        runSpec: runSpec,
        backend: backend,
        claims: guestClaims
    )
    let hostUnsigned = try linuxVzHostUnsignedReceipt(
        challenge: challenge,
        runSpec: runSpec,
        backend: backend,
        claims: hostClaims
    )
    #expect(
        sha256(try canonicalJSONData(guestUnsigned))
            == "sha256:a6a9a44200b03f9865b8ad1a7d5eb58c6bcadd39499f13a22856926e65acec92"
    )
    #expect(
        sha256(try canonicalJSONData(hostUnsigned))
            == "sha256:e983821449e2c24ecd5fb70e7f214fce38f8471314ac0e61f4b5647cc3c3d979"
    )
    var guestReceipt = guestUnsigned
    guestReceipt["signature_ed25519_hex"] =
        "ee436ec19f563a3ac7d93b7f3cf39c36760bb89cdd3e86723dadba2110647c63483a12cb4c851cb3ff1c52b2a25882417cd7bb63c47232cbfde5d40ce6200000"
    var hostReceipt = hostUnsigned
    hostReceipt["signature_ed25519_hex"] =
        "0e3afa3b996a496da21b4ec0851f41288e9f3705fd84edea01aa75afb44fbacdf43ab65735f9ff0fb635818970d024aa5eefb1b3526b4e282369b9268e98040c"
    let guestData = try canonicalJSONData(guestReceipt)
    let hostData = try canonicalJSONData(hostReceipt)
    #expect(
        sha256(guestData)
            == "sha256:9bad56c2d3def2391e9f164f7262963c83ec7ba2fe3946e7301bc3d7122224ef"
    )
    #expect(
        sha256(hostData)
            == "sha256:48a21bb1719681148070688cbf3bf890ca7c84c735eb5ba954558179608dac43"
    )
    var hostSigningSeed = Data(repeating: 0x22, count: 32)
    let signedHostData = try signLinuxVzTelemetryHostReceipt(
        challenge: challenge,
        runSpec: runSpec,
        backend: backend,
        claims: hostClaims,
        signingSeed: &hostSigningSeed
    )
    #expect(!signedHostData.isEmpty)
    #expect(hostSigningSeed == Data(repeating: 0, count: 32))
    let guest = try verifyLinuxVzTelemetryGuestReceipt(
        guestData,
        challenge: challenge,
        runSpec: runSpec,
        backend: backend,
        verifyingKey: guestPrivate.publicKey.rawRepresentation,
        expectedClaims: guestClaims
    )
    let host = try verifyLinuxVzTelemetryHostReceipt(
        hostData,
        challenge: challenge,
        runSpec: runSpec,
        backend: backend,
        verifyingKey: hostPrivate.publicKey.rawRepresentation,
        expectedClaims: hostClaims
    )
    _ = try verifyLinuxVzTelemetryHostReceipt(
        signedHostData,
        challenge: challenge,
        runSpec: runSpec,
        backend: backend,
        verifyingKey: hostPrivate.publicKey.rawRepresentation,
        expectedClaims: hostClaims
    )
    #expect(!guest.packageExecutionAuthorityPermitted)
    #expect(!host.packageExecutionAuthorityPermitted)
    #expect(guest.challengeSHA256 == challenge.challengeSHA256)
    #expect(host.challengeSHA256 == challenge.challengeSHA256)
    let completeCase = try verifyLinuxVzObservationCompleteConformanceCase(
        challenge: challenge,
        runSpec: runSpec,
        backend: backend,
        guest: guest,
        host: host
    )
    #expect(completeCase.guestReceiptPresent)
    #expect(completeCase.hostReceiptPresent)
    #expect(!completeCase.packageExecutionAuthorityPermitted)

    #expect(throws: LinuxVzTelemetryConformanceEvidenceError.invalidReceipt) {
        try verifyLinuxVzTelemetryHostReceipt(
            guestData,
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            verifyingKey: hostPrivate.publicKey.rawRepresentation,
            expectedClaims: hostClaims
        )
    }

    var executing = guestReceipt
    executing["package_execution"] = "enabled"
    #expect(throws: LinuxVzTelemetryConformanceEvidenceError.invalidReceipt) {
        try verifyLinuxVzTelemetryGuestReceipt(
            try canonicalJSONData(executing),
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            verifyingKey: guestPrivate.publicKey.rawRepresentation,
            expectedClaims: guestClaims
        )
    }

    var missingSensor = guestReceipt
    var sensors = try #require(missingSensor["observed_sensors"] as? [String])
    sensors.removeLast()
    missingSensor["observed_sensors"] = sensors
    #expect(throws: LinuxVzTelemetryConformanceEvidenceError.invalidReceipt) {
        try verifyLinuxVzTelemetryGuestReceipt(
            try canonicalJSONData(missingSensor),
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            verifyingKey: guestPrivate.publicKey.rawRepresentation,
            expectedClaims: guestClaims
        )
    }

    var forwarded = hostReceipt
    forwarded["external_frames_forwarded"] = "1"
    #expect(throws: LinuxVzTelemetryConformanceEvidenceError.invalidReceipt) {
        try verifyLinuxVzTelemetryHostReceipt(
            try canonicalJSONData(forwarded),
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            verifyingKey: hostPrivate.publicKey.rawRepresentation,
            expectedClaims: hostClaims
        )
    }

    var badSignature = guestReceipt
    badSignature["signature_ed25519_hex"] = String(repeating: "00", count: 64)
    #expect(throws: LinuxVzTelemetryConformanceEvidenceError.signatureFailed) {
        try verifyLinuxVzTelemetryGuestReceipt(
            try canonicalJSONData(badSignature),
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            verifyingKey: guestPrivate.publicKey.rawRepresentation,
            expectedClaims: guestClaims
        )
    }

    #expect(throws: LinuxVzTelemetryConformanceEvidenceError.publicKeyMismatch) {
        try verifyLinuxVzTelemetryGuestReceipt(
            guestData,
            challenge: challenge,
            runSpec: runSpec,
            backend: backend,
            verifyingKey: hostPrivate.publicKey.rawRepresentation,
            expectedClaims: guestClaims
        )
    }
}

@Test func linuxVzQualificationRecordMatchesRustButParsingCannotGrantAuthority() throws {
    let guestPrivate = try Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(repeating: 0x61, count: 32)
    )
    let hostPrivate = try Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(repeating: 0x62, count: 32)
    )
    let base = try linuxVzConformanceFixture()
    let requirementsSHA256 = try #require(
        base["telemetry_requirements_sha256"] as? String
    )
    var backendValue = try #require(base["backend_identity"] as? [String: Any])
    backendValue["guest_evidence_public_key_sha256"] = sha256(
        guestPrivate.publicKey.rawRepresentation
    )
    backendValue["host_evidence_public_key_sha256"] = sha256(
        hostPrivate.publicKey.rawRepresentation
    )
    let backendData = try canonicalJSONData(backendValue)
    let backendSHA256 = sha256(backendData)
    let backend = try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
        backendData,
        expectedTelemetryRequirementsSHA256: requirementsSHA256
    )
    var bindings: [[String: Any]] = []
    for (index, fixtureCase) in linuxVzAllTelemetryConformanceCasesV1().enumerated() {
        let fixture = try #require(linuxVzConformanceFixture(fixtureCase))
        let terminal = try #require(linuxVzConformanceExpectedTerminal(fixtureCase))
        var runValue = try linuxVzConformanceFixture(
            runID: "linux-vz-qualification-run-\(index)",
            evidenceID: "linux-vz-qualification-evidence-\(index)"
        )
        runValue["backend_identity"] = backendValue
        runValue["backend_identity_sha256"] = backendSHA256
        runValue["fixture_case"] = fixtureCase
        runValue["fixture"] = fixture
        runValue["expected_terminal"] = terminal
        let expectedSensors = linuxVzConformanceExpectedSensors(fixture) ?? []
        #expect(!expectedSensors.isEmpty)
        runValue["expected_sensors"] = expectedSensors
        let runSpec = try decodeLinuxVzTelemetryConformanceRunSpec(
            try canonicalJSONData(runValue)
        )
        let nonceByte = String(format: "%02x", index + 1)
        let challengeValue: [String: Any] = [
            "schema_version": linuxVzTelemetryConformanceChallengeSchemaV1,
            "nonce_hex": String(repeating: nonceByte, count: 32),
            "challenge_purpose": "trusted_inert_telemetry_conformance_only",
            "run_spec_sha256": runSpec.runSpecSHA256,
            "backend_identity_sha256": backend.identitySHA256,
            "telemetry_requirements_sha256": requirementsSHA256,
            "clone_binding_sha256": sha256(
                Data("qualification clone \(index)".utf8)
            ),
            "guest_evidence_public_key_sha256": backend.guestEvidencePublicKeySHA256,
            "host_evidence_public_key_sha256": backend.hostEvidencePublicKeySHA256,
            "package_execution": "disabled",
            "sync_back_policy": "structurally_absent"
        ]
        let challenge = try decodeLinuxVzTelemetryConformanceChallenge(
            try canonicalJSONData(challengeValue),
            expectedRunSpec: runSpec,
            expectedBackend: backend
        )
        bindings.append([
            "fixture_case": fixtureCase,
            "challenge_sha256": challenge.challengeSHA256,
            "run_spec_sha256": runSpec.runSpecSHA256,
            "clone_binding_sha256": challenge.cloneBindingSHA256,
            "guest_receipt_present": ![
                "guest_sensor_death", "channel_interruption", "vm_stop"
            ].contains(fixtureCase)
        ])
    }
    let evidenceSetSHA256 = sha256(try canonicalJSONData(bindings))
    var record: [String: Any] = [
        "schema_version": linuxVzQualifiedTelemetryBackendSchemaV1,
        "qualification_state": "complete_inert_conformance_matrix_verified",
        "backend_identity": backendValue,
        "backend_identity_sha256": backendSHA256,
        "telemetry_requirements_sha256": requirementsSHA256,
        "conformance_cases": bindings,
        "conformance_case_count": "38",
        "conformance_evidence_set_sha256": evidenceSetSHA256,
        "clone_policy": "one_unique_clone_per_case_destroyed",
        "execution_eligibility": "typed_package_scenario_authority_request_only",
        "execution_authority_issued": false,
        "sync_back_policy": "structurally_absent"
    ]
    let data = try canonicalJSONData(record)
    let parsed = try decodeLinuxVzTelemetryQualificationRecord(data)
    #expect(
        parsed.recordSHA256
            == "sha256:455c3566f07451d9a763ba594652938aced20bd8f90eb7c712995a8e13e91c1a"
    )
    #expect(parsed.caseCount == 38)
    #expect(!parsed.executionAuthorityRequestPermitted)
    #expect(!parsed.packageExecutionAuthorityPermitted)
    #expect(!parsed.syncBackPermitted)

    var missing = record
    var missingCases = bindings
    missingCases.removeLast()
    missing["conformance_cases"] = missingCases
    #expect(throws: LinuxVzTelemetryQualificationRecordError.incompleteMatrix) {
        try decodeLinuxVzTelemetryQualificationRecord(try canonicalJSONData(missing))
    }

    var reused = record
    var reusedCases = bindings
    reusedCases[1]["clone_binding_sha256"] = reusedCases[0]["clone_binding_sha256"]
    reused["conformance_cases"] = reusedCases
    reused["conformance_evidence_set_sha256"] = sha256(
        try canonicalJSONData(reusedCases)
    )
    #expect(throws: LinuxVzTelemetryQualificationRecordError.reusedIdentity) {
        try decodeLinuxVzTelemetryQualificationRecord(try canonicalJSONData(reused))
    }

    record["execution_authority_issued"] = true
    #expect(throws: LinuxVzTelemetryQualificationRecordError.invalidSchema) {
        try decodeLinuxVzTelemetryQualificationRecord(try canonicalJSONData(record))
    }
}

@Test func linuxVzConformanceRunSpecRejectsSensorGapsExecutionAndRebinding() throws {
    let fixture = try linuxVzConformanceFixture()

    var missing = fixture
    var sensors = try #require(missing["expected_sensors"] as? [String])
    sensors.removeLast()
    missing["expected_sensors"] = sensors
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.invalidSchema) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(missing))
    }

    var executing = fixture
    executing["package_execution"] = "enabled"
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.invalidSchema) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(executing))
    }

    var relabeled = fixture
    relabeled["fixture_case"] = "mmap_access"
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.invalidSchema) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(relabeled))
    }

    var substituted = fixture
    substituted["fixture_binary_sha256"] = sha256(Data("unmeasured fixture binary".utf8))
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.requirementsMismatch) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(substituted))
    }

    var unknown = fixture
    unknown["execute"] = true
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.invalidSchema) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(unknown))
    }

    var rebound = fixture
    rebound["backend_identity_sha256"] = sha256(Data("rebound backend".utf8))
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.requirementsMismatch) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(rebound))
    }

    var requirementsGap = fixture
    var requirements = try #require(
        requirementsGap["telemetry_requirements"] as? [String: Any]
    )
    var required = try #require(requirements["required_sensors"] as? [String])
    required.removeLast()
    requirements["required_sensors"] = required
    requirementsGap["telemetry_requirements"] = requirements
    requirementsGap["telemetry_requirements_sha256"] = sha256(
        try canonicalJSONData(requirements)
    )
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.requirementsMismatch) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(requirementsGap))
    }
}

private func linuxVzConformanceFixture(
    runID: String = "linux-vz-conformance-run-golden",
    evidenceID: String = "linux-vz-conformance-evidence-golden"
) throws -> [String: Any] {
    let requirements = linuxVzRequirementsFixture()
    let requirementsData = try canonicalJSONData(requirements)
    let requirementsSHA256 = sha256(requirementsData)
    let backend = linuxVzConformanceBackendFixture(
        requirementsSHA256: requirementsSHA256
    )
    let backendData = try canonicalJSONData(backend)
    let fixtureBinarySHA256 = try #require(backend["guest_runner_sha256"] as? String)
    return [
        "schema_version": linuxVzTelemetryConformanceRunSpecSchemaV1,
        "canonicalization": "rfc8785.jcs.v1",
        "conformance_run_id": runID,
        "evidence_id": evidenceID,
        "fixture": "network_intent",
        "fixture_case": "dns_plaintext",
        "fixture_binary_sha256": fixtureBinarySHA256,
        "expected_terminal": "observation_complete",
        "expected_sensors": [
            "guest_network_intent", "host_raw_frames", "dns_sinkhole", "http_sinkhole",
            "process_listener_diff", "sensor_health_heartbeat", "dropped_event_accounting"
        ],
        "telemetry_requirements": requirements,
        "telemetry_requirements_sha256": requirementsSHA256,
        "backend_identity": backend,
        "backend_identity_sha256": sha256(backendData),
        "execution_posture": "trusted_inert_fixture_only_no_package_code",
        "package_execution": "disabled",
        "network_topology": "host_raw_frame_sinkhole_no_external_route",
        "external_network": "no_external_route",
        "clone_policy": "one_boot_one_fixture_destroy_clone",
        "sync_back_policy": "structurally_absent",
        "limits": [
            "wall_clock_millis": "30000",
            "max_guest_events": "1000000",
            "max_host_frames": "65536",
            "max_evidence_bytes": "16777216"
        ],
        "guest_protocol": linuxVzTelemetryConformanceProtocolV1
    ]
}

private func linuxVzRequirementsFixture() -> [String: Any] {
    [
        "schema_version": linuxVzProtectedTelemetryRequirementsSchemaV1,
        "backend_class": "linux_vz_bulk",
        "required_sensors": linuxVzRequiredTelemetrySensorsV1(),
        "network_topology": "host_raw_frame_sinkhole_no_external_route",
        "drop_policy": "incomplete_on_any_gap",
        "process_attribution": "cgroup_and_kernel_lineage",
        "file_observation": "fanotify_permission_plus_bpf_mmap",
        "evidence_authority": "guest_signed_and_host_corroborated",
        "package_privilege": "dedicated_uid_gid_no_capabilities",
        "scenario_reuse": "one_boot_one_scenario_destroy_clone",
        "sync_back_policy": "structurally_absent",
        "limitations": [
            "encrypted_payload_content_not_decrypted",
            "fanotify_mmap_requires_bpf_corroboration",
            "guest_kernel_compromise_can_suppress_guest_sensors_host_frames_remain"
        ]
    ]
}

private func linuxVzConformanceBackendFixture(
    requirementsSHA256: String
) -> [String: Any] {
    [
        "schema_version": linuxVzTelemetryBackendIdentitySchemaV1,
        "qualification_state": "candidate_unqualified",
        "base_generation_id": "linux-vz-base-generation-inert-v1",
        "linux_distribution_id": "whoathere-linux-inert-v1",
        "kernel_release": "6.12.0-whoathere-inert-v1",
        "kernel_image_sha256": sha256(Data("inert kernel image".utf8)),
        "initramfs_sha256": sha256(Data("inert initramfs".utf8)),
        "root_disk_sha256": sha256(Data("inert root disk".utf8)),
        "kernel_config_sha256": sha256(Data("inert kernel config".utf8)),
        "btf_sha256": sha256(Data("inert kernel btf".utf8)),
        "guest_runner_sha256": sha256(Data("inert guest runner".utf8)),
        "guest_sensor_sha256": sha256(Data("inert guest sensor".utf8)),
        "guest_bpf_bundle_sha256": sha256(Data("inert guest bpf bundle".utf8)),
        "guest_sensor_configuration_sha256": sha256(
            Data("inert guest sensor configuration".utf8)
        ),
        "guest_evidence_public_key_sha256": sha256(
            Data("inert guest evidence public key".utf8)
        ),
        "host_helper_sha256": sha256(Data("inert host helper".utf8)),
        "host_packet_sensor_sha256": sha256(Data("inert host packet sensor".utf8)),
        "host_packet_sensor_configuration_sha256": sha256(
            Data("inert host packet configuration".utf8)
        ),
        "host_evidence_public_key_sha256": sha256(
            Data("inert host evidence public key".utf8)
        ),
        "telemetry_requirements_sha256": requirementsSHA256,
        "package_uid": "499",
        "package_gid": "499"
    ]
}
