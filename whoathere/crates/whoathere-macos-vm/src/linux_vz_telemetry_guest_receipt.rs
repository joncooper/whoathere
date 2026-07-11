use crate::{
    LinuxVzTelemetryConformanceObservedTerminalV1, LinuxVzTelemetryConformancePackageExecutionV1,
    MacosLinuxVzTelemetryConformanceChallengeV1, MacosLinuxVzTelemetryConformanceRunSpecV1,
    MacosLinuxVzTelemetryEvidenceErrorV1, UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::{ArtifactProtectedTelemetrySensorV1, ArtifactTelemetrySyncBackPolicyV1};
use zeroize::Zeroize;

pub const MACOS_LINUX_VZ_TELEMETRY_GUEST_RECEIPT_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_telemetry_guest_receipt.v1";
const GUEST_RECEIPT_SIGNATURE_DOMAIN_V1: &[u8] =
    b"whoathere.macos_linux_vz_telemetry_guest_receipt.signature.v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzTelemetryGuestObservationClaimsV1 {
    evidence_payload_sha256: Sha256Digest,
    evidence_byte_length: u64,
    event_sequence_start: u64,
    event_sequence_end: u64,
    event_count: u64,
    heartbeat_count: u64,
    dropped_event_count: u64,
    sensor_healthy: bool,
    evidence_truncated: bool,
    descendant_teardown_complete: bool,
    observed_terminal: LinuxVzTelemetryConformanceObservedTerminalV1,
}

impl LinuxVzTelemetryGuestObservationClaimsV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_payload_sha256: Sha256Digest,
        evidence_byte_length: u64,
        event_sequence_start: u64,
        event_sequence_end: u64,
        event_count: u64,
        heartbeat_count: u64,
        dropped_event_count: u64,
        sensor_healthy: bool,
        evidence_truncated: bool,
        descendant_teardown_complete: bool,
        observed_terminal: LinuxVzTelemetryConformanceObservedTerminalV1,
    ) -> Result<Self, MacosLinuxVzTelemetryEvidenceErrorV1> {
        if evidence_byte_length == 0
            || event_count == 0
            || heartbeat_count == 0
            || event_sequence_end < event_sequence_start
        {
            return Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt);
        }
        Ok(Self {
            evidence_payload_sha256,
            evidence_byte_length,
            event_sequence_start,
            event_sequence_end,
            event_count,
            heartbeat_count,
            dropped_event_count,
            sensor_healthy,
            evidence_truncated,
            descendant_teardown_complete,
            observed_terminal,
        })
    }

    pub fn evidence_payload_sha256(&self) -> &Sha256Digest {
        &self.evidence_payload_sha256
    }

    pub fn dropped_event_count(&self) -> u64 {
        self.dropped_event_count
    }

    pub fn sensor_healthy(&self) -> bool {
        self.sensor_healthy
    }

    pub fn evidence_truncated(&self) -> bool {
        self.evidence_truncated
    }

    pub fn descendant_teardown_complete(&self) -> bool {
        self.descendant_teardown_complete
    }

    pub fn observed_terminal(&self) -> LinuxVzTelemetryConformanceObservedTerminalV1 {
        self.observed_terminal
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedGuestReceiptWireV1 {
    schema_version: String,
    authority: String,
    challenge_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    backend_identity_sha256: Sha256Digest,
    telemetry_requirements_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    fixture: crate::LinuxVzTelemetryConformanceFixtureV1,
    fixture_case: crate::LinuxVzTelemetryConformanceCaseV1,
    fixture_binary_sha256: Sha256Digest,
    expected_terminal: crate::LinuxVzTelemetryConformanceExpectedTerminalV1,
    observed_terminal: LinuxVzTelemetryConformanceObservedTerminalV1,
    observed_sensors: Vec<ArtifactProtectedTelemetrySensorV1>,
    evidence_payload_sha256: Sha256Digest,
    evidence_byte_length: String,
    event_sequence_start: String,
    event_sequence_end: String,
    event_count: String,
    heartbeat_count: String,
    dropped_event_count: String,
    sensor_healthy: bool,
    evidence_truncated: bool,
    descendant_teardown_complete: bool,
    package_uid: String,
    package_gid: String,
    package_capabilities_present: bool,
    public_network_reachable: bool,
    package_execution: LinuxVzTelemetryConformancePackageExecutionV1,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestReceiptWireV1 {
    schema_version: String,
    authority: String,
    challenge_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    backend_identity_sha256: Sha256Digest,
    telemetry_requirements_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    fixture: crate::LinuxVzTelemetryConformanceFixtureV1,
    fixture_case: crate::LinuxVzTelemetryConformanceCaseV1,
    fixture_binary_sha256: Sha256Digest,
    expected_terminal: crate::LinuxVzTelemetryConformanceExpectedTerminalV1,
    observed_terminal: LinuxVzTelemetryConformanceObservedTerminalV1,
    observed_sensors: Vec<ArtifactProtectedTelemetrySensorV1>,
    evidence_payload_sha256: Sha256Digest,
    evidence_byte_length: String,
    event_sequence_start: String,
    event_sequence_end: String,
    event_count: String,
    heartbeat_count: String,
    dropped_event_count: String,
    sensor_healthy: bool,
    evidence_truncated: bool,
    descendant_teardown_complete: bool,
    package_uid: String,
    package_gid: String,
    package_capabilities_present: bool,
    public_network_reachable: bool,
    package_execution: LinuxVzTelemetryConformancePackageExecutionV1,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
    signature_ed25519_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLinuxVzTelemetryGuestReceiptV1 {
    challenge_sha256: Sha256Digest,
    observed_sensors: Vec<ArtifactProtectedTelemetrySensorV1>,
    claims: LinuxVzTelemetryGuestObservationClaimsV1,
}

impl VerifiedLinuxVzTelemetryGuestReceiptV1 {
    pub fn challenge_sha256(&self) -> &Sha256Digest {
        &self.challenge_sha256
    }

    pub fn observed_sensors(&self) -> &[ArtifactProtectedTelemetrySensorV1] {
        &self.observed_sensors
    }

    pub fn claims(&self) -> &LinuxVzTelemetryGuestObservationClaimsV1 {
        &self.claims
    }

    pub const fn package_execution_authority_permitted(&self) -> bool {
        false
    }
}

pub fn sign_macos_linux_vz_telemetry_guest_receipt_v1(
    challenge: &MacosLinuxVzTelemetryConformanceChallengeV1,
    run_spec: &MacosLinuxVzTelemetryConformanceRunSpecV1,
    backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    claims: &LinuxVzTelemetryGuestObservationClaimsV1,
    mut signing_seed: [u8; 32],
) -> Result<Vec<u8>, MacosLinuxVzTelemetryEvidenceErrorV1> {
    validate_context_v1(challenge, run_spec, backend)?;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    signing_seed.zeroize();
    if Sha256Digest::from_bytes(signing_key.verifying_key().as_bytes())
        != *challenge.guest_evidence_public_key_sha256()
    {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::PublicKeyMismatch);
    }
    let unsigned = unsigned_guest_receipt_v1(challenge, run_spec, backend, claims);
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::Serialization)?;
    let signature = signing_key.sign(&signature_message_v1(
        challenge.canonical_json_v1(),
        &unsigned_bytes,
    ));
    let receipt = GuestReceiptWireV1::from_unsigned(unsigned, lower_hex_v1(&signature.to_bytes()));
    let bytes = serde_json_canonicalizer::to_vec(&receipt)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::Serialization)?;
    if bytes.len() > crate::MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1 {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::LimitExceeded);
    }
    Ok(bytes)
}

pub fn verify_macos_linux_vz_telemetry_guest_receipt_v1(
    challenge: &MacosLinuxVzTelemetryConformanceChallengeV1,
    run_spec: &MacosLinuxVzTelemetryConformanceRunSpecV1,
    backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    receipt_bytes: &[u8],
    verifying_key_bytes: [u8; 32],
    expected_claims: &LinuxVzTelemetryGuestObservationClaimsV1,
) -> Result<VerifiedLinuxVzTelemetryGuestReceiptV1, MacosLinuxVzTelemetryEvidenceErrorV1> {
    validate_context_v1(challenge, run_spec, backend)?;
    if receipt_bytes.is_empty() {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::Empty);
    }
    if receipt_bytes.len() > crate::MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1 {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::LimitExceeded);
    }
    if Sha256Digest::from_bytes(&verifying_key_bytes)
        != *challenge.guest_evidence_public_key_sha256()
    {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::PublicKeyMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::PublicKeyMismatch)?;
    if verifying_key.is_weak() {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::PublicKeyMismatch);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(receipt_bytes);
    let receipt = GuestReceiptWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)?;
    deserializer
        .end()
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)?;
    let canonical = serde_json_canonicalizer::to_vec(&receipt)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::Serialization)?;
    if canonical != receipt_bytes || !valid_signature_hex_v1(&receipt.signature_ed25519_hex) {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::NonCanonical);
    }
    let signature_hex = receipt.signature_ed25519_hex.clone();
    let unsigned = receipt.into_unsigned();
    let expected = unsigned_guest_receipt_v1(challenge, run_spec, backend, expected_claims);
    if unsigned != expected {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt);
    }
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::Serialization)?;
    let signature = Signature::from_bytes(&decode_signature_v1(&signature_hex)?);
    verifying_key
        .verify_strict(
            &signature_message_v1(challenge.canonical_json_v1(), &unsigned_bytes),
            &signature,
        )
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::SignatureFailed)?;
    Ok(VerifiedLinuxVzTelemetryGuestReceiptV1 {
        challenge_sha256: challenge.challenge_sha256().clone(),
        observed_sensors: run_spec.expected_guest_sensors_v1(),
        claims: expected_claims.clone(),
    })
}

fn validate_context_v1(
    challenge: &MacosLinuxVzTelemetryConformanceChallengeV1,
    run_spec: &MacosLinuxVzTelemetryConformanceRunSpecV1,
    backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
) -> Result<(), MacosLinuxVzTelemetryEvidenceErrorV1> {
    if challenge.run_spec_sha256() != run_spec.run_spec_sha256() {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::RunSpecMismatch);
    }
    let backend_sha256 = backend
        .identity_sha256_v1()
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::BackendMismatch)?;
    if challenge.backend_identity_sha256() != &backend_sha256
        || run_spec.backend_identity_sha256() != &backend_sha256
        || challenge.telemetry_requirements_sha256() != backend.telemetry_requirements_sha256()
        || challenge.clone_binding_sha256().as_str().is_empty()
        || run_spec.package_execution_authority_permitted()
        || backend.execution_authority_permitted()
    {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::BackendMismatch);
    }
    Ok(())
}

fn unsigned_guest_receipt_v1(
    challenge: &MacosLinuxVzTelemetryConformanceChallengeV1,
    run_spec: &MacosLinuxVzTelemetryConformanceRunSpecV1,
    backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    claims: &LinuxVzTelemetryGuestObservationClaimsV1,
) -> UnsignedGuestReceiptWireV1 {
    UnsignedGuestReceiptWireV1 {
        schema_version: MACOS_LINUX_VZ_TELEMETRY_GUEST_RECEIPT_SCHEMA_V1.to_string(),
        authority: "guest_protected_sensors".to_string(),
        challenge_sha256: challenge.challenge_sha256().clone(),
        run_spec_sha256: run_spec.run_spec_sha256().clone(),
        backend_identity_sha256: run_spec.backend_identity_sha256().clone(),
        telemetry_requirements_sha256: run_spec.telemetry_requirements_sha256().clone(),
        clone_binding_sha256: challenge.clone_binding_sha256().clone(),
        fixture: run_spec.fixture(),
        fixture_case: run_spec.fixture_case(),
        fixture_binary_sha256: run_spec.fixture_binary_sha256().clone(),
        expected_terminal: run_spec.expected_terminal(),
        observed_terminal: claims.observed_terminal,
        observed_sensors: run_spec.expected_guest_sensors_v1(),
        evidence_payload_sha256: claims.evidence_payload_sha256.clone(),
        evidence_byte_length: claims.evidence_byte_length.to_string(),
        event_sequence_start: claims.event_sequence_start.to_string(),
        event_sequence_end: claims.event_sequence_end.to_string(),
        event_count: claims.event_count.to_string(),
        heartbeat_count: claims.heartbeat_count.to_string(),
        dropped_event_count: claims.dropped_event_count.to_string(),
        sensor_healthy: claims.sensor_healthy,
        evidence_truncated: claims.evidence_truncated,
        descendant_teardown_complete: claims.descendant_teardown_complete,
        package_uid: backend.package_uid().to_string(),
        package_gid: backend.package_gid().to_string(),
        package_capabilities_present: false,
        public_network_reachable: false,
        package_execution: LinuxVzTelemetryConformancePackageExecutionV1::Disabled,
        sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
    }
}

impl GuestReceiptWireV1 {
    fn from_unsigned(value: UnsignedGuestReceiptWireV1, signature_ed25519_hex: String) -> Self {
        Self {
            schema_version: value.schema_version,
            authority: value.authority,
            challenge_sha256: value.challenge_sha256,
            run_spec_sha256: value.run_spec_sha256,
            backend_identity_sha256: value.backend_identity_sha256,
            telemetry_requirements_sha256: value.telemetry_requirements_sha256,
            clone_binding_sha256: value.clone_binding_sha256,
            fixture: value.fixture,
            fixture_case: value.fixture_case,
            fixture_binary_sha256: value.fixture_binary_sha256,
            expected_terminal: value.expected_terminal,
            observed_terminal: value.observed_terminal,
            observed_sensors: value.observed_sensors,
            evidence_payload_sha256: value.evidence_payload_sha256,
            evidence_byte_length: value.evidence_byte_length,
            event_sequence_start: value.event_sequence_start,
            event_sequence_end: value.event_sequence_end,
            event_count: value.event_count,
            heartbeat_count: value.heartbeat_count,
            dropped_event_count: value.dropped_event_count,
            sensor_healthy: value.sensor_healthy,
            evidence_truncated: value.evidence_truncated,
            descendant_teardown_complete: value.descendant_teardown_complete,
            package_uid: value.package_uid,
            package_gid: value.package_gid,
            package_capabilities_present: value.package_capabilities_present,
            public_network_reachable: value.public_network_reachable,
            package_execution: value.package_execution,
            sync_back_policy: value.sync_back_policy,
            signature_ed25519_hex,
        }
    }

    fn into_unsigned(self) -> UnsignedGuestReceiptWireV1 {
        UnsignedGuestReceiptWireV1 {
            schema_version: self.schema_version,
            authority: self.authority,
            challenge_sha256: self.challenge_sha256,
            run_spec_sha256: self.run_spec_sha256,
            backend_identity_sha256: self.backend_identity_sha256,
            telemetry_requirements_sha256: self.telemetry_requirements_sha256,
            clone_binding_sha256: self.clone_binding_sha256,
            fixture: self.fixture,
            fixture_case: self.fixture_case,
            fixture_binary_sha256: self.fixture_binary_sha256,
            expected_terminal: self.expected_terminal,
            observed_terminal: self.observed_terminal,
            observed_sensors: self.observed_sensors,
            evidence_payload_sha256: self.evidence_payload_sha256,
            evidence_byte_length: self.evidence_byte_length,
            event_sequence_start: self.event_sequence_start,
            event_sequence_end: self.event_sequence_end,
            event_count: self.event_count,
            heartbeat_count: self.heartbeat_count,
            dropped_event_count: self.dropped_event_count,
            sensor_healthy: self.sensor_healthy,
            evidence_truncated: self.evidence_truncated,
            descendant_teardown_complete: self.descendant_teardown_complete,
            package_uid: self.package_uid,
            package_gid: self.package_gid,
            package_capabilities_present: self.package_capabilities_present,
            public_network_reachable: self.public_network_reachable,
            package_execution: self.package_execution,
            sync_back_policy: self.sync_back_policy,
        }
    }
}

fn signature_message_v1(challenge: &[u8], unsigned_receipt: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        GUEST_RECEIPT_SIGNATURE_DOMAIN_V1.len() + challenge.len() + 1 + unsigned_receipt.len(),
    );
    message.extend_from_slice(GUEST_RECEIPT_SIGNATURE_DOMAIN_V1);
    message.extend_from_slice(challenge);
    message.push(0);
    message.extend_from_slice(unsigned_receipt);
    message
}

fn lower_hex_v1(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

fn valid_signature_hex_v1(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_signature_v1(value: &str) -> Result<[u8; 64], MacosLinuxVzTelemetryEvidenceErrorV1> {
    if !valid_signature_hex_v1(value) {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt);
    }
    let mut decoded = [0_u8; 64];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)?;
    }
    Ok(decoded)
}
