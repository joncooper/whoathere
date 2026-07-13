use crate::{
    decode_linux_vz_package_runtime_qualification_request_v1,
    decode_linux_vz_package_runtime_qualification_response_v1,
    MacosLinuxVzPackageRuntimeQualificationRequestV1, MacosLinuxVzTelemetryEvidenceErrorV1,
    MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use whoathere_artifact::Sha256Digest;

pub const MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_EVIDENCE_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_package_runtime_qualification_host_evidence.v1";
pub const MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_RECEIPT_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_package_runtime_qualification_host_receipt.v1";
pub const MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_EVIDENCE_BYTES_V1: usize =
    1024 * 1024;
pub const MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_RECEIPT_BYTES_V1: usize =
    1024 * 1024;
const RUNTIME_QUALIFICATION_HOST_RECEIPT_SIGNATURE_DOMAIN_V1: &[u8] =
    b"whoathere.macos_linux_vz_package_runtime_qualification_host_receipt.signature.v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMacosLinuxVzPackageRuntimeQualificationHostReceiptV1 {
    qualification_request_sha256: Sha256Digest,
    host_evidence_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
}

impl VerifiedMacosLinuxVzPackageRuntimeQualificationHostReceiptV1 {
    pub fn qualification_request_sha256(&self) -> &Sha256Digest {
        &self.qualification_request_sha256
    }

    pub fn host_evidence_sha256(&self) -> &Sha256Digest {
        &self.host_evidence_sha256
    }

    pub fn clone_binding_sha256(&self) -> &Sha256Digest {
        &self.clone_binding_sha256
    }

    pub const fn execution_authority_permitted(&self) -> bool {
        false
    }

    pub const fn package_execution_permitted(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

pub fn verify_macos_linux_vz_package_runtime_qualification_host_receipt_v1(
    request: &MacosLinuxVzPackageRuntimeQualificationRequestV1,
    request_frame: &[u8],
    response_frame: &[u8],
    host_evidence_bytes: &[u8],
    host_receipt_bytes: &[u8],
    host_verifying_key_bytes: [u8; 32],
) -> Result<
    VerifiedMacosLinuxVzPackageRuntimeQualificationHostReceiptV1,
    MacosLinuxVzTelemetryEvidenceErrorV1,
> {
    if host_evidence_bytes.is_empty() || host_receipt_bytes.is_empty() {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::Empty);
    }
    if host_evidence_bytes.len()
        > MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_EVIDENCE_BYTES_V1
        || host_receipt_bytes.len()
            > MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_RECEIPT_BYTES_V1
    {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::LimitExceeded);
    }
    if decode_linux_vz_package_runtime_qualification_request_v1(request_frame)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)?
        != request.canonical_json_v1()
    {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt);
    }
    let response = decode_linux_vz_package_runtime_qualification_response_v1(response_frame)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)?;
    if response.probe_report() != MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1 {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt);
    }

    let evidence = canonical_value_v1(host_evidence_bytes)?;
    let evidence_object = evidence
        .as_object()
        .ok_or(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)?;
    let serial_log_sha256 = evidence_object
        .get("serial_log_sha256")
        .and_then(Value::as_str)
        .filter(|value| valid_digest_v1(value))
        .ok_or(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)?;
    let expected_evidence = expected_host_evidence_v1(
        request,
        request_frame,
        response_frame,
        response.process_evidence(),
        response.guest_receipt(),
        serial_log_sha256,
    );
    if evidence != expected_evidence {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt);
    }
    let host_evidence_sha256 = Sha256Digest::from_bytes(host_evidence_bytes);

    if Sha256Digest::from_bytes(&host_verifying_key_bytes)
        != *request.host_evidence_public_key_sha256()
    {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::PublicKeyMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&host_verifying_key_bytes)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::PublicKeyMismatch)?;
    if verifying_key.is_weak() {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::PublicKeyMismatch);
    }

    let receipt = canonical_value_v1(host_receipt_bytes)?;
    let mut unsigned = receipt
        .as_object()
        .cloned()
        .ok_or(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)?;
    let signature_hex = unsigned
        .remove("signature_ed25519_hex")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)?;
    let expected_unsigned = expected_unsigned_host_receipt_v1(
        request,
        &host_evidence_sha256,
        request_frame,
        response_frame,
        response.process_evidence(),
        response.guest_receipt(),
        serial_log_sha256,
    );
    if Value::Object(unsigned.clone()) != expected_unsigned {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt);
    }
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&Value::Object(unsigned))
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::Serialization)?;
    let signature = Signature::from_bytes(&decode_signature_v1(&signature_hex)?);
    verifying_key
        .verify_strict(
            &signature_message_v1(
                request.canonical_json_v1(),
                host_evidence_bytes,
                &unsigned_bytes,
            ),
            &signature,
        )
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::SignatureFailed)?;
    Ok(
        VerifiedMacosLinuxVzPackageRuntimeQualificationHostReceiptV1 {
            qualification_request_sha256: request.request_sha256().clone(),
            host_evidence_sha256,
            clone_binding_sha256: request.clone_binding_sha256().clone(),
        },
    )
}

fn expected_host_evidence_v1(
    request: &MacosLinuxVzPackageRuntimeQualificationRequestV1,
    request_frame: &[u8],
    response_frame: &[u8],
    process_evidence: &[u8],
    guest_receipt: &[u8],
    serial_log_sha256: &str,
) -> Value {
    json!({
        "schema_version": MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_EVIDENCE_SCHEMA_V1,
        "authority": "host_vm_network_and_clone_lifecycle",
        "qualification_request_sha256": request.request_sha256(),
        "request_frame_sha256": Sha256Digest::from_bytes(request_frame),
        "response_frame_sha256": Sha256Digest::from_bytes(response_frame),
        "guest_receipt_sha256": Sha256Digest::from_bytes(guest_receipt),
        "process_evidence_sha256": Sha256Digest::from_bytes(process_evidence),
        "probe_report_sha256": Sha256Digest::from_bytes(
            MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1
        ),
        "serial_log_sha256": serial_log_sha256,
        "clone_binding_sha256": request.clone_binding_sha256(),
        "events": [
            {"event": "clone_created_and_bound", "sequence": "1"},
            {"event": "vm_started", "sequence": "2"},
            {"event": "guest_response_completed", "sequence": "3"},
            {"event": "raw_frame_sinkhole_drained", "sequence": "4"},
            {"event": "vm_stopped", "sequence": "5"},
            {"event": "clone_destroyed_after_stop", "sequence": "6"}
        ],
        "event_sequence_start": "1",
        "event_sequence_end": "6",
        "event_count": "6",
        "raw_frame_count": "0",
        "dropped_frame_count": "0",
        "external_frames_forwarded": "0",
        "packet_sensor_healthy": true,
        "guest_channel_terminated": true,
        "vm_started": true,
        "vm_stopped": true,
        "clone_destroyed": true,
        "image_identity_stable": true,
        "public_network_route_present": false,
        "package_execution": false,
        "execution_authority_issued": false,
        "sync_back_policy": "structurally_absent"
    })
}

fn expected_unsigned_host_receipt_v1(
    request: &MacosLinuxVzPackageRuntimeQualificationRequestV1,
    host_evidence_sha256: &Sha256Digest,
    request_frame: &[u8],
    response_frame: &[u8],
    process_evidence: &[u8],
    guest_receipt: &[u8],
    serial_log_sha256: &str,
) -> Value {
    json!({
        "schema_version": MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_RECEIPT_SCHEMA_V1,
        "authority": "host_vm_network_and_clone_lifecycle",
        "qualification_request_sha256": request.request_sha256(),
        "qualified_telemetry_backend_sha256": request.qualified_telemetry_backend_sha256(),
        "backend_identity_sha256": request.backend_identity_sha256(),
        "telemetry_requirements_sha256": request.telemetry_requirements_sha256(),
        "runtime_qualification_initramfs_sha256":
            request.runtime_qualification_initramfs_sha256(),
        "candidate_runtime_rootfs_sha256": request.candidate_runtime_rootfs_sha256(),
        "clone_binding_sha256": request.clone_binding_sha256(),
        "request_challenge_sha256": request.request_challenge_sha256(),
        "host_evidence_sha256": host_evidence_sha256,
        "request_frame_sha256": Sha256Digest::from_bytes(request_frame),
        "response_frame_sha256": Sha256Digest::from_bytes(response_frame),
        "guest_receipt_sha256": Sha256Digest::from_bytes(guest_receipt),
        "process_evidence_sha256": Sha256Digest::from_bytes(process_evidence),
        "serial_log_sha256": serial_log_sha256,
        "observed_sensors": [
            "raw_frame_sinkhole", "vm_lifecycle", "guest_channel_lifecycle",
            "clone_lifecycle", "image_identity"
        ],
        "raw_frame_count": "0",
        "dropped_frame_count": "0",
        "external_frames_forwarded": "0",
        "packet_sensor_healthy": true,
        "guest_channel_terminated": true,
        "vm_started": true,
        "vm_stopped": true,
        "clone_destroyed": true,
        "image_identity_stable": true,
        "public_network_route_present": false,
        "execution_authority_issued": false,
        "package_execution": false,
        "sync_back_policy": "structurally_absent"
    })
}

fn canonical_value_v1(bytes: &[u8]) -> Result<Value, MacosLinuxVzTelemetryEvidenceErrorV1> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::NonCanonical);
    }
    Ok(value)
}

fn signature_message_v1(request: &[u8], evidence: &[u8], unsigned_receipt: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        RUNTIME_QUALIFICATION_HOST_RECEIPT_SIGNATURE_DOMAIN_V1.len()
            + 24
            + request.len()
            + evidence.len()
            + unsigned_receipt.len(),
    );
    message.extend_from_slice(RUNTIME_QUALIFICATION_HOST_RECEIPT_SIGNATURE_DOMAIN_V1);
    message.extend_from_slice(&(request.len() as u64).to_be_bytes());
    message.extend_from_slice(request);
    message.extend_from_slice(&(evidence.len() as u64).to_be_bytes());
    message.extend_from_slice(evidence);
    message.extend_from_slice(&(unsigned_receipt.len() as u64).to_be_bytes());
    message.extend_from_slice(unsigned_receipt);
    message
}

fn decode_signature_v1(value: &str) -> Result<[u8; 64], MacosLinuxVzTelemetryEvidenceErrorV1> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt);
    }
    let mut decoded = [0_u8; 64];
    for (index, output) in decoded.iter_mut().enumerate() {
        let high = decode_nibble_v1(value.as_bytes()[index * 2])?;
        let low = decode_nibble_v1(value.as_bytes()[index * 2 + 1])?;
        *output = (high << 4) | low;
    }
    Ok(decoded)
}

fn decode_nibble_v1(byte: u8) -> Result<u8, MacosLinuxVzTelemetryEvidenceErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt),
    }
}

fn valid_digest_v1(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        decode_macos_linux_vz_package_runtime_qualification_request_v1,
        encode_linux_vz_package_runtime_qualification_request_v1,
        encode_linux_vz_package_runtime_qualification_response_v1,
    };
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn exact_host_lifecycle_receipt_verifies_and_rejects_rebinding() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let request_bytes = request_bytes_v1(&signing_key);
        let request =
            decode_macos_linux_vz_package_runtime_qualification_request_v1(&request_bytes)
                .expect("request");
        let request_frame =
            encode_linux_vz_package_runtime_qualification_request_v1(&request_bytes)
                .expect("request frame");
        let process_evidence = b"inert process evidence";
        let guest_receipt = b"inert guest receipt";
        let response_frame = encode_linux_vz_package_runtime_qualification_response_v1(
            MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1,
            process_evidence,
            guest_receipt,
        )
        .expect("response frame");
        let serial_log_sha256 = Sha256Digest::from_bytes(b"serial log").to_string();
        let evidence_value = expected_host_evidence_v1(
            &request,
            &request_frame,
            &response_frame,
            process_evidence,
            guest_receipt,
            &serial_log_sha256,
        );
        let evidence = serde_json_canonicalizer::to_vec(&evidence_value).expect("evidence");
        let evidence_sha256 = Sha256Digest::from_bytes(&evidence);
        assert_eq!(
            evidence_sha256.to_string(),
            "sha256:2b4e607f017cd84dc667f532fa80c9bb8460f499facb1ddbd6758e3d2612997d"
        );
        let unsigned = expected_unsigned_host_receipt_v1(
            &request,
            &evidence_sha256,
            &request_frame,
            &response_frame,
            process_evidence,
            guest_receipt,
            &serial_log_sha256,
        );
        let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned).expect("unsigned");
        assert_eq!(
            Sha256Digest::from_bytes(&unsigned_bytes).to_string(),
            "sha256:19e145cde9212b195f788f79dc8b6a9bf28fc7214252ee0c0632697d2573d986"
        );
        let mut swift_receipt = unsigned.as_object().cloned().expect("swift receipt object");
        swift_receipt.insert(
            "signature_ed25519_hex".to_string(),
            Value::String(
                "90d579f1142a722e5ccf7a0d55714883d5af147eb8fdb966bfe1aee7d5a122f7233a88aa1c3303bd8ccf9804460d0ff2ff3955da23c2a87cbd846c490a9f2607"
                    .to_string(),
            ),
        );
        let swift_receipt = serde_json_canonicalizer::to_vec(&Value::Object(swift_receipt))
            .expect("swift signed receipt");
        verify_macos_linux_vz_package_runtime_qualification_host_receipt_v1(
            &request,
            &request_frame,
            &response_frame,
            &evidence,
            &swift_receipt,
            *signing_key.verifying_key().as_bytes(),
        )
        .expect("Swift receipt verifies in Rust");
        let signature = signing_key.sign(&signature_message_v1(
            request.canonical_json_v1(),
            &evidence,
            &unsigned_bytes,
        ));
        let mut receipt = unsigned.as_object().cloned().expect("receipt object");
        receipt.insert(
            "signature_ed25519_hex".to_string(),
            Value::String(
                signature
                    .to_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            ),
        );
        let receipt =
            serde_json_canonicalizer::to_vec(&Value::Object(receipt)).expect("signed receipt");
        let verified = verify_macos_linux_vz_package_runtime_qualification_host_receipt_v1(
            &request,
            &request_frame,
            &response_frame,
            &evidence,
            &receipt,
            *signing_key.verifying_key().as_bytes(),
        )
        .expect("verified");
        assert_eq!(
            verified.qualification_request_sha256(),
            request.request_sha256()
        );
        assert!(!verified.execution_authority_permitted());
        assert!(!verified.package_execution_permitted());
        assert!(!verified.sync_back_permitted());

        let mut rebound = evidence_value;
        rebound["raw_frame_count"] = Value::String("1".to_string());
        let rebound = serde_json_canonicalizer::to_vec(&rebound).expect("rebound");
        assert_eq!(
            verify_macos_linux_vz_package_runtime_qualification_host_receipt_v1(
                &request,
                &request_frame,
                &response_frame,
                &rebound,
                &receipt,
                *signing_key.verifying_key().as_bytes(),
            ),
            Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)
        );
    }

    fn request_bytes_v1(signing_key: &SigningKey) -> Vec<u8> {
        let digest = |label: &str| Sha256Digest::from_bytes(label.as_bytes());
        serde_json_canonicalizer::to_vec(&json!({
            "schema_version":
                "whoathere.macos_linux_vz_package_runtime_qualification_request.v1",
            "operation": "fixed_nonexecuting_probe",
            "qualified_telemetry_backend_sha256": digest("qualified backend"),
            "backend_identity_sha256": digest("backend identity"),
            "telemetry_requirements_sha256": digest("requirements"),
            "conformance_evidence_set_sha256": digest("evidence set"),
            "kernel_image_sha256": digest("kernel"),
            "qualified_initramfs_sha256": digest("qualified initramfs"),
            "qualified_guest_signer_sha256": digest("guest signer"),
            "qualified_protected_sensor_sha256": digest("protected sensor"),
            "guest_evidence_public_key_sha256": digest("guest public key"),
            "host_evidence_public_key_sha256":
                Sha256Digest::from_bytes(signing_key.verifying_key().as_bytes()),
            "runtime_qualification_initramfs_sha256": digest("qualification initramfs"),
            "runtime_qualification_guest_agent_sha256": digest("guest agent"),
            "runtime_qualification_guest_init_sha256": digest("guest init"),
            "runtime_qualification_module_bundle_sha256": digest("modules"),
            "candidate_runtime_rootfs_sha256": digest("runtime rootfs"),
            "candidate_runtime_rootfs_byte_length": "42",
            "candidate_runtime_manifest_sha256": digest("runtime manifest"),
            "candidate_package_runner_sha256": digest("package runner"),
            "expected_probe_report_sha256": Sha256Digest::from_bytes(
                MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1
            ),
            "protected_sensor_case": "fork_exec_exit",
            "package_runner_argument": "fork_exec_exit",
            "request_challenge_sha256": digest("fresh challenge"),
            "clone_binding_sha256": digest("unique clone"),
            "package_uid": "65534",
            "package_gid": "65534",
            "storage_policy": "one_unique_writable_clone_destroy_after_vm_stop",
            "network_policy": "host_raw_frame_sinkhole_no_external_route",
            "directory_share_policy": "structurally_absent",
            "public_resolver_reachable": false,
            "nonexecuting_probe_permitted": true,
            "execution_authority_issued": false,
            "package_execution_permitted": false,
            "sync_back_policy": "structurally_absent"
        }))
        .expect("request bytes")
    }
}
