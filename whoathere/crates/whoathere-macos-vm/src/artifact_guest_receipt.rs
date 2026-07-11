use crate::{
    MacosArtifactGuestAuthChallengeV1, MacosArtifactGuestAuthClaimsV1,
    MacosArtifactGuestAuthErrorV1, MAX_MACOS_ARTIFACT_GUEST_AUTH_BYTES_V1,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;
use zeroize::Zeroize;

pub const MACOS_ARTIFACT_GUEST_STAGING_RECEIPT_SCHEMA_V1: &str =
    "whoathere.artifact_guest_staging_receipt.v1";
const STAGING_RECEIPT_SIGNATURE_DOMAIN_V1: &[u8] =
    b"whoathere.artifact_guest_staging_receipt.signature.v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosArtifactGuestStagingReceiptClaimsV1 {
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    first_rehash_sha256: Sha256Digest,
    first_rehash_byte_length: u64,
    staged_device: u64,
    staged_inode: u64,
}

impl MacosArtifactGuestStagingReceiptClaimsV1 {
    pub fn new(
        artifact_sha256: Sha256Digest,
        artifact_byte_length: u64,
        first_rehash_sha256: Sha256Digest,
        first_rehash_byte_length: u64,
        staged_device: u64,
        staged_inode: u64,
    ) -> Result<Self, MacosArtifactGuestAuthErrorV1> {
        if artifact_byte_length == 0
            || first_rehash_byte_length != artifact_byte_length
            || first_rehash_sha256 != artifact_sha256
            || staged_device == 0
            || staged_inode == 0
        {
            return Err(MacosArtifactGuestAuthErrorV1::InvalidResponse);
        }
        Ok(Self {
            artifact_sha256,
            artifact_byte_length,
            first_rehash_sha256,
            first_rehash_byte_length,
            staged_device,
            staged_inode,
        })
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    pub fn first_rehash_sha256(&self) -> &Sha256Digest {
        &self.first_rehash_sha256
    }

    pub fn first_rehash_byte_length(&self) -> u64 {
        self.first_rehash_byte_length
    }

    pub fn staged_device(&self) -> u64 {
        self.staged_device
    }

    pub fn staged_inode(&self) -> u64 {
        self.staged_inode
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedStagingReceiptWireV1 {
    schema_version: String,
    status: String,
    challenge_sha256: Sha256Digest,
    execution_binding_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: String,
    first_rehash_sha256: Sha256Digest,
    first_rehash_byte_length: String,
    staged_device: String,
    staged_inode: String,
    artifact_file_mode: String,
    staging_directory_mode: String,
    package_uid: String,
    package_gid: String,
    package_execution_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingReceiptWireV1 {
    schema_version: String,
    status: String,
    challenge_sha256: Sha256Digest,
    execution_binding_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: String,
    first_rehash_sha256: Sha256Digest,
    first_rehash_byte_length: String,
    staged_device: String,
    staged_inode: String,
    artifact_file_mode: String,
    staging_directory_mode: String,
    package_uid: String,
    package_gid: String,
    package_execution_enabled: bool,
    signature_ed25519_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosArtifactGuestStagingReceiptObservationV1 {
    challenge_sha256: Sha256Digest,
    execution_binding_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    claims: MacosArtifactGuestStagingReceiptClaimsV1,
    package_uid: u32,
    package_gid: u32,
}

impl MacosArtifactGuestStagingReceiptObservationV1 {
    pub fn challenge_sha256(&self) -> &Sha256Digest {
        &self.challenge_sha256
    }

    pub fn execution_binding_sha256(&self) -> &Sha256Digest {
        &self.execution_binding_sha256
    }

    pub fn run_spec_sha256(&self) -> &Sha256Digest {
        &self.run_spec_sha256
    }

    pub fn clone_binding_sha256(&self) -> &Sha256Digest {
        &self.clone_binding_sha256
    }

    pub fn claims(&self) -> &MacosArtifactGuestStagingReceiptClaimsV1 {
        &self.claims
    }

    pub fn package_uid(&self) -> u32 {
        self.package_uid
    }

    pub fn package_gid(&self) -> u32 {
        self.package_gid
    }
}

pub fn sign_macos_artifact_guest_staging_receipt_v1(
    challenge: &MacosArtifactGuestAuthChallengeV1,
    mut signing_seed: [u8; 32],
    auth_claims: &MacosArtifactGuestAuthClaimsV1,
    staging_claims: &MacosArtifactGuestStagingReceiptClaimsV1,
) -> Result<Vec<u8>, MacosArtifactGuestAuthErrorV1> {
    let signing_key = SigningKey::from_bytes(&signing_seed);
    signing_seed.zeroize();
    if Sha256Digest::from_bytes(signing_key.verifying_key().as_bytes())
        != *challenge.guest_auth_public_key_sha256()
    {
        return Err(MacosArtifactGuestAuthErrorV1::PublicKeyMismatch);
    }
    let unsigned = unsigned_receipt_v1(challenge, auth_claims, staging_claims);
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| MacosArtifactGuestAuthErrorV1::Serialization)?;
    let signature = signing_key.sign(&receipt_signature_message_v1(
        challenge.canonical_json_v1(),
        &unsigned_bytes,
    ));
    let receipt = StagingReceiptWireV1 {
        schema_version: unsigned.schema_version,
        status: unsigned.status,
        challenge_sha256: unsigned.challenge_sha256,
        execution_binding_sha256: unsigned.execution_binding_sha256,
        run_spec_sha256: unsigned.run_spec_sha256,
        clone_binding_sha256: unsigned.clone_binding_sha256,
        artifact_sha256: unsigned.artifact_sha256,
        artifact_byte_length: unsigned.artifact_byte_length,
        first_rehash_sha256: unsigned.first_rehash_sha256,
        first_rehash_byte_length: unsigned.first_rehash_byte_length,
        staged_device: unsigned.staged_device,
        staged_inode: unsigned.staged_inode,
        artifact_file_mode: unsigned.artifact_file_mode,
        staging_directory_mode: unsigned.staging_directory_mode,
        package_uid: unsigned.package_uid,
        package_gid: unsigned.package_gid,
        package_execution_enabled: unsigned.package_execution_enabled,
        signature_ed25519_hex: lower_hex_receipt_v1(&signature.to_bytes()),
    };
    let bytes = serde_json_canonicalizer::to_vec(&receipt)
        .map_err(|_| MacosArtifactGuestAuthErrorV1::Serialization)?;
    if bytes.len() > MAX_MACOS_ARTIFACT_GUEST_AUTH_BYTES_V1 {
        return Err(MacosArtifactGuestAuthErrorV1::LimitExceeded);
    }
    Ok(bytes)
}

pub fn verify_macos_artifact_guest_staging_receipt_v1(
    challenge: &MacosArtifactGuestAuthChallengeV1,
    receipt_bytes: &[u8],
    verifying_key_bytes: [u8; 32],
    expected_auth_claims: &MacosArtifactGuestAuthClaimsV1,
    expected_staging_claims: &MacosArtifactGuestStagingReceiptClaimsV1,
) -> Result<MacosArtifactGuestStagingReceiptObservationV1, MacosArtifactGuestAuthErrorV1> {
    if receipt_bytes.is_empty() || receipt_bytes.len() > MAX_MACOS_ARTIFACT_GUEST_AUTH_BYTES_V1 {
        return Err(MacosArtifactGuestAuthErrorV1::LimitExceeded);
    }
    if Sha256Digest::from_bytes(&verifying_key_bytes) != *challenge.guest_auth_public_key_sha256() {
        return Err(MacosArtifactGuestAuthErrorV1::PublicKeyMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| MacosArtifactGuestAuthErrorV1::PublicKeyMismatch)?;
    if verifying_key.is_weak() {
        return Err(MacosArtifactGuestAuthErrorV1::PublicKeyMismatch);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(receipt_bytes);
    let receipt = StagingReceiptWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosArtifactGuestAuthErrorV1::InvalidResponse)?;
    deserializer
        .end()
        .map_err(|_| MacosArtifactGuestAuthErrorV1::InvalidResponse)?;
    let canonical = serde_json_canonicalizer::to_vec(&receipt)
        .map_err(|_| MacosArtifactGuestAuthErrorV1::Serialization)?;
    if canonical != receipt_bytes || !valid_receipt_signature_hex_v1(&receipt.signature_ed25519_hex)
    {
        return Err(MacosArtifactGuestAuthErrorV1::NonCanonical);
    }
    let signature_hex = receipt.signature_ed25519_hex.clone();
    let unsigned = UnsignedStagingReceiptWireV1 {
        schema_version: receipt.schema_version,
        status: receipt.status,
        challenge_sha256: receipt.challenge_sha256,
        execution_binding_sha256: receipt.execution_binding_sha256,
        run_spec_sha256: receipt.run_spec_sha256,
        clone_binding_sha256: receipt.clone_binding_sha256,
        artifact_sha256: receipt.artifact_sha256,
        artifact_byte_length: receipt.artifact_byte_length,
        first_rehash_sha256: receipt.first_rehash_sha256,
        first_rehash_byte_length: receipt.first_rehash_byte_length,
        staged_device: receipt.staged_device,
        staged_inode: receipt.staged_inode,
        artifact_file_mode: receipt.artifact_file_mode,
        staging_directory_mode: receipt.staging_directory_mode,
        package_uid: receipt.package_uid,
        package_gid: receipt.package_gid,
        package_execution_enabled: receipt.package_execution_enabled,
    };
    let expected = unsigned_receipt_v1(challenge, expected_auth_claims, expected_staging_claims);
    if unsigned != expected {
        return Err(MacosArtifactGuestAuthErrorV1::InvalidResponse);
    }
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| MacosArtifactGuestAuthErrorV1::Serialization)?;
    let signature_bytes = decode_receipt_signature_v1(&signature_hex)?;
    verifying_key
        .verify_strict(
            &receipt_signature_message_v1(challenge.canonical_json_v1(), &unsigned_bytes),
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| MacosArtifactGuestAuthErrorV1::SignatureFailed)?;
    Ok(MacosArtifactGuestStagingReceiptObservationV1 {
        challenge_sha256: unsigned.challenge_sha256,
        execution_binding_sha256: unsigned.execution_binding_sha256,
        run_spec_sha256: unsigned.run_spec_sha256,
        clone_binding_sha256: unsigned.clone_binding_sha256,
        claims: expected_staging_claims.clone(),
        package_uid: expected_auth_claims.package_uid(),
        package_gid: expected_auth_claims.package_gid(),
    })
}

fn unsigned_receipt_v1(
    challenge: &MacosArtifactGuestAuthChallengeV1,
    auth_claims: &MacosArtifactGuestAuthClaimsV1,
    staging_claims: &MacosArtifactGuestStagingReceiptClaimsV1,
) -> UnsignedStagingReceiptWireV1 {
    UnsignedStagingReceiptWireV1 {
        schema_version: MACOS_ARTIFACT_GUEST_STAGING_RECEIPT_SCHEMA_V1.to_string(),
        status: "staged_no_execution".to_string(),
        challenge_sha256: Sha256Digest::from_bytes(challenge.canonical_json_v1()),
        execution_binding_sha256: challenge.execution_binding_sha256().clone(),
        run_spec_sha256: challenge.run_spec_sha256().clone(),
        clone_binding_sha256: challenge.clone_binding_sha256().clone(),
        artifact_sha256: staging_claims.artifact_sha256.clone(),
        artifact_byte_length: staging_claims.artifact_byte_length.to_string(),
        first_rehash_sha256: staging_claims.first_rehash_sha256.clone(),
        first_rehash_byte_length: staging_claims.first_rehash_byte_length.to_string(),
        staged_device: staging_claims.staged_device.to_string(),
        staged_inode: staging_claims.staged_inode.to_string(),
        artifact_file_mode: "0444".to_string(),
        staging_directory_mode: "0711".to_string(),
        package_uid: auth_claims.package_uid().to_string(),
        package_gid: auth_claims.package_gid().to_string(),
        package_execution_enabled: false,
    }
}

fn receipt_signature_message_v1(challenge: &[u8], unsigned_receipt: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        STAGING_RECEIPT_SIGNATURE_DOMAIN_V1.len() + challenge.len() + 1 + unsigned_receipt.len(),
    );
    message.extend_from_slice(STAGING_RECEIPT_SIGNATURE_DOMAIN_V1);
    message.extend_from_slice(challenge);
    message.push(0);
    message.extend_from_slice(unsigned_receipt);
    message
}

fn lower_hex_receipt_v1(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

fn valid_receipt_signature_hex_v1(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_receipt_signature_v1(value: &str) -> Result<[u8; 64], MacosArtifactGuestAuthErrorV1> {
    if !valid_receipt_signature_hex_v1(value) {
        return Err(MacosArtifactGuestAuthErrorV1::InvalidResponse);
    }
    let mut decoded = [0_u8; 64];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| MacosArtifactGuestAuthErrorV1::InvalidResponse)?;
    }
    Ok(decoded)
}

impl fmt::Display for MacosArtifactGuestStagingReceiptObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("macos_artifact_guest_staging_receipt_verified")
    }
}
