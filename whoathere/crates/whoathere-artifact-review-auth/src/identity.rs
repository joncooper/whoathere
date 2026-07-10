use crate::ArtifactReviewAuthErrorV2;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::HashMap;
use std::fmt;
use whoathere_artifact::Sha256Digest;
use zeroize::Zeroize;

pub const ARTIFACT_REVIEW_SIGNATURE_ALGORITHM_V2: &str = "ed25519.v1";
pub const MAX_ARTIFACT_REVIEW_AUTH_IDENTITY_BYTES_V2: usize = 256;
pub(crate) const MAX_JCS_SAFE_INTEGER_V2: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactReviewProducerRoleV2 {
    HostControlPlane,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactReviewEvidencePurposeV2 {
    RestrictiveAdvisoryOnly,
}

/// Trusted registry lookup identity. Algorithm, role, and purpose are part of
/// the lookup key rather than being selected by untrusted evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArtifactReviewKeyIdentityV2 {
    trust_domain: String,
    issuer_id: String,
    producer_role: ArtifactReviewProducerRoleV2,
    evidence_purpose: ArtifactReviewEvidencePurposeV2,
    algorithm: String,
    key_id: String,
    key_epoch: u64,
}

impl ArtifactReviewKeyIdentityV2 {
    pub fn new_host_control_plane(
        trust_domain: impl Into<String>,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        key_epoch: u64,
    ) -> Result<Self, ArtifactReviewAuthErrorV2> {
        let identity = Self {
            trust_domain: trust_domain.into(),
            issuer_id: issuer_id.into(),
            producer_role: ArtifactReviewProducerRoleV2::HostControlPlane,
            evidence_purpose: ArtifactReviewEvidencePurposeV2::RestrictiveAdvisoryOnly,
            algorithm: ARTIFACT_REVIEW_SIGNATURE_ALGORITHM_V2.to_string(),
            key_id: key_id.into(),
            key_epoch,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), ArtifactReviewAuthErrorV2> {
        if !valid_identity_component_v2(&self.trust_domain)
            || !valid_identity_component_v2(&self.issuer_id)
            || !valid_identity_component_v2(&self.key_id)
            || self.algorithm != ARTIFACT_REVIEW_SIGNATURE_ALGORITHM_V2
            || self.key_epoch == 0
            || self.key_epoch > MAX_JCS_SAFE_INTEGER_V2
        {
            return Err(ArtifactReviewAuthErrorV2::InvalidIdentity);
        }
        if self.producer_role != ArtifactReviewProducerRoleV2::HostControlPlane {
            return Err(ArtifactReviewAuthErrorV2::WrongKeyRole);
        }
        if self.evidence_purpose != ArtifactReviewEvidencePurposeV2::RestrictiveAdvisoryOnly {
            return Err(ArtifactReviewAuthErrorV2::WrongKeyPurpose);
        }
        Ok(())
    }

    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    pub fn producer_role(&self) -> ArtifactReviewProducerRoleV2 {
        self.producer_role
    }

    pub fn evidence_purpose(&self) -> ArtifactReviewEvidencePurposeV2 {
        self.evidence_purpose
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
}

#[derive(Clone)]
pub struct ArtifactReviewVerificationKeyRecordV2 {
    identity: ArtifactReviewKeyIdentityV2,
    verifying_key: VerifyingKey,
    active_from_unix_seconds: u64,
    active_until_unix_seconds: u64,
    revoked_at_unix_seconds: Option<u64>,
}

impl fmt::Debug for ArtifactReviewVerificationKeyRecordV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactReviewVerificationKeyRecordV2")
            .field("identity", &self.identity)
            .field(
                "verifying_key_sha256",
                &Sha256Digest::from_bytes(self.verifying_key.as_bytes()),
            )
            .field("active_from_unix_seconds", &self.active_from_unix_seconds)
            .field("active_until_unix_seconds", &self.active_until_unix_seconds)
            .field("revoked_at_unix_seconds", &self.revoked_at_unix_seconds)
            .finish()
    }
}

impl ArtifactReviewVerificationKeyRecordV2 {
    pub fn new(
        identity: ArtifactReviewKeyIdentityV2,
        verifying_key_bytes: [u8; 32],
        active_from_unix_seconds: u64,
        active_until_unix_seconds: u64,
        revoked_at_unix_seconds: Option<u64>,
    ) -> Result<Self, ArtifactReviewAuthErrorV2> {
        identity.validate()?;
        if active_from_unix_seconds >= active_until_unix_seconds
            || active_until_unix_seconds > MAX_JCS_SAFE_INTEGER_V2
            || revoked_at_unix_seconds.is_some_and(|value| value > MAX_JCS_SAFE_INTEGER_V2)
        {
            return Err(ArtifactReviewAuthErrorV2::InvalidKey);
        }
        let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
            .map_err(|_| ArtifactReviewAuthErrorV2::InvalidKey)?;
        if verifying_key.is_weak() {
            return Err(ArtifactReviewAuthErrorV2::InvalidKey);
        }
        Ok(Self {
            identity,
            verifying_key,
            active_from_unix_seconds,
            active_until_unix_seconds,
            revoked_at_unix_seconds,
        })
    }

    pub fn identity(&self) -> &ArtifactReviewKeyIdentityV2 {
        &self.identity
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn active_from_unix_seconds(&self) -> u64 {
        self.active_from_unix_seconds
    }

    pub fn active_until_unix_seconds(&self) -> u64 {
        self.active_until_unix_seconds
    }

    pub fn revoked_at_unix_seconds(&self) -> Option<u64> {
        self.revoked_at_unix_seconds
    }

    pub(crate) fn verify_strict(
        &self,
        message: &[u8],
        signature_bytes: &[u8; 64],
    ) -> Result<(), ArtifactReviewAuthErrorV2> {
        let signature = Signature::from_bytes(signature_bytes);
        self.verifying_key
            .verify_strict(message, &signature)
            .map_err(|_| ArtifactReviewAuthErrorV2::SignatureVerificationFailed)
    }

    pub(crate) fn validate_for_evidence(
        &self,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<(), ArtifactReviewAuthErrorV2> {
        if issued_at_unix_seconds < self.active_from_unix_seconds {
            return Err(ArtifactReviewAuthErrorV2::KeyNotYetActive);
        }
        if issued_at_unix_seconds >= self.active_until_unix_seconds
            || expires_at_unix_seconds > self.active_until_unix_seconds
            || now_unix_seconds >= self.active_until_unix_seconds
        {
            return Err(ArtifactReviewAuthErrorV2::KeyExpired);
        }
        if self.revoked_at_unix_seconds.is_some_and(|revoked_at| {
            now_unix_seconds >= revoked_at || issued_at_unix_seconds >= revoked_at
        }) {
            return Err(ArtifactReviewAuthErrorV2::KeyRevoked);
        }
        Ok(())
    }
}

pub struct ArtifactReviewSigningKeyV2 {
    record: ArtifactReviewVerificationKeyRecordV2,
    signing_key: SigningKey,
}

impl fmt::Debug for ArtifactReviewSigningKeyV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactReviewSigningKeyV2")
            .field("record", &self.record)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl ArtifactReviewSigningKeyV2 {
    pub fn from_seed(
        identity: ArtifactReviewKeyIdentityV2,
        seed: &mut [u8; 32],
        active_from_unix_seconds: u64,
        active_until_unix_seconds: u64,
        revoked_at_unix_seconds: Option<u64>,
    ) -> Result<Self, ArtifactReviewAuthErrorV2> {
        let signing_key = SigningKey::from_bytes(seed);
        seed.zeroize();
        let record = ArtifactReviewVerificationKeyRecordV2::new(
            identity,
            signing_key.verifying_key().to_bytes(),
            active_from_unix_seconds,
            active_until_unix_seconds,
            revoked_at_unix_seconds,
        )?;
        Ok(Self {
            record,
            signing_key,
        })
    }

    pub fn identity(&self) -> &ArtifactReviewKeyIdentityV2 {
        self.record.identity()
    }

    pub fn verification_record(&self) -> ArtifactReviewVerificationKeyRecordV2 {
        self.record.clone()
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    pub(crate) fn validate_for_evidence(
        &self,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<(), ArtifactReviewAuthErrorV2> {
        self.record.validate_for_evidence(
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            issued_at_unix_seconds,
        )
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactReviewKeyRegistryV2 {
    records: HashMap<ArtifactReviewKeyIdentityV2, ArtifactReviewVerificationKeyRecordV2>,
}

impl ArtifactReviewKeyRegistryV2 {
    pub fn new(
        records: impl IntoIterator<Item = ArtifactReviewVerificationKeyRecordV2>,
    ) -> Result<Self, ArtifactReviewAuthErrorV2> {
        let mut by_identity = HashMap::new();
        for record in records {
            record.identity.validate()?;
            if by_identity
                .insert(record.identity.clone(), record)
                .is_some()
            {
                return Err(ArtifactReviewAuthErrorV2::DuplicateKey);
            }
        }
        if by_identity.is_empty() {
            return Err(ArtifactReviewAuthErrorV2::InvalidKey);
        }
        Ok(Self {
            records: by_identity,
        })
    }

    pub fn resolve(
        &self,
        identity: &ArtifactReviewKeyIdentityV2,
    ) -> Result<&ArtifactReviewVerificationKeyRecordV2, ArtifactReviewAuthErrorV2> {
        identity.validate()?;
        self.records
            .get(identity)
            .ok_or(ArtifactReviewAuthErrorV2::UnknownKey)
    }
}

pub(crate) fn valid_identity_component_v2(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ARTIFACT_REVIEW_AUTH_IDENTITY_BYTES_V2
        && value.as_bytes().iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}
