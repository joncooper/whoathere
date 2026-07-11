use crate::{
    decode_macos_artifact_guest_auth_challenge_v1, read_macos_artifact_guest_control_frame_v1,
    sign_macos_artifact_guest_auth_response_v1, sign_macos_artifact_guest_staging_receipt_v1,
    stage_macos_artifact_guest_submission_v1, write_macos_artifact_guest_control_frame_v1,
    MacosArtifactGuestAuthClaimsV1, MacosArtifactGuestAuthErrorV1,
    MacosArtifactGuestControlErrorV1, MacosArtifactGuestControlFrameTypeV1,
    MacosArtifactGuestStagingErrorV1, MacosArtifactGuestStagingPolicyV1,
    MacosArtifactGuestStagingReceiptClaimsV1, MAX_MACOS_ARTIFACT_GUEST_AUTH_BYTES_V1,
};
use std::fmt;
use std::io::{Read, Write};
use whoathere_artifact::Sha256Digest;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosArtifactGuestSupervisorPrimaryErrorV1 {
    InvalidConfiguration,
    Control(MacosArtifactGuestControlErrorV1),
    Authentication(MacosArtifactGuestAuthErrorV1),
    Staging(MacosArtifactGuestStagingErrorV1),
    BindingMismatch,
}

impl MacosArtifactGuestSupervisorPrimaryErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "macos_artifact_guest_supervisor_configuration_invalid",
            Self::Control(error) => error.reason_code(),
            Self::Authentication(error) => error.reason_code(),
            Self::Staging(error) => error.reason_code(),
            Self::BindingMismatch => "macos_artifact_guest_supervisor_binding_mismatch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacosArtifactGuestSupervisorFailureV1 {
    primary: MacosArtifactGuestSupervisorPrimaryErrorV1,
    staging_cleanup_failed: bool,
}

impl MacosArtifactGuestSupervisorFailureV1 {
    fn new(primary: MacosArtifactGuestSupervisorPrimaryErrorV1) -> Self {
        Self {
            primary,
            staging_cleanup_failed: false,
        }
    }

    pub fn primary(&self) -> MacosArtifactGuestSupervisorPrimaryErrorV1 {
        self.primary
    }

    pub fn staging_cleanup_failed(&self) -> bool {
        self.staging_cleanup_failed
    }

    pub const fn reason_code(&self) -> &'static str {
        self.primary.reason_code()
    }
}

impl fmt::Display for MacosArtifactGuestSupervisorFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosArtifactGuestSupervisorFailureV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosArtifactGuestNonExecutingSessionObservationV1 {
    challenge_sha256: Sha256Digest,
    execution_binding_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    first_rehash_sha256: Sha256Digest,
    first_rehash_byte_length: u64,
    staged_device: u64,
    staged_inode: u64,
    package_uid: u32,
    package_gid: u32,
    staging_cleanup_succeeded: bool,
    package_execution_enabled: bool,
}

impl MacosArtifactGuestNonExecutingSessionObservationV1 {
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

    pub fn package_uid(&self) -> u32 {
        self.package_uid
    }

    pub fn package_gid(&self) -> u32 {
        self.package_gid
    }

    pub fn staging_cleanup_succeeded(&self) -> bool {
        self.staging_cleanup_succeeded
    }

    pub fn package_execution_enabled(&self) -> bool {
        self.package_execution_enabled
    }
}

/// Run one authenticated artifact session and stop after protected staging.
///
/// The caller owns connection timeouts and must close the write side after this
/// function returns so the host can require final EOF. No package-controlled
/// process is launched, and the staged artifact is explicitly removed before
/// the signed receipt is written.
pub fn run_macos_artifact_guest_nonexecuting_session_v1<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    signing_seed: [u8; 32],
    auth_claims: &MacosArtifactGuestAuthClaimsV1,
    staging_policy: &MacosArtifactGuestStagingPolicyV1,
) -> Result<MacosArtifactGuestNonExecutingSessionObservationV1, MacosArtifactGuestSupervisorFailureV1>
{
    let signing_seed = Zeroizing::new(signing_seed);
    if staging_policy.package_uid() != auth_claims.package_uid() {
        return Err(MacosArtifactGuestSupervisorFailureV1::new(
            MacosArtifactGuestSupervisorPrimaryErrorV1::InvalidConfiguration,
        ));
    }

    let challenge_body = read_macos_artifact_guest_control_frame_v1(
        reader,
        MacosArtifactGuestControlFrameTypeV1::AuthenticationChallenge,
        MAX_MACOS_ARTIFACT_GUEST_AUTH_BYTES_V1,
    )
    .map_err(|error| {
        MacosArtifactGuestSupervisorFailureV1::new(
            MacosArtifactGuestSupervisorPrimaryErrorV1::Control(error),
        )
    })?;
    let challenge =
        decode_macos_artifact_guest_auth_challenge_v1(&challenge_body).map_err(|error| {
            MacosArtifactGuestSupervisorFailureV1::new(
                MacosArtifactGuestSupervisorPrimaryErrorV1::Authentication(error),
            )
        })?;
    let auth_response =
        sign_macos_artifact_guest_auth_response_v1(&challenge, *signing_seed, auth_claims)
            .map_err(|error| {
                MacosArtifactGuestSupervisorFailureV1::new(
                    MacosArtifactGuestSupervisorPrimaryErrorV1::Authentication(error),
                )
            })?;
    write_macos_artifact_guest_control_frame_v1(
        writer,
        MacosArtifactGuestControlFrameTypeV1::AuthenticationResponse,
        &auth_response,
    )
    .map_err(|error| {
        MacosArtifactGuestSupervisorFailureV1::new(
            MacosArtifactGuestSupervisorPrimaryErrorV1::Control(error),
        )
    })?;

    let mut staged =
        stage_macos_artifact_guest_submission_v1(reader, staging_policy).map_err(|error| {
            MacosArtifactGuestSupervisorFailureV1::new(
                MacosArtifactGuestSupervisorPrimaryErrorV1::Staging(error),
            )
        })?;
    let prepared = (|| {
        let transport = staged.transport();
        let run_spec = transport.header().run_spec();
        let backend = run_spec.backend_identity();
        if run_spec.run_spec_sha256() != challenge.run_spec_sha256()
            || transport.header().bindings().execution_binding_sha256()
                != challenge.execution_binding_sha256()
            || backend.guest_supervisor_sha256() != auth_claims.guest_supervisor_sha256()
            || backend.runner_configuration_sha256() != auth_claims.runner_configuration_sha256()
            || backend.package_uid() != auth_claims.package_uid()
            || backend.package_gid() != auth_claims.package_gid()
            || backend.guest_auth_public_key_sha256() != challenge.guest_auth_public_key_sha256()
        {
            return Err(MacosArtifactGuestSupervisorPrimaryErrorV1::BindingMismatch);
        }
        let rehash = staged
            .verify_prelaunch()
            .map_err(MacosArtifactGuestSupervisorPrimaryErrorV1::Staging)?;
        let staging_claims = MacosArtifactGuestStagingReceiptClaimsV1::new(
            rehash.artifact_sha256().clone(),
            rehash.artifact_byte_length(),
            rehash.artifact_sha256().clone(),
            rehash.artifact_byte_length(),
            rehash.device(),
            rehash.inode(),
        )
        .map_err(MacosArtifactGuestSupervisorPrimaryErrorV1::Authentication)?;
        let receipt = sign_macos_artifact_guest_staging_receipt_v1(
            &challenge,
            *signing_seed,
            auth_claims,
            &staging_claims,
        )
        .map_err(MacosArtifactGuestSupervisorPrimaryErrorV1::Authentication)?;
        let observation = MacosArtifactGuestNonExecutingSessionObservationV1 {
            challenge_sha256: Sha256Digest::from_bytes(challenge.canonical_json_v1()),
            execution_binding_sha256: challenge.execution_binding_sha256().clone(),
            run_spec_sha256: challenge.run_spec_sha256().clone(),
            clone_binding_sha256: challenge.clone_binding_sha256().clone(),
            artifact_sha256: staging_claims.artifact_sha256().clone(),
            artifact_byte_length: staging_claims.artifact_byte_length(),
            first_rehash_sha256: staging_claims.first_rehash_sha256().clone(),
            first_rehash_byte_length: staging_claims.first_rehash_byte_length(),
            staged_device: staging_claims.staged_device(),
            staged_inode: staging_claims.staged_inode(),
            package_uid: auth_claims.package_uid(),
            package_gid: auth_claims.package_gid(),
            staging_cleanup_succeeded: true,
            package_execution_enabled: false,
        };
        Ok((receipt, observation))
    })();

    let cleanup_failed = staged.cleanup().is_err();
    let (receipt, observation) = match prepared {
        Ok(value) if !cleanup_failed => value,
        Ok(_) => {
            return Err(MacosArtifactGuestSupervisorFailureV1 {
                primary: MacosArtifactGuestSupervisorPrimaryErrorV1::Staging(
                    MacosArtifactGuestStagingErrorV1::CleanupFailed,
                ),
                staging_cleanup_failed: true,
            });
        }
        Err(primary) => {
            return Err(MacosArtifactGuestSupervisorFailureV1 {
                primary,
                staging_cleanup_failed: cleanup_failed,
            });
        }
    };
    write_macos_artifact_guest_control_frame_v1(
        writer,
        MacosArtifactGuestControlFrameTypeV1::StagingReceipt,
        &receipt,
    )
    .map_err(|error| {
        MacosArtifactGuestSupervisorFailureV1::new(
            MacosArtifactGuestSupervisorPrimaryErrorV1::Control(error),
        )
    })?;
    Ok(observation)
}
