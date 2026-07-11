use crate::{
    decode_macos_sdist_guest_auth_challenge_v1, read_macos_sdist_guest_control_frame_v1,
    sign_macos_sdist_guest_auth_response_v1, sign_macos_sdist_guest_staging_receipt_v1,
    stage_macos_sdist_guest_submission_followed_by_closure_v1,
    write_macos_sdist_guest_control_frame_v1, MacosSdistGuestAuthClaimsV1,
    MacosSdistGuestAuthErrorV1, MacosSdistGuestControlErrorV1, MacosSdistGuestControlFrameTypeV1,
    MacosSdistGuestStagingErrorV1, MacosSdistGuestStagingPolicyV1,
    MacosSdistGuestStagingReceiptClaimsV1, MAX_MACOS_SDIST_GUEST_AUTH_BYTES_V1,
};
use std::fmt;
use std::io::{Read, Write};
use whoathere_artifact::Sha256Digest;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosSdistGuestSupervisorPrimaryErrorV1 {
    InvalidConfiguration,
    Control(MacosSdistGuestControlErrorV1),
    Authentication(MacosSdistGuestAuthErrorV1),
    Staging(MacosSdistGuestStagingErrorV1),
    BindingMismatch,
}

impl MacosSdistGuestSupervisorPrimaryErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "macos_sdist_guest_supervisor_configuration_invalid",
            Self::Control(error) => error.reason_code(),
            Self::Authentication(error) => error.reason_code(),
            Self::Staging(error) => error.reason_code(),
            Self::BindingMismatch => "macos_sdist_guest_supervisor_binding_mismatch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacosSdistGuestSupervisorFailureV1 {
    primary: MacosSdistGuestSupervisorPrimaryErrorV1,
    staging_cleanup_failed: bool,
}

impl MacosSdistGuestSupervisorFailureV1 {
    fn new(primary: MacosSdistGuestSupervisorPrimaryErrorV1) -> Self {
        Self {
            primary,
            staging_cleanup_failed: false,
        }
    }

    pub fn primary(&self) -> MacosSdistGuestSupervisorPrimaryErrorV1 {
        self.primary
    }

    pub fn staging_cleanup_failed(&self) -> bool {
        self.staging_cleanup_failed
    }

    pub const fn reason_code(&self) -> &'static str {
        self.primary.reason_code()
    }
}

impl fmt::Display for MacosSdistGuestSupervisorFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosSdistGuestSupervisorFailureV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosSdistGuestNonExecutingSessionObservationV1 {
    challenge_sha256: Sha256Digest,
    execution_binding_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    build_closure_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    first_rehash_sha256: Sha256Digest,
    first_rehash_byte_length: u64,
    staged_device: u64,
    staged_inode: u64,
    closure_payload_sha256: Sha256Digest,
    closure_artifact_count: u32,
    closure_payload_byte_length: u64,
    closure_manifest_sha256: Sha256Digest,
    closure_staged_device: u64,
    closure_staged_inode: u64,
    package_uid: u32,
    package_gid: u32,
    staging_cleanup_succeeded: bool,
    package_execution_enabled: bool,
    sync_back_enabled: bool,
    build_closure_materialized: bool,
}

impl MacosSdistGuestNonExecutingSessionObservationV1 {
    pub fn challenge_sha256(&self) -> &Sha256Digest {
        &self.challenge_sha256
    }

    pub fn execution_binding_sha256(&self) -> &Sha256Digest {
        &self.execution_binding_sha256
    }

    pub fn run_spec_sha256(&self) -> &Sha256Digest {
        &self.run_spec_sha256
    }

    pub fn build_closure_sha256(&self) -> &Sha256Digest {
        &self.build_closure_sha256
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

    pub fn closure_payload_sha256(&self) -> &Sha256Digest {
        &self.closure_payload_sha256
    }

    pub fn closure_artifact_count(&self) -> u32 {
        self.closure_artifact_count
    }

    pub fn closure_payload_byte_length(&self) -> u64 {
        self.closure_payload_byte_length
    }

    pub fn closure_manifest_sha256(&self) -> &Sha256Digest {
        &self.closure_manifest_sha256
    }

    pub fn closure_staged_device(&self) -> u64 {
        self.closure_staged_device
    }

    pub fn closure_staged_inode(&self) -> u64 {
        self.closure_staged_inode
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

    pub fn sync_back_enabled(&self) -> bool {
        self.sync_back_enabled
    }

    pub fn build_closure_materialized(&self) -> bool {
        self.build_closure_materialized
    }
}

/// Authenticate, stage, rehash, clean, and attest one sdist without executing package code.
pub fn run_macos_sdist_guest_nonexecuting_session_v1<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    signing_seed: [u8; 32],
    auth_claims: &MacosSdistGuestAuthClaimsV1,
    staging_policy: &MacosSdistGuestStagingPolicyV1,
) -> Result<MacosSdistGuestNonExecutingSessionObservationV1, MacosSdistGuestSupervisorFailureV1> {
    let signing_seed = Zeroizing::new(signing_seed);
    if staging_policy.package_uid() != auth_claims.package_uid() {
        return Err(MacosSdistGuestSupervisorFailureV1::new(
            MacosSdistGuestSupervisorPrimaryErrorV1::InvalidConfiguration,
        ));
    }

    let challenge_body = read_macos_sdist_guest_control_frame_v1(
        reader,
        MacosSdistGuestControlFrameTypeV1::AuthenticationChallenge,
        MAX_MACOS_SDIST_GUEST_AUTH_BYTES_V1,
    )
    .map_err(|error| {
        MacosSdistGuestSupervisorFailureV1::new(MacosSdistGuestSupervisorPrimaryErrorV1::Control(
            error,
        ))
    })?;
    let challenge =
        decode_macos_sdist_guest_auth_challenge_v1(&challenge_body).map_err(|error| {
            MacosSdistGuestSupervisorFailureV1::new(
                MacosSdistGuestSupervisorPrimaryErrorV1::Authentication(error),
            )
        })?;
    let auth_response =
        sign_macos_sdist_guest_auth_response_v1(&challenge, *signing_seed, auth_claims).map_err(
            |error| {
                MacosSdistGuestSupervisorFailureV1::new(
                    MacosSdistGuestSupervisorPrimaryErrorV1::Authentication(error),
                )
            },
        )?;
    write_macos_sdist_guest_control_frame_v1(
        writer,
        MacosSdistGuestControlFrameTypeV1::AuthenticationResponse,
        &auth_response,
    )
    .map_err(|error| {
        MacosSdistGuestSupervisorFailureV1::new(MacosSdistGuestSupervisorPrimaryErrorV1::Control(
            error,
        ))
    })?;

    let mut staged =
        stage_macos_sdist_guest_submission_followed_by_closure_v1(reader, staging_policy).map_err(
            |error| {
                MacosSdistGuestSupervisorFailureV1::new(
                    MacosSdistGuestSupervisorPrimaryErrorV1::Staging(error),
                )
            },
        )?;
    let closure_staging = match staged.stage_build_closure(reader) {
        Ok(observation) => observation,
        Err(error) => {
            let cleanup_failed = staged.cleanup().is_err();
            return Err(MacosSdistGuestSupervisorFailureV1 {
                primary: MacosSdistGuestSupervisorPrimaryErrorV1::Staging(error),
                staging_cleanup_failed: cleanup_failed,
            });
        }
    };
    let prepared = (|| {
        let transport = staged.transport();
        let run_spec = transport.header().run_spec();
        let backend = run_spec.backend_identity();
        if run_spec.run_spec_sha256() != challenge.run_spec_sha256()
            || run_spec.build_closure_sha256() != challenge.build_closure_sha256()
            || transport.header().bindings().execution_binding_sha256()
                != challenge.execution_binding_sha256()
            || backend.guest_supervisor_sha256() != auth_claims.guest_supervisor_sha256()
            || backend.runner_configuration_sha256() != auth_claims.runner_configuration_sha256()
            || backend.package_uid() != auth_claims.package_uid()
            || backend.package_gid() != auth_claims.package_gid()
            || backend.guest_auth_public_key_sha256() != challenge.guest_auth_public_key_sha256()
        {
            return Err(MacosSdistGuestSupervisorPrimaryErrorV1::BindingMismatch);
        }
        let build_closure_sha256 = run_spec.build_closure_sha256().clone();
        let rehash = staged
            .verify_prelaunch()
            .map_err(MacosSdistGuestSupervisorPrimaryErrorV1::Staging)?;
        let staging_claims = MacosSdistGuestStagingReceiptClaimsV1::new(
            rehash.artifact_sha256().clone(),
            rehash.artifact_byte_length(),
            build_closure_sha256,
            rehash.artifact_sha256().clone(),
            rehash.artifact_byte_length(),
            rehash.device(),
            rehash.inode(),
            closure_staging.transport().payload_sha256().clone(),
            u32::try_from(closure_staging.transport().artifact_count())
                .map_err(|_| MacosSdistGuestSupervisorPrimaryErrorV1::BindingMismatch)?,
            closure_staging.transport().payload_byte_length(),
            closure_staging.manifest_sha256().clone(),
            closure_staging.payload_device(),
            closure_staging.payload_inode(),
        )
        .map_err(MacosSdistGuestSupervisorPrimaryErrorV1::Authentication)?;
        let receipt = sign_macos_sdist_guest_staging_receipt_v1(
            &challenge,
            *signing_seed,
            auth_claims,
            &staging_claims,
        )
        .map_err(MacosSdistGuestSupervisorPrimaryErrorV1::Authentication)?;
        let observation = MacosSdistGuestNonExecutingSessionObservationV1 {
            challenge_sha256: Sha256Digest::from_bytes(challenge.canonical_json_v1()),
            execution_binding_sha256: challenge.execution_binding_sha256().clone(),
            run_spec_sha256: challenge.run_spec_sha256().clone(),
            build_closure_sha256: challenge.build_closure_sha256().clone(),
            clone_binding_sha256: challenge.clone_binding_sha256().clone(),
            artifact_sha256: staging_claims.artifact_sha256().clone(),
            artifact_byte_length: staging_claims.artifact_byte_length(),
            first_rehash_sha256: staging_claims.first_rehash_sha256().clone(),
            first_rehash_byte_length: staging_claims.first_rehash_byte_length(),
            staged_device: staging_claims.staged_device(),
            staged_inode: staging_claims.staged_inode(),
            closure_payload_sha256: staging_claims.closure_payload_sha256().clone(),
            closure_artifact_count: staging_claims.closure_artifact_count(),
            closure_payload_byte_length: staging_claims.closure_payload_byte_length(),
            closure_manifest_sha256: staging_claims.closure_manifest_sha256().clone(),
            closure_staged_device: staging_claims.closure_staged_device(),
            closure_staged_inode: staging_claims.closure_staged_inode(),
            package_uid: auth_claims.package_uid(),
            package_gid: auth_claims.package_gid(),
            staging_cleanup_succeeded: true,
            package_execution_enabled: false,
            sync_back_enabled: false,
            build_closure_materialized: false,
        };
        Ok((receipt, observation))
    })();

    let cleanup_failed = staged.cleanup().is_err();
    let (receipt, observation) = match prepared {
        Ok(value) if !cleanup_failed => value,
        Ok(_) => {
            return Err(MacosSdistGuestSupervisorFailureV1 {
                primary: MacosSdistGuestSupervisorPrimaryErrorV1::Staging(
                    MacosSdistGuestStagingErrorV1::CleanupFailed,
                ),
                staging_cleanup_failed: true,
            });
        }
        Err(primary) => {
            return Err(MacosSdistGuestSupervisorFailureV1 {
                primary,
                staging_cleanup_failed: cleanup_failed,
            });
        }
    };
    write_macos_sdist_guest_control_frame_v1(
        writer,
        MacosSdistGuestControlFrameTypeV1::StagingReceipt,
        &receipt,
    )
    .map_err(|error| {
        MacosSdistGuestSupervisorFailureV1::new(MacosSdistGuestSupervisorPrimaryErrorV1::Control(
            error,
        ))
    })?;
    Ok(observation)
}
