use crate::{
    MacosSdistGuestAuthChallengeV1, MacosSdistRunSpecV1, MacosSdistSubmissionBindingsV1,
    MacosSdistSubmissionErrorV1, MacosSdistSubmissionHeaderV1,
};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use whoathere_artifact::Sha256Digest;

pub const MACOS_SDIST_LAUNCH_AUTHORITY_SCHEMA_V1: &str = "whoathere.sdist_run_authority.v1";
pub const MAX_MACOS_SDIST_LAUNCH_AUTHORITY_LIFETIME_SECONDS_V1: u64 = 15 * 60;
const AUTHORITY_ROOT_NAME_V1: &str = "sdist-authorities";
const AUTHORITY_PENDING_NAME_V1: &str = "pending";
const AUTHORITY_CONSUMED_NAME_V1: &str = "consumed";
const MAX_AUTHORITY_ISSUE_ATTEMPTS_V1: usize = 8;
const MAX_AUTHORITY_RECORD_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosSdistLaunchAuthorityErrorV1 {
    InvalidTime,
    EntropyUnavailable,
    InvalidStateDirectory,
    UnsafeStateDirectory,
    DirectoryCreationFailed,
    DirectoryOpenFailed,
    AuthorityCollision,
    AuthorityCreateFailed,
    AuthorityWriteFailed,
    AuthorityVerificationFailed,
    AuthorityPersistenceFailed,
    AuthorityUnavailable,
    AuthorityExpired,
    AuthorityBindingMismatch,
    AuthorityRecordInvalid,
    Serialization,
    Submission(MacosSdistSubmissionErrorV1),
}

impl MacosSdistLaunchAuthorityErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidTime => "macos_sdist_launch_authority_time_invalid",
            Self::EntropyUnavailable => "macos_sdist_launch_authority_entropy_unavailable",
            Self::InvalidStateDirectory => "macos_sdist_launch_authority_state_invalid",
            Self::UnsafeStateDirectory => "macos_sdist_launch_authority_state_unsafe",
            Self::DirectoryCreationFailed => {
                "macos_sdist_launch_authority_directory_creation_failed"
            }
            Self::DirectoryOpenFailed => "macos_sdist_launch_authority_directory_open_failed",
            Self::AuthorityCollision => "macos_sdist_launch_authority_collision",
            Self::AuthorityCreateFailed => "macos_sdist_launch_authority_create_failed",
            Self::AuthorityWriteFailed => "macos_sdist_launch_authority_write_failed",
            Self::AuthorityVerificationFailed => "macos_sdist_launch_authority_verification_failed",
            Self::AuthorityPersistenceFailed => "macos_sdist_launch_authority_persistence_failed",
            Self::AuthorityUnavailable => "macos_sdist_launch_authority_unavailable",
            Self::AuthorityExpired => "macos_sdist_launch_authority_expired",
            Self::AuthorityBindingMismatch => "macos_sdist_launch_authority_binding_mismatch",
            Self::AuthorityRecordInvalid => "macos_sdist_launch_authority_record_invalid",
            Self::Serialization => "macos_sdist_launch_authority_serialization_failed",
            Self::Submission(error) => error.reason_code(),
        }
    }
}

impl fmt::Display for MacosSdistLaunchAuthorityErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosSdistLaunchAuthorityErrorV1 {}

impl From<MacosSdistSubmissionErrorV1> for MacosSdistLaunchAuthorityErrorV1 {
    fn from(value: MacosSdistSubmissionErrorV1) -> Self {
        Self::Submission(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosSdistLaunchAuthorityRecordV1 {
    artifact_sha256: Sha256Digest,
    authority_id: String,
    build_closure_sha256: Sha256Digest,
    challenge_binding_sha256: Sha256Digest,
    expires_at_unix_seconds: String,
    issued_at_unix_seconds: String,
    run_spec_sha256: Sha256Digest,
    schema_version: String,
}

impl MacosSdistLaunchAuthorityRecordV1 {
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    pub fn challenge_binding_sha256(&self) -> &Sha256Digest {
        &self.challenge_binding_sha256
    }

    pub fn run_spec_sha256(&self) -> &Sha256Digest {
        &self.run_spec_sha256
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn build_closure_sha256(&self) -> &Sha256Digest {
        &self.build_closure_sha256
    }

    pub fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
            .parse()
            .expect("validated authority issue time")
    }

    pub fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
            .parse()
            .expect("validated authority expiry time")
    }

    pub fn canonical_json_v1(&self) -> Result<Vec<u8>, MacosSdistLaunchAuthorityErrorV1> {
        serde_json_canonicalizer::to_vec(self)
            .map_err(|_| MacosSdistLaunchAuthorityErrorV1::Serialization)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedMacosSdistLaunchAuthorityV1 {
    record: MacosSdistLaunchAuthorityRecordV1,
    record_sha256: Sha256Digest,
    pending_path: PathBuf,
}

impl PersistedMacosSdistLaunchAuthorityV1 {
    pub fn record(&self) -> &MacosSdistLaunchAuthorityRecordV1 {
        &self.record
    }

    pub fn record_sha256(&self) -> &Sha256Digest {
        &self.record_sha256
    }

    pub fn pending_path(&self) -> &Path {
        &self.pending_path
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedMacosSdistLaunchV1 {
    header: MacosSdistSubmissionHeaderV1,
    authority: PersistedMacosSdistLaunchAuthorityV1,
}

impl PreparedMacosSdistLaunchV1 {
    pub fn header(&self) -> &MacosSdistSubmissionHeaderV1 {
        &self.header
    }

    pub fn authority(&self) -> &PersistedMacosSdistLaunchAuthorityV1 {
        &self.authority
    }

    pub fn into_parts(
        self,
    ) -> (
        MacosSdistSubmissionHeaderV1,
        PersistedMacosSdistLaunchAuthorityV1,
    ) {
        (self.header, self.authority)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosSdistLaunchAuthorityConsumptionRequestV1 {
    authority_id: String,
    record_sha256: Sha256Digest,
    header: MacosSdistSubmissionHeaderV1,
}

impl fmt::Debug for MacosSdistLaunchAuthorityConsumptionRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosSdistLaunchAuthorityConsumptionRequestV1")
            .field("authority_id", &self.authority_id)
            .field("record_sha256", &self.record_sha256)
            .field("run_spec_sha256", &self.header.run_spec().run_spec_sha256())
            .field("artifact_sha256", &self.header.run_spec().artifact_sha256())
            .field(
                "build_closure_sha256",
                &self.header.run_spec().build_closure_sha256(),
            )
            .finish()
    }
}

impl MacosSdistLaunchAuthorityConsumptionRequestV1 {
    pub fn new(
        authority_id: impl Into<String>,
        record_sha256: Sha256Digest,
        header: MacosSdistSubmissionHeaderV1,
    ) -> Result<Self, MacosSdistLaunchAuthorityErrorV1> {
        let authority_id = authority_id.into();
        if !valid_authority_id(&authority_id) {
            return Err(MacosSdistLaunchAuthorityErrorV1::AuthorityRecordInvalid);
        }
        Ok(Self {
            authority_id,
            record_sha256,
            header,
        })
    }

    pub fn for_prepared(
        prepared: &PreparedMacosSdistLaunchV1,
    ) -> Result<Self, MacosSdistLaunchAuthorityErrorV1> {
        Self::new(
            prepared.authority.record.authority_id.clone(),
            prepared.authority.record_sha256.clone(),
            prepared.header.clone(),
        )
    }

    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    pub fn record_sha256(&self) -> &Sha256Digest {
        &self.record_sha256
    }

    pub fn header(&self) -> &MacosSdistSubmissionHeaderV1 {
        &self.header
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedMacosSdistLaunchAuthorityV1 {
    record: MacosSdistLaunchAuthorityRecordV1,
    record_sha256: Sha256Digest,
    consumed_path: PathBuf,
    consumed_at_unix_seconds: u64,
}

impl ConsumedMacosSdistLaunchAuthorityV1 {
    pub fn record(&self) -> &MacosSdistLaunchAuthorityRecordV1 {
        &self.record
    }

    pub fn record_sha256(&self) -> &Sha256Digest {
        &self.record_sha256
    }

    pub fn consumed_path(&self) -> &Path {
        &self.consumed_path
    }

    pub fn consumed_at_unix_seconds(&self) -> u64 {
        self.consumed_at_unix_seconds
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedMacosSdistGuestSessionV1 {
    consumed_authority: ConsumedMacosSdistLaunchAuthorityV1,
    header: MacosSdistSubmissionHeaderV1,
    challenge: MacosSdistGuestAuthChallengeV1,
}

impl AuthorizedMacosSdistGuestSessionV1 {
    pub fn consumed_authority(&self) -> &ConsumedMacosSdistLaunchAuthorityV1 {
        &self.consumed_authority
    }

    pub fn header(&self) -> &MacosSdistSubmissionHeaderV1 {
        &self.header
    }

    pub fn challenge(&self) -> &MacosSdistGuestAuthChallengeV1 {
        &self.challenge
    }
}

/// Persist one unpredictable, expiring sdist launch authority before returning its bound header.
///
/// A helper must atomically consume the pending authority before guest authentication or receipt
/// of artifact bytes; this issuer alone does not prove that consumption occurred.
pub fn prepare_macos_sdist_launch_v1(
    state_directory: &Path,
    run_spec: MacosSdistRunSpecV1,
    issued_at_unix_seconds: u64,
    lifetime_seconds: u64,
) -> Result<PreparedMacosSdistLaunchV1, MacosSdistLaunchAuthorityErrorV1> {
    if issued_at_unix_seconds == 0
        || lifetime_seconds == 0
        || lifetime_seconds > MAX_MACOS_SDIST_LAUNCH_AUTHORITY_LIFETIME_SECONDS_V1
    {
        return Err(MacosSdistLaunchAuthorityErrorV1::InvalidTime);
    }
    let expires_at_unix_seconds = issued_at_unix_seconds
        .checked_add(lifetime_seconds)
        .ok_or(MacosSdistLaunchAuthorityErrorV1::InvalidTime)?;
    let directories = AuthorityDirectoriesV1::open_or_create(state_directory)?;
    for _ in 0..MAX_AUTHORITY_ISSUE_ATTEMPTS_V1 {
        let mut authority_random = [0_u8; 32];
        let mut challenge_random = [0_u8; 32];
        getrandom::fill(&mut authority_random)
            .map_err(|_| MacosSdistLaunchAuthorityErrorV1::EntropyUnavailable)?;
        getrandom::fill(&mut challenge_random)
            .map_err(|_| MacosSdistLaunchAuthorityErrorV1::EntropyUnavailable)?;
        let authority_id = format!("sdist-authority-{}", lower_hex(&authority_random));
        let challenge_binding_sha256 = Sha256Digest::from_bytes(&challenge_random);
        let bindings = MacosSdistSubmissionBindingsV1::for_run_spec(
            challenge_binding_sha256.clone(),
            &run_spec,
        );
        let header = MacosSdistSubmissionHeaderV1::new(run_spec.clone(), bindings)?;
        let record = MacosSdistLaunchAuthorityRecordV1 {
            artifact_sha256: run_spec.artifact_sha256().clone(),
            authority_id,
            build_closure_sha256: run_spec.build_closure_sha256().clone(),
            challenge_binding_sha256,
            expires_at_unix_seconds: expires_at_unix_seconds.to_string(),
            issued_at_unix_seconds: issued_at_unix_seconds.to_string(),
            run_spec_sha256: run_spec.run_spec_sha256().clone(),
            schema_version: MACOS_SDIST_LAUNCH_AUTHORITY_SCHEMA_V1.to_string(),
        };
        let canonical = record.canonical_json_v1()?;
        match directories.persist(&record, &canonical) {
            Ok(authority) => return Ok(PreparedMacosSdistLaunchV1 { header, authority }),
            Err(MacosSdistLaunchAuthorityErrorV1::AuthorityCollision) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(MacosSdistLaunchAuthorityErrorV1::AuthorityCollision)
}

/// Irreversibly consume one pending authority before guest authentication or artifact receipt.
///
/// The pending record is moved to the consumed directory before its time and binding checks. Any
/// expired, tampered, or mismatched attempt therefore burns the authority and cannot be retried.
pub fn consume_macos_sdist_launch_authority_v1(
    state_directory: &Path,
    request: &MacosSdistLaunchAuthorityConsumptionRequestV1,
    now_unix_seconds: u64,
) -> Result<ConsumedMacosSdistLaunchAuthorityV1, MacosSdistLaunchAuthorityErrorV1> {
    if now_unix_seconds == 0 {
        return Err(MacosSdistLaunchAuthorityErrorV1::InvalidTime);
    }
    let directories = AuthorityDirectoriesV1::open_or_create(state_directory)?;
    directories.consume(request, now_unix_seconds)
}

/// Consume an authority and only then construct the exact guest-authentication challenge.
pub fn consume_and_authorize_macos_sdist_guest_session_v1(
    state_directory: &Path,
    request: &MacosSdistLaunchAuthorityConsumptionRequestV1,
    now_unix_seconds: u64,
    guest_nonce: [u8; 32],
    clone_binding_sha256: Sha256Digest,
) -> Result<AuthorizedMacosSdistGuestSessionV1, MacosSdistLaunchAuthorityErrorV1> {
    let consumed_authority =
        consume_macos_sdist_launch_authority_v1(state_directory, request, now_unix_seconds)?;
    let run_spec = request.header().run_spec();
    let challenge = MacosSdistGuestAuthChallengeV1::new(
        guest_nonce,
        request
            .header()
            .bindings()
            .execution_binding_sha256()
            .clone(),
        run_spec.run_spec_sha256().clone(),
        run_spec.build_closure_sha256().clone(),
        clone_binding_sha256,
        run_spec
            .backend_identity()
            .guest_auth_public_key_sha256()
            .clone(),
    )
    .map_err(|_| MacosSdistLaunchAuthorityErrorV1::AuthorityBindingMismatch)?;
    Ok(AuthorizedMacosSdistGuestSessionV1 {
        consumed_authority,
        header: request.header().clone(),
        challenge,
    })
}

struct DirectoryFdV1(RawFd);

impl Drop for DirectoryFdV1 {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

struct AuthorityDirectoriesV1 {
    root: DirectoryFdV1,
    pending: DirectoryFdV1,
    consumed: DirectoryFdV1,
    pending_path: PathBuf,
    consumed_path: PathBuf,
}

impl AuthorityDirectoriesV1 {
    fn open_or_create(state_directory: &Path) -> Result<Self, MacosSdistLaunchAuthorityErrorV1> {
        if !state_directory.is_absolute() {
            return Err(MacosSdistLaunchAuthorityErrorV1::InvalidStateDirectory);
        }
        let state = open_directory_path(state_directory, false)?;
        let root = open_or_create_child_directory(state.0, AUTHORITY_ROOT_NAME_V1)?;
        let pending = open_or_create_child_directory(root.0, AUTHORITY_PENDING_NAME_V1)?;
        let consumed = open_or_create_child_directory(root.0, AUTHORITY_CONSUMED_NAME_V1)?;
        Ok(Self {
            root,
            pending,
            consumed,
            pending_path: state_directory
                .join(AUTHORITY_ROOT_NAME_V1)
                .join(AUTHORITY_PENDING_NAME_V1),
            consumed_path: state_directory
                .join(AUTHORITY_ROOT_NAME_V1)
                .join(AUTHORITY_CONSUMED_NAME_V1),
        })
    }

    fn persist(
        &self,
        record: &MacosSdistLaunchAuthorityRecordV1,
        canonical: &[u8],
    ) -> Result<PersistedMacosSdistLaunchAuthorityV1, MacosSdistLaunchAuthorityErrorV1> {
        let name = CString::new(format!("{}.json", record.authority_id()))
            .map_err(|_| MacosSdistLaunchAuthorityErrorV1::AuthorityCreateFailed)?;
        if child_exists(self.consumed.0, &name)? {
            return Err(MacosSdistLaunchAuthorityErrorV1::AuthorityCollision);
        }
        let descriptor = unsafe {
            libc::openat(
                self.pending.0,
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if descriptor < 0 {
            return if io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists {
                Err(MacosSdistLaunchAuthorityErrorV1::AuthorityCollision)
            } else {
                Err(MacosSdistLaunchAuthorityErrorV1::AuthorityCreateFailed)
            };
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let write_result = (|| {
            file.write_all(canonical)
                .map_err(|_| MacosSdistLaunchAuthorityErrorV1::AuthorityWriteFailed)?;
            file.sync_all()
                .map_err(|_| MacosSdistLaunchAuthorityErrorV1::AuthorityPersistenceFailed)?;
            verify_authority_file(&file, canonical.len())?;
            fsync_directory(self.pending.0)?;
            fsync_directory(self.root.0)?;
            Ok(())
        })();
        if let Err(error) = write_result {
            unsafe {
                libc::unlinkat(self.pending.0, name.as_ptr(), 0);
            }
            return Err(error);
        }
        Ok(PersistedMacosSdistLaunchAuthorityV1 {
            record: record.clone(),
            record_sha256: Sha256Digest::from_bytes(canonical),
            pending_path: self
                .pending_path
                .join(format!("{}.json", record.authority_id())),
        })
    }

    fn consume(
        &self,
        request: &MacosSdistLaunchAuthorityConsumptionRequestV1,
        now_unix_seconds: u64,
    ) -> Result<ConsumedMacosSdistLaunchAuthorityV1, MacosSdistLaunchAuthorityErrorV1> {
        let name = CString::new(format!("{}.json", request.authority_id()))
            .map_err(|_| MacosSdistLaunchAuthorityErrorV1::AuthorityRecordInvalid)?;
        if child_exists(self.consumed.0, &name)? {
            return Err(MacosSdistLaunchAuthorityErrorV1::AuthorityUnavailable);
        }
        atomic_move_no_replace(self.pending.0, self.consumed.0, &name)?;
        fsync_directory(self.pending.0)?;
        fsync_directory(self.consumed.0)?;
        fsync_directory(self.root.0)?;

        let descriptor = unsafe {
            libc::openat(
                self.consumed.0,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(MacosSdistLaunchAuthorityErrorV1::AuthorityVerificationFailed);
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file
            .metadata()
            .map_err(|_| MacosSdistLaunchAuthorityErrorV1::AuthorityVerificationFailed)?;
        let length = usize::try_from(metadata.len())
            .map_err(|_| MacosSdistLaunchAuthorityErrorV1::AuthorityRecordInvalid)?;
        if length == 0 || length > MAX_AUTHORITY_RECORD_BYTES_V1 {
            return Err(MacosSdistLaunchAuthorityErrorV1::AuthorityRecordInvalid);
        }
        verify_authority_file(&file, length)?;
        let mut canonical = Vec::with_capacity(length);
        file.read_to_end(&mut canonical)
            .map_err(|_| MacosSdistLaunchAuthorityErrorV1::AuthorityVerificationFailed)?;
        if canonical.len() != length
            || Sha256Digest::from_bytes(&canonical) != *request.record_sha256()
        {
            return Err(MacosSdistLaunchAuthorityErrorV1::AuthorityRecordInvalid);
        }
        let mut deserializer = serde_json::Deserializer::from_slice(&canonical);
        let record = MacosSdistLaunchAuthorityRecordV1::deserialize(&mut deserializer)
            .map_err(|_| MacosSdistLaunchAuthorityErrorV1::AuthorityRecordInvalid)?;
        deserializer
            .end()
            .map_err(|_| MacosSdistLaunchAuthorityErrorV1::AuthorityRecordInvalid)?;
        if serde_json_canonicalizer::to_vec(&record)
            .map_err(|_| MacosSdistLaunchAuthorityErrorV1::Serialization)?
            != canonical
            || record.schema_version != MACOS_SDIST_LAUNCH_AUTHORITY_SCHEMA_V1
            || record.authority_id != request.authority_id
            || !valid_authority_record_times(&record)
        {
            return Err(MacosSdistLaunchAuthorityErrorV1::AuthorityRecordInvalid);
        }
        let issued_at = record.issued_at_unix_seconds();
        let expires_at = record.expires_at_unix_seconds();
        if now_unix_seconds < issued_at || now_unix_seconds >= expires_at {
            return Err(MacosSdistLaunchAuthorityErrorV1::AuthorityExpired);
        }
        let run_spec = request.header().run_spec();
        if request.header().bindings().challenge_binding_sha256()
            != record.challenge_binding_sha256()
            || run_spec.run_spec_sha256() != record.run_spec_sha256()
            || run_spec.artifact_sha256() != record.artifact_sha256()
            || run_spec.build_closure_sha256() != record.build_closure_sha256()
        {
            return Err(MacosSdistLaunchAuthorityErrorV1::AuthorityBindingMismatch);
        }
        Ok(ConsumedMacosSdistLaunchAuthorityV1 {
            record,
            record_sha256: Sha256Digest::from_bytes(&canonical),
            consumed_path: self
                .consumed_path
                .join(format!("{}.json", request.authority_id())),
            consumed_at_unix_seconds: now_unix_seconds,
        })
    }
}

#[cfg(target_os = "macos")]
fn atomic_move_no_replace(
    pending: RawFd,
    consumed: RawFd,
    name: &CString,
) -> Result<(), MacosSdistLaunchAuthorityErrorV1> {
    let result = unsafe {
        libc::renameatx_np(
            pending,
            name.as_ptr(),
            consumed,
            name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        return Ok(());
    }
    match io::Error::last_os_error().kind() {
        io::ErrorKind::NotFound | io::ErrorKind::AlreadyExists => {
            Err(MacosSdistLaunchAuthorityErrorV1::AuthorityUnavailable)
        }
        _ => Err(MacosSdistLaunchAuthorityErrorV1::AuthorityPersistenceFailed),
    }
}

#[cfg(not(target_os = "macos"))]
fn atomic_move_no_replace(
    pending: RawFd,
    consumed: RawFd,
    name: &CString,
) -> Result<(), MacosSdistLaunchAuthorityErrorV1> {
    if child_exists(consumed, name)? {
        return Err(MacosSdistLaunchAuthorityErrorV1::AuthorityUnavailable);
    }
    let result = unsafe { libc::renameat(pending, name.as_ptr(), consumed, name.as_ptr()) };
    if result == 0 {
        return Ok(());
    }
    match io::Error::last_os_error().kind() {
        io::ErrorKind::NotFound | io::ErrorKind::AlreadyExists => {
            Err(MacosSdistLaunchAuthorityErrorV1::AuthorityUnavailable)
        }
        _ => Err(MacosSdistLaunchAuthorityErrorV1::AuthorityPersistenceFailed),
    }
}

fn open_directory_path(
    path: &Path,
    require_exact_mode: bool,
) -> Result<DirectoryFdV1, MacosSdistLaunchAuthorityErrorV1> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| MacosSdistLaunchAuthorityErrorV1::InvalidStateDirectory)?;
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(MacosSdistLaunchAuthorityErrorV1::DirectoryOpenFailed);
    }
    let descriptor = DirectoryFdV1(descriptor);
    verify_directory(descriptor.0, require_exact_mode)?;
    Ok(descriptor)
}

fn open_or_create_child_directory(
    parent: RawFd,
    name: &str,
) -> Result<DirectoryFdV1, MacosSdistLaunchAuthorityErrorV1> {
    let name = CString::new(name)
        .map_err(|_| MacosSdistLaunchAuthorityErrorV1::DirectoryCreationFailed)?;
    let created = unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) };
    if created != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
        return Err(MacosSdistLaunchAuthorityErrorV1::DirectoryCreationFailed);
    }
    if created == 0 {
        fsync_directory(parent)?;
    }
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(MacosSdistLaunchAuthorityErrorV1::DirectoryOpenFailed);
    }
    let descriptor = DirectoryFdV1(descriptor);
    verify_directory(descriptor.0, true)?;
    Ok(descriptor)
}

fn verify_directory(
    descriptor: RawFd,
    require_exact_mode: bool,
) -> Result<(), MacosSdistLaunchAuthorityErrorV1> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(descriptor, status.as_mut_ptr()) } != 0 {
        return Err(MacosSdistLaunchAuthorityErrorV1::UnsafeStateDirectory);
    }
    let status = unsafe { status.assume_init() };
    let mode = status.st_mode & 0o777;
    if status.st_mode & libc::S_IFMT != libc::S_IFDIR
        || status.st_uid != unsafe { libc::geteuid() }
        || mode & 0o022 != 0
        || (require_exact_mode && mode != 0o700)
    {
        return Err(MacosSdistLaunchAuthorityErrorV1::UnsafeStateDirectory);
    }
    Ok(())
}

fn verify_authority_file(
    file: &File,
    expected_length: usize,
) -> Result<(), MacosSdistLaunchAuthorityErrorV1> {
    let metadata = file
        .metadata()
        .map_err(|_| MacosSdistLaunchAuthorityErrorV1::AuthorityVerificationFailed)?;
    if !metadata.file_type().is_file()
        || std::os::unix::fs::MetadataExt::uid(&metadata) != unsafe { libc::geteuid() }
        || std::os::unix::fs::MetadataExt::nlink(&metadata) != 1
        || std::os::unix::fs::MetadataExt::mode(&metadata) & 0o777 != 0o600
        || metadata.len() != expected_length as u64
    {
        return Err(MacosSdistLaunchAuthorityErrorV1::AuthorityVerificationFailed);
    }
    Ok(())
}

fn child_exists(
    directory: RawFd,
    name: &CString,
) -> Result<bool, MacosSdistLaunchAuthorityErrorV1> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            directory,
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
        return Ok(false);
    }
    Err(MacosSdistLaunchAuthorityErrorV1::AuthorityVerificationFailed)
}

fn fsync_directory(descriptor: RawFd) -> Result<(), MacosSdistLaunchAuthorityErrorV1> {
    if unsafe { libc::fsync(descriptor) } != 0 {
        return Err(MacosSdistLaunchAuthorityErrorV1::AuthorityPersistenceFailed);
    }
    Ok(())
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn valid_authority_id(value: &str) -> bool {
    value
        .strip_prefix("sdist-authority-")
        .is_some_and(|suffix| {
            suffix.len() == 64
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn valid_authority_record_times(record: &MacosSdistLaunchAuthorityRecordV1) -> bool {
    let Ok(issued_at) = record.issued_at_unix_seconds.parse::<u64>() else {
        return false;
    };
    let Ok(expires_at) = record.expires_at_unix_seconds.parse::<u64>() else {
        return false;
    };
    issued_at != 0
        && issued_at.to_string() == record.issued_at_unix_seconds
        && expires_at.to_string() == record.expires_at_unix_seconds
        && expires_at > issued_at
        && expires_at - issued_at <= MAX_MACOS_SDIST_LAUNCH_AUTHORITY_LIFETIME_SECONDS_V1
}
