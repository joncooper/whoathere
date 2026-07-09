use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use whoathere_vault_api::{ArtifactRef, CacheKeyError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineReceipt {
    pub quarantine_id: String,
    pub artifact: ArtifactRef,
    pub cache_object_key: String,
    pub byte_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotedCacheObject {
    pub artifact: ArtifactRef,
    pub cache_object_key: String,
    pub byte_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheStoreError {
    InvalidDigest(CacheKeyError),
    EmptyPayload,
    UnsupportedDigestVerification,
    DigestMismatch,
    QuarantineNotFound,
    ObjectAlreadyPromoted,
    PromotedObjectNotFound,
    PromotedObjectKeyMismatch,
    PromotedObjectArtifactMismatch,
}

impl CacheStoreError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidDigest(error) => error.reason_code(),
            Self::EmptyPayload => "cache_payload_empty",
            Self::UnsupportedDigestVerification => "cache_digest_verification_unsupported",
            Self::DigestMismatch => "cache_digest_mismatch",
            Self::QuarantineNotFound => "cache_quarantine_not_found",
            Self::ObjectAlreadyPromoted => "cache_object_already_promoted",
            Self::PromotedObjectNotFound => "cache_promoted_object_not_found",
            Self::PromotedObjectKeyMismatch => "cache_promoted_object_key_mismatch",
            Self::PromotedObjectArtifactMismatch => "cache_promoted_object_artifact_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheObject {
    artifact: ArtifactRef,
    cache_object_key: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct InMemoryCacheStore {
    quarantined: BTreeMap<String, CacheObject>,
    promoted: BTreeMap<String, CacheObject>,
    next_quarantine_id: u64,
}

impl InMemoryCacheStore {
    pub fn new() -> Self {
        Self {
            next_quarantine_id: 1,
            ..Self::default()
        }
    }

    pub fn quarantine(
        &mut self,
        artifact: ArtifactRef,
        bytes: Vec<u8>,
    ) -> Result<QuarantineReceipt, CacheStoreError> {
        if bytes.is_empty() {
            return Err(CacheStoreError::EmptyPayload);
        }
        let cache_object_key = artifact
            .cache_object_key()
            .map_err(CacheStoreError::InvalidDigest)?;
        verify_payload_digest(&artifact.digest, &bytes)?;
        let quarantine_id = format!("quarantine-{}", self.next_quarantine_id);
        self.next_quarantine_id += 1;
        let object = CacheObject {
            artifact: artifact.clone(),
            cache_object_key: cache_object_key.clone(),
            bytes,
        };
        let byte_len = object.bytes.len();
        self.quarantined.insert(quarantine_id.clone(), object);
        Ok(QuarantineReceipt {
            quarantine_id,
            artifact,
            cache_object_key,
            byte_len,
        })
    }

    pub fn promote(&mut self, quarantine_id: &str) -> Result<PromotedCacheObject, CacheStoreError> {
        let object = self
            .quarantined
            .remove(quarantine_id)
            .ok_or(CacheStoreError::QuarantineNotFound)?;
        if self.promoted.contains_key(&object.cache_object_key) {
            return Err(CacheStoreError::ObjectAlreadyPromoted);
        }
        let promoted = PromotedCacheObject {
            artifact: object.artifact.clone(),
            cache_object_key: object.cache_object_key.clone(),
            byte_len: object.bytes.len(),
        };
        self.promoted
            .insert(object.cache_object_key.clone(), object);
        Ok(promoted)
    }

    pub fn promoted_bytes(&self, cache_object_key: &str) -> Option<&[u8]> {
        self.promoted
            .get(cache_object_key)
            .map(|object| object.bytes.as_slice())
    }

    pub fn promoted_bytes_for_artifact(
        &self,
        artifact: &ArtifactRef,
        cache_object_key: &str,
    ) -> Result<&[u8], CacheStoreError> {
        let expected_key = artifact
            .cache_object_key()
            .map_err(CacheStoreError::InvalidDigest)?;
        if expected_key != cache_object_key {
            return Err(CacheStoreError::PromotedObjectKeyMismatch);
        }
        let object = self
            .promoted
            .get(cache_object_key)
            .ok_or(CacheStoreError::PromotedObjectNotFound)?;
        if object.artifact != *artifact {
            return Err(CacheStoreError::PromotedObjectArtifactMismatch);
        }
        Ok(object.bytes.as_slice())
    }
}

/// A persistent, digest-addressed, tamper-evident quarantine for untrusted
/// artifact bytes.
///
/// The caller gives this store a dedicated root. `create` takes ownership of
/// that root's permissions, tightening the root and its internal directories
/// to POSIX owner-only mode bits on Unix. ACL and service-boundary hardening is
/// outside this store's current guarantee. Objects are published under
/// `blobs/sha256/<hex>` and are never replaced in place by this API.
pub struct PersistentQuarantineCas {
    root: PathBuf,
    object_directory: PathBuf,
    max_artifact_bytes: u64,
    root_identity: PathIdentity,
    blobs_identity: PathIdentity,
    object_directory_identity: PathIdentity,
}

impl fmt::Debug for PersistentQuarantineCas {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentQuarantineCas")
            .field("root", &"<redacted>")
            .field("max_artifact_bytes", &self.max_artifact_bytes)
            .finish_non_exhaustive()
    }
}

/// An opaque capability for one exact object in a `PersistentQuarantineCas`.
///
/// Handles are bound to the store root that issued them. Consumers must obtain
/// a [`VerifiedArtifactLease`] before reading artifact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedArtifact {
    digest: String,
    byte_len: u64,
    object_key: String,
    store_identity: PathIdentity,
}

impl QuarantinedArtifact {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub fn object_key(&self) -> &str {
        &self.object_key
    }
}

/// A verified, in-memory snapshot of a quarantined object.
///
/// The CAS reopens the object without following a final-component symlink,
/// checks its path and inode identity before and after reading, enforces the
/// original length bound, and rehashes it before constructing this value.
/// Returning a snapshot rather than a still-mutable file descriptor ensures
/// callers can only observe the bytes that passed verification.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedArtifactLease {
    artifact: QuarantinedArtifact,
    bytes: Vec<u8>,
}

impl fmt::Debug for VerifiedArtifactLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedArtifactLease")
            .field("artifact_digest", &self.artifact.digest())
            .field("object_key", &self.artifact.object_key())
            .field("byte_len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl VerifiedArtifactLease {
    pub fn artifact(&self) -> &QuarantinedArtifact {
        &self.artifact
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistentCasError {
    InvalidMaximumSize,
    InvalidDigest,
    UnsupportedDigestAlgorithm,
    EmptyPayload,
    PayloadTooLarge {
        limit: u64,
    },
    AllocationFailed,
    DigestMismatch,
    ObjectNotFound,
    ObjectNotRegularFile,
    ObjectNotSealed,
    ObjectLengthMismatch,
    ObjectIdentityChanged,
    UnsafePath,
    StoreIdentityChanged,
    HandleStoreMismatch,
    Io {
        operation: &'static str,
        kind: io::ErrorKind,
    },
}

impl PersistentCasError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidMaximumSize => "quarantine_cas_invalid_maximum_size",
            Self::InvalidDigest => "quarantine_cas_invalid_digest",
            Self::UnsupportedDigestAlgorithm => "quarantine_cas_unsupported_digest_algorithm",
            Self::EmptyPayload => "quarantine_cas_empty_payload",
            Self::PayloadTooLarge { .. } => "quarantine_cas_payload_too_large",
            Self::AllocationFailed => "quarantine_cas_allocation_failed",
            Self::DigestMismatch => "quarantine_cas_digest_mismatch",
            Self::ObjectNotFound => "quarantine_cas_object_not_found",
            Self::ObjectNotRegularFile => "quarantine_cas_object_not_regular_file",
            Self::ObjectNotSealed => "quarantine_cas_object_not_sealed",
            Self::ObjectLengthMismatch => "quarantine_cas_object_length_mismatch",
            Self::ObjectIdentityChanged => "quarantine_cas_object_identity_changed",
            Self::UnsafePath => "quarantine_cas_unsafe_path",
            Self::StoreIdentityChanged => "quarantine_cas_store_identity_changed",
            Self::HandleStoreMismatch => "quarantine_cas_handle_store_mismatch",
            Self::Io { .. } => "quarantine_cas_io_error",
        }
    }

    fn io(operation: &'static str, error: io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
        }
    }
}

impl fmt::Display for PersistentCasError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { limit } => {
                write!(
                    formatter,
                    "artifact exceeds the {limit}-byte quarantine limit"
                )
            }
            Self::Io { operation, kind } => {
                write!(formatter, "quarantine CAS {operation} failed: {kind:?}")
            }
            other => formatter.write_str(other.reason_code()),
        }
    }
}

impl std::error::Error for PersistentCasError {}

impl PersistentQuarantineCas {
    /// Creates or opens a private CAS rooted at `root`.
    ///
    /// `max_artifact_bytes` is enforced while ingesting and again while
    /// obtaining verified leases. A zero limit is rejected.
    pub fn create(
        root: impl AsRef<Path>,
        max_artifact_bytes: u64,
    ) -> Result<Self, PersistentCasError> {
        if max_artifact_bytes == 0 {
            return Err(PersistentCasError::InvalidMaximumSize);
        }

        let root = root.as_ref().to_path_buf();
        create_private_directory(&root)?;
        // Retain an absolute path so later operations cannot be redirected by
        // a process-wide current-directory change when the caller supplied a
        // relative root.
        let root = fs::canonicalize(&root)
            .map_err(|error| PersistentCasError::io("canonicalize CAS root", error))?;
        let blobs = root.join("blobs");
        create_private_directory(&blobs)?;
        let object_directory = blobs.join("sha256");
        create_private_directory(&object_directory)?;

        let root_identity = checked_directory_identity(&root)?;
        let blobs_identity = checked_directory_identity(&blobs)?;
        let object_directory_identity = checked_directory_identity(&object_directory)?;

        Ok(Self {
            root,
            object_directory,
            max_artifact_bytes,
            root_identity,
            blobs_identity,
            object_directory_identity,
        })
    }

    pub fn max_artifact_bytes(&self) -> u64 {
        self.max_artifact_bytes
    }

    /// Quarantines a bounded byte slice under its expected SHA-256 digest.
    pub fn quarantine_bytes(
        &self,
        expected_digest: &str,
        bytes: &[u8],
    ) -> Result<QuarantinedArtifact, PersistentCasError> {
        self.quarantine_reader(expected_digest, bytes)
    }

    /// Streams bytes into a create-new temporary file and atomically publishes
    /// the verified object without ever replacing an existing destination.
    pub fn quarantine_reader<R: Read>(
        &self,
        expected_digest: &str,
        mut reader: R,
    ) -> Result<QuarantinedArtifact, PersistentCasError> {
        self.ensure_layout_identity()?;
        let digest_hex = parse_sha256_digest(expected_digest)?;
        let canonical_digest = format!("sha256:{digest_hex}");
        let object_key = format!("blobs/sha256/{digest_hex}");
        let destination = self.object_directory.join(&digest_hex);
        let mut temporary = TemporaryObject::create(&self.object_directory)?;
        let mut payload_hash = Sha256State::new();
        let mut buffer = [0_u8; 16 * 1024];
        let mut byte_len = 0_u64;

        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|error| PersistentCasError::io("read input", error))?;
            if count == 0 {
                break;
            }
            let new_len =
                byte_len
                    .checked_add(count as u64)
                    .ok_or(PersistentCasError::PayloadTooLarge {
                        limit: self.max_artifact_bytes,
                    })?;
            if new_len > self.max_artifact_bytes {
                return Err(PersistentCasError::PayloadTooLarge {
                    limit: self.max_artifact_bytes,
                });
            }
            temporary
                .file_mut()
                .write_all(&buffer[..count])
                .map_err(|error| PersistentCasError::io("write temporary object", error))?;
            payload_hash.update(&buffer[..count]);
            byte_len = new_len;
        }

        if byte_len == 0 {
            return Err(PersistentCasError::EmptyPayload);
        }
        if payload_hash.finalize_hex() != digest_hex {
            return Err(PersistentCasError::DigestMismatch);
        }

        temporary.seal()?;
        self.ensure_layout_identity()?;

        match fs::hard_link(temporary.path(), &destination) {
            Ok(()) => {
                // The hard link is the atomic, no-overwrite publication point.
                // Remove the staging name before verification so the published
                // object has exactly one link when a capability is issued.
                self.ensure_layout_identity()?;
                let handle = QuarantinedArtifact {
                    digest: canonical_digest,
                    byte_len,
                    object_key,
                    store_identity: self.root_identity.clone(),
                };
                temporary.remove()?;
                sync_directory(&self.object_directory)?;
                self.read_verified_bytes(&handle)?;
                Ok(handle)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                // Existing content is accepted only after exact length and
                // digest verification. It is never removed or overwritten.
                let handle = QuarantinedArtifact {
                    digest: canonical_digest,
                    byte_len,
                    object_key,
                    store_identity: self.root_identity.clone(),
                };
                let mut verification = self.read_verified_bytes(&handle);
                for _ in 0..64 {
                    if !matches!(verification, Err(PersistentCasError::ObjectNotSealed)) {
                        break;
                    }
                    // A concurrent publisher briefly has the staging and final
                    // names hard-linked to the same sealed inode. Wait only for
                    // that bounded publication window; a persistent extra link
                    // remains a hard failure.
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    verification = self.read_verified_bytes(&handle);
                }
                verification?;
                temporary.remove()?;
                Ok(handle)
            }
            Err(error) => Err(PersistentCasError::io("publish object", error)),
        }
    }

    /// Reopens, bounds, and rehashes an object before yielding any bytes.
    pub fn verified_lease(
        &self,
        artifact: &QuarantinedArtifact,
    ) -> Result<VerifiedArtifactLease, PersistentCasError> {
        let bytes = self.read_verified_bytes(artifact)?;
        Ok(VerifiedArtifactLease {
            artifact: artifact.clone(),
            bytes,
        })
    }

    /// Reconstructs an opaque capability from a trusted durable receipt and
    /// re-verifies the persisted object before returning it.
    ///
    /// Callers must obtain `expected_digest` and `expected_byte_len` from an
    /// authenticated control-plane record, never from registry re-resolution.
    pub fn reopen_quarantined(
        &self,
        expected_digest: &str,
        expected_byte_len: u64,
    ) -> Result<QuarantinedArtifact, PersistentCasError> {
        self.ensure_layout_identity()?;
        if expected_byte_len == 0 || expected_byte_len > self.max_artifact_bytes {
            return Err(PersistentCasError::ObjectLengthMismatch);
        }
        let digest_hex = parse_sha256_digest(expected_digest)?;
        let artifact = QuarantinedArtifact {
            digest: format!("sha256:{digest_hex}"),
            byte_len: expected_byte_len,
            object_key: format!("blobs/sha256/{digest_hex}"),
            store_identity: self.root_identity.clone(),
        };
        self.read_verified_bytes(&artifact)?;
        Ok(artifact)
    }

    fn read_verified_bytes(
        &self,
        artifact: &QuarantinedArtifact,
    ) -> Result<Vec<u8>, PersistentCasError> {
        self.ensure_layout_identity()?;
        if artifact.store_identity != self.root_identity {
            return Err(PersistentCasError::HandleStoreMismatch);
        }
        if artifact.byte_len == 0 || artifact.byte_len > self.max_artifact_bytes {
            return Err(PersistentCasError::ObjectLengthMismatch);
        }
        let digest_hex = parse_sha256_digest(&artifact.digest)?;
        let expected_key = format!("blobs/sha256/{digest_hex}");
        if artifact.object_key != expected_key {
            return Err(PersistentCasError::UnsafePath);
        }

        let object_path = self.object_directory.join(&digest_hex);
        let path_before = checked_regular_file_snapshot(&object_path)?;
        if path_before.len != artifact.byte_len {
            return Err(PersistentCasError::ObjectLengthMismatch);
        }

        let mut file = open_regular_file_without_following(&object_path)?;
        let file_before = file
            .metadata()
            .map_err(|error| PersistentCasError::io("stat opened object", error))?;
        ensure_sealed_object_metadata(&file_before)?;
        let file_before = FileSnapshot::from_metadata(&file_before);
        if file_before != path_before {
            return Err(PersistentCasError::ObjectIdentityChanged);
        }

        let capacity = usize::try_from(artifact.byte_len)
            .map_err(|_| PersistentCasError::ObjectLengthMismatch)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| PersistentCasError::AllocationFailed)?;
        Read::by_ref(&mut file)
            .take(self.max_artifact_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| PersistentCasError::io("read object", error))?;
        if bytes.len() as u64 != artifact.byte_len {
            return Err(PersistentCasError::ObjectLengthMismatch);
        }

        let file_after = file
            .metadata()
            .map_err(|error| PersistentCasError::io("restat opened object", error))?;
        ensure_sealed_object_metadata(&file_after)?;
        let file_after = FileSnapshot::from_metadata(&file_after);
        let path_after = checked_regular_file_snapshot(&object_path)?;
        if file_before != file_after || file_after != path_after {
            return Err(PersistentCasError::ObjectIdentityChanged);
        }
        self.ensure_layout_identity()?;
        if sha256_hex(&bytes) != digest_hex {
            return Err(PersistentCasError::DigestMismatch);
        }
        Ok(bytes)
    }

    fn ensure_layout_identity(&self) -> Result<(), PersistentCasError> {
        let current_root = checked_directory_identity(&self.root)?;
        let blobs = self.root.join("blobs");
        let current_blobs = checked_directory_identity(&blobs)?;
        let current_objects = checked_directory_identity(&self.object_directory)?;
        if current_root != self.root_identity
            || current_blobs != self.blobs_identity
            || current_objects != self.object_directory_identity
        {
            return Err(PersistentCasError::StoreIdentityChanged);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    owner: u32,
    #[cfg(unix)]
    group: u32,
    #[cfg(unix)]
    mode: u32,
    #[cfg(not(unix))]
    canonical_path: PathBuf,
}

impl PathIdentity {
    fn from_metadata(path: &Path, metadata: &fs::Metadata) -> Result<Self, PersistentCasError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let _ = path;
            if metadata.uid() != current_effective_user_id() || metadata.mode() & 0o7777 != 0o700 {
                return Err(PersistentCasError::UnsafePath);
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                owner: metadata.uid(),
                group: metadata.gid(),
                mode: metadata.mode() & 0o7777,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                canonical_path: fs::canonicalize(path)
                    .map_err(|error| PersistentCasError::io("canonicalize path", error))?,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnapshot {
    identity: FileIdentity,
    len: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(unix)]
    owner: u32,
    #[cfg(unix)]
    group: u32,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    link_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    len: u64,
}

impl FileSnapshot {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                identity: FileIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
                len: metadata.len(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
                owner: metadata.uid(),
                group: metadata.gid(),
                mode: metadata.mode() & 0o7777,
                link_count: metadata.nlink(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                identity: FileIdentity {
                    len: metadata.len(),
                },
                len: metadata.len(),
            }
        }
    }
}

fn create_private_directory(path: &Path) -> Result<(), PersistentCasError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(PersistentCasError::io("create directory", error)),
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            PersistentCasError::UnsafePath
        } else {
            PersistentCasError::io("inspect directory", error)
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PersistentCasError::UnsafePath);
    }
    set_private_directory_permissions(path)?;
    checked_directory_identity(path).map(|_| ())
}

fn checked_directory_identity(path: &Path) -> Result<PathIdentity, PersistentCasError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            PersistentCasError::StoreIdentityChanged
        } else {
            PersistentCasError::io("inspect directory identity", error)
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PersistentCasError::UnsafePath);
    }
    PathIdentity::from_metadata(path, &metadata)
}

fn checked_regular_file_snapshot(path: &Path) -> Result<FileSnapshot, PersistentCasError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            PersistentCasError::ObjectNotFound
        } else {
            PersistentCasError::io("inspect object", error)
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(PersistentCasError::UnsafePath);
    }
    if !metadata.is_file() {
        return Err(PersistentCasError::ObjectNotRegularFile);
    }
    ensure_sealed_object_metadata(&metadata)?;
    Ok(FileSnapshot::from_metadata(&metadata))
}

#[cfg(unix)]
fn ensure_sealed_object_metadata(metadata: &fs::Metadata) -> Result<(), PersistentCasError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != current_effective_user_id()
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
    {
        return Err(PersistentCasError::ObjectNotSealed);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_sealed_object_metadata(metadata: &fs::Metadata) -> Result<(), PersistentCasError> {
    if !metadata.permissions().readonly() {
        return Err(PersistentCasError::ObjectNotSealed);
    }
    Ok(())
}

#[cfg(unix)]
fn current_effective_user_id() -> u32 {
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() }
}

fn parse_sha256_digest(digest: &str) -> Result<String, PersistentCasError> {
    let Some((algorithm, hex)) = digest.split_once(':') else {
        return Err(PersistentCasError::InvalidDigest);
    };
    if algorithm != "sha256" {
        return Err(PersistentCasError::UnsupportedDigestAlgorithm);
    }
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PersistentCasError::InvalidDigest);
    }
    Ok(hex.to_ascii_lowercase())
}

fn open_regular_file_without_following(path: &Path) -> Result<File, PersistentCasError> {
    let mut options = OpenOptions::new();
    options.read(true);
    add_no_follow_flag(&mut options);
    options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            PersistentCasError::ObjectNotFound
        } else {
            PersistentCasError::io("open object without following symlinks", error)
        }
    })
}

#[cfg(unix)]
fn open_directory_without_following(path: &Path) -> Result<File, PersistentCasError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .map_err(|error| PersistentCasError::io("open directory without following symlinks", error))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn add_no_follow_flag(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    const O_NOFOLLOW: i32 = 0x20000;
    options.custom_flags(O_NOFOLLOW);
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn add_no_follow_flag(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    const O_NOFOLLOW: i32 = 0x100;
    options.custom_flags(O_NOFOLLOW);
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn add_no_follow_flag(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), PersistentCasError> {
    use std::os::unix::fs::PermissionsExt;
    let directory = open_directory_without_following(path)?;
    directory
        .set_permissions(fs::Permissions::from_mode(0o700))
        .map_err(|error| PersistentCasError::io("set directory permissions", error))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), PersistentCasError> {
    Ok(())
}

#[cfg(unix)]
fn set_read_only_object_permissions(file: &File) -> Result<(), PersistentCasError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(|error| PersistentCasError::io("set object permissions", error))
}

#[cfg(not(unix))]
fn set_read_only_object_permissions(file: &File) -> Result<(), PersistentCasError> {
    let mut permissions = file
        .metadata()
        .map_err(|error| PersistentCasError::io("read object permissions", error))?
        .permissions();
    permissions.set_readonly(true);
    file.set_permissions(permissions)
        .map_err(|error| PersistentCasError::io("set object permissions", error))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), PersistentCasError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| PersistentCasError::io("sync object directory", error))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), PersistentCasError> {
    Ok(())
}

static TEMPORARY_OBJECT_COUNTER: AtomicU64 = AtomicU64::new(1);

struct TemporaryObject {
    path: PathBuf,
    file: Option<File>,
}

impl TemporaryObject {
    fn create(directory: &Path) -> Result<Self, PersistentCasError> {
        for _ in 0..128 {
            let counter = TEMPORARY_OBJECT_COUNTER.fetch_add(1, Ordering::Relaxed);
            let name = format!(".incoming-{}-{counter:016x}", std::process::id());
            let path = directory.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            set_private_create_mode(&mut options);
            match options.open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(PersistentCasError::io("create temporary object", error));
                }
            }
        }
        Err(PersistentCasError::Io {
            operation: "allocate temporary object name",
            kind: io::ErrorKind::AlreadyExists,
        })
    }

    fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("temporary object file is open")
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn seal(&mut self) -> Result<(), PersistentCasError> {
        let file = self.file.as_ref().expect("temporary object file is open");
        file.sync_all()
            .map_err(|error| PersistentCasError::io("sync temporary object", error))?;
        set_read_only_object_permissions(file)?;
        file.sync_all()
            .map_err(|error| PersistentCasError::io("sync sealed object", error))?;
        let file_snapshot = file
            .metadata()
            .map(|metadata| FileSnapshot::from_metadata(&metadata))
            .map_err(|error| PersistentCasError::io("stat sealed object", error))?;
        let path_snapshot = checked_regular_file_snapshot(&self.path)?;
        if file_snapshot != path_snapshot {
            return Err(PersistentCasError::ObjectIdentityChanged);
        }
        self.file.take();
        Ok(())
    }

    fn remove(&mut self) -> Result<(), PersistentCasError> {
        self.file.take();
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(PersistentCasError::io("remove temporary object", error)),
        }
    }
}

impl Drop for TemporaryObject {
    fn drop(&mut self) {
        self.file.take();
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn set_private_create_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_create_mode(_options: &mut OpenOptions) {}

fn verify_payload_digest(digest: &str, bytes: &[u8]) -> Result<(), CacheStoreError> {
    let Some((algorithm, expected)) = digest.split_once(':') else {
        return Err(CacheStoreError::InvalidDigest(
            CacheKeyError::MissingSeparator,
        ));
    };
    match algorithm {
        "sha256" => {
            let actual = sha256_hex(bytes);
            if expected.eq_ignore_ascii_case(&actual) {
                Ok(())
            } else {
                Err(CacheStoreError::DigestMismatch)
            }
        }
        _ => Err(CacheStoreError::UnsupportedDigestVerification),
    }
}

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256State {
    hash: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    total_bytes: u64,
}

impl Sha256State {
    fn new() -> Self {
        Self {
            hash: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            total_bytes: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(input.len() as u64);
        if self.buffered != 0 {
            let copy_len = (64 - self.buffered).min(input.len());
            self.buffer[self.buffered..self.buffered + copy_len]
                .copy_from_slice(&input[..copy_len]);
            self.buffered += copy_len;
            input = &input[copy_len..];
            if self.buffered < 64 {
                return;
            }
            let block = self.buffer;
            self.process_block(&block);
            self.buffered = 0;
        }
        while input.len() >= 64 {
            let (block, rest) = input.split_at(64);
            self.process_block(block.try_into().expect("SHA-256 block has fixed length"));
            input = rest;
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffered = input.len();
    }

    fn finalize_hex(mut self) -> String {
        let bit_len = self.total_bytes.wrapping_mul(8);
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.process_block(&block);
            self.buffer = [0; 64];
            self.buffered = 0;
        }
        self.buffer[self.buffered..56].fill(0);
        self.buffer[56..].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.process_block(&block);
        self.hash
            .iter()
            .map(|word| format!("{word:08x}"))
            .collect::<Vec<_>>()
            .join("")
    }

    fn process_block(&mut self, chunk: &[u8; 64]) {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            words[index] = small_sigma1(words[index - 2])
                .wrapping_add(words[index - 7])
                .wrapping_add(small_sigma0(words[index - 15]))
                .wrapping_add(words[index - 16]);
        }

        let mut a = self.hash[0];
        let mut b = self.hash[1];
        let mut c = self.hash[2];
        let mut d = self.hash[3];
        let mut e = self.hash[4];
        let mut f = self.hash[5];
        let mut g = self.hash[6];
        let mut h = self.hash[7];

        for index in 0..64 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(SHA256_ROUND_CONSTANTS[index])
                .wrapping_add(words[index]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.hash[0] = self.hash[0].wrapping_add(a);
        self.hash[1] = self.hash[1].wrapping_add(b);
        self.hash[2] = self.hash[2].wrapping_add(c);
        self.hash[3] = self.hash[3].wrapping_add(d);
        self.hash[4] = self.hash[4].wrapping_add(e);
        self.hash[5] = self.hash[5].wrapping_add(f);
        self.hash[6] = self.hash[6].wrapping_add(g);
        self.hash[7] = self.hash[7].wrapping_add(h);
    }
}

fn sha256_hex(input: &[u8]) -> String {
    let mut state = Sha256State::new();
    state.update(input);
    state.finalize_hex()
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn big_sigma0(value: u32) -> u32 {
    value.rotate_right(2) ^ value.rotate_right(13) ^ value.rotate_right(22)
}

fn big_sigma1(value: u32) -> u32 {
    value.rotate_right(6) ^ value.rotate_right(11) ^ value.rotate_right(25)
}

fn small_sigma0(value: u32) -> u32 {
    value.rotate_right(7) ^ value.rotate_right(18) ^ (value >> 3)
}

fn small_sigma1(value: u32) -> u32 {
    value.rotate_right(17) ^ value.rotate_right(19) ^ (value >> 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABC_DIGEST: &str =
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_OBJECT_KEY: &str =
        "blobs/sha256/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ZERO_DIGEST: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn quarantines_then_promotes_inert_bytes() {
        let mut store = InMemoryCacheStore::new();
        let artifact = sample_artifact(ABC_DIGEST);
        let receipt = store.quarantine(artifact.clone(), b"abc".to_vec()).unwrap();
        assert_eq!(receipt.cache_object_key, ABC_OBJECT_KEY);
        assert_eq!(receipt.byte_len, 3);

        let promoted = store.promote(&receipt.quarantine_id).unwrap();
        assert_eq!(promoted.artifact, artifact);
        assert_eq!(promoted.cache_object_key, ABC_OBJECT_KEY);
        assert_eq!(store.promoted_bytes(ABC_OBJECT_KEY).unwrap(), b"abc");
        assert_eq!(
            store
                .promoted_bytes_for_artifact(&artifact, ABC_OBJECT_KEY)
                .unwrap(),
            b"abc"
        );
    }

    #[test]
    fn promoted_lookup_requires_exact_artifact_and_key() {
        let mut store = InMemoryCacheStore::new();
        let artifact = sample_artifact(ABC_DIGEST);
        let receipt = store.quarantine(artifact.clone(), b"abc".to_vec()).unwrap();
        store.promote(&receipt.quarantine_id).unwrap();

        let wrong_key = store
            .promoted_bytes_for_artifact(
                &artifact,
                "blobs/sha256/0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap_err();
        assert_eq!(
            wrong_key.reason_code(),
            "cache_promoted_object_key_mismatch"
        );

        let mut wrong_artifact = artifact.clone();
        wrong_artifact.name = "other".to_string();
        let wrong_artifact_error = store
            .promoted_bytes_for_artifact(&wrong_artifact, ABC_OBJECT_KEY)
            .unwrap_err();
        assert_eq!(
            wrong_artifact_error.reason_code(),
            "cache_promoted_object_artifact_mismatch"
        );
    }

    #[test]
    fn promoted_lookup_fails_closed_when_object_missing() {
        let store = InMemoryCacheStore::new();
        let error = store
            .promoted_bytes_for_artifact(&sample_artifact(ABC_DIGEST), ABC_OBJECT_KEY)
            .unwrap_err();
        assert_eq!(error.reason_code(), "cache_promoted_object_not_found");
    }

    #[test]
    fn sha256_implementation_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(&[b'a'; 55]),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
        );
        assert_eq!(
            sha256_hex(&[b'a'; 56]),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
        assert_eq!(
            sha256_hex(&[b'a'; 64]),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );

        let input = vec![b'z'; 16 * 1024 + 65];
        let expected = sha256_hex(&input);
        let mut incremental = Sha256State::new();
        for chunk in input.chunks(37) {
            incremental.update(chunk);
        }
        assert_eq!(incremental.finalize_hex(), expected);
    }

    #[test]
    fn digest_mismatch_never_enters_quarantine() {
        let mut store = InMemoryCacheStore::new();
        let error = store
            .quarantine(sample_artifact(ZERO_DIGEST), b"bytes".to_vec())
            .unwrap_err();
        assert_eq!(error.reason_code(), "cache_digest_mismatch");
    }

    #[test]
    fn unsupported_digest_verification_fails_closed() {
        let mut store = InMemoryCacheStore::new();
        let error = store
            .quarantine(
                sample_artifact(
                    "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
                ),
                b"bytes".to_vec(),
            )
            .unwrap_err();
        assert_eq!(error.reason_code(), "artifact_digest_algorithm_unsupported");
    }

    #[test]
    fn invalid_digest_never_enters_quarantine() {
        let mut store = InMemoryCacheStore::new();
        let error = store
            .quarantine(sample_artifact("sha256:../escape"), b"bytes".to_vec())
            .unwrap_err();
        assert_eq!(
            error.reason_code(),
            "artifact_digest_contains_unsafe_characters"
        );
    }

    #[test]
    fn empty_payload_fails_closed() {
        let mut store = InMemoryCacheStore::new();
        let error = store
            .quarantine(sample_artifact(ABC_DIGEST), Vec::new())
            .unwrap_err();
        assert_eq!(error.reason_code(), "cache_payload_empty");
    }

    #[test]
    fn unknown_quarantine_cannot_promote() {
        let mut store = InMemoryCacheStore::new();
        let error = store.promote("missing").unwrap_err();
        assert_eq!(error.reason_code(), "cache_quarantine_not_found");
    }

    fn sample_artifact(digest: &str) -> ArtifactRef {
        ArtifactRef {
            ecosystem: "npm".to_string(),
            name: "fixture".to_string(),
            version: "1.0.0".to_string(),
            digest: digest.to_string(),
            source: "inert-test-fixture".to_string(),
        }
    }
}

#[cfg(test)]
mod persistent_cas_tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    static TEST_ROOT_COUNTER: AtomicU64 = AtomicU64::new(1);

    struct TestRoot {
        path: PathBuf,
    }

    impl TestRoot {
        fn new(label: &str) -> Self {
            let counter = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "whoathere-cache-{label}-{}-{counter:016x}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            Self { path }
        }

        fn cas(&self, limit: u64) -> PersistentQuarantineCas {
            PersistentQuarantineCas::create(&self.path, limit).unwrap()
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn persistent_cas_round_trip_keeps_one_redacted_blob() {
        let root = TestRoot::new("round-trip");
        let cas = root.cas(1024);
        let bytes = b"inert npm fixture bytes";
        let digest = format!("sha256:{}", sha256_hex(bytes));

        assert!(cas.root.is_absolute());
        let handle = cas.quarantine_bytes(&digest, bytes).unwrap();
        assert_eq!(handle.digest(), digest);
        assert_eq!(handle.byte_len(), bytes.len() as u64);
        assert_eq!(
            handle.object_key(),
            format!("blobs/sha256/{}", sha256_hex(bytes))
        );
        assert_eq!(cas.verified_lease(&handle).unwrap().bytes(), bytes);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&cas.root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(cas.root.join(handle.object_key()))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
        }

        assert_eq!(
            count_regular_files(&cas.object_directory),
            1,
            "verification must not copy or move the blob"
        );
        let cas_debug = format!("{cas:?}");
        let lease_debug = format!("{:?}", cas.verified_lease(&handle).unwrap());
        assert!(!cas_debug.contains(root.path.to_string_lossy().as_ref()));
        assert!(!lease_debug.contains("inert npm fixture bytes"));
        assert!(lease_debug.contains("<redacted>"));
    }

    #[test]
    fn idempotent_ingest_accepts_only_the_same_existing_bytes() {
        let root = TestRoot::new("idempotent");
        let cas = root.cas(1024);
        let bytes = b"inert wheel fixture bytes";
        let digest = format!("sha256:{}", sha256_hex(bytes));

        let first = cas.quarantine_bytes(&digest, bytes).unwrap();
        let second = cas.quarantine_bytes(&digest, bytes).unwrap();
        assert_eq!(first, second);
        assert_eq!(count_regular_files(&cas.object_directory), 1);
        assert!(incoming_files(&cas.object_directory).is_empty());
    }

    #[test]
    fn persisted_object_reopens_from_a_trusted_digest_receipt_without_reingest() {
        let root = TestRoot::new("reopen");
        let bytes = b"persisted inert artifact bytes";
        let digest = format!("sha256:{}", sha256_hex(bytes));
        {
            let cas = root.cas(1024);
            cas.quarantine_bytes(&digest, bytes).unwrap();
        }

        let reopened_cas = root.cas(1024);
        let handle = reopened_cas
            .reopen_quarantined(&digest, bytes.len() as u64)
            .unwrap();
        assert_eq!(reopened_cas.verified_lease(&handle).unwrap().bytes(), bytes);
        assert_eq!(count_regular_files(&reopened_cas.object_directory), 1);
    }

    #[test]
    fn concurrent_idempotent_publication_never_overwrites() {
        let root = TestRoot::new("concurrent");
        let cas = Arc::new(root.cas(1024));
        let bytes = b"same inert sdist bytes".to_vec();
        let digest = format!("sha256:{}", sha256_hex(&bytes));
        let barrier = Arc::new(Barrier::new(4));
        let mut workers = Vec::new();

        for _ in 0..4 {
            let cas = Arc::clone(&cas);
            let barrier = Arc::clone(&barrier);
            let bytes = bytes.clone();
            let digest = digest.clone();
            workers.push(thread::spawn(move || {
                barrier.wait();
                cas.quarantine_bytes(&digest, &bytes).unwrap()
            }));
        }

        let handles: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(handles.iter().all(|handle| handle == &handles[0]));
        assert_eq!(count_regular_files(&cas.object_directory), 1);
        assert!(incoming_files(&cas.object_directory).is_empty());
    }

    #[test]
    fn changed_registry_bytes_cannot_replace_resolved_object() {
        let root = TestRoot::new("registry-change");
        let cas = root.cas(1024);
        let resolved = b"registry response at resolution time";
        let changed = b"registry response at detonation time";
        let digest = format!("sha256:{}", sha256_hex(resolved));
        let handle = cas.quarantine_bytes(&digest, resolved).unwrap();

        let error = cas.quarantine_bytes(&digest, changed).unwrap_err();
        assert_eq!(error, PersistentCasError::DigestMismatch);
        assert_eq!(cas.verified_lease(&handle).unwrap().bytes(), resolved);
    }

    #[test]
    fn same_name_and_version_with_different_bytes_get_distinct_objects() {
        let root = TestRoot::new("coordinate-substitution");
        let cas = root.cas(1024);
        let package_coordinate = ("npm", "inert-fixture", "1.0.0");
        let first_bytes = b"first bytes for coordinate";
        let second_bytes = b"different bytes for coordinate";
        let first_digest = format!("sha256:{}", sha256_hex(first_bytes));
        let second_digest = format!("sha256:{}", sha256_hex(second_bytes));

        let first = cas.quarantine_bytes(&first_digest, first_bytes).unwrap();
        let second = cas.quarantine_bytes(&second_digest, second_bytes).unwrap();

        assert_eq!(package_coordinate, ("npm", "inert-fixture", "1.0.0"));
        assert_ne!(first.object_key(), second.object_key());
        assert_eq!(cas.verified_lease(&first).unwrap().bytes(), first_bytes);
        assert_eq!(cas.verified_lease(&second).unwrap().bytes(), second_bytes);
    }

    #[test]
    fn expected_digest_mismatch_leaves_no_object_or_temporary_file() {
        let root = TestRoot::new("digest-mismatch");
        let cas = root.cas(1024);
        let expected_for_other_bytes = format!("sha256:{}", sha256_hex(b"other bytes"));

        let error = cas
            .quarantine_bytes(&expected_for_other_bytes, b"received bytes")
            .unwrap_err();
        assert_eq!(error, PersistentCasError::DigestMismatch);
        assert_eq!(count_regular_files(&cas.object_directory), 0);
        assert!(incoming_files(&cas.object_directory).is_empty());
    }

    #[test]
    fn ingest_is_bounded_before_publication() {
        let root = TestRoot::new("bounded");
        let cas = root.cas(8);
        let bytes = b"nine-byte";
        let digest = format!("sha256:{}", sha256_hex(bytes));

        let error = cas.quarantine_bytes(&digest, bytes).unwrap_err();
        assert_eq!(error, PersistentCasError::PayloadTooLarge { limit: 8 });
        assert_eq!(count_regular_files(&cas.object_directory), 0);
        assert!(incoming_files(&cas.object_directory).is_empty());
    }

    #[test]
    fn same_size_mutation_is_rejected_by_verified_lease() {
        let root = TestRoot::new("same-size-mutation");
        let cas = root.cas(1024);
        let bytes = b"original inert payload";
        let replacement = b"mutated! inert payload";
        assert_eq!(bytes.len(), replacement.len());
        let digest = format!("sha256:{}", sha256_hex(bytes));
        let handle = cas.quarantine_bytes(&digest, bytes).unwrap();
        let object_path = cas.root.join(handle.object_key());

        make_owner_writable(&object_path);
        fs::write(&object_path, replacement).unwrap();

        let error = cas.verified_lease(&handle).unwrap_err();
        assert_eq!(error, PersistentCasError::ObjectNotSealed);
        let reingest_error = cas.quarantine_bytes(&digest, bytes).unwrap_err();
        assert_eq!(reingest_error, PersistentCasError::ObjectNotSealed);
        assert_eq!(fs::read(&object_path).unwrap(), replacement);
    }

    #[cfg(unix)]
    #[test]
    fn writable_preseeded_object_is_never_accepted_as_quarantined() {
        use std::os::unix::fs::PermissionsExt;

        let root = TestRoot::new("writable-preseed");
        let cas = root.cas(1024);
        let bytes = b"exact but unsealed inert payload";
        let digest_hex = sha256_hex(bytes);
        let digest = format!("sha256:{digest_hex}");
        let object_path = cas.object_directory.join(digest_hex);
        fs::write(&object_path, bytes).unwrap();
        fs::set_permissions(&object_path, fs::Permissions::from_mode(0o600)).unwrap();

        let error = cas.quarantine_bytes(&digest, bytes).unwrap_err();
        assert_eq!(error, PersistentCasError::ObjectNotSealed);
    }

    #[cfg(unix)]
    #[test]
    fn external_hard_link_invalidates_a_lease() {
        let root = TestRoot::new("external-hard-link");
        let cas = root.cas(1024);
        let bytes = b"inert hard-link payload";
        let digest = format!("sha256:{}", sha256_hex(bytes));
        let handle = cas.quarantine_bytes(&digest, bytes).unwrap();
        let object_path = cas.root.join(handle.object_key());
        let external_alias = cas.root.join("unexpected-object-alias");
        fs::hard_link(&object_path, &external_alias).unwrap();

        let error = cas.verified_lease(&handle).unwrap_err();
        assert_eq!(error, PersistentCasError::ObjectNotSealed);
    }

    #[cfg(unix)]
    #[test]
    fn directory_permission_drift_invalidates_the_store() {
        use std::os::unix::fs::PermissionsExt;

        let root = TestRoot::new("directory-permission-drift");
        let cas = root.cas(1024);
        let bytes = b"inert permission-drift payload";
        let digest = format!("sha256:{}", sha256_hex(bytes));
        let handle = cas.quarantine_bytes(&digest, bytes).unwrap();
        fs::set_permissions(&cas.object_directory, fs::Permissions::from_mode(0o755)).unwrap();

        let error = cas.verified_lease(&handle).unwrap_err();
        assert_eq!(error, PersistentCasError::UnsafePath);
    }

    #[test]
    fn truncated_object_is_not_yielded_or_repaired_by_overwrite() {
        let root = TestRoot::new("truncate");
        let cas = root.cas(1024);
        let bytes = b"immutable inert artifact";
        let digest = format!("sha256:{}", sha256_hex(bytes));
        let handle = cas.quarantine_bytes(&digest, bytes).unwrap();
        let object_path = cas.root.join(handle.object_key());

        #[cfg(unix)]
        assert_eq!(
            OpenOptions::new()
                .write(true)
                .open(&object_path)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied,
            "published artifacts start owner-read-only"
        );

        make_owner_writable(&object_path);
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&object_path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let lease_error = cas.verified_lease(&handle).unwrap_err();
        assert_eq!(lease_error, PersistentCasError::ObjectNotSealed);

        let ingest_error = cas.quarantine_bytes(&digest, bytes).unwrap_err();
        assert_eq!(ingest_error, PersistentCasError::ObjectNotSealed);
        assert_eq!(fs::read(&object_path).unwrap(), b"x");
    }

    #[cfg(unix)]
    #[test]
    fn final_object_symlink_swap_fails_closed_even_for_identical_bytes() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new("object-symlink");
        let cas = root.cas(1024);
        let bytes = b"inert symlink test artifact";
        let digest = format!("sha256:{}", sha256_hex(bytes));
        let handle = cas.quarantine_bytes(&digest, bytes).unwrap();
        let object_path = cas.root.join(handle.object_key());
        let saved_path = cas.object_directory.join("saved-inert-object");
        fs::rename(&object_path, &saved_path).unwrap();
        symlink(&saved_path, &object_path).unwrap();

        let error = cas.verified_lease(&handle).unwrap_err();
        assert_eq!(error, PersistentCasError::UnsafePath);
    }

    #[cfg(unix)]
    #[test]
    fn object_directory_path_swap_fails_store_identity_check() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new("directory-swap");
        let cas = root.cas(1024);
        let bytes = b"inert directory identity artifact";
        let digest = format!("sha256:{}", sha256_hex(bytes));
        let handle = cas.quarantine_bytes(&digest, bytes).unwrap();
        let moved_directory = cas.root.join("sha256-original");
        fs::rename(&cas.object_directory, &moved_directory).unwrap();
        symlink(&moved_directory, &cas.object_directory).unwrap();

        let error = cas.verified_lease(&handle).unwrap_err();
        assert_eq!(error, PersistentCasError::UnsafePath);
    }

    #[cfg(unix)]
    #[test]
    fn constructor_rejects_a_symlink_as_the_caller_root() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new("root-symlink-parent");
        fs::create_dir(&root.path).unwrap();
        let real_root = root.path.join("real");
        fs::create_dir(&real_root).unwrap();
        let linked_root = root.path.join("linked");
        symlink(&real_root, &linked_root).unwrap();

        let error = PersistentQuarantineCas::create(&linked_root, 1024).unwrap_err();
        assert_eq!(error, PersistentCasError::UnsafePath);
    }

    #[test]
    fn handles_are_bound_to_the_store_that_issued_them() {
        let first_root = TestRoot::new("first-store");
        let second_root = TestRoot::new("second-store");
        let first = first_root.cas(1024);
        let second = second_root.cas(1024);
        let bytes = b"inert store binding artifact";
        let digest = format!("sha256:{}", sha256_hex(bytes));
        let handle = first.quarantine_bytes(&digest, bytes).unwrap();
        second.quarantine_bytes(&digest, bytes).unwrap();

        let error = second.verified_lease(&handle).unwrap_err();
        assert_eq!(error, PersistentCasError::HandleStoreMismatch);
    }

    fn count_regular_files(directory: &Path) -> usize {
        fs::read_dir(directory)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_type()
                    .map(|kind| kind.is_file())
                    .unwrap_or(false)
            })
            .count()
    }

    fn incoming_files(directory: &Path) -> Vec<PathBuf> {
        fs::read_dir(directory)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".incoming-")
            })
            .map(|entry| entry.path())
            .collect()
    }

    #[cfg(unix)]
    fn make_owner_writable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn make_owner_writable(path: &Path) {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).unwrap();
    }
}
