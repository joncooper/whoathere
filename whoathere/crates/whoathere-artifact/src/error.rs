use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArtifactModelError {
    #[error("artifact contract serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("artifact manifest expanded-size sum overflowed u64")]
    ExpandedSizeOverflow,
    #[error("artifact contract invariant failed: {0}")]
    InvalidContract(String),
}

/// A fail-closed reason produced while identifying or normalizing an artifact.
#[derive(Debug, Error)]
pub enum NormalizationError {
    #[error("artifact exceeds the original-byte limit: {actual} > {limit}")]
    OriginalSizeLimit { actual: u64, limit: u64 },
    #[error("artifact bytes do not match the envelope digest or length")]
    ArtifactIdentityMismatch,
    #[error("artifact magic or filename is unsupported: {0}")]
    UnsupportedFormat(String),
    #[error("artifact format does not match the envelope")]
    FormatMismatch,
    #[error("archive could not be parsed: {0}")]
    Archive(String),
    #[error("archive contains too many members: {actual} > {limit}")]
    MemberCountLimit { actual: usize, limit: usize },
    #[error("archive member `{path}` exceeds the byte limit: {actual} > {limit}")]
    MemberSizeLimit {
        path: String,
        actual: u64,
        limit: u64,
    },
    #[error("archive expanded bytes exceed the limit: {actual} > {limit}")]
    ExpandedSizeLimit { actual: u64, limit: u64 },
    #[error("archive compression ratio exceeds the limit for `{path}`")]
    CompressionRatioLimit { path: String },
    #[error("archive contains trailing or concatenated payload data")]
    TrailingArchiveData,
    #[error("archive path is invalid (`{path}`): {reason}")]
    InvalidPath { path: String, reason: &'static str },
    #[error("archive contains unsupported member type at `{path}`: {kind}")]
    UnsupportedMemberType { path: String, kind: String },
    #[error("archive contains a duplicate normalized path: `{path}`")]
    DuplicatePath { path: String },
    #[error("archive paths collide after Unicode normalization: `{first}` and `{second}`")]
    UnicodeCollision { first: String, second: String },
    #[error("archive paths collide under portable case folding: `{first}` and `{second}`")]
    CaseCollision { first: String, second: String },
    #[error("archive has a file/directory prefix conflict: `{first}` and `{second}`")]
    PrefixCollision { first: String, second: String },
    #[error("artifact has an unsupported or ambiguous package root: {0}")]
    AmbiguousRoot(String),
    #[error("required package metadata is missing: {0}")]
    MetadataMissing(String),
    #[error("package metadata is invalid: {0}")]
    MetadataInvalid(String),
    #[error("package identity does not agree across artifact inputs: {0}")]
    IdentityMismatch(String),
    #[error("manifest canonicalization failed: {0}")]
    Manifest(String),
}
