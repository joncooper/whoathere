use std::collections::BTreeMap;

use whoathere_evidence::EvidenceJobKind;
use whoathere_hash::sha256_digest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedJobLogEntry {
    pub tenant_id: String,
    pub admission_request_id: String,
    pub job_id: String,
    pub job_kind: EvidenceJobKind,
    pub profile_id: String,
    pub profile_version: u16,
    pub artifact_digest: String,
    pub cache_object_key: String,
    pub log_digest: String,
    pub summary_schema: String,
    pub sanitized_summary: String,
    pub raw_log_captured: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedJobLogReceipt {
    pub log_id: String,
    pub job_id: String,
    pub log_digest: String,
    pub byte_len: usize,
    pub summary_schema: String,
    pub immutable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobLogStoreError {
    EmptyTenantId,
    EmptyAdmissionRequestId,
    EmptyJobId,
    EmptyProfileId,
    ProfileVersionZero,
    InvalidArtifactDigest,
    CacheObjectKeyMismatch,
    InvalidLogDigest,
    EmptySummarySchema,
    EmptySanitizedSummary,
    SummarySchemaMismatch,
    MalformedSummary,
    SummaryDuplicateField,
    SummaryIdentityMismatch,
    SummaryControlCharacter,
    RawLogCaptured,
    LogDigestMismatch,
    JobIdConflict,
    LogDigestConflict,
}

impl JobLogStoreError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::EmptyTenantId => "job_log_tenant_id_empty",
            Self::EmptyAdmissionRequestId => "job_log_admission_request_id_empty",
            Self::EmptyJobId => "job_log_job_id_empty",
            Self::EmptyProfileId => "job_log_profile_id_empty",
            Self::ProfileVersionZero => "job_log_profile_version_zero",
            Self::InvalidArtifactDigest => "job_log_artifact_digest_invalid",
            Self::CacheObjectKeyMismatch => "job_log_cache_object_key_mismatch",
            Self::InvalidLogDigest => "job_log_digest_invalid",
            Self::EmptySummarySchema => "job_log_summary_schema_empty",
            Self::EmptySanitizedSummary => "job_log_summary_empty",
            Self::SummarySchemaMismatch => "job_log_summary_schema_mismatch",
            Self::MalformedSummary => "job_log_summary_malformed",
            Self::SummaryDuplicateField => "job_log_summary_duplicate_field",
            Self::SummaryIdentityMismatch => "job_log_summary_identity_mismatch",
            Self::SummaryControlCharacter => "job_log_summary_control_character",
            Self::RawLogCaptured => "job_log_raw_log_captured",
            Self::LogDigestMismatch => "job_log_digest_mismatch",
            Self::JobIdConflict => "job_log_job_id_conflict",
            Self::LogDigestConflict => "job_log_digest_conflict",
        }
    }
}

#[derive(Debug, Default)]
pub struct InMemoryJobLogStore {
    by_job_id: BTreeMap<String, SanitizedJobLogEntry>,
    job_id_by_digest: BTreeMap<String, String>,
}

impl InMemoryJobLogStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append_sanitized(
        &mut self,
        entry: SanitizedJobLogEntry,
    ) -> Result<SanitizedJobLogReceipt, JobLogStoreError> {
        validate_entry(&entry)?;
        if let Some(existing) = self.by_job_id.get(&entry.job_id) {
            if existing == &entry {
                return Ok(receipt(existing));
            }
            return Err(JobLogStoreError::JobIdConflict);
        }
        if let Some(existing_job_id) = self.job_id_by_digest.get(&entry.log_digest) {
            if existing_job_id != &entry.job_id {
                return Err(JobLogStoreError::LogDigestConflict);
            }
        }
        let output = receipt(&entry);
        self.job_id_by_digest
            .insert(entry.log_digest.clone(), entry.job_id.clone());
        self.by_job_id.insert(entry.job_id.clone(), entry);
        Ok(output)
    }

    pub fn get_by_job_id(&self, job_id: &str) -> Option<&SanitizedJobLogEntry> {
        self.by_job_id.get(job_id)
    }
}

fn validate_entry(entry: &SanitizedJobLogEntry) -> Result<(), JobLogStoreError> {
    if entry.tenant_id.is_empty() {
        return Err(JobLogStoreError::EmptyTenantId);
    }
    if entry.admission_request_id.is_empty() {
        return Err(JobLogStoreError::EmptyAdmissionRequestId);
    }
    if entry.job_id.is_empty() {
        return Err(JobLogStoreError::EmptyJobId);
    }
    if entry.profile_id.is_empty() {
        return Err(JobLogStoreError::EmptyProfileId);
    }
    if entry.profile_version == 0 {
        return Err(JobLogStoreError::ProfileVersionZero);
    }
    if !valid_sha256_digest(&entry.artifact_digest) {
        return Err(JobLogStoreError::InvalidArtifactDigest);
    }
    let expected_cache_key = entry
        .artifact_digest
        .strip_prefix("sha256:")
        .map(|digest| format!("blobs/sha256/{digest}"));
    if expected_cache_key.as_deref() != Some(entry.cache_object_key.as_str()) {
        return Err(JobLogStoreError::CacheObjectKeyMismatch);
    }
    if !valid_sha256_digest(&entry.log_digest) {
        return Err(JobLogStoreError::InvalidLogDigest);
    }
    if entry.summary_schema.is_empty() {
        return Err(JobLogStoreError::EmptySummarySchema);
    }
    if entry.sanitized_summary.is_empty() {
        return Err(JobLogStoreError::EmptySanitizedSummary);
    }
    if !entry
        .sanitized_summary
        .starts_with(&format!("{}\n", entry.summary_schema))
    {
        return Err(JobLogStoreError::SummarySchemaMismatch);
    }
    if entry.raw_log_captured {
        return Err(JobLogStoreError::RawLogCaptured);
    }
    if sha256_digest(entry.sanitized_summary.as_bytes()) != entry.log_digest {
        return Err(JobLogStoreError::LogDigestMismatch);
    }
    let fields = parse_summary_fields(entry)?;
    require_summary_field(&fields, "job_id", &entry.job_id)?;
    require_summary_field(&fields, "profile_id", &entry.profile_id)?;
    require_summary_field(
        &fields,
        "profile_version",
        &entry.profile_version.to_string(),
    )?;
    require_summary_field(&fields, "artifact_digest", &entry.artifact_digest)?;
    require_summary_field(&fields, "cache_object_key", &entry.cache_object_key)?;
    require_summary_field(&fields, "job_kind", &format!("{:?}", entry.job_kind))?;
    require_summary_field(&fields, "execution_enabled", "false")?;
    require_summary_field(&fields, "detonation_attempted", "false")?;
    require_summary_field(&fields, "network_attempted", "false")?;
    require_summary_field(&fields, "raw_log_captured", "false")?;
    Ok(())
}

fn parse_summary_fields(
    entry: &SanitizedJobLogEntry,
) -> Result<BTreeMap<String, String>, JobLogStoreError> {
    if entry
        .sanitized_summary
        .chars()
        .any(|character| character.is_control() && character != '\n')
    {
        return Err(JobLogStoreError::SummaryControlCharacter);
    }
    let mut lines = entry.sanitized_summary.lines();
    if lines.next() != Some(entry.summary_schema.as_str()) {
        return Err(JobLogStoreError::SummarySchemaMismatch);
    }
    let mut fields = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(JobLogStoreError::MalformedSummary);
        };
        if key.is_empty()
            || !key
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            return Err(JobLogStoreError::MalformedSummary);
        }
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(JobLogStoreError::SummaryDuplicateField);
        }
    }
    Ok(fields)
}

fn require_summary_field(
    fields: &BTreeMap<String, String>,
    key: &str,
    expected: &str,
) -> Result<(), JobLogStoreError> {
    if fields.get(key).is_some_and(|actual| actual == expected) {
        Ok(())
    } else {
        Err(JobLogStoreError::SummaryIdentityMismatch)
    }
}

fn receipt(entry: &SanitizedJobLogEntry) -> SanitizedJobLogReceipt {
    SanitizedJobLogReceipt {
        log_id: format!("logs/{}/{}", entry.job_id, entry.log_digest),
        job_id: entry.job_id.clone(),
        log_digest: entry.log_digest.clone(),
        byte_len: entry.sanitized_summary.len(),
        summary_schema: entry.summary_schema.clone(),
        immutable: true,
    }
}

fn valid_sha256_digest(value: &str) -> bool {
    let Some((algorithm, digest)) = value.split_once(':') else {
        return false;
    };
    algorithm == "sha256"
        && digest.len() == 64
        && digest
            .chars()
            .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARTIFACT_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const CACHE_OBJECT_KEY: &str =
        "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111";
    const SUMMARY_SCHEMA: &str = "whoathere.static_manifest_job.v1";

    fn entry(job_id: &str) -> SanitizedJobLogEntry {
        let sanitized_summary = format!(
            "{SUMMARY_SCHEMA}\njob_id={job_id}\nprofile_id=npm.registry_tarball.v1\nprofile_version=1\nartifact_digest={ARTIFACT_DIGEST}\ncache_object_key={CACHE_OBJECT_KEY}\njob_kind=StaticManifest\nexecution_enabled=false\ndetonation_attempted=false\nnetwork_attempted=false\nraw_log_captured=false\n"
        );
        SanitizedJobLogEntry {
            tenant_id: "tenant-local-dev".to_string(),
            admission_request_id: "dev-sim-1".to_string(),
            job_id: job_id.to_string(),
            job_kind: EvidenceJobKind::StaticManifest,
            profile_id: "npm.registry_tarball.v1".to_string(),
            profile_version: 1,
            artifact_digest: ARTIFACT_DIGEST.to_string(),
            cache_object_key: CACHE_OBJECT_KEY.to_string(),
            log_digest: sha256_digest(sanitized_summary.as_bytes()),
            summary_schema: SUMMARY_SCHEMA.to_string(),
            sanitized_summary,
            raw_log_captured: false,
        }
    }

    #[test]
    fn appends_matching_sanitized_log_once_and_is_idempotent() {
        let mut store = InMemoryJobLogStore::new();
        let first = store.append_sanitized(entry("job-1")).unwrap();
        let second = store.append_sanitized(entry("job-1")).unwrap();
        assert_eq!(first, second);
        assert!(first.immutable);
        assert_eq!(first.summary_schema, SUMMARY_SCHEMA);
        assert!(store.get_by_job_id("job-1").is_some());
    }

    #[test]
    fn rejects_digest_mismatch_and_raw_log_capture() {
        let mut store = InMemoryJobLogStore::new();
        let mut mismatched = entry("job-1");
        mismatched.log_digest =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string();
        assert_eq!(
            store.append_sanitized(mismatched),
            Err(JobLogStoreError::LogDigestMismatch)
        );

        let mut raw = entry("job-2");
        raw.raw_log_captured = true;
        assert_eq!(
            store.append_sanitized(raw),
            Err(JobLogStoreError::RawLogCaptured)
        );
    }

    #[test]
    fn rejects_conflicting_rewrite_for_job_id() {
        let mut store = InMemoryJobLogStore::new();
        store.append_sanitized(entry("job-1")).unwrap();
        let mut conflict = entry("job-1");
        conflict
            .sanitized_summary
            .push_str("extra_reason=changed\n");
        conflict.log_digest = sha256_digest(conflict.sanitized_summary.as_bytes());
        assert_eq!(
            store.append_sanitized(conflict),
            Err(JobLogStoreError::JobIdConflict)
        );
    }

    #[test]
    fn rejects_schema_mismatch_and_bad_identity() {
        let mut store = InMemoryJobLogStore::new();
        let mut schema = entry("job-1");
        schema.summary_schema = "whoathere.other.v1".to_string();
        assert_eq!(
            store.append_sanitized(schema),
            Err(JobLogStoreError::SummarySchemaMismatch)
        );

        let mut cache = entry("job-2");
        cache.cache_object_key =
            "blobs/sha256/2222222222222222222222222222222222222222222222222222222222222222"
                .to_string();
        assert_eq!(
            store.append_sanitized(cache),
            Err(JobLogStoreError::CacheObjectKeyMismatch)
        );
    }

    #[test]
    fn rejects_summary_identity_mismatch_and_duplicate_fields() {
        let mut store = InMemoryJobLogStore::new();
        let mut mismatch = entry("job-1");
        mismatch.sanitized_summary = mismatch
            .sanitized_summary
            .replace("job_id=job-1", "job_id=another-job");
        mismatch.log_digest = sha256_digest(mismatch.sanitized_summary.as_bytes());
        assert_eq!(
            store.append_sanitized(mismatch),
            Err(JobLogStoreError::SummaryIdentityMismatch)
        );

        let mut duplicate = entry("job-2");
        duplicate.sanitized_summary.push_str("job_id=job-2\n");
        duplicate.log_digest = sha256_digest(duplicate.sanitized_summary.as_bytes());
        assert_eq!(
            store.append_sanitized(duplicate),
            Err(JobLogStoreError::SummaryDuplicateField)
        );
    }

    #[test]
    fn rejects_malformed_or_control_character_summary() {
        let mut store = InMemoryJobLogStore::new();
        let mut malformed = entry("job-1");
        malformed
            .sanitized_summary
            .push_str("not-a-key-value-line\n");
        malformed.log_digest = sha256_digest(malformed.sanitized_summary.as_bytes());
        assert_eq!(
            store.append_sanitized(malformed),
            Err(JobLogStoreError::MalformedSummary)
        );

        let mut control = entry("job-2");
        control.sanitized_summary.push('\r');
        control.log_digest = sha256_digest(control.sanitized_summary.as_bytes());
        assert_eq!(
            store.append_sanitized(control),
            Err(JobLogStoreError::SummaryControlCharacter)
        );
    }
}
