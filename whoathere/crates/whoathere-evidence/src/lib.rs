#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceJobKind {
    StaticManifest,
    IntegrityCheck,
    ProvenanceCheck,
    LifecycleDetonation,
    ImportSmoke,
    NativeBuild,
    ManualReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    None,
    Blocked,
    RecordedEgress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Pending,
    Passed,
    Failed,
    TimedOut,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRequirement {
    pub job_kind: EvidenceJobKind,
    pub mandatory: bool,
    pub network_mode: NetworkMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceProfile {
    pub id: &'static str,
    pub version: u16,
    pub auto_allow_eligible: bool,
    pub requirements: Vec<EvidenceRequirement>,
    pub never_auto_allow: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceJobResult {
    pub job_id: String,
    pub job_kind: EvidenceJobKind,
    pub state: JobState,
    pub log_digest: String,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceJobBinding {
    pub job_id: String,
    pub job_kind: EvidenceJobKind,
    pub profile_id: String,
    pub profile_version: u16,
    pub artifact_digest: String,
    pub cache_object_key: String,
    pub log_digest: String,
    pub admission_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBundle {
    pub profile_id: String,
    pub profile_version: u16,
    pub artifact_digest: String,
    pub cache_object_key: String,
    pub results: Vec<EvidenceJobResult>,
    pub job_bindings: Vec<EvidenceJobBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceValidationError {
    ProfileIdMismatch,
    ProfileVersionMismatch,
    UnexpectedJobResult,
    DuplicateJobResult,
    EmptyJobId,
    DuplicateJobId,
    InvalidJobLogDigest,
    MissingJobBinding,
    UnexpectedJobBinding,
    DuplicateJobBinding,
    JobBindingMismatch,
    JobBindingNotAdmissionReady,
}

impl EvidenceValidationError {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::ProfileIdMismatch => "evidence_profile_id_mismatch",
            Self::ProfileVersionMismatch => "evidence_profile_version_mismatch",
            Self::UnexpectedJobResult => "evidence_unexpected_job_result",
            Self::DuplicateJobResult => "evidence_duplicate_job_result",
            Self::EmptyJobId => "evidence_job_id_empty",
            Self::DuplicateJobId => "evidence_duplicate_job_id",
            Self::InvalidJobLogDigest => "evidence_job_log_digest_invalid",
            Self::MissingJobBinding => "evidence_job_binding_missing",
            Self::UnexpectedJobBinding => "evidence_unexpected_job_binding",
            Self::DuplicateJobBinding => "evidence_duplicate_job_binding",
            Self::JobBindingMismatch => "evidence_job_binding_mismatch",
            Self::JobBindingNotAdmissionReady => "evidence_job_binding_not_admission_ready",
        }
    }
}

impl EvidenceBundle {
    pub fn validate_for_profile(
        &self,
        profile: &EvidenceProfile,
    ) -> Result<(), EvidenceValidationError> {
        if self.profile_id != profile.id {
            return Err(EvidenceValidationError::ProfileIdMismatch);
        }
        if self.profile_version != profile.version {
            return Err(EvidenceValidationError::ProfileVersionMismatch);
        }
        let mut seen_kinds = Vec::new();
        let mut seen_job_ids = Vec::new();
        for result in &self.results {
            if !profile
                .requirements
                .iter()
                .any(|requirement| requirement.job_kind == result.job_kind)
            {
                return Err(EvidenceValidationError::UnexpectedJobResult);
            }
            if seen_kinds.contains(&result.job_kind) {
                return Err(EvidenceValidationError::DuplicateJobResult);
            }
            if result.job_id.is_empty() {
                return Err(EvidenceValidationError::EmptyJobId);
            }
            if seen_job_ids.contains(&result.job_id) {
                return Err(EvidenceValidationError::DuplicateJobId);
            }
            if !valid_sha256_digest(&result.log_digest) {
                return Err(EvidenceValidationError::InvalidJobLogDigest);
            }
            seen_kinds.push(result.job_kind);
            seen_job_ids.push(result.job_id.clone());
        }

        let mut seen_binding_ids = Vec::new();
        for binding in &self.job_bindings {
            if binding.job_id.is_empty() {
                return Err(EvidenceValidationError::EmptyJobId);
            }
            if seen_binding_ids.contains(&binding.job_id) {
                return Err(EvidenceValidationError::DuplicateJobBinding);
            }
            if !self
                .results
                .iter()
                .any(|result| result.job_id == binding.job_id)
            {
                return Err(EvidenceValidationError::UnexpectedJobBinding);
            }
            if !valid_sha256_digest(&binding.log_digest) {
                return Err(EvidenceValidationError::InvalidJobLogDigest);
            }
            seen_binding_ids.push(binding.job_id.clone());
        }

        for result in &self.results {
            let Some(binding) = self
                .job_bindings
                .iter()
                .find(|binding| binding.job_id == result.job_id)
            else {
                return Err(EvidenceValidationError::MissingJobBinding);
            };
            if !binding.admission_ready {
                return Err(EvidenceValidationError::JobBindingNotAdmissionReady);
            }
            if binding.job_kind != result.job_kind
                || binding.profile_id != self.profile_id
                || binding.profile_version != self.profile_version
                || binding.artifact_digest != self.artifact_digest
                || binding.cache_object_key != self.cache_object_key
                || binding.log_digest != result.log_digest
            {
                return Err(EvidenceValidationError::JobBindingMismatch);
            }
        }
        Ok(())
    }

    pub fn mandatory_jobs_passed(&self, profile: &EvidenceProfile) -> bool {
        if self.validate_for_profile(profile).is_err() {
            return false;
        }
        profile
            .requirements
            .iter()
            .filter(|requirement| requirement.mandatory)
            .all(|requirement| {
                self.results.iter().any(|result| {
                    result.job_kind == requirement.job_kind && result.state == JobState::Passed
                })
            })
    }
}

pub fn minimum_profiles() -> Vec<EvidenceProfile> {
    vec![
        EvidenceProfile {
            id: "npm.registry_tarball.v1",
            version: 1,
            auto_allow_eligible: true,
            never_auto_allow: false,
            requirements: vec![
                mandatory(EvidenceJobKind::StaticManifest, NetworkMode::None),
                mandatory(EvidenceJobKind::IntegrityCheck, NetworkMode::None),
                mandatory(EvidenceJobKind::ProvenanceCheck, NetworkMode::None),
                mandatory(EvidenceJobKind::LifecycleDetonation, NetworkMode::Blocked),
                mandatory(EvidenceJobKind::ImportSmoke, NetworkMode::Blocked),
            ],
        },
        EvidenceProfile {
            id: "npm.native_extension.v1",
            version: 1,
            auto_allow_eligible: true,
            never_auto_allow: false,
            requirements: vec![
                mandatory(EvidenceJobKind::StaticManifest, NetworkMode::None),
                mandatory(EvidenceJobKind::IntegrityCheck, NetworkMode::None),
                mandatory(EvidenceJobKind::LifecycleDetonation, NetworkMode::Blocked),
                mandatory(EvidenceJobKind::NativeBuild, NetworkMode::Blocked),
                mandatory(EvidenceJobKind::ImportSmoke, NetworkMode::Blocked),
            ],
        },
        EvidenceProfile {
            id: "npm.untrusted_source.v1",
            version: 1,
            auto_allow_eligible: false,
            never_auto_allow: true,
            requirements: vec![
                mandatory(EvidenceJobKind::StaticManifest, NetworkMode::None),
                mandatory(EvidenceJobKind::IntegrityCheck, NetworkMode::None),
                mandatory(EvidenceJobKind::ManualReview, NetworkMode::None),
            ],
        },
        EvidenceProfile {
            id: "pypi.wheel.v1",
            version: 1,
            auto_allow_eligible: true,
            never_auto_allow: false,
            requirements: vec![
                mandatory(EvidenceJobKind::StaticManifest, NetworkMode::None),
                mandatory(EvidenceJobKind::IntegrityCheck, NetworkMode::None),
                mandatory(EvidenceJobKind::ImportSmoke, NetworkMode::Blocked),
            ],
        },
        EvidenceProfile {
            id: "pypi.sdist_pep517.v1",
            version: 1,
            auto_allow_eligible: true,
            never_auto_allow: false,
            requirements: vec![
                mandatory(EvidenceJobKind::StaticManifest, NetworkMode::None),
                mandatory(EvidenceJobKind::IntegrityCheck, NetworkMode::None),
                mandatory(EvidenceJobKind::LifecycleDetonation, NetworkMode::Blocked),
                mandatory(EvidenceJobKind::ImportSmoke, NetworkMode::Blocked),
            ],
        },
        EvidenceProfile {
            id: "pypi.editable_vcs_direct.v1",
            version: 1,
            auto_allow_eligible: false,
            never_auto_allow: true,
            requirements: vec![
                mandatory(EvidenceJobKind::StaticManifest, NetworkMode::None),
                mandatory(EvidenceJobKind::IntegrityCheck, NetworkMode::None),
                mandatory(EvidenceJobKind::ManualReview, NetworkMode::None),
            ],
        },
    ]
}

fn mandatory(job_kind: EvidenceJobKind, network_mode: NetworkMode) -> EvidenceRequirement {
    EvidenceRequirement {
        job_kind,
        mandatory: true,
        network_mode,
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
    const LOG_DIGEST: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn result(job_id: &str, job_kind: EvidenceJobKind, state: JobState) -> EvidenceJobResult {
        EvidenceJobResult {
            job_id: job_id.to_string(),
            job_kind,
            state,
            log_digest: LOG_DIGEST.to_string(),
            reason_codes: vec![],
        }
    }

    fn binding(profile: &EvidenceProfile, job: &EvidenceJobResult) -> EvidenceJobBinding {
        EvidenceJobBinding {
            job_id: job.job_id.clone(),
            job_kind: job.job_kind,
            profile_id: profile.id.to_string(),
            profile_version: profile.version,
            artifact_digest: ARTIFACT_DIGEST.to_string(),
            cache_object_key: CACHE_OBJECT_KEY.to_string(),
            log_digest: job.log_digest.clone(),
            admission_ready: true,
        }
    }

    fn bundle(profile: &EvidenceProfile, results: Vec<EvidenceJobResult>) -> EvidenceBundle {
        let job_bindings = results.iter().map(|job| binding(profile, job)).collect();
        EvidenceBundle {
            profile_id: profile.id.to_string(),
            profile_version: profile.version,
            artifact_digest: ARTIFACT_DIGEST.to_string(),
            cache_object_key: CACHE_OBJECT_KEY.to_string(),
            results,
            job_bindings,
        }
    }

    #[test]
    fn minimum_profiles_include_required_artifact_classes() {
        let profiles = minimum_profiles();
        assert_eq!(profiles.len(), 6);
        assert!(profiles.iter().any(|p| p.id == "npm.registry_tarball.v1"));
        assert!(profiles.iter().any(|p| p.id == "pypi.sdist_pep517.v1"));
    }

    #[test]
    fn missing_mandatory_job_does_not_pass() {
        let profile = minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "npm.registry_tarball.v1")
            .unwrap();
        let bundle = bundle(
            &profile,
            vec![result(
                "job-static-manifest",
                EvidenceJobKind::StaticManifest,
                JobState::Passed,
            )],
        );
        assert!(!bundle.mandatory_jobs_passed(&profile));
    }

    #[test]
    fn evidence_profile_identity_must_match() {
        let profile = minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "pypi.wheel.v1")
            .unwrap();
        let wrong_id = EvidenceBundle {
            profile_id: "npm.registry_tarball.v1".to_string(),
            profile_version: profile.version,
            artifact_digest: ARTIFACT_DIGEST.to_string(),
            cache_object_key: CACHE_OBJECT_KEY.to_string(),
            results: Vec::new(),
            job_bindings: Vec::new(),
        };
        assert_eq!(
            wrong_id.validate_for_profile(&profile).unwrap_err(),
            EvidenceValidationError::ProfileIdMismatch
        );
        let wrong_version = EvidenceBundle {
            profile_id: profile.id.to_string(),
            profile_version: profile.version + 1,
            artifact_digest: ARTIFACT_DIGEST.to_string(),
            cache_object_key: CACHE_OBJECT_KEY.to_string(),
            results: Vec::new(),
            job_bindings: Vec::new(),
        };
        assert_eq!(
            wrong_version.validate_for_profile(&profile).unwrap_err(),
            EvidenceValidationError::ProfileVersionMismatch
        );
    }

    #[test]
    fn evidence_results_must_be_profile_unique() {
        let profile = minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "pypi.wheel.v1")
            .unwrap();
        let duplicate = bundle(
            &profile,
            vec![
                result(
                    "job-static-manifest-1",
                    EvidenceJobKind::StaticManifest,
                    JobState::Passed,
                ),
                result(
                    "job-static-manifest-2",
                    EvidenceJobKind::StaticManifest,
                    JobState::Failed,
                ),
            ],
        );
        assert_eq!(
            duplicate.validate_for_profile(&profile).unwrap_err(),
            EvidenceValidationError::DuplicateJobResult
        );
        let unexpected = bundle(
            &profile,
            vec![result(
                "job-native-build",
                EvidenceJobKind::NativeBuild,
                JobState::Passed,
            )],
        );
        assert_eq!(
            unexpected.validate_for_profile(&profile).unwrap_err(),
            EvidenceValidationError::UnexpectedJobResult
        );
    }

    #[test]
    fn evidence_results_require_job_bindings() {
        let profile = minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "pypi.wheel.v1")
            .unwrap();
        let job = result(
            "job-static-manifest",
            EvidenceJobKind::StaticManifest,
            JobState::Passed,
        );
        let missing_binding = EvidenceBundle {
            profile_id: profile.id.to_string(),
            profile_version: profile.version,
            artifact_digest: ARTIFACT_DIGEST.to_string(),
            cache_object_key: CACHE_OBJECT_KEY.to_string(),
            results: vec![job.clone()],
            job_bindings: Vec::new(),
        };
        assert_eq!(
            missing_binding.validate_for_profile(&profile).unwrap_err(),
            EvidenceValidationError::MissingJobBinding
        );

        let mut mismatched = bundle(&profile, vec![job]);
        mismatched.job_bindings[0].log_digest =
            "sha256:3333333333333333333333333333333333333333333333333333333333333333".to_string();
        assert_eq!(
            mismatched.validate_for_profile(&profile).unwrap_err(),
            EvidenceValidationError::JobBindingMismatch
        );
    }
}
