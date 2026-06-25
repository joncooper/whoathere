use std::collections::{btree_map::Entry, BTreeMap};

use whoathere_evidence::{EvidenceBundle, EvidenceProfile};
use whoathere_vault_api::{
    AdmissionRequest, AdmissionState, ApiError, ArtifactRef, FetchResultBinding, FetchResultState,
    Verdict,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServableGeneration {
    pub generation_id: u64,
    pub tenant_id: String,
    pub request_id: String,
    pub artifact: ArtifactRef,
    pub cache_object_key: String,
    pub fetch_job_id: String,
    pub fetch_quarantine_id: String,
    pub fetch_byte_len: u64,
    pub fetch_byte_limit: u64,
    pub fetch_audit_event_id: String,
    pub evidence_profile_id: String,
    pub policy_version: String,
    pub audit_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionManifest {
    pub schema_version: u32,
    pub generation_id: u64,
    pub tenant_id: String,
    pub request_id: String,
    pub artifact: ArtifactRef,
    pub cache_object_key: String,
    pub fetch_job_id: String,
    pub fetch_quarantine_id: String,
    pub fetch_byte_len: u64,
    pub fetch_byte_limit: u64,
    pub fetch_audit_event_id: String,
    pub evidence_profile_id: String,
    pub policy_version: String,
    pub audit_event_id: String,
}

impl ServableGeneration {
    pub fn promotion_manifest(&self) -> PromotionManifest {
        PromotionManifest {
            schema_version: 1,
            generation_id: self.generation_id,
            tenant_id: self.tenant_id.clone(),
            request_id: self.request_id.clone(),
            artifact: self.artifact.clone(),
            cache_object_key: self.cache_object_key.clone(),
            fetch_job_id: self.fetch_job_id.clone(),
            fetch_quarantine_id: self.fetch_quarantine_id.clone(),
            fetch_byte_len: self.fetch_byte_len,
            fetch_byte_limit: self.fetch_byte_limit,
            fetch_audit_event_id: self.fetch_audit_event_id.clone(),
            evidence_profile_id: self.evidence_profile_id.clone(),
            policy_version: self.policy_version.clone(),
            audit_event_id: self.audit_event_id.clone(),
        }
    }
}

impl PromotionManifest {
    pub fn to_canonical_json(&self) -> String {
        format!(
            "{{\"schema_version\":{},\"generation_id\":{},\"tenant_id\":{},\"request_id\":{},\"artifact\":{{\"ecosystem\":{},\"name\":{},\"version\":{},\"digest\":{},\"source\":{}}},\"cache_object_key\":{},\"fetch_job_id\":{},\"fetch_quarantine_id\":{},\"fetch_byte_len\":{},\"fetch_byte_limit\":{},\"fetch_audit_event_id\":{},\"evidence_profile_id\":{},\"policy_version\":{},\"audit_event_id\":{}}}",
            self.schema_version,
            self.generation_id,
            json_string(&self.tenant_id),
            json_string(&self.request_id),
            json_string(&self.artifact.ecosystem),
            json_string(&self.artifact.name),
            json_string(&self.artifact.version),
            json_string(&self.artifact.digest),
            json_string(&self.artifact.source),
            json_string(&self.cache_object_key),
            json_string(&self.fetch_job_id),
            json_string(&self.fetch_quarantine_id),
            self.fetch_byte_len,
            self.fetch_byte_limit,
            json_string(&self.fetch_audit_event_id),
            json_string(&self.evidence_profile_id),
            json_string(&self.policy_version),
            json_string(&self.audit_event_id)
        )
    }
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRecord {
    pub request: AdmissionRequest,
    pub state: AdmissionState,
    pub verdict: Verdict,
    pub evidence: Option<EvidenceBundle>,
    pub fetch_result: Option<FetchResultBinding>,
    pub generation: Option<ServableGeneration>,
}

#[derive(Debug, Default)]
pub struct AdmissionController {
    records: BTreeMap<String, AdmissionRecord>,
    generations: BTreeMap<String, ServableGeneration>,
    next_generation_id: u64,
}

impl AdmissionController {
    pub fn new() -> Self {
        Self {
            next_generation_id: 1,
            ..Self::default()
        }
    }

    pub fn request(&mut self, request: AdmissionRequest) -> Result<&AdmissionRecord, ApiError> {
        let request_id = request.request_id.clone();
        match self.records.entry(request_id) {
            Entry::Occupied(entry) => {
                if entry.get().request == request {
                    Ok(entry.into_mut())
                } else {
                    Err(ApiError::fail_closed(
                        &request,
                        "admission_request_id_conflict",
                    ))
                }
            }
            Entry::Vacant(entry) => Ok(entry.insert(AdmissionRecord {
                request,
                state: AdmissionState::Quarantined,
                verdict: Verdict::Pending,
                evidence: None,
                fetch_result: None,
                generation: None,
            })),
        }
    }

    pub fn attach_fetch_result(
        &mut self,
        request_id: &str,
        binding: FetchResultBinding,
    ) -> Result<(), ApiError> {
        let Some(record) = self.records.get_mut(request_id) else {
            return Err(ApiError::unknown_request(request_id));
        };
        if binding.state != FetchResultState::Verified || !binding.admission_ready {
            record.state = AdmissionState::Rejected;
            record.verdict = Verdict::Deny;
            return Err(ApiError::fail_closed(
                &record.request,
                "fetch_result_not_admission_ready",
            ));
        }
        if binding.tenant_id != record.request.tenant_id
            || binding.artifact != record.request.artifact
        {
            record.state = AdmissionState::Rejected;
            record.verdict = Verdict::Deny;
            return Err(ApiError::fail_closed(
                &record.request,
                "fetch_result_request_mismatch",
            ));
        }
        if binding.admission_request_id != record.request.request_id {
            record.state = AdmissionState::Rejected;
            record.verdict = Verdict::Deny;
            return Err(ApiError::fail_closed(
                &record.request,
                "fetch_result_request_mismatch",
            ));
        }
        let cache_object_key = match record.request.artifact.cache_object_key() {
            Ok(key) => key,
            Err(error) => {
                record.state = AdmissionState::Rejected;
                record.verdict = Verdict::Deny;
                return Err(ApiError::fail_closed(&record.request, error.reason_code()));
            }
        };
        if binding.cache_object_key.as_deref() != Some(cache_object_key.as_str()) {
            record.state = AdmissionState::Rejected;
            record.verdict = Verdict::Deny;
            return Err(ApiError::fail_closed(
                &record.request,
                "fetch_result_cache_key_mismatch",
            ));
        }
        record.fetch_result = Some(binding);
        Ok(())
    }

    pub fn decide(
        &mut self,
        request_id: &str,
        profile: &EvidenceProfile,
        evidence: EvidenceBundle,
    ) -> Result<Verdict, ApiError> {
        let Some(record) = self.records.get_mut(request_id) else {
            return Err(ApiError::unknown_request(request_id));
        };
        record.evidence = Some(evidence.clone());

        if let Err(error) = evidence.validate_for_profile(profile) {
            record.state = AdmissionState::EvidencePending;
            record.verdict = Verdict::Pending;
            return Err(ApiError::fail_closed(&record.request, error.reason_code()));
        }

        let expected_cache_object_key = match record.request.artifact.cache_object_key() {
            Ok(key) => key,
            Err(error) => {
                record.state = AdmissionState::Rejected;
                record.verdict = Verdict::Deny;
                return Err(ApiError::fail_closed(&record.request, error.reason_code()));
            }
        };
        if evidence.artifact_digest != record.request.artifact.digest {
            record.state = AdmissionState::EvidencePending;
            record.verdict = Verdict::Pending;
            return Err(ApiError::fail_closed(
                &record.request,
                "evidence_artifact_digest_mismatch",
            ));
        }
        if evidence.cache_object_key != expected_cache_object_key {
            record.state = AdmissionState::EvidencePending;
            record.verdict = Verdict::Pending;
            return Err(ApiError::fail_closed(
                &record.request,
                "evidence_cache_object_key_mismatch",
            ));
        }

        if profile.never_auto_allow {
            record.state = AdmissionState::EvidenceComplete;
            record.verdict = Verdict::ManualReview;
            return Ok(Verdict::ManualReview);
        }

        if !profile.auto_allow_eligible || !evidence.mandatory_jobs_passed(profile) {
            record.state = AdmissionState::EvidencePending;
            record.verdict = Verdict::Pending;
            return Err(ApiError::fail_closed(
                &record.request,
                "mandatory_evidence_incomplete",
            ));
        }

        let Some(fetch_result) = record.fetch_result.as_ref() else {
            record.state = AdmissionState::EvidenceComplete;
            record.verdict = Verdict::Pending;
            return Err(ApiError::fail_closed(
                &record.request,
                "verified_fetch_result_missing",
            ));
        };
        if fetch_result.cache_object_key.as_deref() != Some(expected_cache_object_key.as_str()) {
            record.state = AdmissionState::Rejected;
            record.verdict = Verdict::Deny;
            return Err(ApiError::fail_closed(
                &record.request,
                "fetch_result_cache_key_mismatch",
            ));
        }

        let generation = ServableGeneration {
            generation_id: self.next_generation_id,
            tenant_id: record.request.tenant_id.clone(),
            request_id: record.request.request_id.clone(),
            artifact: record.request.artifact.clone(),
            cache_object_key: expected_cache_object_key,
            fetch_job_id: fetch_result.job_id.clone(),
            fetch_quarantine_id: fetch_result.quarantine_id.clone(),
            fetch_byte_len: fetch_result.byte_len,
            fetch_byte_limit: fetch_result.byte_limit,
            fetch_audit_event_id: fetch_result.audit_event_id.clone(),
            evidence_profile_id: profile.id.to_string(),
            policy_version: record.request.policy_version.clone(),
            audit_event_id: format!("audit-{}", record.request.request_id),
        };
        self.next_generation_id += 1;
        self.generations.insert(
            generation_key(&generation.tenant_id, &generation.artifact),
            generation.clone(),
        );
        record.state = AdmissionState::Promoted;
        record.verdict = Verdict::Allow;
        record.generation = Some(generation);
        Ok(Verdict::Allow)
    }

    pub fn servable(&self, tenant_id: &str, artifact: &ArtifactRef) -> Option<&ServableGeneration> {
        self.generations.get(&generation_key(tenant_id, artifact))
    }
}

fn generation_key(tenant_id: &str, artifact: &ArtifactRef) -> String {
    format!("{tenant_id}/{}", artifact.cache_key())
}

#[cfg(test)]
mod tests {
    use super::*;
    use whoathere_evidence::{
        minimum_profiles, EvidenceJobBinding, EvidenceJobKind, EvidenceJobResult, JobState,
    };
    use whoathere_vault_api::{
        bind_fetch_job_result, plan_fetch_job, FetchJobRequest, FetchJobResult,
    };

    const ABC_DIGEST: &str =
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_OBJECT_KEY: &str =
        "blobs/sha256/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const LOG_DIGEST: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn incomplete_evidence_fails_closed_and_does_not_promote() {
        let mut controller = AdmissionController::new();
        let request = sample_request("req-1");
        let artifact = request.artifact.clone();
        controller.request(request.clone()).unwrap();
        let profile = minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "npm.registry_tarball.v1")
            .unwrap();
        let evidence = evidence_from_results(
            &profile,
            &request,
            vec![job_result(
                "job-req-1-static",
                EvidenceJobKind::StaticManifest,
                JobState::Passed,
            )],
        );
        let result = controller.decide("req-1", &profile, evidence);
        assert!(result.is_err());
        assert!(controller.servable("tenant-1", &artifact).is_none());
    }

    #[test]
    fn complete_evidence_promotes_generation() {
        let mut controller = AdmissionController::new();
        let request = sample_request("req-2");
        let artifact = request.artifact.clone();
        controller.request(request.clone()).unwrap();
        controller
            .attach_fetch_result("req-2", verified_fetch_binding(&request))
            .unwrap();
        let profile = minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "pypi.wheel.v1")
            .unwrap();
        let evidence = complete_evidence(&profile, &request);
        let verdict = controller.decide("req-2", &profile, evidence).unwrap();
        assert_eq!(verdict, Verdict::Allow);
        let generation = controller.servable("tenant-1", &artifact).unwrap();
        assert_eq!(generation.cache_object_key, ABC_OBJECT_KEY);
        let manifest = generation.promotion_manifest();
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.tenant_id, "tenant-1");
        assert_eq!(manifest.request_id, "req-2");
        assert_eq!(manifest.cache_object_key, ABC_OBJECT_KEY);
        assert_eq!(manifest.fetch_job_id, "fetch-req-2");
        assert_eq!(manifest.fetch_quarantine_id, "quarantine-fetch-req-2");
        assert_eq!(manifest.fetch_byte_len, 3);
        assert_eq!(manifest.fetch_byte_limit, 1024);
        assert_eq!(manifest.fetch_audit_event_id, "audit-fetch-req-2");
        assert_eq!(manifest.audit_event_id, "audit-req-2");
        assert_eq!(
            manifest.to_canonical_json(),
            "{\"schema_version\":1,\"generation_id\":1,\"tenant_id\":\"tenant-1\",\"request_id\":\"req-2\",\"artifact\":{\"ecosystem\":\"npm\",\"name\":\"fixture\",\"version\":\"1.0.0\",\"digest\":\"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\",\"source\":\"registry\"},\"cache_object_key\":\"blobs/sha256/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\",\"fetch_job_id\":\"fetch-req-2\",\"fetch_quarantine_id\":\"quarantine-fetch-req-2\",\"fetch_byte_len\":3,\"fetch_byte_limit\":1024,\"fetch_audit_event_id\":\"audit-fetch-req-2\",\"evidence_profile_id\":\"pypi.wheel.v1\",\"policy_version\":\"policy-1\",\"audit_event_id\":\"audit-req-2\"}"
        );
    }

    #[test]
    fn promotion_manifest_json_escapes_strings() {
        let manifest = PromotionManifest {
            schema_version: 1,
            generation_id: 7,
            tenant_id: "tenant\"1".to_string(),
            request_id: "req\\2".to_string(),
            artifact: ArtifactRef {
                ecosystem: "npm".to_string(),
                name: "line\nbreak".to_string(),
                version: "1.0.0".to_string(),
                digest: ABC_DIGEST.to_string(),
                source: "registry\tlocal".to_string(),
            },
            cache_object_key: ABC_OBJECT_KEY.to_string(),
            fetch_job_id: "fetch-7".to_string(),
            fetch_quarantine_id: "quarantine-7".to_string(),
            fetch_byte_len: 11,
            fetch_byte_limit: 1024,
            fetch_audit_event_id: "audit-fetch-7".to_string(),
            evidence_profile_id: "npm.registry_tarball.v1".to_string(),
            policy_version: "policy-1".to_string(),
            audit_event_id: "audit-7".to_string(),
        };
        let json = manifest.to_canonical_json();
        assert!(json.contains("\"tenant_id\":\"tenant\\\"1\""));
        assert!(json.contains("\"request_id\":\"req\\\\2\""));
        assert!(json.contains("\"name\":\"line\\nbreak\""));
        assert!(json.contains("\"source\":\"registry\\tlocal\""));
        assert!(json.contains("\"fetch_job_id\":\"fetch-7\""));
        assert!(json.contains("\"fetch_quarantine_id\":\"quarantine-7\""));
        assert!(json.contains("\"fetch_byte_len\":11"));
        assert!(json.contains("\"fetch_byte_limit\":1024"));
        assert!(json.contains("\"fetch_audit_event_id\":\"audit-fetch-7\""));
    }

    #[test]
    fn complete_evidence_without_verified_fetch_result_fails_closed() {
        let mut controller = AdmissionController::new();
        let request = sample_request("req-missing-fetch");
        let artifact = request.artifact.clone();
        controller.request(request.clone()).unwrap();
        let profile = minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "pypi.wheel.v1")
            .unwrap();
        let evidence = complete_evidence(&profile, &request);
        let error = controller
            .decide("req-missing-fetch", &profile, evidence)
            .unwrap_err();
        assert_eq!(error.reason_code, "verified_fetch_result_missing");
        assert!(controller.servable("tenant-1", &artifact).is_none());
    }

    #[test]
    fn mismatched_evidence_profile_fails_closed_without_promotion() {
        let mut controller = AdmissionController::new();
        let request = sample_request("req-evidence-profile-mismatch");
        let artifact = request.artifact.clone();
        controller.request(request.clone()).unwrap();
        controller
            .attach_fetch_result(
                "req-evidence-profile-mismatch",
                verified_fetch_binding(&request),
            )
            .unwrap();
        let profile = minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "pypi.wheel.v1")
            .unwrap();
        let mut evidence = complete_evidence(&profile, &request);
        evidence.profile_id = "npm.registry_tarball.v1".to_string();
        for binding in &mut evidence.job_bindings {
            binding.profile_id = evidence.profile_id.clone();
        }
        let error = controller
            .decide("req-evidence-profile-mismatch", &profile, evidence)
            .unwrap_err();
        assert_eq!(error.reason_code, "evidence_profile_id_mismatch");
        assert!(controller.servable("tenant-1", &artifact).is_none());
    }

    #[test]
    fn duplicate_evidence_jobs_fail_closed_without_promotion() {
        let mut controller = AdmissionController::new();
        let request = sample_request("req-evidence-duplicate");
        let artifact = request.artifact.clone();
        controller.request(request.clone()).unwrap();
        controller
            .attach_fetch_result("req-evidence-duplicate", verified_fetch_binding(&request))
            .unwrap();
        let profile = minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "pypi.wheel.v1")
            .unwrap();
        let mut evidence = complete_evidence(&profile, &request);
        let duplicate = EvidenceJobResult {
            job_id: "job-duplicate-conflict".to_string(),
            job_kind: profile.requirements[0].job_kind,
            state: JobState::Failed,
            log_digest: LOG_DIGEST.to_string(),
            reason_codes: vec!["duplicate_conflict".to_string()],
        };
        evidence.job_bindings.push(job_binding(
            &profile,
            &request,
            &duplicate,
            &request.artifact.cache_object_key().unwrap(),
        ));
        evidence.results.push(duplicate);
        let error = controller
            .decide("req-evidence-duplicate", &profile, evidence)
            .unwrap_err();
        assert_eq!(error.reason_code, "evidence_duplicate_job_result");
        assert!(controller.servable("tenant-1", &artifact).is_none());
    }

    #[test]
    fn evidence_subject_mismatch_fails_closed_without_promotion() {
        let mut controller = AdmissionController::new();
        let request = sample_request("req-evidence-subject");
        let artifact = request.artifact.clone();
        controller.request(request.clone()).unwrap();
        controller
            .attach_fetch_result("req-evidence-subject", verified_fetch_binding(&request))
            .unwrap();
        let profile = minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "pypi.wheel.v1")
            .unwrap();
        let mut evidence = complete_evidence(&profile, &request);
        evidence.artifact_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        for binding in &mut evidence.job_bindings {
            binding.artifact_digest = evidence.artifact_digest.clone();
        }
        let error = controller
            .decide("req-evidence-subject", &profile, evidence)
            .unwrap_err();
        assert_eq!(error.reason_code, "evidence_artifact_digest_mismatch");
        assert!(controller.servable("tenant-1", &artifact).is_none());
    }

    #[test]
    fn unknown_request_fails_closed_without_panic() {
        let mut controller = AdmissionController::new();
        let profile = minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "pypi.wheel.v1")
            .unwrap();
        let evidence = EvidenceBundle {
            profile_id: profile.id.to_string(),
            profile_version: profile.version,
            artifact_digest: ABC_DIGEST.to_string(),
            cache_object_key: ABC_OBJECT_KEY.to_string(),
            results: Vec::new(),
            job_bindings: Vec::new(),
        };
        let error = controller
            .decide("missing", &profile, evidence)
            .unwrap_err();
        assert_eq!(error.reason_code, "admission_request_not_found");
        assert_eq!(error.admission_request_id, "missing");
    }

    #[test]
    fn conflicting_duplicate_request_id_fails_closed() {
        let mut controller = AdmissionController::new();
        let first = sample_request("req-conflict");
        let mut second = sample_request("req-conflict");
        second.tenant_id = "tenant-2".to_string();
        controller.request(first).unwrap();
        let error = controller.request(second).unwrap_err();
        assert_eq!(error.reason_code, "admission_request_id_conflict");
    }

    #[test]
    fn same_artifact_generations_are_tenant_isolated() {
        let mut controller = AdmissionController::new();
        let tenant_1 = sample_request_for_tenant("req-tenant-1", "tenant-1");
        let tenant_2 = sample_request_for_tenant("req-tenant-2", "tenant-2");
        let artifact = tenant_1.artifact.clone();
        controller.request(tenant_1.clone()).unwrap();
        controller.request(tenant_2.clone()).unwrap();
        controller
            .attach_fetch_result("req-tenant-1", verified_fetch_binding(&tenant_1))
            .unwrap();
        controller
            .attach_fetch_result("req-tenant-2", verified_fetch_binding(&tenant_2))
            .unwrap();
        let profile = minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "pypi.wheel.v1")
            .unwrap();
        let tenant_1_evidence = complete_evidence(&profile, &tenant_1);
        let tenant_2_evidence = complete_evidence(&profile, &tenant_2);
        controller
            .decide("req-tenant-1", &profile, tenant_1_evidence)
            .unwrap();
        controller
            .decide("req-tenant-2", &profile, tenant_2_evidence)
            .unwrap();
        assert_eq!(
            controller
                .servable("tenant-1", &artifact)
                .unwrap()
                .tenant_id,
            "tenant-1"
        );
        assert_eq!(
            controller
                .servable("tenant-2", &artifact)
                .unwrap()
                .tenant_id,
            "tenant-2"
        );
        assert!(controller.servable("tenant-3", &artifact).is_none());
    }

    #[test]
    fn invalid_digest_fails_closed_and_does_not_promote() {
        let mut controller = AdmissionController::new();
        let mut request = sample_request("req-invalid-digest");
        request.artifact.digest = "sha256:../escape".to_string();
        let artifact = request.artifact.clone();
        controller.request(request.clone()).unwrap();
        let profile = minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "npm.registry_tarball.v1")
            .unwrap();
        let evidence = complete_evidence_with_subject(&profile, &request, "sha256:../escape", "");
        let error = controller
            .decide("req-invalid-digest", &profile, evidence)
            .unwrap_err();
        assert_eq!(
            error.reason_code,
            "artifact_digest_contains_unsafe_characters"
        );
        assert!(controller.servable("tenant-1", &artifact).is_none());
    }

    fn sample_request(id: &str) -> AdmissionRequest {
        sample_request_for_tenant(id, "tenant-1")
    }

    fn sample_request_for_tenant(id: &str, tenant_id: &str) -> AdmissionRequest {
        AdmissionRequest {
            request_id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            policy_version: "policy-1".to_string(),
            artifact: ArtifactRef {
                ecosystem: "npm".to_string(),
                name: "fixture".to_string(),
                version: "1.0.0".to_string(),
                digest: ABC_DIGEST.to_string(),
                source: "registry".to_string(),
            },
        }
    }

    fn complete_evidence(profile: &EvidenceProfile, request: &AdmissionRequest) -> EvidenceBundle {
        complete_evidence_with_subject(
            profile,
            request,
            &request.artifact.digest,
            &request.artifact.cache_object_key().unwrap(),
        )
    }

    fn complete_evidence_with_subject(
        profile: &EvidenceProfile,
        request: &AdmissionRequest,
        artifact_digest: &str,
        cache_object_key: &str,
    ) -> EvidenceBundle {
        let results = profile
            .requirements
            .iter()
            .enumerate()
            .map(|(index, requirement)| {
                job_result(
                    &format!("job-{}-{index}", request.request_id),
                    requirement.job_kind,
                    JobState::Passed,
                )
            })
            .collect::<Vec<_>>();
        evidence_from_results_with_subject(
            profile,
            request,
            artifact_digest,
            cache_object_key,
            results,
        )
    }

    fn evidence_from_results(
        profile: &EvidenceProfile,
        request: &AdmissionRequest,
        results: Vec<EvidenceJobResult>,
    ) -> EvidenceBundle {
        evidence_from_results_with_subject(
            profile,
            request,
            &request.artifact.digest,
            &request.artifact.cache_object_key().unwrap(),
            results,
        )
    }

    fn evidence_from_results_with_subject(
        profile: &EvidenceProfile,
        _request: &AdmissionRequest,
        artifact_digest: &str,
        cache_object_key: &str,
        results: Vec<EvidenceJobResult>,
    ) -> EvidenceBundle {
        let job_bindings = results
            .iter()
            .map(|result| EvidenceJobBinding {
                job_id: result.job_id.clone(),
                job_kind: result.job_kind,
                profile_id: profile.id.to_string(),
                profile_version: profile.version,
                artifact_digest: artifact_digest.to_string(),
                cache_object_key: cache_object_key.to_string(),
                log_digest: result.log_digest.clone(),
                admission_ready: true,
            })
            .collect();
        EvidenceBundle {
            profile_id: profile.id.to_string(),
            profile_version: profile.version,
            artifact_digest: artifact_digest.to_string(),
            cache_object_key: cache_object_key.to_string(),
            results,
            job_bindings,
        }
    }

    fn job_result(job_id: &str, job_kind: EvidenceJobKind, state: JobState) -> EvidenceJobResult {
        EvidenceJobResult {
            job_id: job_id.to_string(),
            job_kind,
            state,
            log_digest: LOG_DIGEST.to_string(),
            reason_codes: Vec::new(),
        }
    }

    fn job_binding(
        profile: &EvidenceProfile,
        request: &AdmissionRequest,
        result: &EvidenceJobResult,
        cache_object_key: &str,
    ) -> EvidenceJobBinding {
        EvidenceJobBinding {
            job_id: result.job_id.clone(),
            job_kind: result.job_kind,
            profile_id: profile.id.to_string(),
            profile_version: profile.version,
            artifact_digest: request.artifact.digest.clone(),
            cache_object_key: cache_object_key.to_string(),
            log_digest: result.log_digest.clone(),
            admission_ready: true,
        }
    }

    fn verified_fetch_binding(request: &AdmissionRequest) -> FetchResultBinding {
        let plan = plan_fetch_job(FetchJobRequest {
            job_id: format!("fetch-{}", request.request_id),
            tenant_id: request.tenant_id.clone(),
            admission_request_id: request.request_id.clone(),
            artifact: request.artifact.clone(),
            source_url: "https://registry.example/fixture.tgz".to_string(),
            expected_digest: request.artifact.digest.clone(),
            byte_limit: 1024,
        });
        bind_fetch_job_result(
            &plan,
            FetchJobResult {
                job_id: plan.job_id.clone(),
                tenant_id: plan.tenant_id.clone(),
                admission_request_id: plan.admission_request_id.clone(),
                artifact: plan.artifact.clone(),
                source_url: plan.source_url.clone(),
                expected_digest: plan.expected_digest.clone(),
                verified_digest: plan.expected_digest.clone(),
                cache_object_key: plan.cache_object_key.clone().unwrap(),
                byte_len: 3,
                byte_limit: plan.byte_limit,
                quarantine_id: format!("quarantine-{}", plan.job_id),
                fetch_enabled: plan.fetch_enabled,
                network_attempted: plan.network_attempted,
                stored_in_quarantine: true,
                audit_event_id: format!("audit-{}", plan.job_id),
            },
        )
    }
}
