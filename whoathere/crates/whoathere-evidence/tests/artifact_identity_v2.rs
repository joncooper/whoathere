use whoathere_evidence::v2::{
    AnalyzerIdentityV2, ArtifactEvidenceSubjectV2, EvidenceCompletenessV2, EvidenceCoverageV2,
    EvidenceEnvelopeV2, EvidenceJobCompletionV2, EvidenceJobExpectationV2, EvidenceJobResultV2,
    EvidenceLimitationStateV2, EvidenceLimitationV2, EvidenceProducerIdentityV2,
    EvidenceValidationContextV2, EvidenceValidationErrorV2, ScenarioIdentityV2,
    EVIDENCE_ENVELOPE_SCHEMA_V2,
};

const ARTIFACT_A: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const ARTIFACT_B: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const MANIFEST_A: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const MANIFEST_B: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const ENVELOPE_A: &str = "sha256:abababababababababababababababababababababababababababababababab";
const ENVELOPE_B: &str = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const POLICY_A: &str = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
const POLICY_B: &str = "sha256:6666666666666666666666666666666666666666666666666666666666666666";
const ANALYZER_A: &str = "sha256:7777777777777777777777777777777777777777777777777777777777777777";
const ANALYZER_B: &str = "sha256:8888888888888888888888888888888888888888888888888888888888888888";
const SCENARIO_A: &str = "sha256:9999999999999999999999999999999999999999999999999999999999999999";
const JOB_SPEC_STATIC: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const JOB_SPEC_DYNAMIC: &str =
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const RESULT_STATIC: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RESULT_DYNAMIC: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn cas_key(digest: &str) -> String {
    format!(
        "blobs/sha256/{}",
        digest.strip_prefix("sha256:").expect("fixture digest")
    )
}

fn subject_a() -> ArtifactEvidenceSubjectV2 {
    ArtifactEvidenceSubjectV2::new(ARTIFACT_A, ENVELOPE_A, MANIFEST_A, cas_key(ARTIFACT_A))
        .expect("valid inert subject A")
}

fn subject_b() -> ArtifactEvidenceSubjectV2 {
    ArtifactEvidenceSubjectV2::new(ARTIFACT_B, ENVELOPE_B, MANIFEST_B, cas_key(ARTIFACT_B))
        .expect("valid inert subject B")
}

fn analyzer_a() -> EvidenceProducerIdentityV2 {
    EvidenceProducerIdentityV2::Analyzer(AnalyzerIdentityV2 {
        analyzer_id: "static-rules".to_string(),
        analyzer_version: "2.0.0".to_string(),
        analyzer_sha256: ANALYZER_A.to_string(),
    })
}

fn scenario_a() -> EvidenceProducerIdentityV2 {
    EvidenceProducerIdentityV2::Scenario(ScenarioIdentityV2 {
        scenario_id: "npm-consumer-install-ci-true".to_string(),
        scenario_sha256: SCENARIO_A.to_string(),
    })
}

fn job(
    job_id: &str,
    producer: EvidenceProducerIdentityV2,
    result_sha256: &str,
) -> EvidenceJobResultV2 {
    EvidenceJobResultV2 {
        job_id: job_id.to_string(),
        evidence_id: "evidence-run-42".to_string(),
        run_id: "run-42".to_string(),
        job_spec_sha256: if job_id == "static-1" {
            JOB_SPEC_STATIC.to_string()
        } else {
            JOB_SPEC_DYNAMIC.to_string()
        },
        produced_at_unix_seconds: 1_025,
        subject: subject_a(),
        policy_sha256: POLICY_A.to_string(),
        producer,
        completion: EvidenceJobCompletionV2::Completed,
        coverage: EvidenceCoverageV2::complete(),
        result_sha256: result_sha256.to_string(),
    }
}

fn envelope() -> EvidenceEnvelopeV2 {
    EvidenceEnvelopeV2 {
        schema_version: EVIDENCE_ENVELOPE_SCHEMA_V2.to_string(),
        evidence_id: "evidence-run-42".to_string(),
        run_id: "run-42".to_string(),
        run_started_at_unix_seconds: 1_000,
        issued_at_unix_seconds: 1_040,
        expires_at_unix_seconds: 1_200,
        subject: subject_a(),
        policy_sha256: POLICY_A.to_string(),
        coverage: EvidenceCoverageV2::complete(),
        jobs: vec![
            job("static-1", analyzer_a(), RESULT_STATIC),
            job("scenario-1", scenario_a(), RESULT_DYNAMIC),
        ],
    }
}

fn context() -> EvidenceValidationContextV2 {
    EvidenceValidationContextV2 {
        expected_evidence_id: "evidence-run-42".to_string(),
        expected_run_id: "run-42".to_string(),
        expected_subject: subject_a(),
        expected_policy_sha256: POLICY_A.to_string(),
        expected_jobs: vec![
            EvidenceJobExpectationV2 {
                job_id: "static-1".to_string(),
                job_spec_sha256: JOB_SPEC_STATIC.to_string(),
                producer: analyzer_a(),
            },
            EvidenceJobExpectationV2 {
                job_id: "scenario-1".to_string(),
                job_spec_sha256: JOB_SPEC_DYNAMIC.to_string(),
                producer: scenario_a(),
            },
        ],
        now_unix_seconds: 1_050,
        maximum_age_seconds: 300,
        previously_accepted_evidence_ids: Vec::new(),
    }
}

#[test]
fn complete_exactly_bound_evidence_is_structural_but_never_allow_authority() {
    let envelope = envelope();
    let validated = envelope
        .validate_structure(&context())
        .expect("valid v2 evidence structure");
    assert!(!validated.is_authenticated());
    assert!(!validated.can_authorize_allow());
    validated.check_complete().expect("complete structure");
    let complete = validated.into_complete().expect("complete structure");
    assert!(!complete.is_authenticated());
    assert!(!complete.can_authorize_allow());
}

#[test]
fn subject_constructor_rejects_missing_invalid_and_noncanonical_cas_bindings() {
    assert_eq!(
        ArtifactEvidenceSubjectV2::new("", ENVELOPE_A, MANIFEST_A, cas_key(ARTIFACT_A))
            .unwrap_err(),
        EvidenceValidationErrorV2::MissingArtifactDigest
    );
    assert_eq!(
        ArtifactEvidenceSubjectV2::new(ARTIFACT_A, "", MANIFEST_A, cas_key(ARTIFACT_A))
            .unwrap_err(),
        EvidenceValidationErrorV2::MissingEnvelopeDigest
    );
    assert_eq!(
        ArtifactEvidenceSubjectV2::new(ARTIFACT_A, ENVELOPE_A, "", cas_key(ARTIFACT_A))
            .unwrap_err(),
        EvidenceValidationErrorV2::MissingManifestDigest
    );
    assert_eq!(
        ArtifactEvidenceSubjectV2::new(ARTIFACT_A, ENVELOPE_A, MANIFEST_A, "").unwrap_err(),
        EvidenceValidationErrorV2::MissingCasObjectKey
    );
    assert_eq!(
        ArtifactEvidenceSubjectV2::new(
            ARTIFACT_A.to_ascii_uppercase(),
            ENVELOPE_A,
            MANIFEST_A,
            cas_key(ARTIFACT_A)
        )
        .unwrap_err(),
        EvidenceValidationErrorV2::InvalidArtifactDigest
    );
    assert_eq!(
        ArtifactEvidenceSubjectV2::new(ARTIFACT_A, ENVELOPE_A, MANIFEST_A, cas_key(ARTIFACT_B))
            .unwrap_err(),
        EvidenceValidationErrorV2::CasObjectKeyDigestMismatch
    );
}

#[test]
fn cross_artifact_and_cross_manifest_splicing_fail_closed() {
    let mut artifact_splice = envelope();
    artifact_splice.jobs[0].subject = subject_b();
    assert_eq!(
        artifact_splice.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::ArtifactBindingMismatch
    );

    let mut manifest_splice = envelope();
    manifest_splice.jobs[0].subject =
        ArtifactEvidenceSubjectV2::new(ARTIFACT_A, ENVELOPE_A, MANIFEST_B, cas_key(ARTIFACT_A))
            .expect("valid cross-manifest subject");
    assert_eq!(
        manifest_splice.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::ManifestBindingMismatch
    );

    let mut custody_splice = envelope();
    custody_splice.jobs[0].subject =
        ArtifactEvidenceSubjectV2::new(ARTIFACT_A, ENVELOPE_B, MANIFEST_A, cas_key(ARTIFACT_A))
            .expect("valid cross-envelope subject");
    assert_eq!(
        custody_splice.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::EnvelopeBindingMismatch
    );

    let mut envelope_splice = envelope();
    envelope_splice.subject = subject_b();
    assert_eq!(
        envelope_splice.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::ArtifactBindingMismatch
    );
}

#[test]
fn policy_and_producer_identity_tampering_fail_closed() {
    let mut missing_policy = envelope();
    missing_policy.jobs[0].policy_sha256.clear();
    assert_eq!(
        missing_policy.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::MissingPolicyDigest
    );

    let mut envelope_policy = envelope();
    envelope_policy.policy_sha256 = POLICY_B.to_string();
    assert_eq!(
        envelope_policy.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::PolicyBindingMismatch
    );

    let mut job_policy = envelope();
    job_policy.jobs[0].policy_sha256 = POLICY_B.to_string();
    assert_eq!(
        job_policy.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::PolicyBindingMismatch
    );

    let mut producer_tamper = envelope();
    producer_tamper.jobs[0].producer = EvidenceProducerIdentityV2::Analyzer(AnalyzerIdentityV2 {
        analyzer_id: "static-rules".to_string(),
        analyzer_version: "2.0.0".to_string(),
        analyzer_sha256: ANALYZER_B.to_string(),
    });
    assert_eq!(
        producer_tamper.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::ProducerIdentityMismatch
    );

    let mut missing_producer = envelope();
    missing_producer.jobs[0].producer = EvidenceProducerIdentityV2::Analyzer(AnalyzerIdentityV2 {
        analyzer_id: String::new(),
        analyzer_version: "2.0.0".to_string(),
        analyzer_sha256: ANALYZER_A.to_string(),
    });
    assert_eq!(
        missing_producer.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::MissingProducerIdentity
    );

    let mut missing_scenario = envelope();
    missing_scenario.jobs[1].producer = EvidenceProducerIdentityV2::Scenario(ScenarioIdentityV2 {
        scenario_id: String::new(),
        scenario_sha256: SCENARIO_A.to_string(),
    });
    assert_eq!(
        missing_scenario.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::MissingProducerIdentity
    );
}

#[test]
fn unsupported_schema_and_duplicate_or_missing_jobs_fail_closed() {
    let mut unsupported = envelope();
    unsupported.schema_version = "whoathere.evidence.v3".to_string();
    assert_eq!(
        unsupported.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::UnsupportedSchema
    );

    let mut duplicate = envelope();
    duplicate.jobs[1].job_id = duplicate.jobs[0].job_id.clone();
    assert_eq!(
        duplicate.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::DuplicateJobId
    );

    let mut missing = envelope();
    missing.jobs.pop();
    assert_eq!(
        missing.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::MissingRequiredJob
    );

    let mut unexpected = envelope();
    unexpected.jobs[0].job_id = "unknown-job".to_string();
    assert_eq!(
        unexpected.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::UnexpectedJob
    );

    let mut duplicate_expectation = context();
    duplicate_expectation.expected_jobs[1].job_id = "static-1".to_string();
    assert_eq!(
        envelope()
            .validate_structure(&duplicate_expectation)
            .unwrap_err(),
        EvidenceValidationErrorV2::DuplicateExpectedJobId
    );
}

#[test]
fn stale_future_replayed_and_wrong_run_identity_fail_closed() {
    let mut stale = envelope();
    stale.expires_at_unix_seconds = context().now_unix_seconds;
    assert_eq!(
        stale.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::StaleEvidence
    );

    let mut too_old = envelope();
    too_old.run_started_at_unix_seconds = 500;
    too_old.issued_at_unix_seconds = 600;
    assert_eq!(
        too_old.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::StaleEvidence
    );

    let mut future = envelope();
    future.issued_at_unix_seconds = 1_051;
    assert_eq!(
        future.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::EvidenceFromFuture
    );

    let mut replay_context = context();
    replay_context
        .previously_accepted_evidence_ids
        .push("evidence-run-42".to_string());
    assert_eq!(
        envelope().validate_structure(&replay_context).unwrap_err(),
        EvidenceValidationErrorV2::ReplayedIdentity
    );

    let mut wrong_run = envelope();
    wrong_run.run_id = "run-41".to_string();
    assert_eq!(
        wrong_run.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::RunIdMismatch
    );
}

#[test]
fn job_run_spec_and_time_repackaging_fails_closed() {
    let mut wrong_job_run = envelope();
    wrong_job_run.jobs[0].run_id = "old-run".to_string();
    assert_eq!(
        wrong_job_run.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::JobRunBindingMismatch
    );

    let mut wrong_job_evidence = envelope();
    wrong_job_evidence.jobs[0].evidence_id = "old-evidence".to_string();
    assert_eq!(
        wrong_job_evidence
            .validate_structure(&context())
            .unwrap_err(),
        EvidenceValidationErrorV2::JobRunBindingMismatch
    );

    let mut wrong_job_spec = envelope();
    wrong_job_spec.jobs[0].job_spec_sha256 = POLICY_B.to_string();
    assert_eq!(
        wrong_job_spec.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::JobSpecBindingMismatch
    );

    let mut stale_job = envelope();
    stale_job.jobs[0].produced_at_unix_seconds = 999;
    assert_eq!(
        stale_job.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::JobTimestampInvalid
    );
}

#[test]
fn path_like_ids_and_unbounded_job_sets_are_rejected() {
    let mut path_like = envelope();
    path_like.evidence_id = "../../evidence".to_string();
    let mut path_context = context();
    path_context.expected_evidence_id = "../../evidence".to_string();
    assert_eq!(
        path_like.validate_structure(&path_context).unwrap_err(),
        EvidenceValidationErrorV2::InvalidEvidenceId
    );

    let mut oversized = envelope();
    oversized.jobs = (0..129)
        .map(|index| {
            let mut result = job("static-1", analyzer_a(), RESULT_STATIC);
            result.job_id = format!("job-{index}");
            result
        })
        .collect();
    assert_eq!(
        oversized.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::TooManyJobs
    );
}

#[test]
fn incomplete_limited_or_unfinished_evidence_is_structural_but_not_complete() {
    let mut incomplete_envelope = envelope();
    incomplete_envelope.coverage.completeness = EvidenceCompletenessV2::Incomplete;
    assert_eq!(
        incomplete_envelope
            .validate_structure(&context())
            .expect("authenticated control plane may retain incomplete structure")
            .check_complete()
            .unwrap_err(),
        EvidenceValidationErrorV2::IncompleteCoverage
    );

    let mut incomplete_job = envelope();
    incomplete_job.jobs[0].coverage.completeness = EvidenceCompletenessV2::Incomplete;
    assert_eq!(
        incomplete_job
            .validate_structure(&context())
            .expect("incomplete job is still structurally useful")
            .check_complete()
            .unwrap_err(),
        EvidenceValidationErrorV2::IncompleteCoverage
    );

    let mut limited = envelope();
    limited.jobs[0].coverage.limitations =
        EvidenceLimitationStateV2::Present(vec![EvidenceLimitationV2 {
            code: "unsupported-generated-code".to_string(),
            evidence_sha256: Some(RESULT_STATIC.to_string()),
        }]);
    assert_eq!(
        limited
            .validate_structure(&context())
            .expect("limited evidence is structurally useful")
            .check_complete()
            .unwrap_err(),
        EvidenceValidationErrorV2::CoverageHasLimitations
    );

    let mut timed_out = envelope();
    timed_out.jobs[0].completion = EvidenceJobCompletionV2::TimedOut;
    assert_eq!(
        timed_out
            .validate_structure(&context())
            .expect("timeout evidence is structurally useful")
            .check_complete()
            .unwrap_err(),
        EvidenceValidationErrorV2::JobNotCompleted
    );
}

#[test]
fn result_digest_tampering_fails_closed() {
    let mut missing = envelope();
    missing.jobs[0].result_sha256.clear();
    assert_eq!(
        missing.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::MissingResultDigest
    );

    let mut malformed = envelope();
    malformed.jobs[0].result_sha256 = "sha256:not-a-digest".to_string();
    assert_eq!(
        malformed.validate_structure(&context()).unwrap_err(),
        EvidenceValidationErrorV2::InvalidResultDigest
    );
}
