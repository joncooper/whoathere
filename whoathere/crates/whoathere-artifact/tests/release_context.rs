use whoathere_artifact::{
    AttestationKind, AttestationVerification, DependencyArtifact, DependencyClosureContext,
    DependencyClosureStatus, Ecosystem, PriorRelease, PublisherIdentity, PublisherIdentityKind,
    RegistryOrigin, RegistryOriginKind, ReleaseAttestation, ReleaseContext,
    ReleaseContextAssessment, ReleaseContextDisposition, ReleaseContextInput, ReleaseContextSignal,
    ReleaseTiming, ReleaseWorkflowIdentity, RequestedPackageCoordinate, ResolvedPackageCoordinate,
    Sha256Digest, SourceArtifactComparison, SourceArtifactComparisonStatus, SourceReference,
    WorkflowProvider,
};

fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::from_bytes(label.as_bytes())
}

fn coordinate(version: &str) -> ResolvedPackageCoordinate {
    ResolvedPackageCoordinate {
        ecosystem: Ecosystem::Npm,
        package_name: "inert-release-context".to_string(),
        version: version.to_string(),
    }
}

fn registry(kind: RegistryOriginKind, origin: &str, label: &str) -> RegistryOrigin {
    RegistryOrigin {
        kind,
        canonical_origin: origin.to_string(),
        metadata_sha256: digest(label),
    }
}

fn source_reference(revision: &str) -> SourceReference {
    SourceReference {
        repository_url: "https://example.invalid/whoathere/inert-release-context".to_string(),
        revision: revision.to_string(),
        subdirectory: Some("packages/inert-release-context".to_string()),
    }
}

fn publisher(stable_id: &str) -> PublisherIdentity {
    PublisherIdentity {
        kind: PublisherIdentityKind::NpmAccount,
        stable_id: stable_id.to_string(),
        display_name: Some("Inert Publisher".to_string()),
    }
}

fn workflow(workflow_ref: &str) -> ReleaseWorkflowIdentity {
    ReleaseWorkflowIdentity {
        provider: WorkflowProvider::GithubActions,
        repository: "whoathere/inert-release-context".to_string(),
        workflow_ref: workflow_ref.to_string(),
        issuer: "https://token.actions.githubusercontent.com".to_string(),
        subject: "repo:whoathere/inert-release-context:ref:refs/heads/main".to_string(),
    }
}

fn prior_release() -> PriorRelease {
    PriorRelease {
        coordinate: coordinate("1.1.0"),
        artifact_sha256: digest("prior artifact"),
        registry_origin: registry(
            RegistryOriginKind::NpmOfficial,
            "https://registry.npmjs.org",
            "prior registry metadata",
        ),
        source_reference: Some(source_reference("prior-revision")),
        publisher_identity: Some(publisher("npm:inert-publisher")),
        workflow_identity: Some(workflow("release.yml@refs/heads/main")),
    }
}

fn complete_input() -> ReleaseContextInput {
    let artifact_sha256 = digest("current artifact");
    ReleaseContextInput {
        artifact_sha256: artifact_sha256.clone(),
        requested: RequestedPackageCoordinate {
            ecosystem: Ecosystem::Npm,
            package_name: "inert-release-context".to_string(),
            requirement: "^1.0.0".to_string(),
        },
        resolved: coordinate("1.2.0"),
        registry_origin: registry(
            RegistryOriginKind::NpmOfficial,
            "https://registry.npmjs.org",
            "current registry metadata",
        ),
        timing: ReleaseTiming {
            observed_at_unix_seconds: 2_000_000,
            published_at_unix_seconds: Some(1_000_000),
            cooldown_seconds: 86_400,
        },
        prior_release: Some(prior_release()),
        publisher_identity: Some(publisher("npm:inert-publisher")),
        workflow_identity: Some(workflow("release.yml@refs/heads/main")),
        attestations: vec![ReleaseAttestation {
            kind: AttestationKind::SlsaProvenance,
            verification: AttestationVerification::Verified,
            statement_sha256: digest("attestation statement"),
            subject_sha256: artifact_sha256,
            issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            predicate_type: Some("https://slsa.dev/provenance/v1".to_string()),
        }],
        dependency_closure: DependencyClosureContext {
            status: DependencyClosureStatus::Complete,
            closure_sha256: Some(digest("dependency closure")),
            artifacts: vec![DependencyArtifact {
                coordinate: ResolvedPackageCoordinate {
                    ecosystem: Ecosystem::Npm,
                    package_name: "inert-dependency".to_string(),
                    version: "3.2.1".to_string(),
                },
                artifact_sha256: digest("inert dependency artifact"),
                registry_origin: registry(
                    RegistryOriginKind::NpmOfficial,
                    "https://registry.npmjs.org",
                    "dependency registry metadata",
                ),
            }],
        },
        source_comparison: SourceArtifactComparison {
            status: SourceArtifactComparisonStatus::VerifiedMatch,
            source_reference: Some(source_reference("current-revision")),
            source_snapshot_sha256: Some(digest("source snapshot")),
            evidence_sha256: Some(digest("source comparison evidence")),
        },
    }
}

fn has_signal(assessment: &ReleaseContextAssessment, signal: ReleaseContextSignal) -> bool {
    assessment
        .observations
        .iter()
        .any(|observation| observation.signal == signal)
}

#[test]
fn verified_release_context_remains_informational_and_non_authorizing() {
    let context = ReleaseContext::new(complete_input()).expect("build inert release context");
    let assessment = context.assess().expect("assess inert release context");

    assert_eq!(
        assessment.disposition,
        ReleaseContextDisposition::Informational
    );
    assert!(assessment.artifact_scanning_required);
    assert!(!assessment.authorizes_admission());
    assert!(!assessment.establishes_malicious_behavior());
    assert!(!assessment.requires_manual_review());
    assert!(has_signal(
        &assessment,
        ReleaseContextSignal::VerifiedAttestationPresent
    ));
    assert!(has_signal(
        &assessment,
        ReleaseContextSignal::SourceArtifactVerifiedMatch
    ));

    let context_json = serde_json::to_vec(&context).expect("serialize release context");
    let decoded: ReleaseContext =
        serde_json::from_slice(&context_json).expect("deserialize release context");
    assert_eq!(decoded, context);

    let assessment_json = serde_json::to_vec(&assessment).expect("serialize assessment");
    let decoded_assessment: ReleaseContextAssessment =
        serde_json::from_slice(&assessment_json).expect("deserialize assessment");
    assert_eq!(decoded_assessment, assessment);
}

#[test]
fn continuity_breaks_and_source_mismatch_are_suspicious_not_behavior_detections() {
    let mut input = complete_input();
    input.registry_origin = registry(
        RegistryOriginKind::Custom,
        "https://registry.example.invalid",
        "custom registry metadata",
    );
    input.publisher_identity = Some(publisher("npm:different-publisher"));
    input.workflow_identity = Some(workflow("different-release.yml@refs/heads/main"));
    input.attestations[0].verification = AttestationVerification::Invalid;
    input.attestations[0].subject_sha256 = digest("wrong attestation subject");
    input.source_comparison.status = SourceArtifactComparisonStatus::Mismatch;

    let assessment = ReleaseContext::new(input)
        .expect("build suspicious inert context")
        .assess()
        .expect("assess suspicious inert context");

    assert_eq!(
        assessment.disposition,
        ReleaseContextDisposition::Suspicious
    );
    for signal in [
        ReleaseContextSignal::RegistryOriginChanged,
        ReleaseContextSignal::PublisherIdentityChanged,
        ReleaseContextSignal::WorkflowIdentityChanged,
        ReleaseContextSignal::InvalidAttestationPresent,
        ReleaseContextSignal::SourceArtifactMismatch,
    ] {
        assert!(has_signal(&assessment, signal), "missing signal {signal:?}");
    }
    assert!(assessment.artifact_scanning_required);
    assert!(assessment.requires_manual_review());
    assert!(!assessment.authorizes_admission());
    assert!(!assessment.establishes_malicious_behavior());
}

#[test]
fn incomplete_release_inputs_require_review_without_fabricating_suspicion() {
    let mut input = complete_input();
    input.timing.observed_at_unix_seconds = 1_000_100;
    input.timing.cooldown_seconds = 1_000;
    input.publisher_identity = None;
    input.attestations[0].verification = AttestationVerification::Unverified;
    input.dependency_closure = DependencyClosureContext {
        status: DependencyClosureStatus::Incomplete,
        closure_sha256: None,
        artifacts: Vec::new(),
    };
    input.source_comparison = SourceArtifactComparison {
        status: SourceArtifactComparisonStatus::NotPerformed,
        source_reference: Some(source_reference("current-revision")),
        source_snapshot_sha256: None,
        evidence_sha256: None,
    };

    let assessment = ReleaseContext::new(input)
        .expect("build review context")
        .assess()
        .expect("assess review context");

    assert_eq!(
        assessment.disposition,
        ReleaseContextDisposition::ManualReview
    );
    for signal in [
        ReleaseContextSignal::FreshReleaseCooldownActive,
        ReleaseContextSignal::PublisherIdentityUnavailable,
        ReleaseContextSignal::UnverifiedAttestationPresent,
        ReleaseContextSignal::DependencyClosureIncomplete,
        ReleaseContextSignal::SourceArtifactComparisonNotPerformed,
    ] {
        assert!(has_signal(&assessment, signal), "missing signal {signal:?}");
    }
    assert!(assessment.artifact_scanning_required);
    assert!(!assessment.authorizes_admission());
    assert!(!assessment.establishes_malicious_behavior());
}

#[test]
fn context_deserialization_rejects_unknown_fields_and_cross_contract_mismatches() {
    let context = ReleaseContext::new(complete_input()).expect("build inert release context");
    let mut value = serde_json::to_value(&context).expect("serialize release context");
    value
        .as_object_mut()
        .expect("context object")
        .insert("auto_allow".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<ReleaseContext>(value).is_err());

    let mut value = serde_json::to_value(&context).expect("serialize release context");
    value["resolved"]["package_name"] = serde_json::json!("different-package");
    assert!(serde_json::from_value::<ReleaseContext>(value).is_err());

    let mut value = serde_json::to_value(&context).expect("serialize release context");
    value["attestations"][0]["subject_sha256"] =
        serde_json::json!(digest("wrong subject").to_string());
    assert!(serde_json::from_value::<ReleaseContext>(value).is_err());

    let mut value = serde_json::to_value(&context).expect("serialize release context");
    value["timing"]["published_at_unix_seconds"] = serde_json::json!(3_000_000u64);
    assert!(serde_json::from_value::<ReleaseContext>(value).is_err());
}

#[test]
fn assessment_deserialization_rejects_any_attempt_to_waive_scanning_or_relabel_signals() {
    let assessment = ReleaseContext::new(complete_input())
        .expect("build inert release context")
        .assess()
        .expect("assess inert release context");

    let mut value = serde_json::to_value(&assessment).expect("serialize assessment");
    value["artifact_scanning_required"] = serde_json::json!(false);
    assert!(serde_json::from_value::<ReleaseContextAssessment>(value).is_err());

    let mut value = serde_json::to_value(&assessment).expect("serialize assessment");
    value["disposition"] = serde_json::json!("suspicious");
    assert!(serde_json::from_value::<ReleaseContextAssessment>(value).is_err());

    let mut value = serde_json::to_value(&assessment).expect("serialize assessment");
    value["observations"][0]["disposition"] = serde_json::json!("suspicious");
    assert!(serde_json::from_value::<ReleaseContextAssessment>(value).is_err());
}

#[test]
fn malformed_source_and_dependency_claims_fail_closed() {
    let mut input = complete_input();
    input.source_comparison.source_reference = Some(SourceReference {
        repository_url: "https://token@example.invalid/repository".to_string(),
        revision: "current-revision".to_string(),
        subdirectory: None,
    });
    assert!(ReleaseContext::new(input).is_err());

    let mut input = complete_input();
    input.dependency_closure.status = DependencyClosureStatus::Incomplete;
    assert!(ReleaseContext::new(input).is_err());

    let mut input = complete_input();
    let mut duplicate_coordinate = input.dependency_closure.artifacts[0].clone();
    duplicate_coordinate.artifact_sha256 = digest("different bytes at duplicate coordinate");
    input
        .dependency_closure
        .artifacts
        .push(duplicate_coordinate);
    assert!(ReleaseContext::new(input).is_err());

    let mut input = complete_input();
    input.source_comparison = SourceArtifactComparison {
        status: SourceArtifactComparisonStatus::VerifiedMatch,
        source_reference: Some(source_reference("current-revision")),
        source_snapshot_sha256: None,
        evidence_sha256: Some(digest("comparison evidence")),
    };
    assert!(ReleaseContext::new(input).is_err());
}
