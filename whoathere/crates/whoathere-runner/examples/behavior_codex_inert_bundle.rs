//! Emits a small inert behavior bundle for the Codex observer smoke test.

use whoathere_artifact::Sha256Digest;
use whoathere_detector::{
    BehaviorAnalysisBundleInputV1, BehaviorAnalysisBundleV1, BehaviorEvidenceCoverageV1,
    BehaviorEvidenceEventV1, BehaviorEvidenceModalityV1, BehaviorEvidenceSignalV1, CanaryActionV1,
    CanaryClassV1, FileOperationV1, FileTargetClassV1, NetworkActionV1, NetworkDestinationClassV1,
    PackageTriggerV1, ProcessActionV1,
};

fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::from_bytes(label.as_bytes())
}

fn main() {
    let events = vec![
        BehaviorEvidenceEventV1::new(
            1,
            "process-1-exec-0",
            digest("verified-process-receipt"),
            BehaviorEvidenceSignalV1::Process {
                action: ProcessActionV1::PackageTrigger,
                trigger: Some(PackageTriggerV1::NpmLifecycle),
            },
            None,
        )
        .expect("inert process event"),
        BehaviorEvidenceEventV1::new(
            2,
            "file-2-sensitive-credential-read-0",
            digest("verified-file-receipt"),
            BehaviorEvidenceSignalV1::Filesystem {
                operation: FileOperationV1::Read,
                target: FileTargetClassV1::CredentialFile,
            },
            None,
        )
        .expect("inert credential event"),
        BehaviorEvidenceEventV1::new(
            3,
            "file-3-protected-canary-read-1",
            digest("verified-file-receipt"),
            BehaviorEvidenceSignalV1::Canary {
                action: CanaryActionV1::Read,
                canary: CanaryClassV1::NpmToken,
            },
            None,
        )
        .expect("inert canary event"),
        BehaviorEvidenceEventV1::new(
            4,
            "network-4-sendto-0",
            digest("verified-network-receipt"),
            BehaviorEvidenceSignalV1::Network {
                action: NetworkActionV1::Send,
                destination: NetworkDestinationClassV1::LocalSinkhole,
            },
            None,
        )
        .expect("inert network event"),
    ];
    let coverage = BehaviorEvidenceModalityV1::ALL
        .iter()
        .copied()
        .map(|modality| {
            BehaviorEvidenceCoverageV1::incomplete(
                modality,
                vec!["independent_host_composition_missing".to_string()],
            )
            .expect("honest incomplete coverage")
        })
        .collect();
    let bundle = BehaviorAnalysisBundleV1::new(
        BehaviorAnalysisBundleInputV1 {
            artifact_sha256: digest("inert-artifact"),
            manifest_sha256: digest("inert-manifest"),
            scenario_id: "inert.npm.postinstall.ci_false.v1".to_string(),
            scenario_sha256: digest("inert-scenario"),
            run_id: "inert-observer-run-1".to_string(),
            root_receipt_sha256: digest("verified-root-receipt"),
            host_receipt_sha256: digest("verified-host-receipt"),
        },
        coverage,
        events,
    )
    .expect("inert behavior bundle");
    println!(
        "{}",
        serde_json::to_string(&bundle).expect("bundle serializes")
    );
}
