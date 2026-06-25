use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactionResult {
    Clean,
    Redacted,
    FieldDropped,
    EventDropped,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub event_id: String,
    pub correlation_id: String,
    pub decision: String,
    pub redaction_result: RedactionResult,
    pub command: String,
    pub reason_codes: Vec<String>,
    pub launch_context_hash: Option<String>,
    pub source_scan_hash: Option<String>,
    pub proof_summaries: Vec<AuditProofSummary>,
    pub cleanup_summary: Option<AuditCleanupSummary>,
    pub replay_store_summary: Option<AuditReplayStoreSummary>,
    pub challenge_authority_summary: Option<AuditChallengeAuthoritySummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditProofSummary {
    pub kind: String,
    pub status: String,
    pub subject: String,
    pub provider_id: String,
    pub provider_version: String,
    pub platform: String,
    pub mechanism: String,
    pub trust: String,
    pub expires_at_unix_seconds: u64,
    pub context_hash: String,
    pub rule_generation_id: String,
    pub evidence_count: usize,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCleanupSummary {
    pub attempted: usize,
    pub removed_count: usize,
    pub refused_count: usize,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReplayStoreSummary {
    pub configured: bool,
    pub operation: String,
    pub available: bool,
    pub stale_lock_recovered: bool,
    pub challenge_id: String,
    pub replay_status: String,
    pub accepted: bool,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditChallengeAuthoritySummary {
    pub operation: String,
    pub authority: String,
    pub request_id: String,
    pub tenant_id: String,
    pub challenge_id: String,
    pub status: String,
    pub accepted: bool,
    pub trusted_time_source: String,
    pub client_time_accepted: bool,
    pub ttl_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub probe_destination_count: usize,
    pub nonce_present: bool,
    pub raw_nonce_returned: bool,
    pub raw_nonce_stored: bool,
    pub reason_codes: Vec<String>,
}

pub fn redact_token_like(input: &str) -> (String, RedactionResult) {
    let lowered = input.to_ascii_lowercase();
    if contains_sensitive_marker(&lowered)
        || contains_sensitive_split_value(input)
        || contains_url_credentials(input)
    {
        ("[REDACTED]".to_string(), RedactionResult::Redacted)
    } else {
        (input.to_string(), RedactionResult::Clean)
    }
}

fn contains_sensitive_marker(lowered: &str) -> bool {
    let markers = [
        "token=",
        "_authtoken=",
        "_auth=",
        "authorization:",
        "api_key=",
        "apikey=",
        "password=",
        "username=",
        "node_auth_token",
        "npm_token",
        "pip_index_url",
        "pip_extra_index_url",
        "http_proxy=",
        "https_proxy=",
        "all_proxy=",
        "proxy=",
        "client-cert",
        "certfile",
        "keyfile",
        "aws_secret_access_key",
        "google_application_credentials",
    ];
    markers.iter().any(|marker| lowered.contains(marker))
}

fn contains_sensitive_split_value(input: &str) -> bool {
    let tokens = input.split_whitespace().collect::<Vec<_>>();
    tokens
        .windows(2)
        .any(|window| sensitive_key_like(window[0]) && !window[1].starts_with('-'))
}

pub fn sensitive_key_like(value: &str) -> bool {
    let lowered = value
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase();
    if lowered.contains("_authtoken")
        || lowered.ends_with(":_auth")
        || lowered.contains(":_auth")
        || lowered == "_auth"
    {
        return true;
    }
    matches!(
        lowered.as_str(),
        "token"
            | "--token"
            | "password"
            | "--password"
            | "username"
            | "--username"
            | "authorization"
            | "--authorization"
            | "api_key"
            | "--api-key"
            | "node_auth_token"
            | "npm_token"
            | "pip_index_url"
            | "pip_extra_index_url"
            | "http_proxy"
            | "https_proxy"
            | "all_proxy"
            | "proxy"
            | "--proxy"
            | "client-cert"
            | "--client-cert"
            | "certfile"
            | "--cert"
            | "keyfile"
            | "aws_secret_access_key"
            | "google_application_credentials"
    )
}

fn contains_url_credentials(input: &str) -> bool {
    for scheme in ["https://", "http://"] {
        let mut remaining = input;
        while let Some(start) = remaining.find(scheme) {
            let after_scheme = &remaining[start + scheme.len()..];
            let authority = after_scheme
                .split(['/', '?', '#', ' ', '\t'])
                .next()
                .unwrap_or("");
            if authority.contains('@') {
                return true;
            }
            remaining = after_scheme;
        }
    }
    false
}

impl AuditRecord {
    pub fn new(
        event_id: impl Into<String>,
        correlation_id: impl Into<String>,
        command: impl Into<String>,
        decision: impl Into<String>,
        reason_codes: Vec<String>,
    ) -> Self {
        let (command, redaction_result) = redact_token_like(&command.into());
        Self {
            event_id: event_id.into(),
            correlation_id: correlation_id.into(),
            decision: decision.into(),
            redaction_result,
            command,
            reason_codes,
            launch_context_hash: None,
            source_scan_hash: None,
            proof_summaries: Vec::new(),
            cleanup_summary: None,
            replay_store_summary: None,
            challenge_authority_summary: None,
        }
    }

    pub fn with_launch_hashes(
        mut self,
        launch_context_hash: Option<impl Into<String>>,
        source_scan_hash: Option<impl Into<String>>,
    ) -> Self {
        self.launch_context_hash = launch_context_hash.map(Into::into);
        self.source_scan_hash = source_scan_hash.map(Into::into);
        self
    }

    pub fn with_proof_summary(mut self, summary: AuditProofSummary) -> Self {
        self.proof_summaries.push(summary);
        self
    }

    pub fn with_cleanup_summary(mut self, summary: AuditCleanupSummary) -> Self {
        self.cleanup_summary = Some(summary);
        self
    }

    pub fn with_replay_store_summary(mut self, summary: AuditReplayStoreSummary) -> Self {
        self.replay_store_summary = Some(summary);
        self
    }

    pub fn with_challenge_authority_summary(
        mut self,
        summary: AuditChallengeAuthoritySummary,
    ) -> Self {
        self.challenge_authority_summary = Some(summary);
        self
    }

    pub fn to_jsonl(&self) -> String {
        format!(
            "{{\"event_id\":\"{}\",\"correlation_id\":\"{}\",\"decision\":\"{}\",\"redaction_result\":\"{:?}\",\"command\":\"{}\",\"reason_codes\":[{}],\"launch_context_hash\":{},\"source_scan_hash\":{},\"proof_summaries\":[{}],\"cleanup_summary\":{},\"replay_store_summary\":{},\"challenge_authority_summary\":{}}}\n",
            escape_json(&self.event_id),
            escape_json(&self.correlation_id),
            escape_json(&self.decision),
            self.redaction_result,
            escape_json(&self.command),
            self.reason_codes
                .iter()
                .map(|code| format!("\"{}\"", escape_json(code)))
                .collect::<Vec<_>>()
                .join(","),
            optional_json_string(self.launch_context_hash.as_deref()),
            optional_json_string(self.source_scan_hash.as_deref()),
            self.proof_summaries
                .iter()
                .map(AuditProofSummary::to_json)
                .collect::<Vec<_>>()
                .join(","),
            self.cleanup_summary
                .as_ref()
                .map(AuditCleanupSummary::to_json)
                .unwrap_or_else(|| "null".to_string()),
            self.replay_store_summary
                .as_ref()
                .map(AuditReplayStoreSummary::to_json)
                .unwrap_or_else(|| "null".to_string()),
            self.challenge_authority_summary
                .as_ref()
                .map(AuditChallengeAuthoritySummary::to_json)
                .unwrap_or_else(|| "null".to_string())
        )
    }
}

impl AuditProofSummary {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"kind\":\"{}\",\"status\":\"{}\",\"subject\":\"{}\",\"provider_id\":\"{}\",\"provider_version\":\"{}\",\"platform\":\"{}\",\"mechanism\":\"{}\",\"trust\":\"{}\",\"expires_at_unix_seconds\":{},\"context_hash\":\"{}\",\"rule_generation_id\":\"{}\",\"evidence_count\":{},\"reason_code\":\"{}\"}}",
            escape_json(&self.kind),
            escape_json(&self.status),
            escape_json(&self.subject),
            escape_json(&self.provider_id),
            escape_json(&self.provider_version),
            escape_json(&self.platform),
            escape_json(&self.mechanism),
            escape_json(&self.trust),
            self.expires_at_unix_seconds,
            escape_json(&self.context_hash),
            escape_json(&self.rule_generation_id),
            self.evidence_count,
            escape_json(&self.reason_code)
        )
    }
}

impl AuditCleanupSummary {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"attempted\":{},\"removed_count\":{},\"refused_count\":{},\"reason_codes\":[{}]}}",
            self.attempted,
            self.removed_count,
            self.refused_count,
            self.reason_codes
                .iter()
                .map(|code| format!("\"{}\"", escape_json(code)))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

impl AuditReplayStoreSummary {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"configured\":{},\"operation\":\"{}\",\"available\":{},\"stale_lock_recovered\":{},\"challenge_id\":\"{}\",\"replay_status\":\"{}\",\"accepted\":{},\"reason_codes\":[{}]}}",
            self.configured,
            escape_json(&self.operation),
            self.available,
            self.stale_lock_recovered,
            escape_json(&self.challenge_id),
            escape_json(&self.replay_status),
            self.accepted,
            self.reason_codes
                .iter()
                .map(|code| format!("\"{}\"", escape_json(code)))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

impl AuditChallengeAuthoritySummary {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"operation\":\"{}\",\"authority\":\"{}\",\"request_id\":\"{}\",\"tenant_id\":\"{}\",\"challenge_id\":\"{}\",\"status\":\"{}\",\"accepted\":{},\"trusted_time_source\":\"{}\",\"client_time_accepted\":{},\"ttl_seconds\":{},\"expires_at_unix_seconds\":{},\"probe_destination_count\":{},\"nonce_present\":{},\"raw_nonce_returned\":{},\"raw_nonce_stored\":{},\"reason_codes\":[{}]}}",
            escape_json(&self.operation),
            escape_json(&self.authority),
            escape_json(&self.request_id),
            escape_json(&self.tenant_id),
            escape_json(&self.challenge_id),
            escape_json(&self.status),
            self.accepted,
            escape_json(&self.trusted_time_source),
            self.client_time_accepted,
            self.ttl_seconds,
            self.expires_at_unix_seconds,
            self.probe_destination_count,
            self.nonce_present,
            self.raw_nonce_returned,
            self.raw_nonce_stored,
            self.reason_codes
                .iter()
                .map(|code| format!("\"{}\"", escape_json(code)))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

pub fn append_jsonl(path: &Path, record: &AuditRecord) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(record.to_jsonl().as_bytes())?;
    file.flush()
}

fn escape_json(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn optional_json_string(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn redacts_token_like_values() {
        let (value, result) = redact_token_like("token=secret");
        assert_eq!(value, "[REDACTED]");
        assert_eq!(result, RedactionResult::Redacted);
    }

    #[test]
    fn redacts_npm_and_pip_sensitive_values() {
        for value in [
            "//registry.npmjs.org/:_authToken=secret",
            "PIP_INDEX_URL=https://user:pass@pypi.example/simple",
            "HTTPS_PROXY=https://user:pass@proxy.example",
            "AWS_SECRET_ACCESS_KEY=secret",
            "npm config set //registry.npmjs.org/:_authToken secret",
            "pip --password secret install pkg",
        ] {
            let (redacted, result) = redact_token_like(value);
            assert_eq!(redacted, "[REDACTED]");
            assert_eq!(result, RedactionResult::Redacted);
        }
    }

    #[test]
    fn leaves_clean_values() {
        let (value, result) = redact_token_like("package left-pad");
        assert_eq!(value, "package left-pad");
        assert_eq!(result, RedactionResult::Clean);
    }

    #[test]
    fn audit_jsonl_redacts_command() {
        let record = AuditRecord::new(
            "event-1",
            "corr-1",
            "npm install token=secret",
            "deny",
            vec!["secret_detected".to_string()],
        );
        let json = record.to_jsonl();
        assert!(json.contains("[REDACTED]"));
        assert!(!json.contains("token=secret"));
    }

    #[test]
    fn audit_jsonl_writer_appends() {
        let path =
            std::env::temp_dir().join(format!("whoathere-audit-test-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);
        let record = AuditRecord::new("event-1", "corr-1", "npm ci", "deny", vec![]);
        append_jsonl(&path, &record).expect("audit write should succeed");
        let content = fs::read_to_string(&path).expect("audit file should exist");
        assert!(content.contains("\"event_id\":\"event-1\""));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn audit_jsonl_includes_proof_and_cleanup_summaries_without_raw_evidence() {
        let record = AuditRecord::new(
            "event-2",
            "corr-2",
            "npm ci --//registry.npmjs.org/:_authToken=secret",
            "deny",
            vec!["egress_verified_proof_required".to_string()],
        )
        .with_launch_hashes(Some("fnv64:context"), Some("fnv64:source"))
        .with_proof_summary(AuditProofSummary {
            kind: "egress".to_string(),
            status: "OperatorAsserted".to_string(),
            subject: "unbound".to_string(),
            provider_id: "cli-operator-assertion".to_string(),
            provider_version: "operator".to_string(),
            platform: "macos".to_string(),
            mechanism: "OperatorAssertion".to_string(),
            trust: "OperatorAssertion".to_string(),
            expires_at_unix_seconds: 0,
            context_hash: "operator-asserted".to_string(),
            rule_generation_id: "operator-asserted".to_string(),
            evidence_count: 0,
            reason_code: "egress_operator_assertion_not_verified".to_string(),
        })
        .with_cleanup_summary(AuditCleanupSummary {
            attempted: 3,
            removed_count: 2,
            refused_count: 1,
            reason_codes: vec!["cleanup_path_outside_runtime_refused".to_string()],
        });
        let json = record.to_jsonl();
        assert!(json.contains("\"proof_summaries\""));
        assert!(json.contains("\"cleanup_summary\""));
        assert!(json.contains("\"replay_store_summary\":null"));
        assert!(json.contains("\"challenge_authority_summary\":null"));
        assert!(json.contains("\"launch_context_hash\":\"fnv64:context\""));
        assert!(json.contains("\"evidence_count\":0"));
        assert!(json.contains("[REDACTED]"));
        assert!(!json.contains("_authToken=secret"));
    }

    #[test]
    fn audit_jsonl_includes_replay_store_summary_without_raw_nonce_or_path() {
        let record = AuditRecord::new(
            "event-3",
            "challenge-sha256:abc",
            "whoathere evidence linux-active-probe-docker replay_store_configured=true",
            "deny",
            vec!["linux_active_probe_docker_execute_required".to_string()],
        )
        .with_replay_store_summary(AuditReplayStoreSummary {
            configured: true,
            operation: "consume".to_string(),
            available: true,
            stale_lock_recovered: true,
            challenge_id: "challenge-sha256:abc".to_string(),
            replay_status: "Accepted".to_string(),
            accepted: false,
            reason_codes: vec!["linux_active_probe_docker_execute_required".to_string()],
        });
        let json = record.to_jsonl();
        assert!(json.contains("\"replay_store_summary\""));
        assert!(json.contains("\"stale_lock_recovered\":true"));
        assert!(json.contains("\"replay_status\":\"Accepted\""));
        assert!(!json.contains("proof-nonce-"));
        assert!(!json.contains("replay-store.txt"));
    }

    #[test]
    fn audit_jsonl_includes_challenge_authority_summary_without_raw_nonce() {
        let record = AuditRecord::new(
            "event-4",
            "challenge-sha256:def",
            "vault challenge issue token=secret",
            "deny",
            vec!["provider_challenge_replayed".to_string()],
        )
        .with_challenge_authority_summary(AuditChallengeAuthoritySummary {
            operation: "consume".to_string(),
            authority: "vault_challenge_authority.v1".to_string(),
            request_id: "consume-1\"quoted".to_string(),
            tenant_id: "tenant-1".to_string(),
            challenge_id: "challenge-sha256:def".to_string(),
            status: "fail_closed".to_string(),
            accepted: false,
            trusted_time_source: "vault_server_clock".to_string(),
            client_time_accepted: false,
            ttl_seconds: 60,
            expires_at_unix_seconds: 1_800_000_060,
            probe_destination_count: 15,
            nonce_present: true,
            raw_nonce_returned: false,
            raw_nonce_stored: false,
            reason_codes: vec!["provider_challenge_replayed".to_string()],
        });
        let json = record.to_jsonl();
        assert!(json.contains("\"challenge_authority_summary\""));
        assert!(json.contains("\"operation\":\"consume\""));
        assert!(json.contains("\"request_id\":\"consume-1\\\"quoted\""));
        assert!(json.contains("\"raw_nonce_returned\":false"));
        assert!(json.contains("\"raw_nonce_stored\":false"));
        assert!(json.contains("[REDACTED]"));
        assert!(!json.contains("proof-nonce-"));
        assert!(!json.contains("replay-store.txt"));
    }
}
