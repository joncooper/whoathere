use whoathere_evidence::{EvidenceJobKind, EvidenceJobResult, JobState};
use whoathere_hash::sha256_digest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSeverity {
    Info,
    Suspicious,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticFinding {
    pub severity: FindingSeverity,
    pub reason_code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticScanReport {
    pub findings: Vec<StaticFinding>,
}

impl StaticScanReport {
    pub fn passed(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::High)
    }

    pub fn to_job_result(&self) -> EvidenceJobResult {
        self.to_job_result_for("detector-static-manifest-unbound")
    }

    pub fn to_job_result_for(&self, job_id: &str) -> EvidenceJobResult {
        let state = if self.passed() {
            JobState::Passed
        } else {
            JobState::Failed
        };
        let reason_codes = self
            .findings
            .iter()
            .map(|finding| finding.reason_code.clone())
            .collect::<Vec<_>>();
        EvidenceJobResult {
            job_id: job_id.to_string(),
            job_kind: EvidenceJobKind::StaticManifest,
            state,
            log_digest: static_scan_log_digest(StaticScanDigestInput {
                job_id,
                profile_id: "unbound",
                profile_version: 0,
                artifact_digest: "unbound",
                cache_object_key: "unbound",
                manifest_kind: "unknown",
                state,
                findings: &self.findings,
                reason_codes: &reason_codes,
            }),
            reason_codes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticManifestKind {
    NpmPackageJson,
    PyprojectToml,
}

impl StaticManifestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NpmPackageJson => "npm-package-json",
            Self::PyprojectToml => "pyproject.toml",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticManifestJobRequest<'a> {
    pub job_id: &'a str,
    pub profile_id: &'a str,
    pub profile_version: u16,
    pub artifact_digest: &'a str,
    pub cache_object_key: &'a str,
    pub manifest_kind: StaticManifestKind,
    pub manifest_contents: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticManifestJobOutput {
    pub job_id: String,
    pub job_kind: EvidenceJobKind,
    pub state: JobState,
    pub log_digest: String,
    pub summary_schema: String,
    pub sanitized_log_summary: String,
    pub reason_codes: Vec<String>,
    pub execution_enabled: bool,
    pub detonation_attempted: bool,
    pub network_attempted: bool,
    pub raw_log_captured: bool,
    pub audit_event_id: String,
}

pub fn run_static_manifest_job(request: StaticManifestJobRequest<'_>) -> StaticManifestJobOutput {
    let mut report = match request.manifest_kind {
        StaticManifestKind::NpmPackageJson => scan_npm_package_json(request.manifest_contents),
        StaticManifestKind::PyprojectToml => scan_pyproject_toml(request.manifest_contents),
    };
    if request.manifest_contents.trim().is_empty() {
        report.findings.push(StaticFinding {
            severity: FindingSeverity::High,
            reason_code: "static_manifest_empty".to_string(),
            detail: "static manifest job received empty manifest contents".to_string(),
        });
    }
    let mut reason_codes = report
        .findings
        .iter()
        .map(|finding| finding.reason_code.clone())
        .collect::<Vec<_>>();
    let metadata_valid = validate_static_job_request(&request, &mut reason_codes);
    let state = if report.passed() && metadata_valid {
        JobState::Passed
    } else {
        JobState::Failed
    };
    let summary_schema = STATIC_MANIFEST_SUMMARY_SCHEMA.to_string();
    let sanitized_log_summary = static_scan_log_summary(StaticScanDigestInput {
        job_id: request.job_id,
        profile_id: request.profile_id,
        profile_version: request.profile_version,
        artifact_digest: request.artifact_digest,
        cache_object_key: request.cache_object_key,
        manifest_kind: request.manifest_kind.as_str(),
        state,
        findings: &report.findings,
        reason_codes: &reason_codes,
    });
    let log_digest = sha256_digest(sanitized_log_summary.as_bytes());
    let audit_event_id = format!(
        "audit-static-manifest-{}",
        log_digest
            .strip_prefix("sha256:")
            .unwrap_or_default()
            .chars()
            .take(16)
            .collect::<String>()
    );
    StaticManifestJobOutput {
        job_id: request.job_id.to_string(),
        job_kind: EvidenceJobKind::StaticManifest,
        state,
        log_digest,
        summary_schema,
        sanitized_log_summary,
        reason_codes,
        execution_enabled: false,
        detonation_attempted: false,
        network_attempted: false,
        raw_log_captured: false,
        audit_event_id,
    }
}

pub fn scan_npm_package_json(contents: &str) -> StaticScanReport {
    let mut findings = Vec::new();
    match collect_json_key_paths(contents) {
        Ok(key_paths) => {
            for key_path in key_paths {
                if key_path.len() == 2
                    && key_path[0] == "scripts"
                    && NPM_INSTALL_LIFECYCLE_SCRIPTS.contains(&key_path[1].as_str())
                {
                    findings.push(StaticFinding {
                        severity: FindingSeverity::High,
                        reason_code: format!(
                            "npm_lifecycle_{}",
                            reason_fragment_for_script(&key_path[1])
                        ),
                        detail: format!("package.json declares {} lifecycle script", key_path[1]),
                    });
                }
            }
        }
        Err(_) => findings.push(StaticFinding {
            severity: FindingSeverity::High,
            reason_code: "npm_package_json_malformed".to_string(),
            detail: "package.json is not valid supported JSON".to_string(),
        }),
    }
    if contents.trim().is_empty() {
        findings.push(StaticFinding {
            severity: FindingSeverity::High,
            reason_code: "npm_package_json_empty".to_string(),
            detail: "package.json is empty".to_string(),
        });
    }
    if contains_exfil_hint(contents) {
        findings.push(StaticFinding {
            severity: FindingSeverity::High,
            reason_code: "npm_static_exfil_hint".to_string(),
            detail: "manifest or scripts contain network/credential access indicators".to_string(),
        });
    }
    StaticScanReport { findings }
}

pub fn scan_pyproject_toml(contents: &str) -> StaticScanReport {
    let mut findings = Vec::new();
    if !looks_like_supported_pyproject_toml(contents) {
        findings.push(StaticFinding {
            severity: FindingSeverity::High,
            reason_code: "pypi_pyproject_malformed".to_string(),
            detail: "pyproject.toml is not valid supported TOML shape".to_string(),
        });
    }
    if contents.contains("build-backend") {
        findings.push(StaticFinding {
            severity: FindingSeverity::Suspicious,
            reason_code: "pypi_pep517_build_backend".to_string(),
            detail: "pyproject.toml declares a PEP 517 build backend".to_string(),
        });
    }
    if contains_exfil_hint(contents) {
        findings.push(StaticFinding {
            severity: FindingSeverity::High,
            reason_code: "pypi_static_exfil_hint".to_string(),
            detail: "build metadata contains network/credential access indicators".to_string(),
        });
    }
    StaticScanReport { findings }
}

const NPM_INSTALL_LIFECYCLE_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
    "prepack",
    "postpack",
];
const STATIC_MANIFEST_SUMMARY_SCHEMA: &str = "whoathere.static_manifest_job.v1";

fn validate_static_job_request(
    request: &StaticManifestJobRequest<'_>,
    reason_codes: &mut Vec<String>,
) -> bool {
    let mut valid = true;
    if request.job_id.is_empty() {
        reason_codes.push("static_manifest_job_id_empty".to_string());
        valid = false;
    }
    if request.profile_id.is_empty() {
        reason_codes.push("static_manifest_profile_id_empty".to_string());
        valid = false;
    }
    if request.profile_version == 0 {
        reason_codes.push("static_manifest_profile_version_zero".to_string());
        valid = false;
    }
    for value in [
        request.job_id,
        request.profile_id,
        request.artifact_digest,
        request.cache_object_key,
    ] {
        if !summary_value_is_safe(value) {
            reason_codes.push("static_manifest_metadata_control_character".to_string());
            valid = false;
            break;
        }
    }
    if !valid_sha256_digest(request.artifact_digest) {
        reason_codes.push("static_manifest_artifact_digest_invalid".to_string());
        valid = false;
    }
    let expected_cache_key = request
        .artifact_digest
        .strip_prefix("sha256:")
        .map(|digest| format!("blobs/sha256/{digest}"));
    if expected_cache_key.as_deref() != Some(request.cache_object_key) {
        reason_codes.push("static_manifest_cache_object_key_mismatch".to_string());
        valid = false;
    }
    valid
}

fn collect_json_key_paths(contents: &str) -> Result<Vec<Vec<String>>, String> {
    let chars = contents.chars().collect::<Vec<_>>();
    let mut parser = JsonKeyPathParser {
        chars: &chars,
        index: 0,
        key_paths: Vec::new(),
    };
    parser.parse_value(&mut Vec::new())?;
    parser.skip_whitespace();
    if parser.index != chars.len() {
        return Err("trailing JSON characters".to_string());
    }
    Ok(parser.key_paths)
}

struct JsonKeyPathParser<'a> {
    chars: &'a [char],
    index: usize,
    key_paths: Vec<Vec<String>>,
}

impl JsonKeyPathParser<'_> {
    fn parse_value(&mut self, path: &mut Vec<String>) -> Result<(), String> {
        self.skip_whitespace();
        match self.peek() {
            Some('{') => self.parse_object(path),
            Some('[') => self.parse_array(path),
            Some('"') => self.parse_string().map(|_| ()),
            Some('t') => self.parse_literal("true"),
            Some('f') => self.parse_literal("false"),
            Some('n') => self.parse_literal("null"),
            Some('-' | '0'..='9') => self.parse_number(),
            _ => Err("unexpected JSON value".to_string()),
        }
    }

    fn parse_object(&mut self, path: &mut Vec<String>) -> Result<(), String> {
        self.expect('{')?;
        self.skip_whitespace();
        if self.consume('}') {
            return Ok(());
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            let mut key_path = path.clone();
            key_path.push(key.clone());
            self.key_paths.push(key_path);
            self.skip_whitespace();
            self.expect(':')?;
            path.push(key);
            self.parse_value(path)?;
            path.pop();
            self.skip_whitespace();
            if self.consume('}') {
                return Ok(());
            }
            self.expect(',')?;
        }
    }

    fn parse_array(&mut self, path: &mut Vec<String>) -> Result<(), String> {
        self.expect('[')?;
        self.skip_whitespace();
        if self.consume(']') {
            return Ok(());
        }
        loop {
            self.parse_value(path)?;
            self.skip_whitespace();
            if self.consume(']') {
                return Ok(());
            }
            self.expect(',')?;
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut out = String::new();
        while let Some(ch) = self.peek() {
            self.index += 1;
            match ch {
                '"' => return Ok(out),
                '\\' => {
                    let Some(escaped) = self.peek() else {
                        return Err("unterminated escape sequence".to_string());
                    };
                    self.index += 1;
                    match escaped {
                        '"' | '\\' | '/' => out.push(escaped),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => out.push(self.parse_unicode_escape()?),
                        _ => return Err("invalid escape sequence".to_string()),
                    }
                }
                character if character.is_control() => {
                    return Err("control character in JSON string".to_string());
                }
                _ => out.push(ch),
            }
        }
        Err("unterminated JSON string".to_string())
    }

    fn parse_unicode_escape(&mut self) -> Result<char, String> {
        if self.index + 4 > self.chars.len() {
            return Err("truncated unicode escape".to_string());
        }
        let hex = self.chars[self.index..self.index + 4]
            .iter()
            .collect::<String>();
        self.index += 4;
        let codepoint =
            u32::from_str_radix(&hex, 16).map_err(|_| "invalid unicode escape".to_string())?;
        char::from_u32(codepoint).ok_or_else(|| "invalid unicode codepoint".to_string())
    }

    fn parse_number(&mut self) -> Result<(), String> {
        if self.consume('-') && !self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
            return Err("invalid JSON number".to_string());
        }
        match self.peek() {
            Some('0') => self.index += 1,
            Some('1'..='9') => {
                self.index += 1;
                while self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                    self.index += 1;
                }
            }
            _ => return Err("invalid JSON number".to_string()),
        }
        if self.consume('.') {
            if !self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                return Err("invalid JSON number".to_string());
            }
            while self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                self.index += 1;
            }
        }
        if self.peek().is_some_and(|ch| matches!(ch, 'e' | 'E')) {
            self.index += 1;
            if self.peek().is_some_and(|ch| matches!(ch, '+' | '-')) {
                self.index += 1;
            }
            if !self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                return Err("invalid JSON number".to_string());
            }
            while self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                self.index += 1;
            }
        }
        Ok(())
    }

    fn parse_literal(&mut self, literal: &str) -> Result<(), String> {
        for expected in literal.chars() {
            self.expect(expected)?;
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(|ch| ch.is_whitespace()) {
            self.index += 1;
        }
    }

    fn consume(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: char) -> Result<(), String> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(format!("expected JSON character {expected}"))
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.index).copied()
    }
}

fn reason_fragment_for_script(script: &str) -> String {
    script
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
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

fn summary_value_is_safe(value: &str) -> bool {
    value
        .chars()
        .all(|character| !character.is_control() && character != '\n' && character != '\r')
}

fn safe_summary_value(value: &str) -> String {
    if summary_value_is_safe(value) {
        value.to_string()
    } else {
        "<invalid-summary-value>".to_string()
    }
}

fn looks_like_supported_pyproject_toml(contents: &str) -> bool {
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut in_multiline_array = false;
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if in_multiline_array {
            if !toml_line_has_balanced_quotes(line) {
                return false;
            }
            if line.ends_with(']') {
                in_multiline_array = false;
            }
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') || line.len() <= 2 || !toml_line_has_balanced_quotes(line) {
                return false;
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        if !key
            .trim()
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        {
            return false;
        }
        let value = value.trim();
        if value.is_empty() || !toml_line_has_balanced_quotes(value) {
            return false;
        }
        if value.starts_with('[') && !value.ends_with(']') {
            in_multiline_array = true;
        }
    }
    !in_multiline_array
}

fn toml_line_has_balanced_quotes(line: &str) -> bool {
    let mut escaped = false;
    let mut in_string = false;
    for character in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            _ => {}
        }
    }
    !in_string && !escaped
}

fn contains_exfil_hint(contents: &str) -> bool {
    let lowered = contents.to_ascii_lowercase();
    lowered.contains("process.env")
        || lowered.contains("authorization")
        || lowered.contains("token")
        || lowered.contains("api_key")
        || lowered.contains("curl ")
        || lowered.contains("fetch(")
        || lowered.contains("https://")
        || lowered.contains("http://")
}

struct StaticScanDigestInput<'a> {
    job_id: &'a str,
    profile_id: &'a str,
    profile_version: u16,
    artifact_digest: &'a str,
    cache_object_key: &'a str,
    manifest_kind: &'a str,
    state: JobState,
    findings: &'a [StaticFinding],
    reason_codes: &'a [String],
}

fn static_scan_log_digest(input: StaticScanDigestInput<'_>) -> String {
    sha256_digest(static_scan_log_summary(input).as_bytes())
}

fn static_scan_log_summary(input: StaticScanDigestInput<'_>) -> String {
    let high_count = input
        .findings
        .iter()
        .filter(|finding| finding.severity == FindingSeverity::High)
        .count();
    let suspicious_count = input
        .findings
        .iter()
        .filter(|finding| finding.severity == FindingSeverity::Suspicious)
        .count();
    format!(
        "{STATIC_MANIFEST_SUMMARY_SCHEMA}\njob_id={}\nprofile_id={}\nprofile_version={}\nartifact_digest={}\ncache_object_key={}\nmanifest_kind={}\njob_kind=StaticManifest\nstate={:?}\nfinding_count={}\nhigh_count={high_count}\nsuspicious_count={suspicious_count}\nreason_codes={}\nexecution_enabled=false\ndetonation_attempted=false\nnetwork_attempted=false\nraw_log_captured=false\n",
        safe_summary_value(input.job_id),
        safe_summary_value(input.profile_id),
        input.profile_version,
        safe_summary_value(input.artifact_digest),
        safe_summary_value(input.cache_object_key),
        input.manifest_kind,
        input.state,
        input.findings.len(),
        input.reason_codes.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_npm_postinstall() {
        let report = scan_npm_package_json(r#"{"scripts":{"postinstall":"node x.js"}}"#);
        assert!(!report.passed());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "npm_lifecycle_postinstall"));
    }

    #[test]
    fn detects_escaped_and_broader_npm_lifecycle_scripts() {
        let report = scan_npm_package_json(
            r#"{"scripts":{"\u0070ostinstall":"node x.js","preprepare":"node y.js","postprepare":"node z.js","prepublish":"node p.js"}}"#,
        );
        assert!(!report.passed());
        for reason in [
            "npm_lifecycle_postinstall",
            "npm_lifecycle_preprepare",
            "npm_lifecycle_postprepare",
            "npm_lifecycle_prepublish",
        ] {
            assert!(report
                .findings
                .iter()
                .any(|finding| finding.reason_code == reason));
        }
    }

    #[test]
    fn malformed_npm_manifest_fails_closed() {
        let report = scan_npm_package_json(r#"{"scripts":{"postinstall":"node x.js"}"#);
        assert!(!report.passed());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "npm_package_json_malformed"));
    }

    #[test]
    fn detects_pypi_pep517_backend_without_auto_failure() {
        let report = scan_pyproject_toml(
            r#"[build-system]
build-backend = "fixture_backend""#,
        );
        assert!(report.passed());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "pypi_pep517_build_backend"));
    }

    #[test]
    fn malformed_pyproject_fails_closed() {
        let report = scan_pyproject_toml("[build-system\nbuild-backend = \"unterminated");
        assert!(!report.passed());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "pypi_pyproject_malformed"));
    }

    #[test]
    fn scans_inert_npm_fixture_without_execution() {
        let package_json =
            include_str!("../../../tests/fixtures/npm/postinstall-exfil/package.json");
        let report = scan_npm_package_json(package_json);
        assert!(!report.passed());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "npm_lifecycle_postinstall"));
    }

    #[test]
    fn scans_inert_pypi_fixture_without_execution() {
        let pyproject = include_str!("../../../tests/fixtures/pypi/pep517-backend/pyproject.toml");
        let report = scan_pyproject_toml(pyproject);
        assert!(report.passed());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "pypi_pep517_build_backend"));
    }

    #[test]
    fn static_manifest_job_passes_clean_npm_metadata_without_execution() {
        let output = run_static_manifest_job(StaticManifestJobRequest {
            job_id: "static-job-1",
            profile_id: "npm.registry_tarball.v1",
            profile_version: 1,
            artifact_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            cache_object_key:
                "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111",
            manifest_kind: StaticManifestKind::NpmPackageJson,
            manifest_contents: r#"{"name":"clean","version":"1.0.0"}"#,
        });
        assert_eq!(output.state, JobState::Passed);
        assert!(output.reason_codes.is_empty());
        assert!(output.log_digest.starts_with("sha256:"));
        assert_eq!(output.log_digest.len(), 71);
        assert_eq!(output.summary_schema, STATIC_MANIFEST_SUMMARY_SCHEMA);
        assert!(output
            .sanitized_log_summary
            .starts_with("whoathere.static_manifest_job.v1\n"));
        assert!(output
            .sanitized_log_summary
            .contains("raw_log_captured=false"));
        assert!(!output.execution_enabled);
        assert!(!output.detonation_attempted);
        assert!(!output.network_attempted);
        assert!(!output.raw_log_captured);
        assert_eq!(
            output.log_digest,
            sha256_digest(output.sanitized_log_summary.as_bytes())
        );
        assert!(output.audit_event_id.starts_with("audit-static-manifest-"));
    }

    #[test]
    fn static_manifest_job_fails_postinstall_without_raw_log_capture() {
        let package_json =
            include_str!("../../../tests/fixtures/npm/postinstall-exfil/package.json");
        let output = run_static_manifest_job(StaticManifestJobRequest {
            job_id: "static-job-2",
            profile_id: "npm.registry_tarball.v1",
            profile_version: 1,
            artifact_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            cache_object_key:
                "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111",
            manifest_kind: StaticManifestKind::NpmPackageJson,
            manifest_contents: package_json,
        });
        assert_eq!(output.state, JobState::Failed);
        assert!(output
            .reason_codes
            .iter()
            .any(|reason| reason == "npm_lifecycle_postinstall"));
        assert!(!output.log_digest.contains("postinstall"));
        assert!(!output.sanitized_log_summary.contains("node postinstall.js"));
        assert!(!output.audit_event_id.contains("postinstall"));
        assert!(!output.execution_enabled);
    }

    #[test]
    fn static_manifest_job_keeps_pep517_suspicion_admission_bindable() {
        let pyproject = include_str!("../../../tests/fixtures/pypi/pep517-backend/pyproject.toml");
        let output = run_static_manifest_job(StaticManifestJobRequest {
            job_id: "static-job-3",
            profile_id: "pypi.sdist_pep517.v1",
            profile_version: 1,
            artifact_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            cache_object_key:
                "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111",
            manifest_kind: StaticManifestKind::PyprojectToml,
            manifest_contents: pyproject,
        });
        assert_eq!(output.state, JobState::Passed);
        assert!(output
            .reason_codes
            .iter()
            .any(|reason| reason == "pypi_pep517_build_backend"));
    }

    #[test]
    fn static_manifest_job_empty_manifest_fails_closed() {
        let output = run_static_manifest_job(StaticManifestJobRequest {
            job_id: "static-job-4",
            profile_id: "npm.registry_tarball.v1",
            profile_version: 1,
            artifact_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            cache_object_key:
                "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111",
            manifest_kind: StaticManifestKind::NpmPackageJson,
            manifest_contents: "",
        });
        assert_eq!(output.state, JobState::Failed);
        assert!(output
            .reason_codes
            .iter()
            .any(|reason| reason == "static_manifest_empty"));
    }

    #[test]
    fn static_manifest_job_invalid_identity_fails_closed() {
        let output = run_static_manifest_job(StaticManifestJobRequest {
            job_id: "static-job-5",
            profile_id: "",
            profile_version: 0,
            artifact_digest: "sha256:not-canonical",
            cache_object_key:
                "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111",
            manifest_kind: StaticManifestKind::NpmPackageJson,
            manifest_contents: r#"{"name":"clean","version":"1.0.0"}"#,
        });
        assert_eq!(output.state, JobState::Failed);
        for reason in [
            "static_manifest_profile_id_empty",
            "static_manifest_profile_version_zero",
            "static_manifest_artifact_digest_invalid",
            "static_manifest_cache_object_key_mismatch",
        ] {
            assert!(output
                .reason_codes
                .iter()
                .any(|candidate| candidate == reason));
        }
    }

    #[test]
    fn static_manifest_job_rejects_control_character_metadata_without_summary_injection() {
        let output = run_static_manifest_job(StaticManifestJobRequest {
            job_id: "static-job-6\nforged=true",
            profile_id: "npm.registry_tarball.v1",
            profile_version: 1,
            artifact_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            cache_object_key:
                "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111",
            manifest_kind: StaticManifestKind::NpmPackageJson,
            manifest_contents: r#"{"name":"clean","version":"1.0.0"}"#,
        });

        assert_eq!(output.state, JobState::Failed);
        assert!(output
            .reason_codes
            .iter()
            .any(|reason| reason == "static_manifest_metadata_control_character"));
        assert!(!output.sanitized_log_summary.contains("forged=true"));
        assert!(output
            .sanitized_log_summary
            .contains("job_id=<invalid-summary-value>"));
    }
}
