use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use whoathere_admission::{AdmissionController, ServableGeneration};
use whoathere_audit::{append_jsonl, AuditChallengeAuthoritySummary, AuditRecord};
use whoathere_cache::InMemoryCacheStore;
use whoathere_detector::{run_static_manifest_job, StaticManifestJobRequest, StaticManifestKind};
use whoathere_evidence::{
    minimum_profiles, EvidenceBundle, EvidenceJobBinding, EvidenceJobResult, EvidenceProfile,
    JobState,
};
use whoathere_hash::{sha256_digest, sha256_hex};
use whoathere_job_log::{InMemoryJobLogStore, SanitizedJobLogEntry};
use whoathere_registry::{
    deny_unpromoted, render_npm_packument, render_pypi_simple_with_file_base,
};
use whoathere_vault_api::{
    bind_evidence_job_result, bind_fetch_job_result, cache_object_key_for_digest,
    plan_challenge_authority, plan_evidence_job, plan_fetch_job, AdmissionRequest, ArtifactRef,
    ChallengeAuthorityDecision, ChallengeAuthorityFileStore, ChallengeAuthorityRequest,
    ChallengeAuthorityScenario, ChallengeConsumeDecision, ChallengeConsumeRequest,
    ChallengeIssueDecision, ChallengeIssueRequest, EvidenceJobRequest, EvidenceJobResultRecord,
    EvidenceJobResultState, FetchJobRequest, FetchJobResult, InMemoryChallengeAuthority,
};

static JOB_LOG_STORE: OnceLock<Mutex<InMemoryJobLogStore>> = OnceLock::new();
static CHALLENGE_AUTHORITY: OnceLock<Mutex<InMemoryChallengeAuthority>> = OnceLock::new();

const LOCAL_DEV_CACHE_BYTES: &[u8] = b"inert cache fixture bytes";
const LOCAL_DEV_ARTIFACT_DIGEST: &str =
    "sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f";
const LOCAL_DEV_CACHE_OBJECT_KEY: &str =
    "blobs/sha256/b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f";
const LOCAL_DEV_COMPAT_SOURCE: &str = "local-dev-registry-compat";
const LOCAL_DEV_CHALLENGE_AUTHORITY_NOW: u64 = 1_800_000_000;
const LOCAL_DEV_CHALLENGE_AUTHORITY_TTL_SECONDS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChallengeAuthorityRouteStoreStatus {
    mode: &'static str,
    available: bool,
    stale_lock_recovered: bool,
    reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChallengeAuthorityRouteAuditStatus {
    configured: bool,
    status: &'static str,
    reason_codes: Vec<String>,
}

fn job_log_store() -> &'static Mutex<InMemoryJobLogStore> {
    JOB_LOG_STORE.get_or_init(|| Mutex::new(InMemoryJobLogStore::new()))
}

fn challenge_authority() -> &'static Mutex<InMemoryChallengeAuthority> {
    CHALLENGE_AUTHORITY.get_or_init(|| {
        Mutex::new(InMemoryChallengeAuthority::new(
            LOCAL_DEV_CHALLENGE_AUTHORITY_TTL_SECONDS,
        ))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status_code: u16,
    pub content_type: &'static str,
    pub headers: Vec<HttpHeader>,
    pub body: HttpBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    pub name: &'static str,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBody {
    bytes: Vec<u8>,
    declared_len: Option<usize>,
}

impl HttpBody {
    pub fn from_text(body: &str) -> Self {
        Self::from_bytes(body.as_bytes().to_vec())
    }

    pub fn from_bytes(body: Vec<u8>) -> Self {
        Self {
            bytes: body,
            declared_len: None,
        }
    }

    pub fn head_only(content_length: usize) -> Self {
        Self {
            bytes: Vec::new(),
            declared_len: Some(content_length),
        }
    }

    pub fn len(&self) -> usize {
        self.declared_len.unwrap_or(self.bytes.len())
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn contains(&self, pattern: &str) -> bool {
        String::from_utf8_lossy(&self.bytes).contains(pattern)
    }
}

impl std::fmt::Display for HttpBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&String::from_utf8_lossy(&self.bytes))
    }
}

impl HttpResponse {
    pub fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push(HttpHeader {
            name,
            value: value.into(),
        });
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindValidationError {
    NotSocketAddress,
    NotLoopback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevServerSummary {
    pub bind_addr: SocketAddr,
    pub served_requests: usize,
    pub max_requests: usize,
    pub idle_timeout_ms: u64,
    pub request_logs: Vec<SanitizedRequestLogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedRequestLogEntry {
    pub method: String,
    pub route_kind: &'static str,
    pub status_code: u16,
    pub range_state: &'static str,
    pub declared_response_body_bytes: usize,
    pub wire_response_body_bytes: usize,
    pub request_body_logged: bool,
    pub response_body_logged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevServerError {
    BindValidation(BindValidationError),
    MaxRequestsZero,
    BindFailed,
    LocalAddrFailed,
    SetNonblockingFailed,
    AcceptFailed,
    ReadFailed,
    WriteFailed,
}

impl DevServerError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::BindValidation(BindValidationError::NotSocketAddress) => {
                "dev_server_bind_not_socket_address"
            }
            Self::BindValidation(BindValidationError::NotLoopback) => {
                "dev_server_bind_not_loopback"
            }
            Self::MaxRequestsZero => "dev_server_max_requests_zero",
            Self::BindFailed => "dev_server_bind_failed",
            Self::LocalAddrFailed => "dev_server_local_addr_failed",
            Self::SetNonblockingFailed => "dev_server_set_nonblocking_failed",
            Self::AcceptFailed => "dev_server_accept_failed",
            Self::ReadFailed => "dev_server_read_failed",
            Self::WriteFailed => "dev_server_write_failed",
        }
    }
}

pub fn validate_loopback_bind(addr: &str) -> Result<SocketAddr, BindValidationError> {
    let parsed = addr
        .parse::<SocketAddr>()
        .map_err(|_| BindValidationError::NotSocketAddress)?;
    if parsed.ip().is_loopback() {
        Ok(parsed)
    } else {
        Err(BindValidationError::NotLoopback)
    }
}

pub fn serve_loopback_http(
    bind_addr: &str,
    max_requests: usize,
    idle_timeout: Duration,
) -> Result<DevServerSummary, DevServerError> {
    if max_requests == 0 {
        return Err(DevServerError::MaxRequestsZero);
    }
    let parsed = validate_loopback_bind(bind_addr).map_err(DevServerError::BindValidation)?;
    let listener = TcpListener::bind(parsed).map_err(|_| DevServerError::BindFailed)?;
    serve_loopback_listener(listener, max_requests, idle_timeout)
}

pub fn serve_loopback_listener(
    listener: TcpListener,
    max_requests: usize,
    idle_timeout: Duration,
) -> Result<DevServerSummary, DevServerError> {
    if max_requests == 0 {
        return Err(DevServerError::MaxRequestsZero);
    }
    let bind_addr = listener
        .local_addr()
        .map_err(|_| DevServerError::LocalAddrFailed)?;
    if !bind_addr.ip().is_loopback() {
        return Err(DevServerError::BindValidation(
            BindValidationError::NotLoopback,
        ));
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| DevServerError::SetNonblockingFailed)?;

    let idle_deadline = Instant::now() + idle_timeout;
    let mut served_requests = 0usize;
    let mut request_logs = Vec::new();
    while served_requests < max_requests {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .map_err(|_| DevServerError::ReadFailed)?;
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .map_err(|_| DevServerError::ReadFailed)?;
                let mut buffer = vec![0u8; 16 * 1024];
                let bytes_read = stream
                    .read(&mut buffer)
                    .map_err(|_| DevServerError::ReadFailed)?;
                let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
                let response = handle_http_request(&request);
                let log_entry = sanitized_request_log_entry(&request, &response);
                let response = to_http_wire_bytes(&response);
                stream
                    .write_all(&response)
                    .map_err(|_| DevServerError::WriteFailed)?;
                request_logs.push(log_entry);
                served_requests += 1;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= idle_deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return Err(DevServerError::AcceptFailed),
        }
    }

    Ok(DevServerSummary {
        bind_addr,
        served_requests,
        max_requests,
        idle_timeout_ms: idle_timeout.as_millis() as u64,
        request_logs,
    })
}

pub fn handle_http_request(request: &str) -> HttpResponse {
    let (method, target) = parse_request_line(request);
    match (method, target) {
        ("GET", "/healthz") => json_response(200, r#"{"status":"ok","mode":"local_dev"}"#),
        ("GET", "/readyz") => json_response(
            200,
            r#"{"status":"ready","dependencies":"in_memory_only","mode":"local_dev"}"#,
        ),
        ("GET", "/v1/evidence-profiles") => render_profiles_response(),
        ("POST", "/v1/admission-simulations") => render_admission_simulation(request),
        ("POST", "/v1/cache-simulations") => render_cache_simulation(request),
        ("POST", "/v1/fetch-job-simulations") => render_fetch_job_simulation(request),
        ("POST", "/v1/evidence-job-simulations") => render_evidence_job_simulation(request),
        ("POST", "/v1/challenge-authority-simulations") => {
            render_challenge_authority_simulation(request)
        }
        ("POST", "/v1/challenge-authority/issue") => render_challenge_authority_issue(request),
        ("POST", "/v1/challenge-authority/consume") => render_challenge_authority_consume(request),
        ("POST", "/v1/static-manifest-job-simulations") => {
            render_static_manifest_job_simulation(request)
        }
        ("GET", target) if target.starts_with("/v1/registry-compat/npm/tarballs/") => {
            render_npm_tarball_compat(target, request)
        }
        ("HEAD", target) if target.starts_with("/v1/registry-compat/npm/tarballs/") => {
            head_response(render_npm_tarball_compat(target, request))
        }
        ("GET", target) if target.starts_with("/v1/registry-compat/npm/") => {
            render_npm_registry_compat(target, request)
        }
        ("GET", target) if target.starts_with("/v1/registry-compat/pypi/files/") => {
            render_pypi_file_compat(target, request)
        }
        ("HEAD", target) if target.starts_with("/v1/registry-compat/pypi/files/") => {
            head_response(render_pypi_file_compat(target, request))
        }
        ("GET", target) if target.starts_with("/v1/registry-compat/pypi/simple/") => {
            render_pypi_simple_compat(target, request)
        }
        ("GET", target) if target.starts_with("/v1/registry-simulations/npm/tarballs/") => {
            render_npm_tarball_simulation(target, request)
        }
        ("HEAD", target) if target.starts_with("/v1/registry-simulations/npm/tarballs/") => {
            head_response(render_npm_tarball_simulation(target, request))
        }
        ("GET", target) if target.starts_with("/v1/registry-simulations/npm/") => {
            render_npm_registry_simulation(target)
        }
        ("GET", target) if target.starts_with("/v1/registry-simulations/pypi/files/") => {
            render_pypi_file_simulation(target, request)
        }
        ("HEAD", target) if target.starts_with("/v1/registry-simulations/pypi/files/") => {
            head_response(render_pypi_file_simulation(target, request))
        }
        ("GET", target) if target.starts_with("/v1/registry-simulations/pypi/") => {
            render_pypi_registry_simulation(target)
        }
        _ => json_response(404, r#"{"status":"error","reason_code":"route_not_found"}"#),
    }
}

pub fn to_http_wire(response: &HttpResponse) -> String {
    String::from_utf8_lossy(&to_http_wire_bytes(response)).to_string()
}

pub fn to_http_wire_bytes(response: &HttpResponse) -> Vec<u8> {
    let reason = match response.status_code {
        200 => "OK",
        206 => "Partial Content",
        304 => "Not Modified",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        416 => "Range Not Satisfiable",
        503 => "Service Unavailable",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let mut header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
        response.status_code,
        reason,
        response.content_type,
        response.body.len(),
    );
    for extra_header in &response.headers {
        header.push_str(extra_header.name);
        header.push_str(": ");
        header.push_str(&extra_header.value);
        header.push_str("\r\n");
    }
    header.push_str("Connection: close\r\n\r\n");
    let mut wire = header.into_bytes();
    wire.extend_from_slice(response.body.as_bytes());
    wire
}

fn head_response(mut response: HttpResponse) -> HttpResponse {
    let content_length = response.body.len();
    response.body = HttpBody::head_only(content_length);
    response
}

fn parse_request_line(request: &str) -> (&str, &str) {
    let mut parts = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    (method, target)
}

fn request_header_value<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    for line in request.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((candidate, value)) = line.split_once(':') {
            if candidate.trim().eq_ignore_ascii_case(name) {
                return Some(value.trim());
            }
        }
    }
    None
}

fn compat_base_url_for_request(request: &str) -> Result<String, &'static str> {
    let host = request_header_value(request, "Host").unwrap_or("127.0.0.1:4873");
    if valid_loopback_host_header(host) {
        Ok(format!("http://{host}"))
    } else {
        Err("registry_compat_host_not_loopback")
    }
}

fn valid_loopback_host_header(host: &str) -> bool {
    if host.is_empty()
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || host.bytes().any(|byte| matches!(byte, b'/' | b'\\' | b'@'))
    {
        return false;
    }
    if let Some(port) = host.strip_prefix("[::1]:") {
        return valid_port(port);
    }
    let Some((hostname, port)) = host.rsplit_once(':') else {
        return false;
    };
    matches!(hostname, "127.0.0.1" | "localhost") && valid_port(port)
}

fn valid_port(port: &str) -> bool {
    port.parse::<u16>().is_ok_and(|port| port > 0)
}

fn sanitized_request_log_entry(request: &str, response: &HttpResponse) -> SanitizedRequestLogEntry {
    let (method, target) = parse_request_line(request);
    SanitizedRequestLogEntry {
        method: method.to_string(),
        route_kind: route_kind_for_target(target),
        status_code: response.status_code,
        range_state: range_state_for_request(request, response),
        declared_response_body_bytes: response.body.len(),
        wire_response_body_bytes: response.body.as_bytes().len(),
        request_body_logged: false,
        response_body_logged: false,
    }
}

fn route_kind_for_target(target: &str) -> &'static str {
    let path = target
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(target);
    if path.starts_with("/v1/registry-simulations/npm/tarballs/")
        || path.starts_with("/v1/registry-compat/npm/tarballs/")
    {
        "registry_npm_tarball"
    } else if path.starts_with("/v1/registry-simulations/pypi/files/")
        || path.starts_with("/v1/registry-compat/pypi/files/")
    {
        "registry_pypi_file"
    } else if path.starts_with("/v1/registry-simulations/npm/")
        || path.starts_with("/v1/registry-compat/npm/")
    {
        "registry_npm_metadata"
    } else if path.starts_with("/v1/registry-simulations/pypi/")
        || path.starts_with("/v1/registry-compat/pypi/simple/")
    {
        "registry_pypi_metadata"
    } else if path == "/v1/challenge-authority-simulations" {
        "challenge_authority"
    } else if path == "/v1/challenge-authority/issue" {
        "challenge_authority_issue"
    } else if path == "/v1/challenge-authority/consume" {
        "challenge_authority_consume"
    } else if path == "/healthz" {
        "healthz"
    } else if path == "/readyz" {
        "readyz"
    } else {
        "other"
    }
}

fn range_state_for_request(request: &str, response: &HttpResponse) -> &'static str {
    if request_header_value(request, "Range").is_none() {
        "absent"
    } else if response.status_code == 206 {
        "served"
    } else if response.status_code == 416 {
        "rejected"
    } else {
        "ignored"
    }
}

fn render_profiles_response() -> HttpResponse {
    let rows = minimum_profiles()
        .into_iter()
        .map(|profile| {
            format!(
                "{{\"id\":\"{}\",\"version\":{},\"auto_allow_eligible\":{},\"never_auto_allow\":{},\"mandatory_jobs\":{}}}",
                profile.id,
                profile.version,
                profile.auto_allow_eligible,
                profile.never_auto_allow,
                profile
                    .requirements
                    .iter()
                    .filter(|requirement| requirement.mandatory)
                    .count()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    json_response(
        200,
        &format!("{{\"mode\":\"local_dev\",\"profiles\":[{rows}]}}"),
    )
}

fn render_admission_simulation(request: &str) -> HttpResponse {
    let complete = request.contains("complete=true");
    let fetch_missing = request.contains("fetch_missing=true");
    let fetch_mismatch = request.contains("fetch_mismatch=true");
    let evidence_profile_mismatch = request.contains("evidence_profile_mismatch=true");
    let evidence_duplicate = request.contains("evidence_duplicate=true");
    let evidence_subject_mismatch = request.contains("evidence_subject_mismatch=true");
    let mut controller = AdmissionController::new();
    let request = AdmissionRequest {
        request_id: "dev-sim-1".to_string(),
        tenant_id: "tenant-local-dev".to_string(),
        policy_version: "policy-local-dev".to_string(),
        artifact: ArtifactRef {
            ecosystem: "npm".to_string(),
            name: "fixture".to_string(),
            version: "1.0.0".to_string(),
            digest: "sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f"
                .to_string(),
            source: "local-dev-admission-simulation".to_string(),
        },
    };
    if let Err(error) = controller.request(request.clone()) {
        return json_response(
            409,
            &format!(
                "{{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"reason_code\":\"{}\",\"promoted\":false}}",
                error.reason_code
            ),
        );
    }
    if !fetch_missing {
        let mut store = InMemoryCacheStore::new();
        let receipt = match store.quarantine(
            request.artifact.clone(),
            b"inert cache fixture bytes".to_vec(),
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                return json_response(
                    409,
                    &format!(
                        "{{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"reason_code\":\"{}\",\"promoted\":false}}",
                        error.reason_code()
                    ),
                );
            }
        };
        let plan = plan_fetch_job(FetchJobRequest {
            job_id: "fetch-dev-sim-1".to_string(),
            tenant_id: request.tenant_id.clone(),
            admission_request_id: request.request_id.clone(),
            artifact: request.artifact.clone(),
            source_url: "https://registry.example/fixture.tgz".to_string(),
            expected_digest: request.artifact.digest.clone(),
            byte_limit: 10_485_760,
        });
        let verified_digest = if fetch_mismatch {
            "sha256:mismatch".to_string()
        } else {
            request.artifact.digest.clone()
        };
        let cache_object_key = if fetch_mismatch {
            "blobs/sha256/mismatch".to_string()
        } else {
            receipt.cache_object_key.clone()
        };
        let binding = bind_fetch_job_result(
            &plan,
            FetchJobResult {
                job_id: plan.job_id.clone(),
                tenant_id: plan.tenant_id.clone(),
                admission_request_id: plan.admission_request_id.clone(),
                artifact: plan.artifact.clone(),
                source_url: plan.source_url.clone(),
                expected_digest: plan.expected_digest.clone(),
                verified_digest,
                cache_object_key,
                byte_len: receipt.byte_len as u64,
                byte_limit: plan.byte_limit,
                quarantine_id: receipt.quarantine_id.clone(),
                fetch_enabled: plan.fetch_enabled,
                network_attempted: plan.network_attempted,
                stored_in_quarantine: true,
                audit_event_id: "audit-fetch-dev-sim-1".to_string(),
            },
        );
        if let Err(error) = controller.attach_fetch_result("dev-sim-1", binding.clone()) {
            let reason_codes = binding
                .reason_codes
                .iter()
                .map(|reason| format!("\"{reason}\""))
                .collect::<Vec<_>>()
                .join(",");
            return json_response(
                409,
                &format!(
                    "{{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"reason_code\":\"{}\",\"fetch_result_reasons\":[{}],\"promoted\":false}}",
                    error.reason_code, reason_codes
                ),
            );
        }
    }
    let profile = minimum_profiles()
        .into_iter()
        .find(|profile| profile.id == "npm.registry_tarball.v1")
        .expect("minimum evidence profile exists");
    let mut evidence = simulation_evidence_bundle(&profile, &request.artifact, complete);
    if evidence_duplicate {
        let duplicate = EvidenceJobResult {
            job_id: "evidence-dev-duplicate-job".to_string(),
            job_kind: profile.requirements[0].job_kind,
            state: JobState::Failed,
            log_digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            reason_codes: vec!["duplicate_conflict".to_string()],
        };
        evidence.job_bindings.push(EvidenceJobBinding {
            job_id: duplicate.job_id.clone(),
            job_kind: duplicate.job_kind,
            profile_id: evidence.profile_id.clone(),
            profile_version: evidence.profile_version,
            artifact_digest: evidence.artifact_digest.clone(),
            cache_object_key: evidence.cache_object_key.clone(),
            log_digest: duplicate.log_digest.clone(),
            admission_ready: true,
        });
        evidence.results.push(duplicate);
    }
    if evidence_profile_mismatch {
        evidence.profile_id = "pypi.wheel.v1".to_string();
        for binding in &mut evidence.job_bindings {
            binding.profile_id = evidence.profile_id.clone();
        }
    }
    if evidence_subject_mismatch {
        evidence.artifact_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        for binding in &mut evidence.job_bindings {
            binding.artifact_digest = evidence.artifact_digest.clone();
        }
    }
    match controller.decide("dev-sim-1", &profile, evidence) {
        Ok(verdict) => {
            let generation = controller.servable(&request.tenant_id, &request.artifact);
            let manifest = generation.map(|generation| generation.promotion_manifest());
            let cache_object_key = manifest
                .as_ref()
                .map(|manifest| manifest.cache_object_key.as_str())
                .unwrap_or_default();
            let generation_id = manifest
                .as_ref()
                .map(|manifest| manifest.generation_id)
                .unwrap_or_default();
            let audit_event_id = manifest
                .as_ref()
                .map(|manifest| manifest.audit_event_id.as_str())
                .unwrap_or_default();
            let fetch_job_id = manifest
                .as_ref()
                .map(|manifest| manifest.fetch_job_id.as_str())
                .unwrap_or_default();
            let fetch_quarantine_id = manifest
                .as_ref()
                .map(|manifest| manifest.fetch_quarantine_id.as_str())
                .unwrap_or_default();
            let fetch_byte_len = manifest
                .as_ref()
                .map(|manifest| manifest.fetch_byte_len)
                .unwrap_or_default();
            let fetch_byte_limit = manifest
                .as_ref()
                .map(|manifest| manifest.fetch_byte_limit)
                .unwrap_or_default();
            let fetch_audit_event_id = manifest
                .as_ref()
                .map(|manifest| manifest.fetch_audit_event_id.as_str())
                .unwrap_or_default();
            let manifest_json = manifest
                .as_ref()
                .map(|manifest| manifest.to_canonical_json())
                .unwrap_or_else(|| "null".to_string());
            json_response(
                200,
                &format!(
                    "{{\"status\":\"ok\",\"mode\":\"local_dev\",\"verdict\":\"{:?}\",\"promoted\":{},\"generation_id\":{},\"cache_object_key\":\"{}\",\"fetch_job_id\":\"{}\",\"fetch_quarantine_id\":\"{}\",\"fetch_byte_len\":{},\"fetch_byte_limit\":{},\"fetch_audit_event_id\":\"{}\",\"audit_event_id\":\"{}\",\"promotion_manifest\":{}}}",
                    verdict,
                    generation.is_some(),
                    generation_id,
                    cache_object_key,
                    fetch_job_id,
                    fetch_quarantine_id,
                    fetch_byte_len,
                    fetch_byte_limit,
                    fetch_audit_event_id,
                    audit_event_id,
                    manifest_json
                ),
            )
        }
        Err(error) => json_response(
            409,
            &format!(
                "{{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"reason_code\":\"{}\",\"promoted\":false}}",
                error.reason_code
            ),
        ),
    }
}

fn render_cache_simulation(request: &str) -> HttpResponse {
    let promote = request.contains("promote=true");
    let mut store = InMemoryCacheStore::new();
    let artifact = ArtifactRef {
        ecosystem: "npm".to_string(),
        name: "fixture".to_string(),
        version: "1.0.0".to_string(),
        digest: "sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f"
            .to_string(),
        source: "local-dev-cache-simulation".to_string(),
    };
    let receipt = match store.quarantine(artifact, b"inert cache fixture bytes".to_vec()) {
        Ok(receipt) => receipt,
        Err(error) => {
            return json_response(
                409,
                &format!(
                    "{{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"reason_code\":\"{}\",\"quarantined\":false,\"promoted\":false}}",
                    error.reason_code()
                ),
            );
        }
    };
    if !promote {
        return json_response(
            200,
            &format!(
                "{{\"status\":\"ok\",\"mode\":\"local_dev\",\"quarantined\":true,\"promoted\":false,\"quarantine_id\":\"{}\",\"cache_object_key\":\"{}\",\"byte_len\":{}}}",
                receipt.quarantine_id, receipt.cache_object_key, receipt.byte_len
            ),
        );
    }

    match store.promote(&receipt.quarantine_id) {
        Ok(promoted) => json_response(
            200,
            &format!(
                "{{\"status\":\"ok\",\"mode\":\"local_dev\",\"quarantined\":true,\"promoted\":true,\"cache_object_key\":\"{}\",\"byte_len\":{}}}",
                promoted.cache_object_key, promoted.byte_len
            ),
        ),
        Err(error) => json_response(
            409,
            &format!(
                "{{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"reason_code\":\"{}\",\"quarantined\":true,\"promoted\":false}}",
                error.reason_code()
            ),
        ),
    }
}

fn render_npm_registry_simulation(target: &str) -> HttpResponse {
    let promoted = target_contains_query_flag(target, "promoted=true");
    let generation = local_dev_servable_generation("npm", "fixture", "1.0.0");
    if !promoted {
        return plain_response(503, &deny_unpromoted(&generation.artifact));
    }
    HttpResponse {
        status_code: 200,
        content_type: "application/json",
        headers: Vec::new(),
        body: HttpBody::from_text(&render_npm_packument(
            &generation,
            "http://127.0.0.1:4873/v1/registry-simulations/npm/tarballs",
        )),
    }
}

fn render_npm_registry_compat(target: &str, request: &str) -> HttpResponse {
    let Some(name) = registry_package_target_component(target, "/v1/registry-compat/npm/") else {
        return plain_response(503, "status=503\nreason_code=artifact_not_promoted");
    };
    let Ok(base_url) = compat_base_url_for_request(request) else {
        return plain_response(
            503,
            "status=503\nreason_code=registry_compat_host_not_loopback",
        );
    };
    let generation = local_dev_compat_servable_generation("npm", name, "1.0.0");
    if generation.artifact.name != "fixture" {
        return plain_response(503, &deny_unpromoted(&generation.artifact));
    }
    HttpResponse {
        status_code: 200,
        content_type: "application/json",
        headers: Vec::new(),
        body: HttpBody::from_text(&render_npm_compat_packument(&generation, &base_url)),
    }
}

fn render_npm_tarball_simulation(target: &str, request: &str) -> HttpResponse {
    let Some((name, version)) =
        registry_file_target_components(target, "/v1/registry-simulations/npm/tarballs/", false)
    else {
        return plain_response(503, "status=503\nreason_code=artifact_not_promoted");
    };
    let mut generation = local_dev_servable_generation("npm", name, version);
    if generation.artifact.name != "fixture" || generation.artifact.version != "1.0.0" {
        return plain_response(503, &deny_unpromoted(&generation.artifact));
    }
    if target_contains_query_flag(target, "cache_key_mismatch=true") {
        generation.cache_object_key =
            "blobs/sha256/0000000000000000000000000000000000000000000000000000000000000000"
                .to_string();
    }
    render_promoted_bytes(&generation, request)
}

fn render_npm_tarball_compat(target: &str, request: &str) -> HttpResponse {
    let Some((name, version)) = registry_file_target_components_allow_filename(
        target,
        "/v1/registry-compat/npm/tarballs/",
        false,
        Some("fixture-1.0.0.tgz"),
    ) else {
        return plain_response(503, "status=503\nreason_code=artifact_not_promoted");
    };
    let generation = local_dev_compat_servable_generation("npm", name, version);
    if generation.artifact.name != "fixture" || generation.artifact.version != "1.0.0" {
        return plain_response(503, &deny_unpromoted(&generation.artifact));
    }
    render_promoted_bytes(&generation, request)
}

fn render_pypi_registry_simulation(target: &str) -> HttpResponse {
    let promoted = target_contains_query_flag(target, "promoted=true");
    let generation = local_dev_servable_generation("pypi", "fixture", "1.0.0");
    if !promoted {
        return plain_response(503, &deny_unpromoted(&generation.artifact));
    }
    HttpResponse {
        status_code: 200,
        content_type: "text/html",
        headers: Vec::new(),
        body: HttpBody::from_text(&render_pypi_simple_with_file_base(
            &[generation],
            "http://127.0.0.1:4873/v1/registry-simulations/pypi/files",
        )),
    }
}

fn render_pypi_simple_compat(target: &str, request: &str) -> HttpResponse {
    let Some(name) = registry_package_target_component(target, "/v1/registry-compat/pypi/simple/")
    else {
        return plain_response(503, "status=503\nreason_code=artifact_not_promoted");
    };
    let Ok(base_url) = compat_base_url_for_request(request) else {
        return plain_response(
            503,
            "status=503\nreason_code=registry_compat_host_not_loopback",
        );
    };
    let generation = local_dev_compat_servable_generation("pypi", name, "1.0.0");
    if generation.artifact.name != "fixture" {
        return plain_response(503, &deny_unpromoted(&generation.artifact));
    }
    HttpResponse {
        status_code: 200,
        content_type: "text/html",
        headers: Vec::new(),
        body: HttpBody::from_text(&render_pypi_compat_simple(&generation, &base_url)),
    }
}

fn render_pypi_file_simulation(target: &str, request: &str) -> HttpResponse {
    let Some((name, version)) =
        registry_file_target_components(target, "/v1/registry-simulations/pypi/files/", true)
    else {
        return plain_response(503, "status=503\nreason_code=artifact_not_promoted");
    };
    let mut generation = local_dev_servable_generation("pypi", name, version);
    if generation.artifact.name != "fixture" || generation.artifact.version != "1.0.0" {
        return plain_response(503, &deny_unpromoted(&generation.artifact));
    }
    if target_contains_query_flag(target, "cache_key_mismatch=true") {
        generation.cache_object_key =
            "blobs/sha256/0000000000000000000000000000000000000000000000000000000000000000"
                .to_string();
    }
    render_promoted_bytes(&generation, request)
}

fn render_pypi_file_compat(target: &str, request: &str) -> HttpResponse {
    let Some((name, version)) = registry_file_target_components_allow_filename(
        target,
        "/v1/registry-compat/pypi/files/",
        true,
        Some("fixture-1.0.0-py3-none-any.whl"),
    ) else {
        return plain_response(503, "status=503\nreason_code=artifact_not_promoted");
    };
    let generation = local_dev_compat_servable_generation("pypi", name, version);
    if generation.artifact.name != "fixture" || generation.artifact.version != "1.0.0" {
        return plain_response(503, &deny_unpromoted(&generation.artifact));
    }
    render_promoted_bytes(&generation, request)
}

fn render_npm_compat_packument(generation: &ServableGeneration, base_url: &str) -> String {
    let artifact = &generation.artifact;
    let tarball_url = format!(
        "{}/v1/registry-compat/npm/tarballs/{}/{}/{}",
        base_url.trim_end_matches('/'),
        percent_encode_component(&artifact.name),
        percent_encode_component(&artifact.version),
        percent_encode_component("fixture-1.0.0.tgz")
    );
    let bytes = local_dev_compat_package_bytes("npm");
    let integrity = sha256_sri_for_bytes(&bytes);
    format!(
        "{{\"_id\":\"{}\",\"name\":\"{}\",\"dist-tags\":{{\"latest\":\"{}\"}},\"versions\":{{\"{}\":{{\"name\":\"{}\",\"version\":\"{}\",\"scripts\":{{}},\"dist\":{{\"tarball\":\"{}\",\"integrity\":\"{}\"}}}}}}}}",
        escape_json(&artifact.name),
        escape_json(&artifact.name),
        escape_json(&artifact.version),
        escape_json(&artifact.version),
        escape_json(&artifact.name),
        escape_json(&artifact.version),
        escape_json(&tarball_url),
        escape_json(&integrity)
    )
}

fn render_pypi_compat_simple(generation: &ServableGeneration, base_url: &str) -> String {
    let artifact = &generation.artifact;
    let digest_hex = artifact
        .digest
        .strip_prefix("sha256:")
        .unwrap_or(&artifact.digest);
    let href = format!(
        "{}/v1/registry-compat/pypi/files/{}/{}/{}/{}#sha256={}",
        base_url.trim_end_matches('/'),
        percent_encode_component(&artifact.ecosystem),
        percent_encode_component(&artifact.name),
        percent_encode_component(&artifact.version),
        percent_encode_component("fixture-1.0.0-py3-none-any.whl"),
        percent_encode_component(digest_hex)
    );
    format!(
        "<!doctype html><html><body>\n<a href=\"{}\">fixture-1.0.0-py3-none-any.whl</a>\n</body></html>",
        href
    )
}

fn render_promoted_bytes(generation: &ServableGeneration, request: &str) -> HttpResponse {
    match local_dev_promoted_cache_bytes(generation) {
        Ok(bytes) => match request_header_value(request, "Range") {
            _ if request_header_value(request, "If-None-Match")
                .is_some_and(|header| if_none_match_matches(header, &etag_for_generation(generation))) =>
            {
                not_modified_response(generation)
            }
            Some(range_header) => render_promoted_byte_range(generation, bytes, range_header),
            None => promoted_byte_response(generation, 200, bytes, None),
        },
        Err(error) => json_response(
            409,
            &format!(
                "{{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"reason_code\":\"{}\",\"served\":false}}",
                error.reason_code()
            ),
        ),
    }
}

fn render_promoted_byte_range(
    generation: &ServableGeneration,
    bytes: Vec<u8>,
    range_header: &str,
) -> HttpResponse {
    let total_len = bytes.len();
    match parse_single_byte_range(range_header, total_len) {
        Ok(range) => {
            let body = bytes[range.start..=range.end].to_vec();
            promoted_byte_response(generation, 206, body, Some(range))
        }
        Err(reason_code) => json_response(
            416,
            &format!(
                "{{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"reason_code\":\"{}\",\"served\":false}}",
                reason_code
            ),
        )
        .with_header("Accept-Ranges", "bytes")
        .with_header("Content-Range", format!("bytes */{total_len}")),
    }
}

fn promoted_byte_response(
    generation: &ServableGeneration,
    status_code: u16,
    bytes: Vec<u8>,
    range: Option<ByteRange>,
) -> HttpResponse {
    let mut response = HttpResponse {
        status_code,
        content_type: "application/octet-stream",
        headers: Vec::new(),
        body: HttpBody::from_bytes(bytes),
    }
    .with_header("Accept-Ranges", "bytes")
    .with_header("Cache-Control", "private, max-age=31536000, immutable")
    .with_header("ETag", etag_for_generation(generation))
    .with_header("X-Content-Type-Options", "nosniff");
    if let Some(range) = range {
        response = response.with_header(
            "Content-Range",
            format!("bytes {}-{}/{}", range.start, range.end, range.total_len),
        );
    }
    response
}

fn not_modified_response(generation: &ServableGeneration) -> HttpResponse {
    HttpResponse {
        status_code: 304,
        content_type: "application/octet-stream",
        headers: Vec::new(),
        body: HttpBody::from_bytes(Vec::new()),
    }
    .with_header("Accept-Ranges", "bytes")
    .with_header("Cache-Control", "private, max-age=31536000, immutable")
    .with_header("ETag", etag_for_generation(generation))
    .with_header("X-Content-Type-Options", "nosniff")
}

fn etag_for_generation(generation: &ServableGeneration) -> String {
    format!("\"{}\"", generation.artifact.digest)
}

fn if_none_match_matches(header: &str, etag: &str) -> bool {
    let weak_etag = format!("W/{etag}");
    header.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || candidate == etag || candidate == weak_etag
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ByteRange {
    start: usize,
    end: usize,
    total_len: usize,
}

fn parse_single_byte_range(value: &str, total_len: usize) -> Result<ByteRange, &'static str> {
    if total_len == 0 {
        return Err("range_empty_object");
    }
    let Some(spec) = value.trim().strip_prefix("bytes=") else {
        return Err("range_unit_unsupported");
    };
    if spec.contains(',') {
        return Err("range_multiple_unsupported");
    }
    let Some((start, end)) = spec.split_once('-') else {
        return Err("range_malformed");
    };
    if start.is_empty() {
        let suffix_len = parse_range_number(end)?;
        if suffix_len == 0 {
            return Err("range_malformed");
        }
        let start = total_len.saturating_sub(suffix_len);
        return Ok(ByteRange {
            start,
            end: total_len - 1,
            total_len,
        });
    }
    let start = parse_range_number(start)?;
    let end = if end.is_empty() {
        total_len - 1
    } else {
        parse_range_number(end)?.min(total_len - 1)
    };
    if start >= total_len || start > end {
        return Err("range_not_satisfiable");
    }
    Ok(ByteRange {
        start,
        end,
        total_len,
    })
}

fn parse_range_number(value: &str) -> Result<usize, &'static str> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("range_malformed");
    }
    value.parse().map_err(|_| "range_malformed")
}

fn local_dev_promoted_cache_bytes(
    generation: &ServableGeneration,
) -> Result<Vec<u8>, whoathere_cache::CacheStoreError> {
    let mut store = InMemoryCacheStore::new();
    let receipt = store.quarantine(
        generation.artifact.clone(),
        local_dev_bytes_for_generation(generation),
    )?;
    store.promote(&receipt.quarantine_id)?;
    store
        .promoted_bytes_for_artifact(&generation.artifact, &generation.cache_object_key)
        .map(|bytes| bytes.to_vec())
}

fn local_dev_bytes_for_generation(generation: &ServableGeneration) -> Vec<u8> {
    if generation.artifact.source == LOCAL_DEV_COMPAT_SOURCE {
        return local_dev_compat_package_bytes(&generation.artifact.ecosystem);
    }
    LOCAL_DEV_CACHE_BYTES.to_vec()
}

fn local_dev_compat_package_bytes(ecosystem: &str) -> Vec<u8> {
    match ecosystem {
        "npm" => build_npm_fixture_tgz(),
        "pypi" => build_pypi_fixture_wheel(),
        _ => LOCAL_DEV_CACHE_BYTES.to_vec(),
    }
}

fn registry_file_target_components(
    target: &str,
    prefix: &str,
    includes_ecosystem: bool,
) -> Option<(String, String)> {
    let path = target
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(target);
    let suffix = path.strip_prefix(prefix)?;
    let mut parts = suffix.split('/');
    if includes_ecosystem {
        let ecosystem = percent_decode_component(parts.next()?)?;
        if ecosystem != "pypi" {
            return None;
        }
    }
    let name = percent_decode_component(parts.next()?)?;
    let version = percent_decode_component(parts.next()?)?;
    parts.next().is_none().then_some((name, version))
}

fn registry_file_target_components_allow_filename(
    target: &str,
    prefix: &str,
    includes_ecosystem: bool,
    expected_filename: Option<&str>,
) -> Option<(String, String)> {
    let path = target
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(target);
    let suffix = path.strip_prefix(prefix)?;
    let mut parts = suffix.split('/');
    if includes_ecosystem {
        let ecosystem = percent_decode_component(parts.next()?)?;
        if ecosystem != "pypi" {
            return None;
        }
    }
    let name = percent_decode_component(parts.next()?)?;
    let version = percent_decode_component(parts.next()?)?;
    match parts.next() {
        None => Some((name, version)),
        Some(filename) if Some(filename) == expected_filename && parts.next().is_none() => {
            Some((name, version))
        }
        _ => None,
    }
}

fn registry_package_target_component(target: &str, prefix: &str) -> Option<String> {
    let path = target
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(target)
        .trim_end_matches('/');
    let suffix = path.strip_prefix(prefix.trim_end_matches('/'))?;
    let suffix = suffix.strip_prefix('/').unwrap_or(suffix);
    if suffix.is_empty() || suffix.contains('/') {
        return None;
    }
    percent_decode_component(suffix)
}

fn percent_decode_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn percent_encode_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(*byte as char);
            }
            byte => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn escape_json(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
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
    escaped
}

fn sha256_sri_for_bytes(bytes: &[u8]) -> String {
    let digest = sha256_hex(bytes);
    format!("sha256-{}", base64_encode(&hex_to_bytes(&digest)))
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_value(pair[0]).expect("sha256 digest hex");
            let low = hex_value(pair[1]).expect("sha256 digest hex");
            (high << 4) | low
        })
        .collect()
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    let mut index = 0;
    while index < bytes.len() {
        let first = bytes[index];
        let second = bytes.get(index + 1).copied();
        let third = bytes.get(index + 2).copied();

        encoded.push(TABLE[(first >> 2) as usize] as char);
        encoded.push(
            TABLE[(((first & 0b0000_0011) << 4) | (second.unwrap_or(0) >> 4)) as usize] as char,
        );
        match (second, third) {
            (Some(second), Some(third)) => {
                encoded
                    .push(TABLE[(((second & 0b0000_1111) << 2) | (third >> 6)) as usize] as char);
                encoded.push(TABLE[(third & 0b0011_1111) as usize] as char);
            }
            (Some(second), None) => {
                encoded.push(TABLE[((second & 0b0000_1111) << 2) as usize] as char);
                encoded.push('=');
            }
            (None, _) => {
                encoded.push('=');
                encoded.push('=');
            }
        }
        index += 3;
    }
    encoded
}

fn target_contains_query_flag(target: &str, flag: &str) -> bool {
    target
        .split_once('?')
        .map(|(_, query)| query.split('&').any(|pair| pair == flag))
        .unwrap_or(false)
}

fn local_dev_servable_generation(
    ecosystem: impl Into<String>,
    name: impl Into<String>,
    version: impl Into<String>,
) -> ServableGeneration {
    let ecosystem = ecosystem.into();
    let evidence_profile_id = if ecosystem == "npm" {
        "npm.registry_tarball.v1"
    } else {
        "pypi.sdist_pep517.v1"
    };
    ServableGeneration {
        generation_id: 1,
        tenant_id: "tenant-local-dev".to_string(),
        request_id: "dev-sim-1".to_string(),
        cache_object_key: LOCAL_DEV_CACHE_OBJECT_KEY.to_string(),
        fetch_job_id: "fetch-dev-sim-1".to_string(),
        fetch_quarantine_id: "quarantine-1".to_string(),
        fetch_byte_len: LOCAL_DEV_CACHE_BYTES.len() as u64,
        fetch_byte_limit: 10_485_760,
        fetch_audit_event_id: "audit-fetch-dev-sim-1".to_string(),
        evidence_profile_id: evidence_profile_id.to_string(),
        policy_version: "policy-local-dev".to_string(),
        audit_event_id: "audit-dev-sim-1".to_string(),
        artifact: ArtifactRef {
            ecosystem,
            name: name.into(),
            version: version.into(),
            digest: LOCAL_DEV_ARTIFACT_DIGEST.to_string(),
            source: "local-dev-registry-simulation".to_string(),
        },
    }
}

fn local_dev_compat_servable_generation(
    ecosystem: impl Into<String>,
    name: impl Into<String>,
    version: impl Into<String>,
) -> ServableGeneration {
    let ecosystem = ecosystem.into();
    let bytes = local_dev_compat_package_bytes(&ecosystem);
    let digest = sha256_digest(&bytes);
    let cache_object_key =
        cache_object_key_for_digest(&digest).expect("local-dev compat digest is canonical");
    let evidence_profile_id = if ecosystem == "npm" {
        "npm.registry_tarball.v1"
    } else {
        "pypi.wheel.v1"
    };
    ServableGeneration {
        generation_id: 1,
        tenant_id: "tenant-local-dev".to_string(),
        request_id: "dev-sim-1".to_string(),
        cache_object_key,
        fetch_job_id: "fetch-dev-sim-1".to_string(),
        fetch_quarantine_id: "quarantine-1".to_string(),
        fetch_byte_len: bytes.len() as u64,
        fetch_byte_limit: 10_485_760,
        fetch_audit_event_id: "audit-fetch-dev-sim-1".to_string(),
        evidence_profile_id: evidence_profile_id.to_string(),
        policy_version: "policy-local-dev".to_string(),
        audit_event_id: "audit-dev-sim-1".to_string(),
        artifact: ArtifactRef {
            ecosystem,
            name: name.into(),
            version: version.into(),
            digest,
            source: LOCAL_DEV_COMPAT_SOURCE.to_string(),
        },
    }
}

fn build_npm_fixture_tgz() -> Vec<u8> {
    let package_json = br#"{"name":"fixture","version":"1.0.0","description":"WhoaThere local-dev safe fixture","main":"index.js","license":"UNLICENSED","scripts":{}}"#;
    let index_js = br#"module.exports = { source: "whoathere-local-dev-fixture" };
"#;
    let tar = build_tar_archive(&[
        ("package/package.json", package_json.as_slice()),
        ("package/index.js", index_js.as_slice()),
    ]);
    gzip_store(&tar)
}

fn build_tar_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut archive = Vec::new();
    for (name, contents) in entries {
        append_tar_file(&mut archive, name, contents);
    }
    archive.extend_from_slice(&[0; 1024]);
    archive
}

fn append_tar_file(archive: &mut Vec<u8>, name: &str, contents: &[u8]) {
    let mut header = [0u8; 512];
    write_bytes(&mut header[0..100], name.as_bytes());
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], contents.len() as u64);
    write_octal(&mut header[136..148], 0);
    for byte in &mut header[148..156] {
        *byte = b' ';
    }
    header[156] = b'0';
    write_bytes(&mut header[257..263], b"ustar\0");
    write_bytes(&mut header[263..265], b"00");
    let checksum = header.iter().map(|byte| *byte as u32).sum::<u32>();
    write_tar_checksum(&mut header[148..156], checksum);

    archive.extend_from_slice(&header);
    archive.extend_from_slice(contents);
    let padding = (512 - (contents.len() % 512)) % 512;
    archive.extend(std::iter::repeat_n(0, padding));
}

fn write_bytes(field: &mut [u8], bytes: &[u8]) {
    let len = bytes.len().min(field.len());
    field[..len].copy_from_slice(&bytes[..len]);
}

fn write_octal(field: &mut [u8], value: u64) {
    let digits = format!("{:0width$o}", value, width = field.len() - 1);
    let start = digits.len().saturating_sub(field.len() - 1);
    write_bytes(field, &digits.as_bytes()[start..]);
}

fn write_tar_checksum(field: &mut [u8], checksum: u32) {
    let checksum = format!("{checksum:06o}\0 ");
    field.copy_from_slice(checksum.as_bytes());
}

fn gzip_store(payload: &[u8]) -> Vec<u8> {
    let mut gzip = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
    for (index, chunk) in payload.chunks(65_535).enumerate() {
        let final_block = index == payload.len().saturating_sub(1) / 65_535;
        gzip.push(if final_block { 0x01 } else { 0x00 });
        let len = chunk.len() as u16;
        gzip.extend_from_slice(&len.to_le_bytes());
        gzip.extend_from_slice(&(!len).to_le_bytes());
        gzip.extend_from_slice(chunk);
    }
    gzip.extend_from_slice(&crc32(payload).to_le_bytes());
    gzip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    gzip
}

fn build_pypi_fixture_wheel() -> Vec<u8> {
    let init = br#"VALUE = "whoathere-local-dev-fixture"
"#;
    let metadata = br#"Metadata-Version: 2.1
Name: fixture
Version: 1.0.0
Summary: WhoaThere local-dev safe fixture
"#;
    let wheel = br#"Wheel-Version: 1.0
Generator: whoathere-local-dev
Root-Is-Purelib: true
Tag: py3-none-any
"#;
    let record = br#"fixture/__init__.py,,
fixture-1.0.0.dist-info/METADATA,,
fixture-1.0.0.dist-info/WHEEL,,
fixture-1.0.0.dist-info/RECORD,,
"#;
    build_zip_archive(&[
        ("fixture/__init__.py", init.as_slice()),
        ("fixture-1.0.0.dist-info/METADATA", metadata.as_slice()),
        ("fixture-1.0.0.dist-info/WHEEL", wheel.as_slice()),
        ("fixture-1.0.0.dist-info/RECORD", record.as_slice()),
    ])
}

struct ZipCentralEntry {
    name: String,
    crc32: u32,
    byte_len: u32,
    local_header_offset: u32,
}

fn build_zip_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut archive = Vec::new();
    let mut central_entries = Vec::new();
    for (name, contents) in entries {
        let local_header_offset = archive.len() as u32;
        let checksum = crc32(contents);
        push_le32(&mut archive, 0x0403_4b50);
        push_le16(&mut archive, 20);
        push_le16(&mut archive, 0);
        push_le16(&mut archive, 0);
        push_le16(&mut archive, 0);
        push_le16(&mut archive, 0x0021);
        push_le32(&mut archive, checksum);
        push_le32(&mut archive, contents.len() as u32);
        push_le32(&mut archive, contents.len() as u32);
        push_le16(&mut archive, name.len() as u16);
        push_le16(&mut archive, 0);
        archive.extend_from_slice(name.as_bytes());
        archive.extend_from_slice(contents);
        central_entries.push(ZipCentralEntry {
            name: (*name).to_string(),
            crc32: checksum,
            byte_len: contents.len() as u32,
            local_header_offset,
        });
    }

    let central_directory_offset = archive.len() as u32;
    for entry in &central_entries {
        push_le32(&mut archive, 0x0201_4b50);
        push_le16(&mut archive, 20);
        push_le16(&mut archive, 20);
        push_le16(&mut archive, 0);
        push_le16(&mut archive, 0);
        push_le16(&mut archive, 0);
        push_le16(&mut archive, 0x0021);
        push_le32(&mut archive, entry.crc32);
        push_le32(&mut archive, entry.byte_len);
        push_le32(&mut archive, entry.byte_len);
        push_le16(&mut archive, entry.name.len() as u16);
        push_le16(&mut archive, 0);
        push_le16(&mut archive, 0);
        push_le16(&mut archive, 0);
        push_le16(&mut archive, 0);
        push_le32(&mut archive, 0);
        push_le32(&mut archive, entry.local_header_offset);
        archive.extend_from_slice(entry.name.as_bytes());
    }
    let central_directory_size = archive.len() as u32 - central_directory_offset;

    push_le32(&mut archive, 0x0605_4b50);
    push_le16(&mut archive, 0);
    push_le16(&mut archive, 0);
    push_le16(&mut archive, central_entries.len() as u16);
    push_le16(&mut archive, central_entries.len() as u16);
    push_le32(&mut archive, central_directory_size);
    push_le32(&mut archive, central_directory_offset);
    push_le16(&mut archive, 0);
    archive
}

fn push_le16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_le32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn simulation_evidence_bundle(
    profile: &EvidenceProfile,
    artifact: &ArtifactRef,
    complete: bool,
) -> EvidenceBundle {
    let selected = if complete {
        profile.requirements.as_slice()
    } else {
        &profile.requirements[..1]
    };
    let results = selected
        .iter()
        .enumerate()
        .map(|(index, requirement)| EvidenceJobResult {
            job_id: format!("evidence-dev-job-{index}"),
            job_kind: requirement.job_kind,
            state: JobState::Passed,
            log_digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            reason_codes: Vec::new(),
        })
        .collect::<Vec<_>>();
    let cache_object_key = artifact.cache_object_key().unwrap_or_default();
    let job_bindings = results
        .iter()
        .map(|result| EvidenceJobBinding {
            job_id: result.job_id.clone(),
            job_kind: result.job_kind,
            profile_id: profile.id.to_string(),
            profile_version: profile.version,
            artifact_digest: artifact.digest.clone(),
            cache_object_key: cache_object_key.clone(),
            log_digest: result.log_digest.clone(),
            admission_ready: true,
        })
        .collect();
    EvidenceBundle {
        profile_id: profile.id.to_string(),
        profile_version: profile.version,
        artifact_digest: artifact.digest.clone(),
        cache_object_key,
        results,
        job_bindings,
    }
}

fn render_fetch_job_simulation(request: &str) -> HttpResponse {
    let digest = if request.contains("invalid_digest=true") {
        "sha256:../escape"
    } else {
        "sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f"
    };
    let expected_digest = if request.contains("digest_mismatch=true") {
        "sha256:mismatch"
    } else {
        digest
    };
    let source_url = if request.contains("http_source=true") {
        "http://registry.example/fixture.tgz"
    } else {
        "https://registry.example/fixture.tgz"
    };
    let byte_limit = if request.contains("zero_limit=true") {
        0
    } else {
        10_485_760
    };
    let plan = plan_fetch_job(FetchJobRequest {
        job_id: "fetch-dev-sim-1".to_string(),
        tenant_id: "tenant-local-dev".to_string(),
        admission_request_id: "dev-sim-1".to_string(),
        artifact: ArtifactRef {
            ecosystem: "npm".to_string(),
            name: "fixture".to_string(),
            version: "1.0.0".to_string(),
            digest: digest.to_string(),
            source: "local-dev-fetch-simulation".to_string(),
        },
        source_url: source_url.to_string(),
        expected_digest: expected_digest.to_string(),
        byte_limit,
    });
    let cache_object_key = plan.cache_object_key.as_deref().unwrap_or_default();
    let status = if matches!(plan.state, whoathere_vault_api::FetchJobState::Planned) {
        "ok"
    } else {
        "fail_closed"
    };
    let reason_codes = plan
        .reason_codes
        .iter()
        .map(|reason| format!("\"{reason}\""))
        .collect::<Vec<_>>()
        .join(",");
    json_response(
        if status == "ok" { 200 } else { 409 },
        &format!(
            "{{\"status\":\"{}\",\"mode\":\"local_dev\",\"job_id\":\"{}\",\"state\":\"{:?}\",\"fetch_enabled\":{},\"cache_object_key\":\"{}\",\"byte_limit\":{},\"reason_codes\":[{}]}}",
            status,
            plan.job_id,
            plan.state,
            plan.fetch_enabled,
            cache_object_key,
            plan.byte_limit,
            reason_codes
        ),
    )
}

fn render_challenge_authority_simulation(request: &str) -> HttpResponse {
    let subject = form_value(request, "subject").unwrap_or("vault-challenge-dev-sim");
    let context_hash = form_value(request, "context_hash")
        .unwrap_or("sha256:1111111111111111111111111111111111111111111111111111111111111111");
    let vault_host = form_value(request, "vault_host").unwrap_or("127.0.0.1:4873");
    let decision = plan_challenge_authority(ChallengeAuthorityRequest {
        request_id: "challenge-dev-sim-1".to_string(),
        tenant_id: "tenant-local-dev".to_string(),
        subject: subject.to_string(),
        context_hash: context_hash.to_string(),
        configured_vault_host: vault_host.to_string(),
        now_unix_seconds: LOCAL_DEV_CHALLENGE_AUTHORITY_NOW,
        ttl_seconds: LOCAL_DEV_CHALLENGE_AUTHORITY_TTL_SECONDS,
        scenario: ChallengeAuthorityScenario {
            replay: request.contains("replay=true"),
            unknown_challenge: request.contains("unknown_challenge=true"),
            mutate_context: request.contains("mutate_context=true"),
            expired: request.contains("expired=true"),
        },
    });
    json_response(
        decision.http_status_code,
        &render_challenge_authority_decision_json(&decision),
    )
}

fn render_challenge_authority_issue(request: &str) -> HttpResponse {
    let request_id = form_value(request, "request_id").unwrap_or("challenge-issue-dev-1");
    let tenant_id = form_value(request, "tenant_id").unwrap_or("tenant-local-dev");
    let subject = form_value(request, "subject").unwrap_or("vault-challenge-dev-issue");
    let context_hash = form_value(request, "context_hash")
        .unwrap_or("sha256:1111111111111111111111111111111111111111111111111111111111111111");
    let vault_host = form_value(request, "vault_host").unwrap_or("127.0.0.1:4873");
    let now = if request.contains("expired=true") {
        LOCAL_DEV_CHALLENGE_AUTHORITY_NOW.saturating_sub(LOCAL_DEV_CHALLENGE_AUTHORITY_TTL_SECONDS)
    } else {
        LOCAL_DEV_CHALLENGE_AUTHORITY_NOW
    };
    let audit_path = match challenge_authority_audit_path(request) {
        Ok(path) => path,
        Err(reason_code) => return render_challenge_authority_audit_error(reason_code, 409),
    };
    let issue_request = ChallengeIssueRequest {
        request_id: request_id.to_string(),
        tenant_id: tenant_id.to_string(),
        subject: subject.to_string(),
        context_hash: context_hash.to_string(),
        configured_vault_host: vault_host.to_string(),
        now_unix_seconds: now,
    };
    let (decision, store_status) = match challenge_authority_store_path(request) {
        Ok(Some(path)) => {
            match ChallengeAuthorityFileStore::new(path, LOCAL_DEV_CHALLENGE_AUTHORITY_TTL_SECONDS)
                .issue_with_outcome(issue_request)
            {
                Ok((decision, outcome)) => (
                    decision,
                    ChallengeAuthorityRouteStoreStatus {
                        mode: "file",
                        available: true,
                        stale_lock_recovered: outcome.stale_lock_recovered,
                        reason_codes: Vec::new(),
                    },
                ),
                Err(_) => {
                    return render_challenge_authority_store_error(
                        "challenge_authority_file_store_unavailable",
                    );
                }
            }
        }
        Ok(None) => match challenge_authority().lock() {
            Ok(mut authority) => (
                authority.issue(issue_request),
                ChallengeAuthorityRouteStoreStatus {
                    mode: "memory",
                    available: true,
                    stale_lock_recovered: false,
                    reason_codes: Vec::new(),
                },
            ),
            Err(_) => {
                return json_response(
                    503,
                    r#"{"status":"fail_closed","mode":"local_dev","reason_codes":["challenge_authority_lock_poisoned"],"exit_code":20}"#,
                );
            }
        },
        Err(reason_code) => return render_challenge_authority_store_error(reason_code),
    };
    json_response(
        decision.http_status_code,
        &render_challenge_issue_decision_json(
            &decision,
            &store_status,
            &write_challenge_issue_audit(audit_path.as_deref(), &decision),
        ),
    )
}

fn render_challenge_authority_consume(request: &str) -> HttpResponse {
    let request_id = form_value(request, "request_id").unwrap_or("challenge-consume-dev-1");
    let tenant_id = form_value(request, "tenant_id").unwrap_or("tenant-local-dev");
    let challenge_id = form_value(request, "challenge_id").unwrap_or_default();
    let submitted_subject = form_value(request, "subject").unwrap_or_default();
    let submitted_context_hash = form_value(request, "context_hash").unwrap_or_default();
    let submitted_vault_host = form_value(request, "vault_host").unwrap_or_default();
    let now = if request.contains("expired=true") {
        LOCAL_DEV_CHALLENGE_AUTHORITY_NOW.saturating_add(LOCAL_DEV_CHALLENGE_AUTHORITY_TTL_SECONDS)
    } else {
        LOCAL_DEV_CHALLENGE_AUTHORITY_NOW
    };
    let audit_path = match challenge_authority_audit_path(request) {
        Ok(path) => path,
        Err(reason_code) => return render_challenge_authority_audit_error(reason_code, 409),
    };
    let consume_request = ChallengeConsumeRequest {
        request_id: request_id.to_string(),
        tenant_id: tenant_id.to_string(),
        challenge_id: challenge_id.to_string(),
        submitted_subject: submitted_subject.to_string(),
        submitted_context_hash: submitted_context_hash.to_string(),
        submitted_configured_vault_host: submitted_vault_host.to_string(),
        now_unix_seconds: now,
    };
    let (decision, store_status) = match challenge_authority_store_path(request) {
        Ok(Some(path)) => {
            match ChallengeAuthorityFileStore::new(path, LOCAL_DEV_CHALLENGE_AUTHORITY_TTL_SECONDS)
                .consume_with_outcome(consume_request)
            {
                Ok((decision, outcome)) => (
                    decision,
                    ChallengeAuthorityRouteStoreStatus {
                        mode: "file",
                        available: true,
                        stale_lock_recovered: outcome.stale_lock_recovered,
                        reason_codes: Vec::new(),
                    },
                ),
                Err(_) => {
                    return render_challenge_authority_store_error(
                        "challenge_authority_file_store_unavailable",
                    );
                }
            }
        }
        Ok(None) => match challenge_authority().lock() {
            Ok(mut authority) => (
                authority.consume(consume_request),
                ChallengeAuthorityRouteStoreStatus {
                    mode: "memory",
                    available: true,
                    stale_lock_recovered: false,
                    reason_codes: Vec::new(),
                },
            ),
            Err(_) => {
                return json_response(
                    503,
                    r#"{"status":"fail_closed","mode":"local_dev","reason_codes":["challenge_authority_lock_poisoned"],"exit_code":20}"#,
                );
            }
        },
        Err(reason_code) => return render_challenge_authority_store_error(reason_code),
    };
    json_response(
        decision.http_status_code,
        &render_challenge_consume_decision_json(
            &decision,
            &store_status,
            &write_challenge_consume_audit(audit_path.as_deref(), &decision),
        ),
    )
}

fn render_evidence_job_simulation(request: &str) -> HttpResponse {
    let profile = minimum_profiles()
        .into_iter()
        .find(|profile| profile.id == "npm.registry_tarball.v1")
        .expect("minimum evidence profile exists");
    let artifact_digest = "sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f";
    let artifact = ArtifactRef {
        ecosystem: "npm".to_string(),
        name: "fixture".to_string(),
        version: "1.0.0".to_string(),
        digest: artifact_digest.to_string(),
        source: "local-dev-evidence-job-simulation".to_string(),
    };
    let cache_object_key = artifact.cache_object_key().unwrap_or_default();
    let mut plan = plan_evidence_job(
        EvidenceJobRequest {
            job_id: "evidence-dev-job-1".to_string(),
            tenant_id: "tenant-local-dev".to_string(),
            admission_request_id: "dev-sim-1".to_string(),
            artifact: artifact.clone(),
            profile_id: if request.contains("profile_mismatch=true") {
                "pypi.wheel.v1".to_string()
            } else {
                profile.id.to_string()
            },
            profile_version: profile.version,
            job_kind: profile.requirements[0].job_kind,
            cache_object_key: cache_object_key.clone(),
            timeout_seconds: 300,
        },
        &profile,
    );
    if request.contains("plan_rejected=true") {
        plan.state = whoathere_vault_api::EvidenceJobPlanState::Rejected;
        plan.reason_codes
            .push("evidence_job_plan_forced_rejected".to_string());
    }
    let mut result_artifact = artifact.clone();
    if request.contains("artifact_mismatch=true") {
        result_artifact.digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
    }
    let binding = bind_evidence_job_result(
        &plan,
        EvidenceJobResultRecord {
            job_id: if request.contains("job_mismatch=true") {
                "evidence-dev-job-mismatch".to_string()
            } else {
                plan.job_id.clone()
            },
            tenant_id: plan.tenant_id.clone(),
            admission_request_id: plan.admission_request_id.clone(),
            artifact: result_artifact,
            profile_id: plan.profile_id.clone(),
            profile_version: plan.profile_version,
            job_kind: plan.job_kind,
            cache_object_key: if request.contains("cache_mismatch=true") {
                "blobs/sha256/0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string()
            } else {
                cache_object_key
            },
            state: if request.contains("worker_failed=true") {
                JobState::Failed
            } else {
                JobState::Passed
            },
            log_digest: if request.contains("invalid_log_digest=true") {
                "sha256:not-canonical".to_string()
            } else {
                "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string()
            },
            execution_enabled: request.contains("execution_attempted=true"),
            detonation_attempted: request.contains("detonation_attempted=true"),
            network_attempted: request.contains("network_attempted=true"),
            audit_event_id: if request.contains("missing_audit=true") {
                String::new()
            } else {
                "audit-evidence-dev-job-1".to_string()
            },
        },
    );
    let mut reason_codes = plan.reason_codes.clone();
    reason_codes.extend(binding.reason_codes.clone());
    reason_codes.sort();
    reason_codes.dedup();
    let reasons = reason_codes
        .iter()
        .map(|reason| format!("\"{reason}\""))
        .collect::<Vec<_>>()
        .join(",");
    let ok = binding.state == EvidenceJobResultState::Bound;
    json_response(
        if ok { 200 } else { 409 },
        &format!(
            "{{\"status\":\"{}\",\"mode\":\"local_dev\",\"job_id\":\"{}\",\"profile_id\":\"{}\",\"job_kind\":\"{:?}\",\"execution_enabled\":{},\"detonation_attempted\":{},\"network_attempted\":{},\"job_state\":\"{:?}\",\"evidence_binding_ready\":{},\"reason_codes\":[{}]}}",
            if ok { "ok" } else { "fail_closed" },
            binding.job_id,
            binding.profile_id,
            binding.job_kind,
            binding.execution_enabled,
            binding.detonation_attempted,
            binding.network_attempted,
            binding.job_state,
            binding.admission_ready,
            reasons
        ),
    )
}

fn render_static_manifest_job_simulation(request: &str) -> HttpResponse {
    let Some(manifest_selector) = form_value(request, "manifest") else {
        return json_response(
            409,
            "{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"reason_codes\":[\"static_manifest_selector_missing\"]}",
        );
    };
    let (profile_id, ecosystem, manifest_kind, manifest_contents) = match manifest_selector {
        "clean_npm" => (
            "npm.registry_tarball.v1",
            "npm",
            StaticManifestKind::NpmPackageJson,
            r#"{"name":"fixture","version":"1.0.0"}"#,
        ),
        "malicious_npm" => (
            "npm.registry_tarball.v1",
            "npm",
            StaticManifestKind::NpmPackageJson,
            include_str!("../../../tests/fixtures/npm/postinstall-exfil/package.json"),
        ),
        "pyproject" => (
            "pypi.sdist_pep517.v1",
            "pypi",
            StaticManifestKind::PyprojectToml,
            include_str!("../../../tests/fixtures/pypi/pep517-backend/pyproject.toml"),
        ),
        "empty" => (
            "npm.registry_tarball.v1",
            "npm",
            StaticManifestKind::NpmPackageJson,
            "",
        ),
        _ => {
            return json_response(
                409,
                "{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"reason_codes\":[\"static_manifest_selector_invalid\"]}",
            )
        }
    };
    let profile = minimum_profiles()
        .into_iter()
        .find(|profile| profile.id == profile_id)
        .expect("minimum evidence profile exists");
    let job_id = form_value(request, "job_id")
        .map(str::to_string)
        .unwrap_or_else(|| format!("static-manifest-dev-job-{manifest_selector}"));
    let artifact_digest = "sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f";
    let artifact = ArtifactRef {
        ecosystem: ecosystem.to_string(),
        name: "fixture".to_string(),
        version: "1.0.0".to_string(),
        digest: artifact_digest.to_string(),
        source: "local-dev-static-manifest-job-simulation".to_string(),
    };
    let cache_object_key = artifact.cache_object_key().unwrap_or_default();
    let plan = plan_evidence_job(
        EvidenceJobRequest {
            job_id,
            tenant_id: "tenant-local-dev".to_string(),
            admission_request_id: "dev-sim-1".to_string(),
            artifact: artifact.clone(),
            profile_id: profile.id.to_string(),
            profile_version: profile.version,
            job_kind: whoathere_evidence::EvidenceJobKind::StaticManifest,
            cache_object_key: cache_object_key.clone(),
            timeout_seconds: 300,
        },
        &profile,
    );
    let output = run_static_manifest_job(StaticManifestJobRequest {
        job_id: &plan.job_id,
        profile_id: &plan.profile_id,
        profile_version: plan.profile_version,
        artifact_digest,
        cache_object_key: &cache_object_key,
        manifest_kind,
        manifest_contents,
    });
    let raw_log_captured =
        output.raw_log_captured || form_value(request, "raw_log_captured") == Some("true");
    let log_digest = if form_value(request, "tamper_log_digest") == Some("true") {
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
    } else {
        output.log_digest.clone()
    };
    let mut log_store = match job_log_store().lock() {
        Ok(guard) => guard,
        Err(_) => {
            return json_response(
                409,
                &format!(
                    "{{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"reason_codes\":[\"job_log_store_lock_poisoned\"],\"job_log_stored\":false,\"raw_log_captured\":{}}}",
                    raw_log_captured
                ),
            )
        }
    };
    let log_receipt = match log_store.append_sanitized(SanitizedJobLogEntry {
        tenant_id: plan.tenant_id.clone(),
        admission_request_id: plan.admission_request_id.clone(),
        job_id: output.job_id.clone(),
        job_kind: output.job_kind,
        profile_id: plan.profile_id.clone(),
        profile_version: plan.profile_version,
        artifact_digest: artifact.digest.clone(),
        cache_object_key: cache_object_key.clone(),
        log_digest: log_digest.clone(),
        summary_schema: output.summary_schema.clone(),
        sanitized_summary: output.sanitized_log_summary.clone(),
        raw_log_captured,
    }) {
        Ok(receipt) => receipt,
        Err(error) => {
            return json_response(
                409,
                &format!(
                    "{{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"reason_codes\":[\"{}\"],\"job_log_stored\":false,\"raw_log_captured\":{}}}",
                    error.reason_code(),
                    raw_log_captured
                ),
            )
        }
    };
    let binding = bind_evidence_job_result(
        &plan,
        EvidenceJobResultRecord {
            job_id: output.job_id.clone(),
            tenant_id: plan.tenant_id.clone(),
            admission_request_id: plan.admission_request_id.clone(),
            artifact: plan.artifact.clone(),
            profile_id: plan.profile_id.clone(),
            profile_version: plan.profile_version,
            job_kind: output.job_kind,
            cache_object_key: cache_object_key.clone(),
            state: output.state,
            log_digest: log_receipt.log_digest.clone(),
            execution_enabled: output.execution_enabled,
            detonation_attempted: output.detonation_attempted,
            network_attempted: output.network_attempted,
            audit_event_id: output.audit_event_id.clone(),
        },
    );
    let mut reason_codes = plan.reason_codes.clone();
    reason_codes.extend(output.reason_codes.clone());
    reason_codes.extend(binding.reason_codes.clone());
    reason_codes.sort();
    reason_codes.dedup();
    let reasons = reason_codes
        .iter()
        .map(|reason| format!("\"{reason}\""))
        .collect::<Vec<_>>()
        .join(",");
    let ok = binding.state == EvidenceJobResultState::Bound;
    json_response(
        if ok { 200 } else { 409 },
        &format!(
            "{{\"status\":\"{}\",\"mode\":\"local_dev\",\"manifest_kind\":\"{}\",\"job_id\":\"{}\",\"job_state\":\"{:?}\",\"evidence_binding_ready\":{},\"execution_enabled\":{},\"detonation_attempted\":{},\"network_attempted\":{},\"log_digest\":\"{}\",\"audit_event_id\":\"{}\",\"job_log_stored\":true,\"job_log_id\":\"{}\",\"job_log_byte_len\":{},\"raw_log_captured\":{},\"reason_codes\":[{}]}}",
            if ok { "ok" } else { "fail_closed" },
            manifest_kind.as_str(),
            binding.job_id,
            binding.job_state,
            binding.admission_ready,
            binding.execution_enabled,
            binding.detonation_attempted,
            binding.network_attempted,
            binding.log_digest,
            binding.audit_event_id,
            log_receipt.log_id,
            log_receipt.byte_len,
            raw_log_captured,
            reasons
        ),
    )
}

fn render_challenge_authority_decision_json(decision: &ChallengeAuthorityDecision) -> String {
    let replay_consume_status = decision
        .replay_consume_status_label()
        .map(|status| format!("\"{status}\""))
        .unwrap_or_else(|| "null".to_string());
    format!(
        "{{\"status\":\"{}\",\"mode\":\"local_dev\",\"authority\":\"{}\",\"authorization\":{},\"proof_minted\":{},\"execution_allowed\":{},\"trusted_time_source\":\"{}\",\"client_time_accepted\":{},\"ttl_seconds\":{},\"issued_challenge_id\":\"{}\",\"submitted_challenge_id\":\"{}\",\"nonce_present\":{},\"raw_nonce_returned\":{},\"probe_destination_count\":{},\"expires_at_unix_seconds\":{},\"scenario\":{{\"replay\":{},\"unknown_challenge\":{},\"mutate_context\":{},\"expired\":{}}},\"first_consume_status\":\"{}\",\"replay_consume_status\":{},\"accepted\":{},\"reason_codes\":{},\"replay_reason_codes\":{},\"exit_code\":{}}}",
        decision.status.label(),
        decision.authority,
        decision.authorization,
        decision.proof_minted,
        decision.execution_allowed,
        decision.trusted_time_source,
        decision.client_time_accepted,
        decision.ttl_seconds,
        decision.issued_challenge_id,
        decision.submitted_challenge_id,
        decision.nonce_present,
        decision.raw_nonce_returned,
        decision.probe_destination_count,
        decision.expires_at_unix_seconds,
        decision.scenario.replay,
        decision.scenario.unknown_challenge,
        decision.scenario.mutate_context,
        decision.scenario.expired,
        decision.first_consume_status_label(),
        replay_consume_status,
        decision.accepted,
        json_string_list(&decision.reason_codes),
        json_string_list(&decision.replay_reason_codes),
        decision.exit_code
    )
}

fn render_challenge_issue_decision_json(
    decision: &ChallengeIssueDecision,
    store_status: &ChallengeAuthorityRouteStoreStatus,
    audit_status: &ChallengeAuthorityRouteAuditStatus,
) -> String {
    let audit_event_id = challenge_authority_audit_event_id("issue", &decision.request_id);
    let audit_summary = challenge_issue_audit_summary(decision).to_json();
    format!(
        "{{\"status\":\"{}\",\"mode\":\"local_dev\",\"authority\":\"{}\",\"request_id\":\"{}\",\"tenant_id\":\"{}\",\"trusted_time_source\":\"{}\",\"client_time_accepted\":{},\"ttl_seconds\":{},\"challenge_id\":\"{}\",\"subject\":\"{}\",\"context_hash\":\"{}\",\"configured_vault_host\":\"{}\",\"nonce_present\":{},\"raw_nonce_returned\":{},\"probe_destination_count\":{},\"expires_at_unix_seconds\":{},\"store_mode\":\"{}\",\"store_available\":{},\"store_stale_lock_recovered\":{},\"store_reason_codes\":{},\"audit_configured\":{},\"audit_status\":\"{}\",\"audit_reason_codes\":{},\"audit_event_id\":\"{}\",\"challenge_authority_audit_summary\":{},\"reason_codes\":{},\"exit_code\":{}}}",
        decision.status.label(),
        escape_json(decision.authority),
        escape_json(&decision.request_id),
        escape_json(&decision.tenant_id),
        escape_json(decision.trusted_time_source),
        decision.client_time_accepted,
        decision.ttl_seconds,
        escape_json(&decision.challenge_id),
        escape_json(&decision.subject),
        escape_json(&decision.context_hash),
        escape_json(&decision.configured_vault_host),
        decision.nonce_present,
        decision.raw_nonce_returned,
        decision.probe_destination_count,
        decision.expires_at_unix_seconds,
        store_status.mode,
        store_status.available,
        store_status.stale_lock_recovered,
        json_string_list(&store_status.reason_codes),
        audit_status.configured,
        audit_status.status,
        json_string_list(&audit_status.reason_codes),
        escape_json(&audit_event_id),
        audit_summary,
        json_string_list(&decision.reason_codes),
        decision.exit_code
    )
}

fn render_challenge_consume_decision_json(
    decision: &ChallengeConsumeDecision,
    store_status: &ChallengeAuthorityRouteStoreStatus,
    audit_status: &ChallengeAuthorityRouteAuditStatus,
) -> String {
    let audit_event_id = challenge_authority_audit_event_id("consume", &decision.request_id);
    let audit_summary = challenge_consume_audit_summary(decision).to_json();
    format!(
        "{{\"status\":\"{}\",\"mode\":\"local_dev\",\"authority\":\"{}\",\"request_id\":\"{}\",\"tenant_id\":\"{}\",\"trusted_time_source\":\"{}\",\"client_time_accepted\":{},\"ttl_seconds\":{},\"challenge_id\":\"{}\",\"consume_status\":\"{}\",\"accepted\":{},\"nonce_present\":{},\"raw_nonce_returned\":{},\"raw_nonce_stored\":{},\"probe_destination_count\":{},\"expires_at_unix_seconds\":{},\"store_mode\":\"{}\",\"store_available\":{},\"store_stale_lock_recovered\":{},\"store_reason_codes\":{},\"audit_configured\":{},\"audit_status\":\"{}\",\"audit_reason_codes\":{},\"audit_event_id\":\"{}\",\"challenge_authority_audit_summary\":{},\"reason_codes\":{},\"exit_code\":{}}}",
        decision.status.label(),
        escape_json(decision.authority),
        escape_json(&decision.request_id),
        escape_json(&decision.tenant_id),
        escape_json(decision.trusted_time_source),
        decision.client_time_accepted,
        decision.ttl_seconds,
        escape_json(&decision.challenge_id),
        decision.consume_status_label(),
        decision.accepted,
        decision.nonce_present,
        decision.raw_nonce_returned,
        decision.raw_nonce_stored,
        decision.probe_destination_count,
        decision.expires_at_unix_seconds,
        store_status.mode,
        store_status.available,
        store_status.stale_lock_recovered,
        json_string_list(&store_status.reason_codes),
        audit_status.configured,
        audit_status.status,
        json_string_list(&audit_status.reason_codes),
        escape_json(&audit_event_id),
        audit_summary,
        json_string_list(&decision.reason_codes),
        decision.exit_code
    )
}

fn challenge_authority_store_path(request: &str) -> Result<Option<PathBuf>, &'static str> {
    let Some(raw_path) = form_value(request, "store_path") else {
        return Ok(None);
    };
    if raw_path.is_empty() {
        return Err("challenge_authority_store_path_empty");
    }
    let path = PathBuf::from(raw_path);
    if !path.is_absolute() {
        return Err("challenge_authority_store_path_not_absolute");
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("challenge_authority_store_path_parent_dir");
    }
    if !path.starts_with(std::env::temp_dir()) {
        return Err("challenge_authority_store_path_outside_temp");
    }
    Ok(Some(path))
}

fn challenge_authority_audit_path(request: &str) -> Result<Option<PathBuf>, &'static str> {
    let Some(raw_path) = form_value(request, "audit_path") else {
        return Ok(None);
    };
    if raw_path.is_empty() {
        return Err("challenge_authority_audit_path_empty");
    }
    let path = PathBuf::from(raw_path);
    if !path.is_absolute() {
        return Err("challenge_authority_audit_path_not_absolute");
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("challenge_authority_audit_path_parent_dir");
    }
    if !path.starts_with(std::env::temp_dir()) {
        return Err("challenge_authority_audit_path_outside_temp");
    }
    Ok(Some(path))
}

fn render_challenge_authority_store_error(reason_code: &'static str) -> HttpResponse {
    let store_status = ChallengeAuthorityRouteStoreStatus {
        mode: "file",
        available: false,
        stale_lock_recovered: false,
        reason_codes: vec![reason_code.to_string()],
    };
    json_response(
        409,
        &format!(
            "{{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"store_mode\":\"{}\",\"store_available\":{},\"store_stale_lock_recovered\":{},\"store_reason_codes\":{},\"reason_codes\":[\"{}\"],\"exit_code\":20}}",
            store_status.mode,
            store_status.available,
            store_status.stale_lock_recovered,
            json_string_list(&store_status.reason_codes),
            reason_code
        ),
    )
}

fn render_challenge_authority_audit_error(
    reason_code: &'static str,
    status_code: u16,
) -> HttpResponse {
    let audit_status = ChallengeAuthorityRouteAuditStatus {
        configured: true,
        status: "error",
        reason_codes: vec![reason_code.to_string()],
    };
    json_response(
        status_code,
        &format!(
            "{{\"status\":\"fail_closed\",\"mode\":\"local_dev\",\"audit_configured\":{},\"audit_status\":\"{}\",\"audit_reason_codes\":{},\"reason_codes\":[\"{}\"],\"exit_code\":20}}",
            audit_status.configured,
            audit_status.status,
            json_string_list(&audit_status.reason_codes),
            reason_code
        ),
    )
}

fn challenge_authority_audit_event_id(operation: &str, request_id: &str) -> String {
    format!("audit-challenge-authority-{operation}-{request_id}")
}

fn write_challenge_issue_audit(
    audit_path: Option<&Path>,
    decision: &ChallengeIssueDecision,
) -> ChallengeAuthorityRouteAuditStatus {
    let Some(path) = audit_path else {
        return ChallengeAuthorityRouteAuditStatus {
            configured: false,
            status: "not_configured",
            reason_codes: Vec::new(),
        };
    };
    let event_id = challenge_authority_audit_event_id("issue", &decision.request_id);
    let record = AuditRecord::new(
        event_id,
        decision.challenge_id.clone(),
        "whoathere vault challenge-authority issue",
        decision.status.label(),
        decision.reason_codes.clone(),
    )
    .with_challenge_authority_summary(challenge_issue_audit_summary(decision));
    match append_challenge_authority_audit(path, &record) {
        Ok(()) => ChallengeAuthorityRouteAuditStatus {
            configured: true,
            status: "written",
            reason_codes: Vec::new(),
        },
        Err(_) => ChallengeAuthorityRouteAuditStatus {
            configured: true,
            status: "error",
            reason_codes: vec!["challenge_authority_audit_write_failed".to_string()],
        },
    }
}

fn write_challenge_consume_audit(
    audit_path: Option<&Path>,
    decision: &ChallengeConsumeDecision,
) -> ChallengeAuthorityRouteAuditStatus {
    let Some(path) = audit_path else {
        return ChallengeAuthorityRouteAuditStatus {
            configured: false,
            status: "not_configured",
            reason_codes: Vec::new(),
        };
    };
    let event_id = challenge_authority_audit_event_id("consume", &decision.request_id);
    let record = AuditRecord::new(
        event_id,
        decision.challenge_id.clone(),
        "whoathere vault challenge-authority consume",
        decision.status.label(),
        decision.reason_codes.clone(),
    )
    .with_challenge_authority_summary(challenge_consume_audit_summary(decision));
    match append_challenge_authority_audit(path, &record) {
        Ok(()) => ChallengeAuthorityRouteAuditStatus {
            configured: true,
            status: "written",
            reason_codes: Vec::new(),
        },
        Err(_) => ChallengeAuthorityRouteAuditStatus {
            configured: true,
            status: "error",
            reason_codes: vec!["challenge_authority_audit_write_failed".to_string()],
        },
    }
}

fn append_challenge_authority_audit(path: &Path, record: &AuditRecord) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    append_jsonl(path, record)
}

fn challenge_issue_audit_summary(
    decision: &ChallengeIssueDecision,
) -> AuditChallengeAuthoritySummary {
    AuditChallengeAuthoritySummary {
        operation: "issue".to_string(),
        authority: decision.authority.to_string(),
        request_id: decision.request_id.clone(),
        tenant_id: decision.tenant_id.clone(),
        challenge_id: decision.challenge_id.clone(),
        status: decision.status.label().to_string(),
        accepted: decision.status == whoathere_vault_api::ChallengeAuthorityStatus::Ok,
        trusted_time_source: decision.trusted_time_source.to_string(),
        client_time_accepted: decision.client_time_accepted,
        ttl_seconds: decision.ttl_seconds,
        expires_at_unix_seconds: decision.expires_at_unix_seconds,
        probe_destination_count: decision.probe_destination_count,
        nonce_present: decision.nonce_present,
        raw_nonce_returned: decision.raw_nonce_returned,
        raw_nonce_stored: false,
        reason_codes: decision.reason_codes.clone(),
    }
}

fn challenge_consume_audit_summary(
    decision: &ChallengeConsumeDecision,
) -> AuditChallengeAuthoritySummary {
    AuditChallengeAuthoritySummary {
        operation: "consume".to_string(),
        authority: decision.authority.to_string(),
        request_id: decision.request_id.clone(),
        tenant_id: decision.tenant_id.clone(),
        challenge_id: decision.challenge_id.clone(),
        status: decision.status.label().to_string(),
        accepted: decision.accepted,
        trusted_time_source: decision.trusted_time_source.to_string(),
        client_time_accepted: decision.client_time_accepted,
        ttl_seconds: decision.ttl_seconds,
        expires_at_unix_seconds: decision.expires_at_unix_seconds,
        probe_destination_count: decision.probe_destination_count,
        nonce_present: decision.nonce_present,
        raw_nonce_returned: decision.raw_nonce_returned,
        raw_nonce_stored: decision.raw_nonce_stored,
        reason_codes: decision.reason_codes.clone(),
    }
}

fn json_string_list(values: &[String]) -> String {
    let values = values
        .iter()
        .map(|reason| format!("\"{}\"", escape_json(reason)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{values}]")
}

fn form_value<'a>(request: &'a str, key: &str) -> Option<&'a str> {
    let body = request.split_once("\r\n\r\n").map(|(_, body)| body)?;
    body.split('&').find_map(|pair| {
        let (candidate_key, value) = pair.split_once('=')?;
        (candidate_key == key).then_some(value)
    })
}

fn json_response(status_code: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status_code,
        content_type: "application/json",
        headers: Vec::new(),
        body: HttpBody::from_text(body),
    }
}

fn plain_response(status_code: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status_code,
        content_type: "text/plain",
        headers: Vec::new(),
        body: HttpBody::from_text(body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_loopback_socket_addresses() {
        assert!(validate_loopback_bind("127.0.0.1:0").is_ok());
        assert!(validate_loopback_bind("[::1]:0").is_ok());
        assert_eq!(
            validate_loopback_bind("0.0.0.0:8080"),
            Err(BindValidationError::NotLoopback)
        );
        assert_eq!(
            validate_loopback_bind("vault.local:8080"),
            Err(BindValidationError::NotSocketAddress)
        );
    }

    #[test]
    fn loopback_dev_server_serves_one_request_then_exits() {
        let Some(listener) = bind_loopback_test_listener() else {
            return;
        };
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || {
            serve_loopback_listener(listener, 1, Duration::from_secs(2)).expect("serve listener")
        });

        let mut stream = std::net::TcpStream::connect(addr).expect("connect dev server");
        std::io::Write::write_all(
            &mut stream,
            b"GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .expect("write request");
        let mut response = String::new();
        std::io::Read::read_to_string(&mut stream, &mut response).expect("read response");

        let summary = handle.join().expect("server thread");
        assert_eq!(summary.served_requests, 1);
        assert_eq!(summary.max_requests, 1);
        assert_eq!(summary.request_logs.len(), 1);
        let log_entry = &summary.request_logs[0];
        assert_eq!(log_entry.method, "GET");
        assert_eq!(log_entry.route_kind, "registry_npm_tarball");
        assert_eq!(log_entry.status_code, 200);
        assert_eq!(log_entry.range_state, "absent");
        assert_eq!(log_entry.declared_response_body_bytes, 25);
        assert_eq!(log_entry.wire_response_body_bytes, 25);
        assert!(!log_entry.request_body_logged);
        assert!(!log_entry.response_body_logged);
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Content-Type: application/octet-stream"));
        assert!(response.ends_with("inert cache fixture bytes"));
    }

    #[test]
    fn loopback_dev_server_idle_timeout_exits_without_blocking() {
        let Some(listener) = bind_loopback_test_listener() else {
            return;
        };
        let summary =
            serve_loopback_listener(listener, 1, Duration::from_millis(1)).expect("serve listener");
        assert_eq!(summary.served_requests, 0);
        assert_eq!(summary.max_requests, 1);
        assert_eq!(summary.idle_timeout_ms, 1);
        assert!(summary.request_logs.is_empty());
    }

    #[test]
    fn loopback_dev_server_rejects_non_loopback_bind() {
        let error = serve_loopback_http("0.0.0.0:0", 1, Duration::from_millis(1))
            .expect_err("non-loopback bind rejected");
        assert_eq!(error.reason_code(), "dev_server_bind_not_loopback");
    }

    fn bind_loopback_test_listener() -> Option<TcpListener> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => Some(listener),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
            Err(error) => panic!("bind test listener: {error}"),
        }
    }

    fn header_value<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
        response
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }

    fn json_field(body: &str, name: &str) -> String {
        let needle = format!("\"{name}\":\"");
        let Some(start) = body.find(&needle).map(|index| index + needle.len()) else {
            return String::new();
        };
        let rest = &body[start..];
        rest.split('"').next().unwrap_or_default().to_string()
    }

    fn unique_dev_store_path(label: &str) -> PathBuf {
        unique_dev_temp_file_path(label, "store.txt")
    }

    fn unique_dev_audit_path(label: &str) -> PathBuf {
        unique_dev_temp_file_path(label, "audit.jsonl")
    }

    fn unique_dev_temp_file_path(label: &str, filename: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir()
            .join(format!("{label}-{}-{unique}", std::process::id()))
            .join(filename)
    }

    fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn healthz_is_local_dev_only() {
        let response = handle_http_request("GET /healthz HTTP/1.1\r\n\r\n");
        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"mode\":\"local_dev\""));
    }

    #[test]
    fn evidence_profiles_do_not_include_registry_urls() {
        let response = handle_http_request("GET /v1/evidence-profiles HTTP/1.1\r\n\r\n");
        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("npm.registry_tarball.v1"));
        assert!(!response.body.contains("registry.npmjs.org"));
        assert!(!response.body.contains("files.pythonhosted.org"));
    }

    #[test]
    fn admission_simulation_fails_closed_when_incomplete() {
        let response = handle_http_request(
            "POST /v1/admission-simulations HTTP/1.1\r\nContent-Length: 14\r\n\r\ncomplete=false",
        );
        assert_eq!(response.status_code, 409);
        assert!(response.body.contains("mandatory_evidence_incomplete"));
        assert!(response.body.contains("\"promoted\":false"));
    }

    #[test]
    fn admission_simulation_promotes_when_complete() {
        let response = handle_http_request(
            "POST /v1/admission-simulations HTTP/1.1\r\nContent-Length: 13\r\n\r\ncomplete=true",
        );
        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"verdict\":\"Allow\""));
        assert!(response.body.contains("\"promoted\":true"));
        assert!(response.body.contains("\"generation_id\":1"));
        assert!(response
            .body
            .contains("\"cache_object_key\":\"blobs/sha256/b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f\""));
        assert!(response
            .body
            .contains("\"fetch_job_id\":\"fetch-dev-sim-1\""));
        assert!(response
            .body
            .contains("\"fetch_quarantine_id\":\"quarantine-1\""));
        assert!(response.body.contains("\"fetch_byte_len\":25"));
        assert!(response.body.contains("\"fetch_byte_limit\":10485760"));
        assert!(response
            .body
            .contains("\"fetch_audit_event_id\":\"audit-fetch-dev-sim-1\""));
        assert!(response
            .body
            .contains("\"audit_event_id\":\"audit-dev-sim-1\""));
        assert!(response.body.contains("\"promotion_manifest\""));
        assert!(response.body.contains("\"tenant_id\":\"tenant-local-dev\""));
        assert!(response.body.contains("\"request_id\":\"dev-sim-1\""));
    }

    #[test]
    fn admission_simulation_fails_closed_when_fetch_result_missing() {
        let response = handle_http_request(
            "POST /v1/admission-simulations HTTP/1.1\r\nContent-Length: 32\r\n\r\ncomplete=true&fetch_missing=true",
        );
        assert_eq!(response.status_code, 409);
        assert!(response.body.contains("verified_fetch_result_missing"));
        assert!(response.body.contains("\"promoted\":false"));
    }

    #[test]
    fn admission_simulation_fails_closed_when_fetch_result_mismatches() {
        let response = handle_http_request(
            "POST /v1/admission-simulations HTTP/1.1\r\nContent-Length: 33\r\n\r\ncomplete=true&fetch_mismatch=true",
        );
        assert_eq!(response.status_code, 409);
        assert!(response.body.contains("fetch_result_not_admission_ready"));
        assert!(response
            .body
            .contains("fetch_result_verified_digest_mismatch"));
        assert!(response.body.contains("fetch_result_cache_key_mismatch"));
        assert!(response.body.contains("\"promoted\":false"));
    }

    #[test]
    fn admission_simulation_fails_closed_when_evidence_profile_mismatches() {
        let response = handle_http_request(
            "POST /v1/admission-simulations HTTP/1.1\r\nContent-Length: 44\r\n\r\ncomplete=true&evidence_profile_mismatch=true",
        );
        assert_eq!(response.status_code, 409);
        assert!(response.body.contains("evidence_profile_id_mismatch"));
        assert!(response.body.contains("\"promoted\":false"));
    }

    #[test]
    fn admission_simulation_fails_closed_when_evidence_is_duplicate() {
        let response = handle_http_request(
            "POST /v1/admission-simulations HTTP/1.1\r\nContent-Length: 37\r\n\r\ncomplete=true&evidence_duplicate=true",
        );
        assert_eq!(response.status_code, 409);
        assert!(response.body.contains("evidence_duplicate_job_result"));
        assert!(response.body.contains("\"promoted\":false"));
    }

    #[test]
    fn admission_simulation_fails_closed_when_evidence_subject_mismatches() {
        let response = handle_http_request(
            "POST /v1/admission-simulations HTTP/1.1\r\nContent-Length: 44\r\n\r\ncomplete=true&evidence_subject_mismatch=true",
        );
        assert_eq!(response.status_code, 409);
        assert!(response.body.contains("evidence_artifact_digest_mismatch"));
        assert!(response.body.contains("\"promoted\":false"));
    }

    #[test]
    fn cache_simulation_quarantines_without_serving() {
        let response = handle_http_request(
            "POST /v1/cache-simulations HTTP/1.1\r\nContent-Length: 13\r\n\r\npromote=false",
        );
        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"quarantined\":true"));
        assert!(response.body.contains("\"promoted\":false"));
        assert!(response
            .body
            .contains("\"cache_object_key\":\"blobs/sha256/b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f\""));
    }

    #[test]
    fn cache_simulation_promotes_inert_bytes() {
        let response = handle_http_request(
            "POST /v1/cache-simulations HTTP/1.1\r\nContent-Length: 12\r\n\r\npromote=true",
        );
        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"promoted\":true"));
        assert!(response
            .body
            .contains("\"cache_object_key\":\"blobs/sha256/b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f\""));
    }

    #[test]
    fn registry_simulation_unpromoted_npm_fails_closed() {
        let response =
            handle_http_request("GET /v1/registry-simulations/npm/fixture HTTP/1.1\r\n\r\n");
        assert_eq!(response.status_code, 503);
        assert_eq!(response.content_type, "text/plain");
        assert!(response.body.contains("artifact_not_promoted"));
        assert!(response.body.contains("ecosystem=npm"));

        let wire = to_http_wire(&response);
        assert!(wire.starts_with("HTTP/1.1 503 Service Unavailable"));
    }

    #[test]
    fn registry_simulation_promoted_npm_renders_packument_without_public_registry() {
        let response = handle_http_request(
            "GET /v1/registry-simulations/npm/fixture?promoted=true HTTP/1.1\r\n\r\n",
        );
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, "application/json");
        assert!(response.body.contains("\"name\":\"fixture\""));
        assert!(response.body.contains("\"dist-tags\""));
        assert!(response
            .body
            .contains("/v1/registry-simulations/npm/tarballs/fixture/1.0.0"));
        assert!(!response.body.contains("registry.npmjs.org"));
    }

    #[test]
    fn registry_compat_npm_renders_promoted_packument_without_query_flag() {
        let response = handle_http_request("GET /v1/registry-compat/npm/fixture HTTP/1.1\r\n\r\n");
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, "application/json");
        assert!(response.body.contains("\"name\":\"fixture\""));
        assert!(response
            .body
            .contains("/v1/registry-compat/npm/tarballs/fixture/1.0.0/fixture-1.0.0.tgz"));
        assert!(response.body.contains("\"integrity\":\"sha256-"));
        assert!(!response.body.contains("postinstall"));
        assert!(!response.body.contains("registry.npmjs.org"));
    }

    #[test]
    fn registry_compat_npm_packument_uses_loopback_host_header() {
        let response = handle_http_request(
            "GET /v1/registry-compat/npm/fixture HTTP/1.1\r\nHost: 127.0.0.1:49123\r\n\r\n",
        );
        assert_eq!(response.status_code, 200);
        assert!(response.body.contains(
            "\"tarball\":\"http://127.0.0.1:49123/v1/registry-compat/npm/tarballs/fixture/1.0.0/fixture-1.0.0.tgz\""
        ));
    }

    #[test]
    fn registry_compat_metadata_rejects_public_host_header() {
        let response = handle_http_request(
            "GET /v1/registry-compat/npm/fixture HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n",
        );
        assert_eq!(response.status_code, 503);
        assert!(response.body.contains("registry_compat_host_not_loopback"));
        assert!(!response.body.contains("registry.npmjs.org"));
    }

    #[test]
    fn registry_compat_npm_unknown_package_fails_closed() {
        let response = handle_http_request("GET /v1/registry-compat/npm/unknown HTTP/1.1\r\n\r\n");
        assert_eq!(response.status_code, 503);
        assert_eq!(response.content_type, "text/plain");
        assert!(response.body.contains("artifact_not_promoted"));
        assert!(response.body.contains("name=unknown"));
    }

    #[test]
    fn registry_compat_npm_tarball_serves_valid_safe_archive_bytes() {
        let response = handle_http_request(
            "GET /v1/registry-compat/npm/tarballs/fixture/1.0.0/fixture-1.0.0.tgz HTTP/1.1\r\n\r\n",
        );
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, "application/octet-stream");
        assert!(response.body.as_bytes().starts_with(&[0x1f, 0x8b]));
        assert!(bytes_contain(
            response.body.as_bytes(),
            b"package/package.json"
        ));
        assert!(bytes_contain(response.body.as_bytes(), b"package/index.js"));
        assert!(!bytes_contain(response.body.as_bytes(), b"postinstall"));
        assert!(!bytes_contain(response.body.as_bytes(), b"preinstall"));
        assert_ne!(response.body.as_bytes(), LOCAL_DEV_CACHE_BYTES);
        assert_eq!(
            header_value(&response, "ETag"),
            Some(
                etag_for_generation(&local_dev_compat_servable_generation(
                    "npm", "fixture", "1.0.0"
                ))
                .as_str()
            )
        );
    }

    #[test]
    fn registry_compat_npm_tarball_supports_range_over_archive_bytes() {
        let response = handle_http_request(
            "GET /v1/registry-compat/npm/tarballs/fixture/1.0.0/fixture-1.0.0.tgz HTTP/1.1\r\nRange: bytes=0-1\r\n\r\n",
        );
        let archive_len = build_npm_fixture_tgz().len();
        assert_eq!(response.status_code, 206);
        assert_eq!(response.content_type, "application/octet-stream");
        assert_eq!(response.body.as_bytes(), &[0x1f, 0x8b]);
        assert_eq!(
            header_value(&response, "Content-Range"),
            Some(format!("bytes 0-1/{archive_len}").as_str())
        );
    }

    #[test]
    fn registry_compat_routes_have_sanitized_registry_log_kinds() {
        assert_eq!(
            route_kind_for_target("/v1/registry-compat/npm/fixture"),
            "registry_npm_metadata"
        );
        assert_eq!(
            route_kind_for_target("/v1/registry-compat/npm/tarballs/fixture/1.0.0"),
            "registry_npm_tarball"
        );
        assert_eq!(
            route_kind_for_target("/v1/registry-compat/pypi/simple/fixture/"),
            "registry_pypi_metadata"
        );
        assert_eq!(
            route_kind_for_target("/v1/registry-compat/pypi/files/pypi/fixture/1.0.0"),
            "registry_pypi_file"
        );
    }

    #[test]
    fn registry_simulation_npm_tarball_serves_exact_promoted_cache_bytes() {
        let response = handle_http_request(
            "GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\n\r\n",
        );
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, "application/octet-stream");
        assert_eq!(response.body.as_bytes(), LOCAL_DEV_CACHE_BYTES);
        assert_eq!(header_value(&response, "Accept-Ranges"), Some("bytes"));
        assert_eq!(
            header_value(&response, "Cache-Control"),
            Some("private, max-age=31536000, immutable")
        );
        assert_eq!(
            header_value(&response, "ETag"),
            Some("\"sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f\"")
        );
        assert_eq!(
            header_value(&response, "X-Content-Type-Options"),
            Some("nosniff")
        );

        let wire = to_http_wire(&response);
        assert!(wire.starts_with("HTTP/1.1 200 OK"));
        assert!(wire.contains("Content-Length: 25"));
        assert!(wire.contains("Accept-Ranges: bytes"));
        assert!(wire.contains("Cache-Control: private, max-age=31536000, immutable"));
        assert!(wire.contains(
            "ETag: \"sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f\""
        ));
    }

    #[test]
    fn http_wire_bytes_preserve_non_utf8_body() {
        let response = HttpResponse {
            status_code: 200,
            content_type: "application/octet-stream",
            headers: Vec::new(),
            body: HttpBody::from_bytes(vec![0, 159, 255, b'a']),
        };
        let wire = to_http_wire_bytes(&response);
        assert!(wire.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(wire
            .windows(b"Content-Length: 4".len())
            .any(|window| window == b"Content-Length: 4"));
        assert_eq!(&wire[wire.len() - 4..], &[0, 159, 255, b'a']);
    }

    #[test]
    fn registry_simulation_npm_tarball_head_declares_length_without_body() {
        let response = handle_http_request(
            "HEAD /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\n\r\n",
        );
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, "application/octet-stream");
        assert_eq!(response.body.len(), LOCAL_DEV_CACHE_BYTES.len());
        assert!(response.body.as_bytes().is_empty());
        assert_eq!(
            header_value(&response, "ETag"),
            Some("\"sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f\"")
        );

        let wire = to_http_wire_bytes(&response);
        assert!(wire.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(wire
            .windows(b"Content-Length: 25".len())
            .any(|window| window == b"Content-Length: 25"));
        assert!(wire.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn registry_simulation_npm_tarball_if_none_match_returns_not_modified() {
        let response = handle_http_request(
            "GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\nIf-None-Match: \"sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f\"\r\n\r\n",
        );
        assert_eq!(response.status_code, 304);
        assert_eq!(response.content_type, "application/octet-stream");
        assert_eq!(response.body.len(), 0);
        assert!(response.body.as_bytes().is_empty());
        assert_eq!(header_value(&response, "Accept-Ranges"), Some("bytes"));
        assert_eq!(
            header_value(&response, "ETag"),
            Some("\"sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f\"")
        );

        let wire = to_http_wire_bytes(&response);
        assert!(wire.starts_with(b"HTTP/1.1 304 Not Modified\r\n"));
        assert!(wire
            .windows(b"Content-Length: 0".len())
            .any(|window| window == b"Content-Length: 0"));
        assert!(wire.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn registry_simulation_npm_tarball_if_none_match_supports_weak_and_wildcard() {
        let weak = handle_http_request(
            "GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\nIf-None-Match: W/\"sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f\"\r\n\r\n",
        );
        assert_eq!(weak.status_code, 304);

        let wildcard = handle_http_request(
            "GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\nIf-None-Match: *\r\n\r\n",
        );
        assert_eq!(wildcard.status_code, 304);
    }

    #[test]
    fn registry_simulation_npm_tarball_mismatched_if_none_match_serves_body() {
        let response = handle_http_request(
            "GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\nIf-None-Match: \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\r\n\r\n",
        );
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body.as_bytes(), LOCAL_DEV_CACHE_BYTES);
    }

    #[test]
    fn registry_simulation_npm_tarball_matching_validator_precedes_range() {
        let response = handle_http_request(
            "GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\nIf-None-Match: \"sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f\"\r\nRange: bytes=0-4\r\n\r\n",
        );
        assert_eq!(response.status_code, 304);
        assert!(response.body.as_bytes().is_empty());
        assert_eq!(header_value(&response, "Content-Range"), None);
    }

    #[test]
    fn registry_simulation_npm_tarball_serves_single_byte_range() {
        let response = handle_http_request(
            "GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\nRange: bytes=6-10\r\n\r\n",
        );
        assert_eq!(response.status_code, 206);
        assert_eq!(response.content_type, "application/octet-stream");
        assert_eq!(response.body.as_bytes(), b"cache");
        assert_eq!(response.body.len(), 5);
        assert_eq!(header_value(&response, "Accept-Ranges"), Some("bytes"));
        assert_eq!(
            header_value(&response, "Content-Range"),
            Some("bytes 6-10/25")
        );

        let wire = to_http_wire(&response);
        assert!(wire.starts_with("HTTP/1.1 206 Partial Content"));
        assert!(wire.contains("Content-Length: 5"));
        assert!(wire.ends_with("cache"));

        let log_entry = sanitized_request_log_entry(
            "GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\nRange: bytes=6-10\r\nAuthorization: Bearer secret\r\n\r\n",
            &response,
        );
        assert_eq!(log_entry.method, "GET");
        assert_eq!(log_entry.route_kind, "registry_npm_tarball");
        assert_eq!(log_entry.status_code, 206);
        assert_eq!(log_entry.range_state, "served");
        assert_eq!(log_entry.declared_response_body_bytes, 5);
        assert_eq!(log_entry.wire_response_body_bytes, 5);
        assert!(!log_entry.request_body_logged);
        assert!(!log_entry.response_body_logged);
    }

    #[test]
    fn registry_simulation_npm_tarball_head_serves_range_headers_without_body() {
        let response = handle_http_request(
            "HEAD /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\nRange: bytes=0-4\r\n\r\n",
        );
        assert_eq!(response.status_code, 206);
        assert_eq!(response.content_type, "application/octet-stream");
        assert_eq!(response.body.len(), 5);
        assert!(response.body.as_bytes().is_empty());
        assert_eq!(
            header_value(&response, "Content-Range"),
            Some("bytes 0-4/25")
        );

        let wire = to_http_wire_bytes(&response);
        assert!(wire.starts_with(b"HTTP/1.1 206 Partial Content\r\n"));
        assert!(wire
            .windows(b"Content-Length: 5".len())
            .any(|window| window == b"Content-Length: 5"));
        assert!(wire.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn registry_simulation_npm_tarball_rejects_unsatisfiable_range() {
        let response = handle_http_request(
            "GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\nRange: bytes=99-100\r\n\r\n",
        );
        assert_eq!(response.status_code, 416);
        assert_eq!(response.content_type, "application/json");
        assert!(response.body.contains("range_not_satisfiable"));
        assert!(response.body.contains("\"served\":false"));
        assert_eq!(header_value(&response, "Accept-Ranges"), Some("bytes"));
        assert_eq!(header_value(&response, "Content-Range"), Some("bytes */25"));
        assert!(!response.body.contains("inert cache fixture bytes"));

        let log_entry = sanitized_request_log_entry(
            "GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\nRange: bytes=99-100\r\n\r\n",
            &response,
        );
        assert_eq!(log_entry.range_state, "rejected");
        assert_eq!(log_entry.status_code, 416);
        assert!(!log_entry.request_body_logged);
        assert!(!log_entry.response_body_logged);
    }

    #[test]
    fn registry_simulation_npm_tarball_rejects_unsupported_ranges() {
        let multiple = handle_http_request(
            "GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\nRange: bytes=0-1,3-4\r\n\r\n",
        );
        assert_eq!(multiple.status_code, 416);
        assert!(multiple.body.contains("range_multiple_unsupported"));
        assert_eq!(header_value(&multiple, "Content-Range"), Some("bytes */25"));

        let unit = handle_http_request(
            "GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 HTTP/1.1\r\nRange: items=0-4\r\n\r\n",
        );
        assert_eq!(unit.status_code, 416);
        assert!(unit.body.contains("range_unit_unsupported"));
        assert_eq!(header_value(&unit, "Accept-Ranges"), Some("bytes"));
    }

    #[test]
    fn registry_simulation_npm_tarball_fails_closed_for_unpromoted_path() {
        let response = handle_http_request(
            "GET /v1/registry-simulations/npm/tarballs/unknown/9.9.9 HTTP/1.1\r\n\r\n",
        );
        assert_eq!(response.status_code, 503);
        assert_eq!(response.content_type, "text/plain");
        assert!(response.body.contains("artifact_not_promoted"));
        assert!(response.body.contains("name=unknown"));
    }

    #[test]
    fn registry_simulation_npm_tarball_requires_exact_cache_key_lookup() {
        let response = handle_http_request(
            "GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0?cache_key_mismatch=true HTTP/1.1\r\n\r\n",
        );
        assert_eq!(response.status_code, 409);
        assert_eq!(response.content_type, "application/json");
        assert!(response.body.contains("cache_promoted_object_key_mismatch"));
        assert!(response.body.contains("\"served\":false"));
    }

    #[test]
    fn registry_simulation_promoted_pypi_renders_simple_without_public_index() {
        let response = handle_http_request(
            "GET /v1/registry-simulations/pypi/fixture?promoted=true HTTP/1.1\r\n\r\n",
        );
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, "text/html");
        assert!(response.body.contains("<!doctype html>"));
        assert!(response.body.contains("fixture-1.0.0"));
        assert!(response
            .body
            .contains("/v1/registry-simulations/pypi/files/pypi/fixture/1.0.0"));
        assert!(!response.body.contains("files.pythonhosted.org"));
        assert!(!response.body.contains("pypi.org"));
    }

    #[test]
    fn registry_compat_pypi_renders_simple_with_trailing_slash() {
        let response =
            handle_http_request("GET /v1/registry-compat/pypi/simple/fixture/ HTTP/1.1\r\n\r\n");
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, "text/html");
        assert!(response.body.contains("<!doctype html>"));
        assert!(response.body.contains("fixture-1.0.0"));
        assert!(response.body.contains(
            "/v1/registry-compat/pypi/files/pypi/fixture/1.0.0/fixture-1.0.0-py3-none-any.whl"
        ));
        assert!(response.body.contains("#sha256="));
        assert!(!response.body.contains("files.pythonhosted.org"));
        assert!(!response.body.contains("pypi.org"));
    }

    #[test]
    fn registry_compat_pypi_simple_uses_loopback_host_header() {
        let response = handle_http_request(
            "GET /v1/registry-compat/pypi/simple/fixture/ HTTP/1.1\r\nHost: 127.0.0.1:49124\r\n\r\n",
        );
        assert_eq!(response.status_code, 200);
        assert!(response.body.contains(
            "http://127.0.0.1:49124/v1/registry-compat/pypi/files/pypi/fixture/1.0.0/fixture-1.0.0-py3-none-any.whl#sha256="
        ));
    }

    #[test]
    fn registry_compat_pypi_file_supports_head() {
        let response = handle_http_request(
            "HEAD /v1/registry-compat/pypi/files/pypi/fixture/1.0.0/fixture-1.0.0-py3-none-any.whl HTTP/1.1\r\n\r\n",
        );
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, "application/octet-stream");
        assert_eq!(response.body.len(), build_pypi_fixture_wheel().len());
        assert!(response.body.as_bytes().is_empty());
        assert_eq!(header_value(&response, "Accept-Ranges"), Some("bytes"));
    }

    #[test]
    fn registry_compat_pypi_file_serves_valid_safe_wheel_bytes() {
        let response = handle_http_request(
            "GET /v1/registry-compat/pypi/files/pypi/fixture/1.0.0/fixture-1.0.0-py3-none-any.whl HTTP/1.1\r\n\r\n",
        );
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, "application/octet-stream");
        assert!(response.body.as_bytes().starts_with(b"PK\x03\x04"));
        assert!(bytes_contain(
            response.body.as_bytes(),
            b"fixture-1.0.0.dist-info/METADATA"
        ));
        assert!(bytes_contain(
            response.body.as_bytes(),
            b"fixture-1.0.0.dist-info/WHEEL"
        ));
        assert!(bytes_contain(
            response.body.as_bytes(),
            b"Root-Is-Purelib: true"
        ));
        assert!(!bytes_contain(response.body.as_bytes(), b"setup.py"));
        assert!(!bytes_contain(response.body.as_bytes(), b"build_backend"));
        assert_ne!(response.body.as_bytes(), LOCAL_DEV_CACHE_BYTES);
    }

    #[test]
    fn registry_simulation_pypi_file_serves_exact_promoted_cache_bytes() {
        let response = handle_http_request(
            "GET /v1/registry-simulations/pypi/files/pypi/fixture/1.0.0 HTTP/1.1\r\n\r\n",
        );
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, "application/octet-stream");
        assert_eq!(response.body.as_bytes(), LOCAL_DEV_CACHE_BYTES);
        assert_eq!(header_value(&response, "Accept-Ranges"), Some("bytes"));
        assert_eq!(
            header_value(&response, "Cache-Control"),
            Some("private, max-age=31536000, immutable")
        );
        assert_eq!(
            header_value(&response, "ETag"),
            Some("\"sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f\"")
        );
    }

    #[test]
    fn registry_simulation_pypi_file_head_declares_length_without_body() {
        let response = handle_http_request(
            "HEAD /v1/registry-simulations/pypi/files/pypi/fixture/1.0.0 HTTP/1.1\r\n\r\n",
        );
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, "application/octet-stream");
        assert_eq!(response.body.len(), LOCAL_DEV_CACHE_BYTES.len());
        assert!(response.body.as_bytes().is_empty());
        assert_eq!(
            header_value(&response, "ETag"),
            Some("\"sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f\"")
        );
    }

    #[test]
    fn registry_simulation_pypi_file_serves_suffix_range() {
        let response = handle_http_request(
            "GET /v1/registry-simulations/pypi/files/pypi/fixture/1.0.0 HTTP/1.1\r\nRange: bytes=-5\r\n\r\n",
        );
        assert_eq!(response.status_code, 206);
        assert_eq!(response.content_type, "application/octet-stream");
        assert_eq!(response.body.as_bytes(), b"bytes");
        assert_eq!(
            header_value(&response, "Content-Range"),
            Some("bytes 20-24/25")
        );
    }

    #[test]
    fn registry_simulation_pypi_file_fails_closed_for_wrong_ecosystem() {
        let response = handle_http_request(
            "GET /v1/registry-simulations/pypi/files/npm/fixture/1.0.0 HTTP/1.1\r\n\r\n",
        );
        assert_eq!(response.status_code, 503);
        assert!(response.body.contains("artifact_not_promoted"));
    }

    #[test]
    fn fetch_job_simulation_plans_without_fetching() {
        let response = handle_http_request(
            "POST /v1/fetch-job-simulations HTTP/1.1\r\nContent-Length: 10\r\n\r\nvalid=true",
        );
        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"state\":\"Planned\""));
        assert!(response.body.contains("\"fetch_enabled\":false"));
        assert!(response.body.contains("\"fetch_execution_not_enabled\""));
    }

    #[test]
    fn fetch_job_simulation_fails_closed_for_invalid_metadata() {
        let response = handle_http_request(
            "POST /v1/fetch-job-simulations HTTP/1.1\r\nContent-Length: 20\r\n\r\ndigest_mismatch=true",
        );
        assert_eq!(response.status_code, 409);
        assert!(response.body.contains("\"status\":\"fail_closed\""));
        assert!(response.body.contains("\"fetch_expected_digest_mismatch\""));
    }

    #[test]
    fn evidence_job_simulation_binds_metadata_without_execution() {
        let response = handle_http_request(
            "POST /v1/evidence-job-simulations HTTP/1.1\r\nContent-Length: 10\r\n\r\nvalid=true",
        );
        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"evidence_binding_ready\":true"));
        assert!(response.body.contains("\"execution_enabled\":false"));
        assert!(response.body.contains("\"detonation_attempted\":false"));
        assert!(response.body.contains("\"network_attempted\":false"));
        assert!(response
            .body
            .contains("\"evidence_job_execution_not_enabled\""));
    }

    #[test]
    fn evidence_job_simulation_fails_closed_for_attempts_or_mismatch() {
        let response = handle_http_request(
            "POST /v1/evidence-job-simulations HTTP/1.1\r\nContent-Length: 53\r\n\r\nnetwork_attempted=true&detonation_attempted=true",
        );
        assert_eq!(response.status_code, 409);
        assert!(response.body.contains("\"status\":\"fail_closed\""));
        assert!(response
            .body
            .contains("evidence_job_result_network_attempted"));
        assert!(response
            .body
            .contains("evidence_job_result_detonation_attempted"));

        let mismatch = handle_http_request(
            "POST /v1/evidence-job-simulations HTTP/1.1\r\nContent-Length: 17\r\n\r\njob_mismatch=true",
        );
        assert_eq!(mismatch.status_code, 409);
        assert!(mismatch.body.contains("evidence_job_result_job_mismatch"));
    }

    #[test]
    fn challenge_authority_simulation_accepts_first_consume_without_returning_nonce() {
        let response = handle_http_request(
            "POST /v1/challenge-authority-simulations HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(response.status_code, 200);
        assert!(response
            .body
            .contains("\"authority\":\"vault_challenge_authority.v1\""));
        assert!(response
            .body
            .contains("\"trusted_time_source\":\"vault_server_clock\""));
        assert!(response.body.contains("\"client_time_accepted\":false"));
        assert!(response
            .body
            .contains("\"first_consume_status\":\"Accepted\""));
        assert!(response.body.contains("\"accepted\":true"));
        assert!(response.body.contains("\"nonce_present\":true"));
        assert!(response.body.contains("\"raw_nonce_returned\":false"));
        assert!(!response.body.contains("proof-nonce-"));
    }

    #[test]
    fn challenge_authority_simulation_fails_closed_for_replay_unknown_tamper_and_expiry() {
        for (body, reason) in [
            ("replay=true", "provider_challenge_replayed"),
            ("unknown_challenge=true", "provider_challenge_not_issued"),
            ("mutate_context=true", "provider_challenge_context_mutated"),
            ("expired=true", "provider_challenge_expired"),
        ] {
            let response = handle_http_request(&format!(
                "POST /v1/challenge-authority-simulations HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            ));
            assert_eq!(response.status_code, 409, "{body}");
            assert!(
                response.body.contains("\"status\":\"fail_closed\""),
                "{body}"
            );
            assert!(response.body.contains(reason), "{body}");
            assert!(response.body.contains("\"accepted\":false"), "{body}");
            assert!(response.body.contains("\"exit_code\":20"), "{body}");
            assert!(!response.body.contains("proof-nonce-"), "{body}");
        }
    }

    #[test]
    fn challenge_authority_issue_and_consume_routes_are_stateful_and_sanitized() {
        let issue = handle_http_request(
            "POST /v1/challenge-authority/issue HTTP/1.1\r\nContent-Length: 79\r\n\r\nrequest_id=issue-route-1&tenant_id=tenant-route-1&subject=launch-route-1",
        );
        assert_eq!(issue.status_code, 200);
        assert!(issue.body.contains("\"status\":\"ok\""));
        assert!(issue.body.contains("\"raw_nonce_returned\":false"));
        assert!(issue.body.contains("\"nonce_present\":true"));
        assert!(issue.body.contains("\"challenge_authority_audit_summary\""));
        assert!(issue.body.contains("\"operation\":\"issue\""));
        assert!(issue.body.contains("\"raw_nonce_stored\":false"));
        assert!(issue
            .body
            .contains("\"audit_event_id\":\"audit-challenge-authority-issue-issue-route-1\""));
        assert!(!issue.body.contains("proof-nonce-"));
        let challenge_id = json_field(&issue.body.to_string(), "challenge_id");
        assert!(!challenge_id.is_empty());

        let body = format!(
            "request_id=consume-route-1&tenant_id=tenant-route-1&challenge_id={}&subject=launch-route-1&context_hash=sha256:1111111111111111111111111111111111111111111111111111111111111111&vault_host=127.0.0.1:4873",
            challenge_id
        );
        let consume = handle_http_request(&format!(
            "POST /v1/challenge-authority/consume HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        ));
        assert_eq!(consume.status_code, 200);
        assert!(consume.body.contains("\"consume_status\":\"Accepted\""));
        assert!(consume.body.contains("\"accepted\":true"));
        assert!(consume.body.contains("\"operation\":\"consume\""));
        assert!(consume.body.contains("\"raw_nonce_returned\":false"));
        assert!(consume.body.contains("\"raw_nonce_stored\":false"));
        assert!(consume.body.contains("\"probe_destination_count\":15"));
        assert!(consume
            .body
            .contains("\"audit_event_id\":\"audit-challenge-authority-consume-consume-route-1\""));
        assert!(!consume.body.contains("proof-nonce-"));

        let replay = handle_http_request(&format!(
            "POST /v1/challenge-authority/consume HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        ));
        assert_eq!(replay.status_code, 409);
        assert!(replay.body.contains("provider_challenge_replayed"));
        assert!(replay.body.contains("\"accepted\":false"));
        assert!(replay.body.contains("\"operation\":\"consume\""));
        assert!(replay.body.contains("\"raw_nonce_stored\":false"));
    }

    #[test]
    fn challenge_authority_consume_route_rejects_unknown_and_cross_tenant_ids() {
        let unknown_body = "tenant_id=tenant-route-unknown&challenge_id=proof-challenge-sha256:missing&subject=launch-route-unknown&context_hash=sha256:1111111111111111111111111111111111111111111111111111111111111111&vault_host=127.0.0.1:4873";
        let unknown = handle_http_request(&format!(
            "POST /v1/challenge-authority/consume HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            unknown_body.len(),
            unknown_body
        ));
        assert_eq!(unknown.status_code, 409);
        assert!(unknown.body.contains("provider_challenge_not_issued"));

        let issue = handle_http_request(
            "POST /v1/challenge-authority/issue HTTP/1.1\r\nContent-Length: 84\r\n\r\nrequest_id=issue-route-tenant&tenant_id=tenant-route-owned&subject=launch-route-tenant",
        );
        let challenge_id = json_field(&issue.body.to_string(), "challenge_id");
        let body = format!(
            "tenant_id=tenant-route-other&challenge_id={}&subject=launch-route-tenant&context_hash=sha256:1111111111111111111111111111111111111111111111111111111111111111&vault_host=127.0.0.1:4873",
            challenge_id
        );
        let mismatch = handle_http_request(&format!(
            "POST /v1/challenge-authority/consume HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        ));
        assert_eq!(mismatch.status_code, 409);
        assert!(mismatch
            .body
            .contains("challenge_authority_tenant_mismatch"));
        assert!(mismatch.body.contains("\"probe_destination_count\":0"));
        assert!(mismatch.body.contains("\"expires_at_unix_seconds\":0"));
    }

    #[test]
    fn challenge_authority_file_store_routes_persist_and_do_not_echo_store_path() {
        let store_path = unique_dev_store_path("challenge-authority-route-file-store");
        let store_arg = store_path.to_string_lossy().to_string();
        let issue_body = format!(
            "request_id=issue-file-route&tenant_id=tenant-file-route&subject=launch-file-route&store_path={store_arg}"
        );
        let issue = handle_http_request(&format!(
            "POST /v1/challenge-authority/issue HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            issue_body.len(),
            issue_body
        ));
        assert_eq!(issue.status_code, 200);
        assert!(issue.body.contains("\"store_mode\":\"file\""));
        assert!(issue.body.contains("\"store_available\":true"));
        assert!(issue.body.contains("\"store_stale_lock_recovered\":false"));
        assert!(!issue.body.contains(&store_arg));
        assert!(!issue.body.contains("proof-nonce-"));
        let challenge_id = json_field(&issue.body.to_string(), "challenge_id");
        assert!(!challenge_id.is_empty());

        let consume_body = format!(
            "request_id=consume-file-route&tenant_id=tenant-file-route&challenge_id={challenge_id}&subject=launch-file-route&context_hash=sha256:1111111111111111111111111111111111111111111111111111111111111111&vault_host=127.0.0.1:4873&store_path={store_arg}"
        );
        let consume = handle_http_request(&format!(
            "POST /v1/challenge-authority/consume HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            consume_body.len(),
            consume_body
        ));
        assert_eq!(consume.status_code, 200);
        assert!(consume.body.contains("\"store_mode\":\"file\""));
        assert!(consume.body.contains("\"consume_status\":\"Accepted\""));
        assert!(consume.body.contains("\"accepted\":true"));
        assert!(!consume.body.contains(&store_arg));

        let replay = handle_http_request(&format!(
            "POST /v1/challenge-authority/consume HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            consume_body.len(),
            consume_body
        ));
        assert_eq!(replay.status_code, 409);
        assert!(replay.body.contains("provider_challenge_replayed"));
        assert!(replay.body.contains("\"store_mode\":\"file\""));
        assert!(!replay.body.contains(&store_arg));
        let _ = std::fs::remove_file(&store_path);
    }

    #[test]
    fn challenge_authority_consume_route_rejects_metadata_mismatch_without_consuming() {
        let issue = handle_http_request(
            "POST /v1/challenge-authority/issue HTTP/1.1\r\nContent-Length: 83\r\n\r\nrequest_id=issue-route-bind&tenant_id=tenant-route-bind&subject=launch-route-bind",
        );
        assert_eq!(issue.status_code, 200);
        let challenge_id = json_field(&issue.body.to_string(), "challenge_id");
        let mismatch_body = format!(
            "request_id=consume-route-bind-bad&tenant_id=tenant-route-bind&challenge_id={challenge_id}&subject=other-launch&context_hash=sha256:1111111111111111111111111111111111111111111111111111111111111111&vault_host=127.0.0.1:4873"
        );
        let mismatch = handle_http_request(&format!(
            "POST /v1/challenge-authority/consume HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            mismatch_body.len(),
            mismatch_body
        ));
        assert_eq!(mismatch.status_code, 409);
        assert!(mismatch
            .body
            .contains("challenge_authority_subject_mismatch"));
        assert!(!mismatch.body.contains("proof-nonce-"));

        let good_body = format!(
            "request_id=consume-route-bind-good&tenant_id=tenant-route-bind&challenge_id={challenge_id}&subject=launch-route-bind&context_hash=sha256:1111111111111111111111111111111111111111111111111111111111111111&vault_host=127.0.0.1:4873"
        );
        let accepted = handle_http_request(&format!(
            "POST /v1/challenge-authority/consume HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            good_body.len(),
            good_body
        ));
        assert_eq!(accepted.status_code, 200);
        assert!(accepted.body.contains("\"accepted\":true"));
    }

    #[test]
    fn challenge_authority_file_store_route_rejects_non_temp_paths() {
        let outside = std::env::current_dir()
            .expect("current dir")
            .join("challenge-authority-outside-store.txt");
        let outside_arg = outside.to_string_lossy().to_string();
        let body = format!(
            "request_id=issue-bad-store&tenant_id=tenant-bad-store&store_path={outside_arg}"
        );
        let response = handle_http_request(&format!(
            "POST /v1/challenge-authority/issue HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        ));
        assert_eq!(response.status_code, 409);
        assert!(response.body.contains("\"status\":\"fail_closed\""));
        assert!(response
            .body
            .contains("challenge_authority_store_path_outside_temp"));
        assert!(response.body.contains("\"store_available\":false"));
        assert!(!response.body.contains(&outside_arg));
        assert!(!outside.exists());
    }

    #[test]
    fn challenge_authority_routes_write_minimized_audit_when_configured() {
        let store_path = unique_dev_store_path("challenge-authority-route-audit-store");
        let audit_path = unique_dev_audit_path("challenge-authority-route-audit");
        let store_arg = store_path.to_string_lossy().to_string();
        let audit_arg = audit_path.to_string_lossy().to_string();
        let issue_body = format!(
            "request_id=issue-audit-route&tenant_id=tenant-audit-route&subject=launch-audit-route&store_path={store_arg}&audit_path={audit_arg}"
        );
        let issue = handle_http_request(&format!(
            "POST /v1/challenge-authority/issue HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            issue_body.len(),
            issue_body
        ));
        assert_eq!(issue.status_code, 200);
        assert!(issue.body.contains("\"audit_configured\":true"));
        assert!(issue.body.contains("\"audit_status\":\"written\""));
        assert!(!issue.body.contains(&audit_arg));
        assert!(!issue.body.contains(&store_arg));
        assert!(!issue.body.contains("proof-nonce-"));
        let challenge_id = json_field(&issue.body.to_string(), "challenge_id");

        let consume_body = format!(
            "request_id=consume-audit-route&tenant_id=tenant-audit-route&challenge_id={challenge_id}&subject=launch-audit-route&context_hash=sha256:1111111111111111111111111111111111111111111111111111111111111111&vault_host=127.0.0.1:4873&store_path={store_arg}&audit_path={audit_arg}"
        );
        let consume = handle_http_request(&format!(
            "POST /v1/challenge-authority/consume HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            consume_body.len(),
            consume_body
        ));
        assert_eq!(consume.status_code, 200);
        assert!(consume.body.contains("\"audit_configured\":true"));
        assert!(consume.body.contains("\"audit_status\":\"written\""));
        assert!(!consume.body.contains(&audit_arg));
        assert!(!consume.body.contains(&store_arg));

        let persisted = std::fs::read_to_string(&audit_path).expect("audit jsonl");
        assert_eq!(persisted.lines().count(), 2);
        assert!(persisted.contains("\"challenge_authority_summary\""));
        assert!(persisted.contains("\"operation\":\"issue\""));
        assert!(persisted.contains("\"operation\":\"consume\""));
        assert!(persisted.contains("\"raw_nonce_returned\":false"));
        assert!(persisted.contains("\"raw_nonce_stored\":false"));
        assert!(!persisted.contains("proof-nonce-"));
        assert!(!persisted.contains(&audit_arg));
        assert!(!persisted.contains(&store_arg));
        let _ = std::fs::remove_file(&store_path);
        let _ = std::fs::remove_file(&audit_path);
    }

    #[test]
    fn challenge_authority_audit_path_rejection_happens_before_store_mutation() {
        let store_path = unique_dev_store_path("challenge-authority-route-audit-reject-store");
        let store_arg = store_path.to_string_lossy().to_string();
        let outside = std::env::current_dir()
            .expect("current dir")
            .join("challenge-authority-outside-audit.jsonl");
        let outside_arg = outside.to_string_lossy().to_string();
        let body = format!(
            "request_id=issue-bad-audit&tenant_id=tenant-bad-audit&store_path={store_arg}&audit_path={outside_arg}"
        );
        let response = handle_http_request(&format!(
            "POST /v1/challenge-authority/issue HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        ));
        assert_eq!(response.status_code, 409);
        assert!(response.body.contains("\"status\":\"fail_closed\""));
        assert!(response
            .body
            .contains("challenge_authority_audit_path_outside_temp"));
        assert!(response.body.contains("\"audit_status\":\"error\""));
        assert!(!response.body.contains(&outside_arg));
        assert!(!response.body.contains(&store_arg));
        assert!(!store_path.exists());
        assert!(!outside.exists());
    }

    #[test]
    fn challenge_authority_routes_escape_request_controlled_json_fields() {
        let body = "request_id=issue-route-quote\"&tenant_id=tenant-route-quote\"&subject=launch-route-quote\"&context_hash=sha256:quote\"&vault_host=127.0.0.1:4873\"";
        let issue = handle_http_request(&format!(
            "POST /v1/challenge-authority/issue HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        ));
        assert_eq!(issue.status_code, 200);
        assert!(issue.body.contains("issue-route-quote\\\""));
        assert!(issue.body.contains("tenant-route-quote\\\""));
        assert!(issue.body.contains("launch-route-quote\\\""));
        assert!(issue.body.contains("sha256:quote\\\""));
        assert!(issue.body.contains("127.0.0.1:4873\\\""));
        assert!(!issue.body.contains("proof-nonce-"));
    }

    #[test]
    fn static_manifest_job_simulation_binds_clean_metadata_only() {
        let response = handle_http_request(
            "POST /v1/static-manifest-job-simulations HTTP/1.1\r\nContent-Length: 18\r\n\r\nmanifest=clean_npm&job_id=static-route-clean",
        );
        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"evidence_binding_ready\":true"));
        assert!(response.body.contains("\"job_log_stored\":true"));
        assert!(response
            .body
            .contains("\"job_log_id\":\"logs/static-route-clean/sha256:"));
        assert!(response.body.contains("\"raw_log_captured\":false"));
        assert!(response.body.contains("\"execution_enabled\":false"));
        assert!(response.body.contains("\"detonation_attempted\":false"));
        assert!(response.body.contains("\"network_attempted\":false"));
        assert!(response.body.contains("\"log_digest\":\"sha256:"));
        assert!(!response.body.contains("postinstall"));
        assert!(!response.body.contains("build-backend"));
    }

    #[test]
    fn static_manifest_job_simulation_fails_closed_for_malicious_manifest() {
        let response = handle_http_request(
            "POST /v1/static-manifest-job-simulations HTTP/1.1\r\nContent-Length: 22\r\n\r\nmanifest=malicious_npm&job_id=static-route-malicious",
        );
        assert_eq!(response.status_code, 409);
        assert!(response.body.contains("\"status\":\"fail_closed\""));
        assert!(response.body.contains("\"job_log_stored\":true"));
        assert!(response.body.contains("npm_lifecycle_postinstall"));
        assert!(response.body.contains("evidence_job_result_not_passed"));
        assert!(response.body.contains("\"execution_enabled\":false"));
        assert!(!response.body.contains("node postinstall.js"));
    }

    #[test]
    fn static_manifest_job_simulation_binds_pep517_suspicion_without_execution() {
        let response = handle_http_request(
            "POST /v1/static-manifest-job-simulations HTTP/1.1\r\nContent-Length: 18\r\n\r\nmanifest=pyproject&job_id=static-route-pyproject",
        );
        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("pypi_pep517_build_backend"));
        assert!(response.body.contains("\"evidence_binding_ready\":true"));
        assert!(response.body.contains("\"job_log_stored\":true"));
        assert!(response.body.contains("\"execution_enabled\":false"));
        assert!(!response.body.contains("fixture_backend"));
    }

    #[test]
    fn static_manifest_job_simulation_fails_closed_for_empty_manifest() {
        let response = handle_http_request(
            "POST /v1/static-manifest-job-simulations HTTP/1.1\r\nContent-Length: 14\r\n\r\nmanifest=empty&job_id=static-route-empty",
        );
        assert_eq!(response.status_code, 409);
        assert!(response.body.contains("static_manifest_empty"));
        assert!(response.body.contains("evidence_job_result_not_passed"));
    }

    #[test]
    fn static_manifest_job_simulation_rejects_raw_or_tampered_log_storage() {
        let raw = handle_http_request(
            "POST /v1/static-manifest-job-simulations HTTP/1.1\r\nContent-Length: 39\r\n\r\nmanifest=clean_npm&job_id=static-route-raw&raw_log_captured=true",
        );
        assert_eq!(raw.status_code, 409);
        assert!(raw.body.contains("job_log_raw_log_captured"));
        assert!(raw.body.contains("\"job_log_stored\":false"));
        assert!(raw.body.contains("\"raw_log_captured\":true"));

        let tampered = handle_http_request(
            "POST /v1/static-manifest-job-simulations HTTP/1.1\r\nContent-Length: 43\r\n\r\nmanifest=clean_npm&job_id=static-route-tampered&tamper_log_digest=true",
        );
        assert_eq!(tampered.status_code, 409);
        assert!(tampered.body.contains("job_log_digest_mismatch"));
        assert!(tampered.body.contains("\"job_log_stored\":false"));
    }

    #[test]
    fn static_manifest_job_simulation_rejects_rewrite_for_same_job_id() {
        let first = handle_http_request(
            "POST /v1/static-manifest-job-simulations HTTP/1.1\r\n\r\nmanifest=clean_npm&job_id=static-route-conflict",
        );
        assert_eq!(first.status_code, 200);
        assert!(first.body.contains("\"job_log_stored\":true"));

        let second = handle_http_request(
            "POST /v1/static-manifest-job-simulations HTTP/1.1\r\n\r\nmanifest=malicious_npm&job_id=static-route-conflict",
        );
        assert_eq!(second.status_code, 409);
        assert!(second.body.contains("job_log_job_id_conflict"));
        assert!(second.body.contains("\"job_log_stored\":false"));
    }

    #[test]
    fn static_manifest_job_simulation_rejects_missing_or_unknown_selector() {
        let missing =
            handle_http_request("POST /v1/static-manifest-job-simulations HTTP/1.1\r\n\r\n");
        assert_eq!(missing.status_code, 409);
        assert!(missing.body.contains("static_manifest_selector_missing"));

        let unknown = handle_http_request(
            "POST /v1/static-manifest-job-simulations HTTP/1.1\r\nX-Test: manifest=clean_npm\r\nContent-Length: 16\r\n\r\nmanifest=unknown",
        );
        assert_eq!(unknown.status_code, 409);
        assert!(unknown.body.contains("static_manifest_selector_invalid"));
        assert!(!unknown.body.contains("\"evidence_binding_ready\":true"));
    }

    #[test]
    fn unknown_route_fails_closed() {
        let response = handle_http_request("GET /npm/fixture HTTP/1.1\r\n\r\n");
        assert_eq!(response.status_code, 404);
        assert!(response.body.contains("route_not_found"));
    }
}
