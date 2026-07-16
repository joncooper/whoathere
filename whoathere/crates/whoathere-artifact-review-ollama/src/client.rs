use crate::protocol::{
    prepare_ollama_chat_request_v1, OllamaAdapterErrorV1, OllamaAdapterOutcomeV1,
    OllamaAdapterTerminalFrameV1, OllamaInvocationResultV1, MAX_OLLAMA_CHAT_RESPONSE_BYTES_V1,
    MAX_OLLAMA_HTTP_HEADER_BYTES_V1, MAX_OLLAMA_METADATA_RESPONSE_BYTES_V1,
};
use crate::{
    OLLAMA_ADAPTER_ID_V1, OLLAMA_ADAPTER_VERSION_V1, OLLAMA_LOOPBACK_ENDPOINT_V1,
    OLLAMA_TERMINAL_FRAME_SCHEMA_V1,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;
use whoathere_artifact::Sha256Digest;
use whoathere_detector::{
    ValidatedArtifactReviewProviderInputV2, MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2,
};

const OLLAMA_ADDRESS_V1: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 11_434);
const CONNECT_TIMEOUT_V1: Duration = Duration::from_secs(2);
const IO_TIMEOUT_V1: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OllamaVersionResponseV1 {
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OllamaTagsResponseV1 {
    models: Vec<OllamaTagV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OllamaTagV1 {
    name: String,
    model: String,
    modified_at: String,
    size: u64,
    digest: String,
    details: OllamaModelDetailsV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OllamaModelDetailsV1 {
    #[serde(default)]
    parent_model: String,
    format: String,
    family: String,
    families: Vec<String>,
    parameter_size: String,
    quantization_level: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OllamaChatResponseV1 {
    model: String,
    created_at: String,
    message: OllamaChatResponseMessageV1,
    done: bool,
    done_reason: String,
    total_duration: u64,
    load_duration: u64,
    prompt_eval_count: u64,
    prompt_eval_duration: u64,
    eval_count: u64,
    eval_duration: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OllamaChatResponseMessageV1 {
    role: String,
    content: String,
    #[serde(default)]
    thinking: Option<String>,
    #[serde(default)]
    images: Option<Vec<String>>,
    #[serde(default)]
    tool_calls: Option<Vec<serde_json::Value>>,
}

struct RawHttpResponseV1 {
    body: Vec<u8>,
}

pub fn execute_ollama_chat_v1(
    input: &ValidatedArtifactReviewProviderInputV2,
) -> Result<OllamaInvocationResultV1, OllamaAdapterErrorV1> {
    execute_ollama_chat_at_v1(input, OLLAMA_ADDRESS_V1)
}

fn execute_ollama_chat_at_v1(
    input: &ValidatedArtifactReviewProviderInputV2,
    address: SocketAddrV4,
) -> Result<OllamaInvocationResultV1, OllamaAdapterErrorV1> {
    let prepared = prepare_ollama_chat_request_v1(input)?;
    let pre_version: OllamaVersionResponseV1 = get_json(
        address,
        "/api/version",
        MAX_OLLAMA_METADATA_RESPONSE_BYTES_V1,
    )?;
    validate_identity_text(&pre_version.version)?;
    let pre_tags: OllamaTagsResponseV1 =
        get_json(address, "/api/tags", MAX_OLLAMA_METADATA_RESPONSE_BYTES_V1)?;
    let pre_digest = exact_model_digest(&pre_tags, &input.model().model_id)?;
    let expected_model_content_sha256 = input
        .model()
        .measured_content_sha256()
        .ok_or(OllamaAdapterErrorV1::ModelDigestMismatch)?;
    if &pre_digest != expected_model_content_sha256 {
        return Err(OllamaAdapterErrorV1::ModelDigestMismatch);
    }

    let raw_chat = request_json(
        address,
        "POST",
        "/api/chat",
        Some(prepared.request_bytes()),
        MAX_OLLAMA_CHAT_RESPONSE_BYTES_V1,
    )?;
    let chat: OllamaChatResponseV1 = strict_json(&raw_chat.body)?;

    let post_version: OllamaVersionResponseV1 = get_json(
        address,
        "/api/version",
        MAX_OLLAMA_METADATA_RESPONSE_BYTES_V1,
    )?;
    let post_tags: OllamaTagsResponseV1 =
        get_json(address, "/api/tags", MAX_OLLAMA_METADATA_RESPONSE_BYTES_V1)?;
    let post_digest = exact_model_digest(&post_tags, &input.model().model_id)?;
    if pre_version.version != post_version.version || pre_digest != post_digest {
        return Err(OllamaAdapterErrorV1::ModelIdentityDrift);
    }
    if post_digest != *expected_model_content_sha256 {
        return Err(OllamaAdapterErrorV1::ModelDigestMismatch);
    }

    validate_chat_response(input, &chat)?;
    let model_output = chat.message.content.into_bytes();
    let inference = input.inference();
    let terminal_frame = OllamaAdapterTerminalFrameV1 {
        schema_version: OLLAMA_TERMINAL_FRAME_SCHEMA_V1.to_string(),
        adapter_id: OLLAMA_ADAPTER_ID_V1.to_string(),
        adapter_version: OLLAMA_ADAPTER_VERSION_V1.to_string(),
        outcome: OllamaAdapterOutcomeV1::Completed,
        work_item_id: input.work_item_id().clone(),
        invocation_sha256: input.invocation_sha256().clone(),
        provider_input_sha256: input.provider_input_sha256().clone(),
        endpoint: OLLAMA_LOOPBACK_ENDPOINT_V1.to_string(),
        server_version: post_version.version,
        requested_model: input.model().model_id.clone(),
        response_model: chat.model,
        expected_model_content_sha256: expected_model_content_sha256.clone(),
        pre_model_content_sha256: pre_digest,
        post_model_content_sha256: post_digest,
        system_message_sha256: prepared.system_message_sha256().clone(),
        user_message_sha256: prepared.user_message_sha256().clone(),
        role_mapping_contract_sha256: prepared.role_mapping_contract_sha256().clone(),
        api_request_sha256: prepared.api_request_sha256().clone(),
        raw_api_response_sha256: Sha256Digest::from_bytes(&raw_chat.body),
        model_output_sha256: Sha256Digest::from_bytes(&model_output),
        model_output_byte_len: model_output.len() as u64,
        prompt_eval_count: chat.prompt_eval_count,
        eval_count: chat.eval_count,
        done_reason: chat.done_reason,
        seed: inference.seed,
        temperature_milli: inference.temperature_milli,
        top_p_milli: inference.top_p_milli,
        context_tokens: inference.context_tokens,
        max_output_tokens: inference.max_output_tokens,
        observed_transport: "literal_ipv4_loopback_http_1_1".to_string(),
        model_identity_posture: "server_reported_manifest_digest_matched_pinned_expected_value"
            .to_string(),
    };
    terminal_frame.validate_static_contract()?;
    Ok(OllamaInvocationResultV1 {
        model_output,
        terminal_frame,
    })
}

fn validate_chat_response(
    input: &ValidatedArtifactReviewProviderInputV2,
    response: &OllamaChatResponseV1,
) -> Result<(), OllamaAdapterErrorV1> {
    if response.model != input.model().model_id {
        return Err(OllamaAdapterErrorV1::ResponseModelMismatch);
    }
    if !response.done {
        return Err(OllamaAdapterErrorV1::ResponseIncomplete);
    }
    if response.done_reason == "length" {
        return Err(OllamaAdapterErrorV1::ResponseTruncated);
    }
    if response.done_reason != "stop" {
        return Err(OllamaAdapterErrorV1::ResponseIncomplete);
    }
    if response.message.role != "assistant"
        || response
            .message
            .thinking
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || response
            .message
            .images
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || response
            .message
            .tool_calls
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || response.message.content.len() > MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2
    {
        return Err(OllamaAdapterErrorV1::UnsupportedResponseContent);
    }
    if response.prompt_eval_count > u64::from(input.inference().context_tokens)
        || response.eval_count > u64::from(input.inference().max_output_tokens)
    {
        return Err(OllamaAdapterErrorV1::ResponseTokenLimitExceeded);
    }
    validate_identity_text(&response.created_at)?;
    let _ = (
        response.total_duration,
        response.load_duration,
        response.prompt_eval_duration,
        response.eval_duration,
    );
    Ok(())
}

fn exact_model_digest(
    tags: &OllamaTagsResponseV1,
    expected_name: &str,
) -> Result<Sha256Digest, OllamaAdapterErrorV1> {
    let matches = tags
        .models
        .iter()
        .filter(|model| model.name == expected_name && model.model == expected_name)
        .collect::<Vec<_>>();
    let [model] = matches.as_slice() else {
        return if matches.is_empty() {
            Err(OllamaAdapterErrorV1::ModelMissing)
        } else {
            Err(OllamaAdapterErrorV1::ModelAmbiguous)
        };
    };
    validate_identity_text(&model.modified_at)?;
    if model.details.parent_model.len() > 256
        || !model.details.parent_model.is_ascii()
        || model
            .details
            .parent_model
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err(OllamaAdapterErrorV1::InvalidApiResponse);
    }
    validate_identity_text(&model.details.format)?;
    validate_identity_text(&model.details.family)?;
    validate_identity_text(&model.details.parameter_size)?;
    validate_identity_text(&model.details.quantization_level)?;
    if model.size == 0
        || model.details.families.is_empty()
        || model
            .details
            .families
            .iter()
            .any(|value| validate_identity_text(value).is_err())
    {
        return Err(OllamaAdapterErrorV1::InvalidApiResponse);
    }
    parse_ollama_digest(&model.digest)
}

fn parse_ollama_digest(value: &str) -> Result<Sha256Digest, OllamaAdapterErrorV1> {
    let canonical = if value.starts_with("sha256:") {
        value.to_string()
    } else {
        format!("sha256:{value}")
    };
    Sha256Digest::parse(canonical).map_err(|_| OllamaAdapterErrorV1::InvalidApiResponse)
}

fn validate_identity_text(value: &str) -> Result<(), OllamaAdapterErrorV1> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || !byte.is_ascii())
    {
        return Err(OllamaAdapterErrorV1::InvalidApiResponse);
    }
    Ok(())
}

fn get_json<T: DeserializeOwned>(
    address: SocketAddrV4,
    path: &str,
    limit: usize,
) -> Result<T, OllamaAdapterErrorV1> {
    let response = request_json(address, "GET", path, None, limit)?;
    strict_json(&response.body)
}

fn strict_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, OllamaAdapterErrorV1> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value =
        T::deserialize(&mut deserializer).map_err(|_| OllamaAdapterErrorV1::InvalidApiResponse)?;
    deserializer
        .end()
        .map_err(|_| OllamaAdapterErrorV1::InvalidApiResponse)?;
    Ok(value)
}

fn request_json(
    address: SocketAddrV4,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    body_limit: usize,
) -> Result<RawHttpResponseV1, OllamaAdapterErrorV1> {
    if !matches!(method, "GET" | "POST")
        || !matches!(path, "/api/version" | "/api/tags" | "/api/chat")
        || (method == "GET" && body.is_some())
        || (method == "POST" && body.is_none())
    {
        return Err(OllamaAdapterErrorV1::InvalidHttpResponse);
    }
    let socket = SocketAddr::V4(address);
    let mut stream = TcpStream::connect_timeout(&socket, CONNECT_TIMEOUT_V1)
        .map_err(|_| OllamaAdapterErrorV1::ConnectFailed)?;
    if stream
        .peer_addr()
        .map_err(|_| OllamaAdapterErrorV1::IoFailed)?
        != socket
        || !stream
            .peer_addr()
            .map_err(|_| OllamaAdapterErrorV1::IoFailed)?
            .ip()
            .is_loopback()
    {
        return Err(OllamaAdapterErrorV1::ConnectFailed);
    }
    stream
        .set_read_timeout(Some(IO_TIMEOUT_V1))
        .map_err(|_| OllamaAdapterErrorV1::IoFailed)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT_V1))
        .map_err(|_| OllamaAdapterErrorV1::IoFailed)?;
    stream
        .set_nodelay(true)
        .map_err(|_| OllamaAdapterErrorV1::IoFailed)?;

    let body = body.unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
        address.ip(),
        address.port()
    )
    .into_bytes();
    if method == "POST" {
        request.extend_from_slice(b"Content-Type: application/json\r\n");
        request.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(body);
    stream
        .write_all(&request)
        .map_err(|_| OllamaAdapterErrorV1::IoFailed)?;
    stream.flush().map_err(|_| OllamaAdapterErrorV1::IoFailed)?;

    let total_limit = MAX_OLLAMA_HTTP_HEADER_BYTES_V1
        .checked_add(body_limit)
        .and_then(|value| value.checked_add(1))
        .ok_or(OllamaAdapterErrorV1::ResponseLimitExceeded)?;
    let mut received = Vec::with_capacity(total_limit.min(64 * 1024));
    stream
        .take(total_limit as u64)
        .read_to_end(&mut received)
        .map_err(|_| OllamaAdapterErrorV1::IoFailed)?;
    if received.len() >= total_limit {
        return Err(OllamaAdapterErrorV1::ResponseLimitExceeded);
    }
    parse_http_response(received, body_limit)
}

fn parse_http_response(
    received: Vec<u8>,
    body_limit: usize,
) -> Result<RawHttpResponseV1, OllamaAdapterErrorV1> {
    let header_end = received
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or(OllamaAdapterErrorV1::InvalidHttpResponse)?;
    if header_end > MAX_OLLAMA_HTTP_HEADER_BYTES_V1 {
        return Err(OllamaAdapterErrorV1::InvalidHttpResponse);
    }
    let header_text = std::str::from_utf8(&received[..header_end - 4])
        .map_err(|_| OllamaAdapterErrorV1::InvalidHttpResponse)?;
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .ok_or(OllamaAdapterErrorV1::InvalidHttpResponse)?;
    let mut status_parts = status.splitn(3, ' ');
    if status_parts.next() != Some("HTTP/1.1") {
        return Err(OllamaAdapterErrorV1::InvalidHttpResponse);
    }
    let status_code = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(OllamaAdapterErrorV1::InvalidHttpResponse)?;
    if status_parts.next().is_none() {
        return Err(OllamaAdapterErrorV1::InvalidHttpResponse);
    }
    if status_code != 200 {
        return Err(OllamaAdapterErrorV1::HttpStatusRejected);
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() || line.starts_with([' ', '\t']) {
            return Err(OllamaAdapterErrorV1::InvalidHttpResponse);
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(OllamaAdapterErrorV1::InvalidHttpResponse)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(OllamaAdapterErrorV1::InvalidHttpResponse);
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty()
            || !value.is_ascii()
            || value.bytes().any(|byte| byte.is_ascii_control())
            || headers.insert(name, value.to_string()).is_some()
        {
            return Err(OllamaAdapterErrorV1::InvalidHttpResponse);
        }
    }
    let content_type = headers
        .get("content-type")
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if content_type != Some("application/json")
        || headers.contains_key("transfer-encoding")
        || headers.contains_key("location")
        || headers
            .get("content-encoding")
            .is_some_and(|value| value != "identity")
    {
        return Err(OllamaAdapterErrorV1::InvalidHttpResponse);
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or(OllamaAdapterErrorV1::InvalidHttpResponse)?;
    let body = received
        .get(header_end..)
        .ok_or(OllamaAdapterErrorV1::InvalidHttpResponse)?;
    if content_length != body.len() || body.len() > body_limit {
        return Err(OllamaAdapterErrorV1::ResponseLimitExceeded);
    }
    Ok(RawHttpResponseV1 {
        body: body.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::validated_input;
    use serde_json::json;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    struct FakeResponse {
        status: &'static str,
        headers: Vec<(&'static str, &'static str)>,
        body: Vec<u8>,
    }

    fn json_response(value: serde_json::Value) -> FakeResponse {
        FakeResponse {
            status: "200 OK",
            headers: vec![("Content-Type", "application/json")],
            body: serde_json::to_vec(&value).expect("fake JSON response"),
        }
    }

    fn version_response() -> FakeResponse {
        json_response(json!({"version":"0.12.0-inert"}))
    }

    fn tags_response(input: &ValidatedArtifactReviewProviderInputV2, digest: &str) -> FakeResponse {
        json_response(json!({
            "models":[{
                "name":input.model().model_id,
                "model":input.model().model_id,
                "modified_at":"2026-07-10T00:00:00Z",
                "size":4096,
                "digest":digest,
                "details":{
                    "format":"gguf",
                    "family":"qwen3",
                    "families":["qwen3"],
                    "parameter_size":"8B",
                    "quantization_level":"Q4_K_M"
                }
            }]
        }))
    }

    fn chat_response(
        input: &ValidatedArtifactReviewProviderInputV2,
        done_reason: &str,
    ) -> FakeResponse {
        let model_output = json!({
            "schema_version":"whoathere.artifact_review_model_output.v2",
            "work_item_id":input.work_item_id(),
            "invocation_sha256":input.invocation_sha256(),
            "verdict":"no_finding",
            "findings":[]
        });
        json_response(json!({
            "model":input.model().model_id,
            "created_at":"2026-07-10T00:00:01Z",
            "message":{
                "role":"assistant",
                "content":serde_json::to_string(&model_output).expect("model output JSON")
            },
            "done":true,
            "done_reason":done_reason,
            "total_duration":1000,
            "load_duration":100,
            "prompt_eval_count":512,
            "prompt_eval_duration":200,
            "eval_count":64,
            "eval_duration":700
        }))
    }

    fn spawn_fake_server(
        responses: Vec<FakeResponse>,
    ) -> (
        SocketAddrV4,
        mpsc::Receiver<Vec<u8>>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake Ollama");
        let address = match listener.local_addr().expect("fake address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => panic!("IPv4 listener returned IPv6 address"),
        };
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            for response in responses {
                let (mut stream, peer) = listener.accept().expect("accept fake request");
                assert!(peer.ip().is_loopback());
                let request = read_http_request(&mut stream);
                sender.send(request).expect("capture fake request");
                let mut encoded = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status,
                    response.body.len()
                )
                .into_bytes();
                for (name, value) in response.headers {
                    encoded.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
                }
                encoded.extend_from_slice(b"\r\n");
                encoded.extend_from_slice(&response.body);
                stream.write_all(&encoded).expect("write fake response");
                stream.flush().expect("flush fake response");
            }
        });
        (address, receiver, handle)
    }

    fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("fake read timeout");
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut chunk).expect("read fake request");
            assert!(read > 0, "request ended before headers");
            request.extend_from_slice(&chunk[..read]);
            assert!(request.len() <= 1024 * 1024, "fake request exceeded cap");
            if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = std::str::from_utf8(&request[..header_end]).expect("request headers UTF-8");
        let content_length = headers
            .split("\r\n")
            .find_map(|line| {
                line.strip_prefix("Content-Length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .unwrap_or(0);
        let expected = header_end + content_length;
        while request.len() < expected {
            let read = stream.read(&mut chunk).expect("read fake request body");
            assert!(read > 0, "request ended before body");
            request.extend_from_slice(&chunk[..read]);
        }
        assert_eq!(request.len(), expected);
        request
    }

    fn successful_responses(
        input: &ValidatedArtifactReviewProviderInputV2,
        done_reason: &str,
    ) -> Vec<FakeResponse> {
        let digest = input
            .model()
            .measured_content_sha256()
            .expect("measured local fixture model")
            .as_str()
            .strip_prefix("sha256:")
            .expect("canonical digest");
        vec![
            version_response(),
            tags_response(input, digest),
            chat_response(input, done_reason),
            version_response(),
            tags_response(input, digest),
        ]
    }

    #[test]
    fn fake_loopback_server_executes_exact_pinned_role_separated_request() {
        let input = validated_input();
        let prepared = prepare_ollama_chat_request_v1(&input).expect("prepared request");
        let (address, receiver, handle) = spawn_fake_server(successful_responses(&input, "stop"));
        let result = execute_ollama_chat_at_v1(&input, address).expect("fake Ollama invocation");
        handle.join().expect("fake server thread");
        let requests = receiver.into_iter().collect::<Vec<_>>();
        assert_eq!(requests.len(), 5);
        assert!(requests[0].starts_with(b"GET /api/version HTTP/1.1\r\n"));
        assert!(requests[1].starts_with(b"GET /api/tags HTTP/1.1\r\n"));
        assert!(requests[2].starts_with(b"POST /api/chat HTTP/1.1\r\n"));
        assert!(requests[3].starts_with(b"GET /api/version HTTP/1.1\r\n"));
        assert!(requests[4].starts_with(b"GET /api/tags HTTP/1.1\r\n"));
        assert!(requests.iter().all(|request| {
            request
                .windows(b"Accept-Encoding: identity".len())
                .any(|window| window == b"Accept-Encoding: identity")
        }));
        let chat_body = requests[2].split(|byte| *byte == b'\n').collect::<Vec<_>>();
        assert!(chat_body
            .last()
            .expect("chat request body")
            .ends_with(prepared.request_bytes()));
        assert_eq!(
            result.terminal_frame().api_request_sha256,
            prepared.api_request_sha256().clone()
        );
        assert_eq!(
            result.terminal_frame().model_output_sha256,
            Sha256Digest::from_bytes(result.model_output())
        );
        assert!(std::str::from_utf8(result.model_output())
            .expect("model output UTF-8")
            .contains("\"verdict\":\"no_finding\""));
        let mut stderr_capture = crate::OLLAMA_READY_MARKER_V1.to_vec();
        serde_json::to_writer(&mut stderr_capture, result.terminal_frame())
            .expect("terminal frame JSON");
        stderr_capture.push(b'\n');
        let parsed =
            crate::parse_ollama_terminal_frame_v1(&stderr_capture).expect("strict terminal frame");
        let observation =
            crate::verify_ollama_terminal_frame_v1(parsed.clone(), &input, result.model_output())
                .expect("verified terminal frame");
        assert_eq!(observation.terminal_frame(), &parsed);
        assert!(matches!(
            crate::verify_ollama_terminal_frame_v1(parsed, &input, b"tampered stdout"),
            Err(OllamaAdapterErrorV1::InvalidApiResponse)
        ));
    }

    #[test]
    fn fake_server_model_digest_mismatch_fails_before_chat() {
        let input = validated_input();
        let wrong = Sha256Digest::from_bytes(b"wrong model manifest");
        let responses = vec![
            version_response(),
            tags_response(
                &input,
                wrong
                    .as_str()
                    .strip_prefix("sha256:")
                    .expect("canonical digest"),
            ),
        ];
        let (address, receiver, handle) = spawn_fake_server(responses);
        assert!(matches!(
            execute_ollama_chat_at_v1(&input, address),
            Err(OllamaAdapterErrorV1::ModelDigestMismatch)
        ));
        handle.join().expect("fake server thread");
        assert_eq!(receiver.into_iter().count(), 2);
    }

    #[test]
    fn fake_server_length_stop_is_truncated_not_completed() {
        let input = validated_input();
        let (address, _receiver, handle) =
            spawn_fake_server(successful_responses(&input, "length"));
        assert!(matches!(
            execute_ollama_chat_at_v1(&input, address),
            Err(OllamaAdapterErrorV1::ResponseTruncated)
        ));
        handle.join().expect("fake server thread");
    }

    #[test]
    fn redirect_status_is_rejected_without_following_location() {
        let input = validated_input();
        let (address, receiver, handle) = spawn_fake_server(vec![FakeResponse {
            status: "302 Found",
            headers: vec![
                ("Content-Type", "application/json"),
                ("Location", "http://127.0.0.1:9/elsewhere"),
            ],
            body: b"{}".to_vec(),
        }]);
        assert!(matches!(
            execute_ollama_chat_at_v1(&input, address),
            Err(OllamaAdapterErrorV1::HttpStatusRejected)
        ));
        handle.join().expect("fake server thread");
        assert_eq!(receiver.into_iter().count(), 1);
    }
}
