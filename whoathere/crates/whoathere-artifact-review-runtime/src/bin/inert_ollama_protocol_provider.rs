//! Inert wire fixture for the Ollama adapter runtime protocol.
//!
//! This binary performs no network I/O and invokes no model. It exists only
//! to exercise runtime capture and terminal-frame verification.

use serde_json::json;
use std::io::{self, Read, Write};
use whoathere_artifact::Sha256Digest;
use whoathere_artifact_review_ollama::{
    prepare_ollama_chat_request_v1, OllamaAdapterOutcomeV1, OllamaAdapterTerminalFrameV1,
    OLLAMA_ADAPTER_ID_V1, OLLAMA_ADAPTER_VERSION_V1, OLLAMA_LOOPBACK_ENDPOINT_V1,
    OLLAMA_READY_MARKER_V1, OLLAMA_TERMINAL_FRAME_SCHEMA_V1,
};
use whoathere_detector::{
    decode_and_validate_artifact_review_provider_input_v2,
    MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2,
};

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 2 || arguments[1] != "artifact-review-v2-stdin" {
        return 64;
    }
    let mut input_bytes = Vec::new();
    if io::stdin()
        .take((MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2 + 1) as u64)
        .read_to_end(&mut input_bytes)
        .is_err()
        || input_bytes.len() > MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2
    {
        return 65;
    }
    let Ok(input) = decode_and_validate_artifact_review_provider_input_v2(&input_bytes) else {
        return 66;
    };
    let Ok(prepared) = prepare_ollama_chat_request_v1(&input) else {
        return 67;
    };
    let output = json!({
        "schema_version":"whoathere.artifact_review_model_output.v2",
        "work_item_id":input.work_item_id(),
        "invocation_sha256":input.invocation_sha256(),
        "verdict":"no_finding",
        "findings":[]
    });
    let Ok(output_bytes) = serde_json::to_vec(&output) else {
        return 68;
    };
    let inference = input.inference();
    let mut terminal = OllamaAdapterTerminalFrameV1 {
        schema_version: OLLAMA_TERMINAL_FRAME_SCHEMA_V1.to_string(),
        adapter_id: OLLAMA_ADAPTER_ID_V1.to_string(),
        adapter_version: OLLAMA_ADAPTER_VERSION_V1.to_string(),
        outcome: OllamaAdapterOutcomeV1::Completed,
        work_item_id: input.work_item_id().clone(),
        invocation_sha256: input.invocation_sha256().clone(),
        provider_input_sha256: input.provider_input_sha256().clone(),
        endpoint: OLLAMA_LOOPBACK_ENDPOINT_V1.to_string(),
        server_version: "inert-no-server".to_string(),
        requested_model: input.model().model_id.clone(),
        response_model: input.model().model_id.clone(),
        expected_model_content_sha256: measured_model_digest(&input),
        pre_model_content_sha256: measured_model_digest(&input),
        post_model_content_sha256: measured_model_digest(&input),
        system_message_sha256: prepared.system_message_sha256().clone(),
        user_message_sha256: prepared.user_message_sha256().clone(),
        role_mapping_contract_sha256: prepared.role_mapping_contract_sha256().clone(),
        api_request_sha256: prepared.api_request_sha256().clone(),
        raw_api_response_sha256: Sha256Digest::from_bytes(b"inert protocol fixture no response"),
        model_output_sha256: Sha256Digest::from_bytes(&output_bytes),
        model_output_byte_len: output_bytes.len() as u64,
        prompt_eval_count: 512,
        eval_count: 64,
        done_reason: "stop".to_string(),
        seed: inference.seed,
        temperature_milli: inference.temperature_milli,
        top_p_milli: inference.top_p_milli,
        context_tokens: inference.context_tokens,
        max_output_tokens: inference.max_output_tokens,
        observed_transport: "literal_ipv4_loopback_http_1_1".to_string(),
        model_identity_posture: "server_reported_manifest_digest_matched_pinned_expected_value"
            .to_string(),
    };
    if input.model().model_id.ends_with("-tampered-terminal") {
        terminal.api_request_sha256 = Sha256Digest::from_bytes(b"tampered API request digest");
    }
    let mut stderr = io::stderr().lock();
    if stderr.write_all(OLLAMA_READY_MARKER_V1).is_err()
        || serde_json::to_writer(&mut stderr, &terminal).is_err()
        || stderr.write_all(b"\n").is_err()
        || stderr.flush().is_err()
    {
        return 69;
    }
    let mut stdout = io::stdout().lock();
    if stdout.write_all(&output_bytes).is_err() || stdout.flush().is_err() {
        return 70;
    }
    0
}

fn measured_model_digest(
    input: &whoathere_detector::ValidatedArtifactReviewProviderInputV2,
) -> whoathere_artifact::Sha256Digest {
    input
        .model()
        .measured_content_sha256()
        .expect("inert Ollama fixture requires measured local model content")
        .clone()
}
