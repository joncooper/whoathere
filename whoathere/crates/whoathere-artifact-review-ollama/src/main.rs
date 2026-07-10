use std::io::{self, Read, Write};
use whoathere_artifact_review_ollama::{execute_ollama_chat_v1, OLLAMA_READY_MARKER_V1};
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
    let mut input = Vec::new();
    if io::stdin()
        .take((MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2 + 1) as u64)
        .read_to_end(&mut input)
        .is_err()
        || input.len() > MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2
    {
        return 65;
    }
    let Ok(validated) = decode_and_validate_artifact_review_provider_input_v2(&input) else {
        return 66;
    };
    let mut stderr = io::stderr().lock();
    if stderr.write_all(OLLAMA_READY_MARKER_V1).is_err() || stderr.flush().is_err() {
        return 67;
    }
    let Ok(result) = execute_ollama_chat_v1(&validated) else {
        return 68;
    };
    let (model_output, terminal_frame) = result.into_parts();
    let mut stdout = io::stdout().lock();
    if stdout.write_all(&model_output).is_err() || stdout.flush().is_err() {
        return 69;
    }
    if serde_json::to_writer(&mut stderr, &terminal_frame).is_err()
        || stderr.write_all(b"\n").is_err()
        || stderr.flush().is_err()
    {
        return 70;
    }
    0
}
