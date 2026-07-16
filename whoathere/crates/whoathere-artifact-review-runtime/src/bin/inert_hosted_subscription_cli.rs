//! Inert Claude/Codex CLI protocol fixture.
//!
//! It performs no model or network access. The fixture deliberately accepts
//! only the adapter's complete argument and environment contracts so a newly
//! added or reordered client option cannot pass qualification accidentally.

use serde_json::json;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use whoathere_artifact_review_runtime::{
    CLAUDE_CODE_SUPPORTED_VERSION_V2, CODEX_CLI_SUPPORTED_VERSION_V2,
};
use whoathere_detector::{
    artifact_review_model_output_schema_json_v2, artifact_review_system_prompt_v2,
    decode_and_validate_artifact_review_provider_input_v2, ArtifactReviewContextKindV2,
    MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2,
};

const CLAUDE_INERT_MODEL: &str = "claude-inert-opaque-2026-07-15";
const CODEX_INERT_MODEL: &str = "gpt-inert-opaque-2026-07-15";

const CODEX_DISABLED_TOOL_FEATURES: &[&str] = &[
    "apps",
    "enable_mcp_apps",
    "auth_elicitation",
    "browser_use",
    "browser_use_external",
    "computer_use",
    "in_app_browser",
    "image_generation",
    "workspace_dependencies",
    "plugins",
    "plugin_sharing",
    "remote_plugin",
    "skill_mcp_dependency_install",
    "tool_call_mcp_elicitation",
    "tool_suggest",
    "multi_agent",
    "multi_agent_v2",
    "enable_fanout",
    "shell_tool",
    "unified_exec",
    "shell_snapshot",
    "hooks",
    "goals",
    "network_proxy",
    "standalone_web_search",
    "artifact",
    "code_mode",
    "code_mode_only",
    "request_permissions_tool",
];

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.as_slice() == ["__detached_pipe_holder"] {
        thread::sleep(Duration::from_secs(2));
        return 0;
    }
    let mode = fake_mode();
    if args.as_slice() == ["--version"] {
        let provider = provider_kind_from_environment();
        if !environment_is_sanitized(provider) {
            return 71;
        }
        if mode.as_deref() == Some("version_timeout") {
            thread::sleep(Duration::from_secs(60));
        }
        match provider {
            Some(FakeProviderKind::Claude) => println!("{CLAUDE_CODE_SUPPORTED_VERSION_V2}"),
            Some(FakeProviderKind::Codex) => println!("{CODEX_CLI_SUPPORTED_VERSION_V2}"),
            None => return 71,
        }
        return 0;
    }
    if args.as_slice() == ["auth", "status", "--json"] {
        if !environment_is_sanitized(Some(FakeProviderKind::Claude)) {
            return 71;
        }
        return emit_auth_status(FakeProviderKind::Claude, mode.as_deref());
    }
    if args.as_slice() == ["login", "status"] {
        if !environment_is_sanitized(Some(FakeProviderKind::Codex)) {
            return 71;
        }
        return emit_auth_status(FakeProviderKind::Codex, mode.as_deref());
    }

    let provider = match args.first().map(String::as_str) {
        Some("--print") => FakeProviderKind::Claude,
        Some("exec") => FakeProviderKind::Codex,
        _ => return 64,
    };
    if !environment_is_sanitized(Some(provider)) {
        return 71;
    }
    if args.iter().filter(|argument| *argument == "--help").count() == 1 {
        let mut invocation_arguments = args.clone();
        let Some(help_index) = invocation_arguments
            .iter()
            .position(|argument| argument == "--help")
        else {
            return 64;
        };
        let expected_index = match provider {
            FakeProviderKind::Claude => invocation_arguments.len().saturating_sub(1),
            FakeProviderKind::Codex => invocation_arguments.len().saturating_sub(2),
        };
        if help_index != expected_index {
            return 64;
        }
        invocation_arguments.remove(help_index);
        if !exact_invocation_arguments_match(&invocation_arguments, provider) {
            return 64;
        }
        println!("whoathere inert hosted parser contract qualified");
        return 0;
    }
    if !exact_invocation_arguments_match(&args, provider) {
        return 64;
    }
    if mode.as_deref() == Some("invocation_timeout")
        || mode.as_deref() == Some("stdin_backpressure")
    {
        thread::sleep(Duration::from_secs(60));
    }
    let mut provider_input = Vec::new();
    if io::stdin()
        .take((MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2 + 1) as u64)
        .read_to_end(&mut provider_input)
        .is_err()
        || provider_input.len() > MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2
    {
        return 65;
    }
    let Ok(input) = decode_and_validate_artifact_review_provider_input_v2(&provider_input) else {
        return 66;
    };
    if mode.as_deref() == Some("invocation_wait_for_cancel") {
        let Some(home) = env::var_os("HOME") else {
            return 73;
        };
        if fs::write(Path::new(&home).join(".whoathere-invocation-started"), b"1").is_err() {
            return 73;
        }
        thread::sleep(Duration::from_secs(60));
    }
    if mode.as_deref() == Some("detached_pipe_holder") && spawn_detached_pipe_holder().is_err() {
        return 72;
    }

    let source = input.untrusted().bytes();
    let needle = b"process.env.INERT_TOKEN";
    let (verdict, findings) = match source
        .windows(needle.len())
        .position(|window| window == needle)
    {
        Some(start) => {
            let Some(context) = input.untrusted().contexts().first() else {
                return 68;
            };
            let context_kind = match context.kind() {
                ArtifactReviewContextKindV2::TriggerSurface => "trigger_surface",
                ArtifactReviewContextKindV2::InventoryOnly => "inventory_only",
            };
            (
                "suspicious",
                json!([{
                    "category": "credential_access",
                    "severity": "high",
                    "context_id": context.context_id(),
                    "context_kind": context_kind,
                    "chunk_relative_start_byte": start,
                    "chunk_relative_end_byte": start + needle.len(),
                    "explanation": "Reads an environment credential from a package-triggered execution path."
                }]),
            )
        }
        None if mode.as_deref() == Some("mixed_failure") => return 67,
        None => ("no_finding", json!([])),
    };
    let output = json!({
        "schema_version": "whoathere.artifact_review_model_output.v2",
        "work_item_id": input.work_item_id(),
        "invocation_sha256": input.invocation_sha256(),
        "verdict": verdict,
        "findings": findings
    });
    let wire = match provider {
        FakeProviderKind::Claude => json!({
            "type": "result",
            "model": if mode.as_deref() == Some("model_mismatch") {
                "claude-unexpected-model"
            } else {
                CLAUDE_INERT_MODEL
            },
            "structured_output": output
        }),
        FakeProviderKind::Codex => output,
    };
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &wire).is_err() || stdout.flush().is_err() {
        return 69;
    }
    if mode.as_deref() == Some("auth_flip_post") && write_fake_mode("api_key").is_err() {
        return 73;
    }
    0
}

fn emit_auth_status(provider: FakeProviderKind, mode: Option<&str>) -> i32 {
    match (provider, mode) {
        (FakeProviderKind::Claude, Some("api_key")) => {
            println!(r#"{{"loggedIn":true,"authMethod":"apiKey","apiProvider":"firstParty"}}"#);
        }
        (FakeProviderKind::Claude, Some("ambiguous_auth")) => {
            println!(r#"{{"loggedIn":true,"authMethod":"oauth","apiProvider":"firstParty"}}"#);
            eprintln!("API key configured");
        }
        (FakeProviderKind::Claude, _) => {
            println!(r#"{{"loggedIn":true,"authMethod":"oauth","apiProvider":"firstParty"}}"#);
        }
        (FakeProviderKind::Codex, Some("api_key")) => println!("Logged in using API key"),
        (FakeProviderKind::Codex, Some("ambiguous_auth")) => {
            println!("Logged in using ChatGPT");
            eprintln!("API key configured");
        }
        (FakeProviderKind::Codex, _) => println!("Logged in using ChatGPT"),
    }
    0
}

fn exact_invocation_arguments_match(args: &[String], provider: FakeProviderKind) -> bool {
    match provider {
        FakeProviderKind::Claude => args == expected_claude_arguments(),
        FakeProviderKind::Codex => {
            let Some(schema_index) = args
                .iter()
                .position(|argument| argument == "--output-schema")
            else {
                return false;
            };
            let Some(schema_path) = args.get(schema_index + 1).map(PathBuf::from) else {
                return false;
            };
            let schema_matches = fs::read_to_string(&schema_path)
                .ok()
                .is_some_and(|value| value == artifact_review_model_output_schema_json_v2());
            if !schema_path.is_absolute() || !schema_matches {
                return false;
            }
            let Ok(cwd) = env::current_dir() else {
                return false;
            };
            args == expected_codex_arguments(&schema_path, &cwd)
        }
    }
}

fn expected_claude_arguments() -> Vec<String> {
    [
        "--print",
        "--input-format",
        "text",
        "--safe-mode",
        "--disable-slash-commands",
        "--no-chrome",
        "--no-session-persistence",
        "--setting-sources",
        "",
        "--permission-mode",
        "plan",
        "--tools",
        "",
        "--strict-mcp-config",
        "--mcp-config",
        r#"{"mcpServers":{}}"#,
        "--system-prompt",
        artifact_review_system_prompt_v2(),
        "--json-schema",
        artifact_review_model_output_schema_json_v2(),
        "--output-format",
        "json",
        "--model",
        CLAUDE_INERT_MODEL,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn expected_codex_arguments(schema_path: &Path, cwd: &Path) -> Vec<String> {
    let mut expected = [
        "exec",
        "--ephemeral",
        "--sandbox",
        "read-only",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--skip-git-repo-check",
        "--output-schema",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    expected.push(schema_path.to_string_lossy().into_owned());
    expected.extend(
        ["--color", "never", "--model", CODEX_INERT_MODEL]
            .into_iter()
            .map(str::to_string),
    );
    for feature in CODEX_DISABLED_TOOL_FEATURES {
        expected.push("--disable".to_string());
        expected.push((*feature).to_string());
    }
    let developer_instructions = format!(
        "developer_instructions={}",
        serde_json::to_string(artifact_review_system_prompt_v2())
            .expect("static system prompt serializes")
    );
    expected.extend([
        "-c".to_string(),
        "model_provider=\"openai\"".to_string(),
        "-c".to_string(),
        "forced_login_method=\"chatgpt\"".to_string(),
        "-c".to_string(),
        "web_search=\"disabled\"".to_string(),
        "-c".to_string(),
        "apps._default.enabled=false".to_string(),
        "-c".to_string(),
        "mcp_servers={}".to_string(),
        "-c".to_string(),
        "history.persistence=\"none\"".to_string(),
        "-c".to_string(),
        "check_for_update_on_startup=false".to_string(),
        "-c".to_string(),
        "feedback.enabled=false".to_string(),
        "-c".to_string(),
        "analytics.enabled=false".to_string(),
        "-c".to_string(),
        "approval_policy=\"never\"".to_string(),
        "-c".to_string(),
        developer_instructions,
        "-C".to_string(),
        cwd.to_string_lossy().into_owned(),
        "-".to_string(),
    ]);
    expected
}

fn spawn_detached_pipe_holder() -> io::Result<()> {
    let executable = env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg("__detached_pipe_holder")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().map(|_| ())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FakeProviderKind {
    Claude,
    Codex,
}

fn provider_kind_from_environment() -> Option<FakeProviderKind> {
    let claude = env::var_os("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC").is_some()
        || env::var_os("DISABLE_AUTOUPDATER").is_some();
    let codex = env::var_os("CODEX_HOME").is_some();
    match (claude, codex) {
        (true, false) => Some(FakeProviderKind::Claude),
        (false, true) => Some(FakeProviderKind::Codex),
        _ => None,
    }
}

fn environment_is_sanitized(provider: Option<FakeProviderKind>) -> bool {
    const FORBIDDEN: [&str; 9] = [
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
        "CODEX_ACCESS_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "WHOATHERE_TEST_SECRET",
    ];
    if FORBIDDEN.iter().any(|name| env::var_os(name).is_some()) {
        return false;
    }
    let allowed = [
        "HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "TZ",
        "PATH",
        "CODEX_HOME",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
        "DISABLE_AUTOUPDATER",
    ];
    if env::vars_os().any(|(name, _)| !allowed.iter().any(|allowed| name == *allowed)) {
        return false;
    }
    if env::var("LANG").as_deref() != Ok("C")
        || env::var("LC_ALL").as_deref() != Ok("C")
        || env::var("TZ").as_deref() != Ok("UTC")
    {
        return false;
    }
    match provider {
        Some(FakeProviderKind::Claude) => {
            if env::var("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC").as_deref() != Ok("1")
                || env::var("DISABLE_AUTOUPDATER").as_deref() != Ok("1")
                || env::var_os("CODEX_HOME").is_some()
            {
                return false;
            }
        }
        Some(FakeProviderKind::Codex) => {
            if env::var_os("CODEX_HOME") != env::var_os("HOME")
                || env::var_os("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC").is_some()
                || env::var_os("DISABLE_AUTOUPDATER").is_some()
            {
                return false;
            }
        }
        None => return false,
    }
    let Ok(current) = env::current_dir() else {
        return false;
    };
    fs_directory_is_empty(&current)
}

fn fake_mode() -> Option<String> {
    fs::read_to_string(fake_mode_path()?)
        .ok()
        .map(|mode| mode.trim().to_string())
}

fn write_fake_mode(mode: &str) -> io::Result<()> {
    let path = fake_mode_path().ok_or_else(|| io::Error::other("HOME missing"))?;
    fs::write(path, format!("{mode}\n"))
}

fn fake_mode_path() -> Option<PathBuf> {
    let home = env::var_os("HOME")?;
    Some(Path::new(&home).join(".whoathere-inert-hosted-cli-mode"))
}

fn fs_directory_is_empty(path: &Path) -> bool {
    fs::read_dir(path)
        .ok()
        .and_then(|mut entries| entries.next().transpose().ok())
        .flatten()
        .is_none()
}
