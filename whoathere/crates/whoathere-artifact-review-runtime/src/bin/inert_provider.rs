//! Compiled inert fixture for the Artifact Review local-runtime tests.
//!
//! This is not a model adapter. It performs no package execution, filesystem
//! discovery, model loading, registry access, or network I/O.

use serde_json::{json, Value};
use std::env;
use std::ffi::CStr;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::process::{self, Command, Stdio};
use std::thread;
use std::time::Duration;

const MAX_INPUT_BYTES: u64 = 256 * 1024;
const STDOUT_CAPTURE_LIMIT: usize = 256 * 1024;
const STDERR_CAPTURE_LIMIT: usize = 64 * 1024;
const READY_MARKER: &[u8] = b"whoathere-inert-provider-ready-v2\n";

fn main() {
    // SAFETY: the inert fixture is single-threaded at startup. Installing the
    // handler before argument or stdin parsing makes SIGKILL-escalation tests
    // deterministic without a timing-dependent readiness race.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }
    let arguments = env::args().collect::<Vec<_>>();
    if arguments.len() == 2 && arguments[1] == "inert-descendant" {
        thread::sleep(Duration::from_secs(30));
        return;
    }
    if arguments.len() != 2 || arguments[1] != "artifact-review-v2-stdin" {
        process::exit(64);
    }
    if io::stderr().write_all(READY_MARKER).is_err() {
        process::exit(74);
    }

    let mut input = Vec::new();
    if io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut input)
        .is_err()
        || input.len() as u64 > MAX_INPUT_BYTES
    {
        process::exit(65);
    }
    let Ok(wire) = serde_json::from_slice::<Value>(&input) else {
        process::exit(66);
    };
    let Some(work_item_id) = wire.get("work_item_id").and_then(Value::as_str) else {
        process::exit(67);
    };
    let Some(invocation_sha256) = wire.get("invocation_sha256").and_then(Value::as_str) else {
        process::exit(68);
    };
    let Some(model_id) = wire
        .pointer("/trusted/model/model_id")
        .and_then(Value::as_str)
    else {
        process::exit(69);
    };

    match model_id {
        "whoathere-inert-fixture-echo" => emit_empty_result(work_item_id, invocation_sha256),
        "whoathere-inert-fixture-stderr" => {
            let _ = io::stderr().write_all(b"inert provider diagnostic\n");
            emit_empty_result(work_item_id, invocation_sha256);
        }
        "whoathere-inert-fixture-malformed" => {
            let _ = io::stdout().write_all(b"{\"intentionally\":");
        }
        "whoathere-inert-fixture-stdout-overflow" => {
            let bytes = vec![b'x'; STDOUT_CAPTURE_LIMIT + 1];
            let _ = io::stdout().write_all(&bytes);
        }
        "whoathere-inert-fixture-stderr-overflow" => {
            let bytes = vec![b'e'; STDERR_CAPTURE_LIMIT + 1];
            let _ = io::stderr().write_all(&bytes);
            emit_empty_result(work_item_id, invocation_sha256);
        }
        "whoathere-inert-fixture-hang" => thread::sleep(Duration::from_secs(30)),
        "whoathere-inert-fixture-ignore-term" => thread::sleep(Duration::from_secs(30)),
        "whoathere-inert-fixture-nonzero" => {
            let _ = io::stderr().write_all(b"inert nonzero fixture\n");
            process::exit(7);
        }
        "whoathere-inert-fixture-descendant" => {
            let Ok(_descendant) = Command::new(&arguments[0])
                .arg("inert-descendant")
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
            else {
                process::exit(70);
            };
            emit_empty_result(work_item_id, invocation_sha256);
        }
        "whoathere-inert-fixture-environment" => {
            if !environment_is_private_and_minimal() {
                process::exit(71);
            }
            emit_empty_result(work_item_id, invocation_sha256);
        }
        "whoathere-inert-fixture-prefix-then-block-next" => {
            if !block_next_invocation_directory() {
                process::exit(75);
            }
            emit_empty_result(work_item_id, invocation_sha256);
        }
        "whoathere-inert-fixture-fd-hygiene" => {
            if inherited_descriptor_exposes_test_sentinel() {
                process::exit(76);
            }
            emit_empty_result(work_item_id, invocation_sha256);
        }
        _ => process::exit(72),
    }
}

fn inherited_descriptor_exposes_test_sentinel() -> bool {
    let Ok(descriptors) = fs::read_dir("/dev/fd") else {
        return true;
    };
    descriptors.filter_map(Result::ok).any(|entry| {
        let descriptor = entry.file_name().to_string_lossy().parse::<i32>().ok();
        let Some(descriptor) = descriptor else {
            return false;
        };
        if descriptor <= 2 {
            return false;
        }
        let mut path = [0 as libc::c_char; libc::PATH_MAX as usize];
        // SAFETY: path is writable PATH_MAX storage and descriptor came from
        // the live /dev/fd directory listing for this process.
        if unsafe { libc::fcntl(descriptor, libc::F_GETPATH, path.as_mut_ptr()) } < 0 {
            return false;
        }
        // SAFETY: successful F_GETPATH writes a NUL-terminated path.
        unsafe { CStr::from_ptr(path.as_ptr()) }
            .to_string_lossy()
            .contains("whoathere-fd-leak-sentinel")
    })
}

fn block_next_invocation_directory() -> bool {
    let Ok(current) = env::current_dir() else {
        return false;
    };
    let Some(invocation_directory) = current.parent() else {
        return false;
    };
    if invocation_directory
        .file_name()
        .and_then(|name| name.to_str())
        != Some("invocation-000000")
    {
        return true;
    }
    let Some(run_directory) = invocation_directory.parent() else {
        return false;
    };
    let blocker = run_directory.join("invocation-000001");
    fs::write(
        blocker,
        b"inert fixture blocks the next invocation directory",
    )
    .is_ok()
}

fn emit_empty_result(work_item_id: &str, invocation_sha256: &str) {
    let output = json!({
        "schema_version": "whoathere.artifact_review_model_output.v2",
        "work_item_id": work_item_id,
        "invocation_sha256": invocation_sha256,
        "verdict": "uncertain",
        "findings": [],
    });
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &output).is_err() || stdout.flush().is_err() {
        process::exit(73);
    }
}

fn environment_is_private_and_minimal() -> bool {
    const ALLOWED: [&str; 5] = ["HOME", "TMPDIR", "LANG", "LC_ALL", "TZ"];
    if env::vars_os().any(|(name, _)| !ALLOWED.iter().any(|allowed| name == *allowed)) {
        return false;
    }
    if env::var_os("PATH").is_some() || env::var_os("WHOATHERE_TEST_SECRET").is_some() {
        return false;
    }
    if env::var("LANG").as_deref() != Ok("C")
        || env::var("LC_ALL").as_deref() != Ok("C")
        || env::var("TZ").as_deref() != Ok("UTC")
    {
        return false;
    }
    let Ok(current) = env::current_dir().and_then(fs::canonicalize) else {
        return false;
    };
    let Some(home) = env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .and_then(|path| fs::canonicalize(path).ok())
    else {
        return false;
    };
    let Some(temporary) = env::var_os("TMPDIR")
        .map(std::path::PathBuf::from)
        .and_then(|path| fs::canonicalize(path).ok())
    else {
        return false;
    };
    for (path, expected_name) in [(&current, "cwd"), (&home, "home"), (&temporary, "tmp")] {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return false;
        };
        if !path.is_absolute()
            || path.file_name().and_then(|name| name.to_str()) != Some(expected_name)
            || !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return false;
        }
    }
    current.parent() == home.parent() && current.parent() == temporary.parent()
}
