use std::path::{Path, PathBuf};
use std::process::ExitCode;
use whoathere_artifact::{Ecosystem, NormalizationLimits, Sha256Digest};
use whoathere_runner::{
    verify_static_download_execute_projections_v1, StaticProjectionErrorV1,
    StaticProjectionRequestV1, STATIC_PROJECTION_METADATA_SCHEMA_V1,
};

const EXIT_USAGE: u8 = 64;
const EXIT_IO: u8 = 74;

struct Args {
    artifact: PathBuf,
    ecosystem: Ecosystem,
    acquired_at: String,
    expected_artifact_sha256: Sha256Digest,
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(reason) => return emit_argument_error(reason),
    };
    let result = verify_static_download_execute_projections_v1(StaticProjectionRequestV1 {
        artifact_path: &args.artifact,
        ecosystem: args.ecosystem,
        acquired_at: &args.acquired_at,
        expected_artifact_sha256: &args.expected_artifact_sha256,
        normalization_limits: NormalizationLimits::default(),
    });
    match result {
        Ok(metadata) => match metadata.canonical_json_bytes() {
            Ok(bytes) => {
                use std::io::Write;
                if std::io::stdout().write_all(&bytes).is_err() {
                    ExitCode::from(EXIT_IO)
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(error) => emit_verification_error(&error),
        },
        Err(error) => emit_verification_error(&error),
    }
}

fn parse_args(arguments: impl Iterator<Item = String>) -> Result<Args, &'static str> {
    let mut artifact = None;
    let mut ecosystem = None;
    let mut acquired_at = None;
    let mut expected_artifact_sha256 = None;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        let value = match argument.as_str() {
            "--artifact" | "--ecosystem" | "--acquired-at" | "--expected-artifact-sha256" => {
                arguments
                    .next()
                    .ok_or("static_projection_argument_value_missing")?
            }
            "--help" | "-h" => return Err("static_projection_help_requested"),
            _ => return Err("static_projection_argument_unknown"),
        };
        match argument.as_str() {
            "--artifact" if artifact.is_none() => artifact = Some(PathBuf::from(value)),
            "--ecosystem" if ecosystem.is_none() => {
                ecosystem = Some(match value.as_str() {
                    "npm" => Ecosystem::Npm,
                    "pypi" => Ecosystem::Pypi,
                    _ => return Err("static_projection_ecosystem_invalid"),
                })
            }
            "--acquired-at" if acquired_at.is_none() => acquired_at = Some(value),
            "--expected-artifact-sha256" if expected_artifact_sha256.is_none() => {
                expected_artifact_sha256 = Some(
                    Sha256Digest::parse(value)
                        .map_err(|_| "static_projection_expected_artifact_digest_invalid")?,
                )
            }
            _ => return Err("static_projection_argument_duplicate"),
        }
    }
    let artifact = artifact.ok_or("static_projection_artifact_path_required")?;
    if !absolute_path(&artifact) {
        return Err("static_projection_paths_must_be_absolute");
    }
    let acquired_at = acquired_at.ok_or("static_projection_acquired_at_required")?;
    if !canonical_utc_seconds(&acquired_at) {
        return Err("static_projection_acquired_at_invalid");
    }
    Ok(Args {
        artifact,
        ecosystem: ecosystem.ok_or("static_projection_ecosystem_required")?,
        acquired_at,
        expected_artifact_sha256: expected_artifact_sha256
            .ok_or("static_projection_expected_artifact_digest_required")?,
    })
}

fn absolute_path(path: &Path) -> bool {
    path.is_absolute()
}

fn canonical_utc_seconds(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}

fn emit_verification_error(error: &StaticProjectionErrorV1) -> ExitCode {
    use std::io::Write;
    let _ = std::io::stderr().write_all(&error.canonical_json_bytes());
    ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(70))
}

fn emit_argument_error(reason: &'static str) -> ExitCode {
    use std::io::Write;
    let bytes = format!(
        "{{\"admission_authority\":false,\"exit_code\":64,\"observed_clean\":false,\"reason_codes\":[\"{reason}\"],\"schema\":\"{STATIC_PROJECTION_METADATA_SCHEMA_V1}\",\"verification_status\":\"failed\"}}\n"
    );
    let _ = std::io::stderr().write_all(bytes.as_bytes());
    ExitCode::from(EXIT_USAGE)
}
