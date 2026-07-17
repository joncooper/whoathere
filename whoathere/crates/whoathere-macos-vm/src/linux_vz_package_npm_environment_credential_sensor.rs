use serde::Serialize;
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_npm_environment_credential_sensor.v1";
pub const LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_ACTIVATION_V1: &str =
    "npm_lifecycle_descendant";
pub const LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_ABSOLUTE_PATH_V1: &str =
    "/run/whoathere/input/npm-environment-credential-read-preload-v1.cjs";
pub const LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_RELATIVE_PATH_V1: &str =
    "npm-environment-credential-read-preload-v1.cjs";

const NPM_TOKEN_READ_MARKER_RELATIVE_PATH_V1: &str =
    "home/.whoathere-canaries/environment-read-npm-token";
const GITHUB_TOKEN_READ_MARKER_RELATIVE_PATH_V1: &str =
    "home/.whoathere-canaries/environment-read-github-token";
const AWS_ACCESS_KEY_ID_READ_MARKER_RELATIVE_PATH_V1: &str =
    "home/.whoathere-canaries/environment-read-aws-access-key-id";

/// This source is copied byte-for-byte into the disposable guest and measured before the npm
/// process is released. It deliberately does nothing in the npm leader. npm adds
/// `npm_lifecycle_event` only to lifecycle descendants, so package hooks are the only processes
/// in which the proxy and its marker writes become active.
///
/// Marker files contain only the fixed byte `1` and never a canary value. Sensor write failure is
/// swallowed so instrumentation cannot grant package code extra authority; the verifier treats a
/// missing marker as incomplete and never as clean evidence. Package code can also forge these
/// paths, so marker activity is unauthenticated supporting telemetry and cannot itself satisfy a
/// behavior-detection claim.
pub const LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_V1: &[u8] = br#"'use strict';
(() => {
  const lifecycle = process.env.npm_lifecycle_event;
  if (typeof lifecycle !== 'string' || lifecycle.length === 0) return;

  const fs = require('node:fs');
  const originalEnvironment = process.env;
  const markers = Object.freeze({
    NPM_TOKEN: '/run/whoathere/home/.whoathere-canaries/environment-read-npm-token',
    GITHUB_TOKEN: '/run/whoathere/home/.whoathere-canaries/environment-read-github-token',
    AWS_ACCESS_KEY_ID: '/run/whoathere/home/.whoathere-canaries/environment-read-aws-access-key-id',
  });
  const successfulMarkers = new Set();

  function record(path) {
    if (successfulMarkers.has(path)) return;
    try {
      const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND |
        fs.constants.O_CLOEXEC | fs.constants.O_NOFOLLOW;
      const descriptor = fs.openSync(path, flags, 0o600);
      try {
        fs.writeSync(descriptor, '1\n');
      } finally {
        fs.closeSync(descriptor);
      }
      successfulMarkers.add(path);
    } catch (_) {
      // Missing or suppressed marker telemetry is incomplete, never evidence of cleanliness.
    }
  }

  process.env = new Proxy(originalEnvironment, {
    get(target, property) {
      if (typeof property === 'string' && Object.prototype.hasOwnProperty.call(markers, property)) {
        record(markers[property]);
      }
      return Reflect.get(target, property);
    },
    has(target, property) {
      if (typeof property === 'string' && Object.prototype.hasOwnProperty.call(markers, property)) {
        record(markers[property]);
      }
      return Reflect.has(target, property);
    },
    getOwnPropertyDescriptor(target, property) {
      if (typeof property === 'string' && Object.prototype.hasOwnProperty.call(markers, property)) {
        record(markers[property]);
      }
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  });
})();
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum LinuxVzPackageNpmEnvironmentCredentialMarkerKindV1 {
    #[serde(rename = "npm_token_read")]
    NpmToken,
    #[serde(rename = "git_hub_token_read")]
    GitHubToken,
    #[serde(rename = "aws_access_key_id_read")]
    AwsAccessKeyId,
}

impl LinuxVzPackageNpmEnvironmentCredentialMarkerKindV1 {
    pub const fn environment_name(self) -> Option<&'static str> {
        match self {
            Self::NpmToken => Some("NPM_TOKEN"),
            Self::GitHubToken => Some("GITHUB_TOKEN"),
            Self::AwsAccessKeyId => Some("AWS_ACCESS_KEY_ID"),
        }
    }

    pub const fn marker_relative_path(self) -> &'static str {
        match self {
            Self::NpmToken => NPM_TOKEN_READ_MARKER_RELATIVE_PATH_V1,
            Self::GitHubToken => GITHUB_TOKEN_READ_MARKER_RELATIVE_PATH_V1,
            Self::AwsAccessKeyId => AWS_ACCESS_KEY_ID_READ_MARKER_RELATIVE_PATH_V1,
        }
    }

    pub fn marker_absolute_path(self) -> String {
        format!("/run/whoathere/{}", self.marker_relative_path())
    }
}

const MARKER_KINDS_V1: [LinuxVzPackageNpmEnvironmentCredentialMarkerKindV1; 3] = [
    LinuxVzPackageNpmEnvironmentCredentialMarkerKindV1::NpmToken,
    LinuxVzPackageNpmEnvironmentCredentialMarkerKindV1::GitHubToken,
    LinuxVzPackageNpmEnvironmentCredentialMarkerKindV1::AwsAccessKeyId,
];

/// These paths are instrumentation output, not credential canaries. Package code can create them
/// directly, so collectors must classify them as protected-sensor telemetry and never as a
/// claim-bearing canary read.
pub fn is_linux_vz_package_npm_environment_credential_sensor_marker_relative_path_v1(
    relative_path: &[u8],
) -> bool {
    MARKER_KINDS_V1
        .iter()
        .any(|kind| relative_path == kind.marker_relative_path().as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxVzPackageNpmEnvironmentCredentialMarkerBindingV1 {
    kind: LinuxVzPackageNpmEnvironmentCredentialMarkerKindV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment_name: Option<&'static str>,
    marker_absolute_path: String,
    marker_relative_path: &'static str,
    marker_relative_path_sha256: Sha256Digest,
}

impl LinuxVzPackageNpmEnvironmentCredentialMarkerBindingV1 {
    pub const fn kind(&self) -> LinuxVzPackageNpmEnvironmentCredentialMarkerKindV1 {
        self.kind
    }

    pub const fn environment_name(&self) -> Option<&'static str> {
        self.environment_name
    }

    pub fn marker_absolute_path(&self) -> &str {
        &self.marker_absolute_path
    }

    pub const fn marker_relative_path(&self) -> &'static str {
        self.marker_relative_path
    }

    pub fn marker_relative_path_sha256(&self) -> &Sha256Digest {
        &self.marker_relative_path_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct SensorBindingDigestWireV1<'a> {
    activation: &'static str,
    hook_absolute_path: &'static str,
    hook_byte_length: String,
    hook_relative_path: &'static str,
    hook_sha256: &'a Sha256Digest,
    markers: &'a [LinuxVzPackageNpmEnvironmentCredentialMarkerBindingV1],
    schema_version: &'static str,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxVzPackageNpmEnvironmentCredentialSensorBindingV1 {
    activation: &'static str,
    binding_sha256: Sha256Digest,
    hook_absolute_path: &'static str,
    hook_byte_length: String,
    hook_relative_path: &'static str,
    hook_sha256: Sha256Digest,
    markers: Vec<LinuxVzPackageNpmEnvironmentCredentialMarkerBindingV1>,
    schema_version: &'static str,
}

impl fmt::Debug for LinuxVzPackageNpmEnvironmentCredentialSensorBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageNpmEnvironmentCredentialSensorBindingV1")
            .field("binding_sha256", &self.binding_sha256)
            .field("hook_sha256", &self.hook_sha256)
            .field("marker_count", &self.markers.len())
            .finish()
    }
}

impl LinuxVzPackageNpmEnvironmentCredentialSensorBindingV1 {
    pub const fn activation(&self) -> &'static str {
        self.activation
    }

    pub fn binding_sha256(&self) -> &Sha256Digest {
        &self.binding_sha256
    }

    pub const fn hook_absolute_path(&self) -> &'static str {
        self.hook_absolute_path
    }

    pub const fn hook_relative_path(&self) -> &'static str {
        self.hook_relative_path
    }

    pub fn hook_sha256(&self) -> &Sha256Digest {
        &self.hook_sha256
    }

    pub fn hook_byte_length(&self) -> usize {
        self.hook_byte_length
            .parse()
            .expect("fixed sensor hook byte length")
    }

    pub fn markers(&self) -> &[LinuxVzPackageNpmEnvironmentCredentialMarkerBindingV1] {
        &self.markers
    }

    pub fn marker(
        &self,
        kind: LinuxVzPackageNpmEnvironmentCredentialMarkerKindV1,
    ) -> &LinuxVzPackageNpmEnvironmentCredentialMarkerBindingV1 {
        self.markers
            .iter()
            .find(|marker| marker.kind == kind)
            .expect("fixed sensor marker kind")
    }

    pub fn node_options_value_v1(&self) -> String {
        format!("--require={}", self.hook_absolute_path)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageNpmEnvironmentCredentialSensorErrorV1 {
    Serialization,
    HookMeasurementMismatch,
}

impl LinuxVzPackageNpmEnvironmentCredentialSensorErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Serialization => {
                "linux_vz_package_npm_environment_credential_sensor_serialization_failed"
            }
            Self::HookMeasurementMismatch => {
                "linux_vz_package_npm_environment_credential_sensor_hook_measurement_mismatch"
            }
        }
    }
}

impl fmt::Display for LinuxVzPackageNpmEnvironmentCredentialSensorErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageNpmEnvironmentCredentialSensorErrorV1 {}

pub fn fixed_linux_vz_package_npm_environment_credential_sensor_binding_v1() -> Result<
    LinuxVzPackageNpmEnvironmentCredentialSensorBindingV1,
    LinuxVzPackageNpmEnvironmentCredentialSensorErrorV1,
> {
    let hook_sha256 =
        Sha256Digest::from_bytes(LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_V1);
    let markers = MARKER_KINDS_V1
        .into_iter()
        .map(
            |kind| LinuxVzPackageNpmEnvironmentCredentialMarkerBindingV1 {
                kind,
                environment_name: kind.environment_name(),
                marker_absolute_path: kind.marker_absolute_path(),
                marker_relative_path: kind.marker_relative_path(),
                marker_relative_path_sha256: Sha256Digest::from_bytes(
                    kind.marker_relative_path().as_bytes(),
                ),
            },
        )
        .collect::<Vec<_>>();
    let digest_wire = SensorBindingDigestWireV1 {
        activation: LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_ACTIVATION_V1,
        hook_absolute_path:
            LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_ABSOLUTE_PATH_V1,
        hook_byte_length: LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_V1
            .len()
            .to_string(),
        hook_relative_path:
            LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_RELATIVE_PATH_V1,
        hook_sha256: &hook_sha256,
        markers: &markers,
        schema_version: LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_SCHEMA_V1,
    };
    let canonical = serde_json_canonicalizer::to_vec(&digest_wire)
        .map_err(|_| LinuxVzPackageNpmEnvironmentCredentialSensorErrorV1::Serialization)?;
    Ok(LinuxVzPackageNpmEnvironmentCredentialSensorBindingV1 {
        activation: LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_ACTIVATION_V1,
        binding_sha256: Sha256Digest::from_bytes(&canonical),
        hook_absolute_path:
            LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_ABSOLUTE_PATH_V1,
        hook_byte_length: LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_V1
            .len()
            .to_string(),
        hook_relative_path:
            LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_RELATIVE_PATH_V1,
        hook_sha256,
        markers,
        schema_version: LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_SCHEMA_V1,
    })
}

pub fn verify_linux_vz_package_npm_environment_credential_sensor_hook_v1(
    materialized_hook: &[u8],
    binding: &LinuxVzPackageNpmEnvironmentCredentialSensorBindingV1,
) -> Result<(), LinuxVzPackageNpmEnvironmentCredentialSensorErrorV1> {
    let fixed = fixed_linux_vz_package_npm_environment_credential_sensor_binding_v1()?;
    if binding != &fixed
        || materialized_hook.len() != binding.hook_byte_length()
        || Sha256Digest::from_bytes(materialized_hook) != *binding.hook_sha256()
        || materialized_hook != LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_V1
    {
        return Err(LinuxVzPackageNpmEnvironmentCredentialSensorErrorV1::HookMeasurementMismatch);
    }
    Ok(())
}
