use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_GUEST_ENVIRONMENT_CANARIES_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_guest_environment_canaries.v1";
pub const LINUX_VZ_PACKAGE_GUEST_ENVIRONMENT_CANARY_MATRIX_BINDING_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_guest_environment_canary_matrix_binding.v1";

const ENVIRONMENT_CANARY_KINDS_V1: [LinuxVzPackageGuestEnvironmentCanaryKindV1; 3] = [
    LinuxVzPackageGuestEnvironmentCanaryKindV1::NpmToken,
    LinuxVzPackageGuestEnvironmentCanaryKindV1::GitHubToken,
    LinuxVzPackageGuestEnvironmentCanaryKindV1::AwsAccessKeyId,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzPackageGuestEnvironmentCanaryKindV1 {
    NpmToken,
    GitHubToken,
    AwsAccessKeyId,
}

impl LinuxVzPackageGuestEnvironmentCanaryKindV1 {
    pub const fn environment_name(self) -> &'static str {
        match self {
            Self::NpmToken => "NPM_TOKEN",
            Self::GitHubToken => "GITHUB_TOKEN",
            Self::AwsAccessKeyId => "AWS_ACCESS_KEY_ID",
        }
    }

    const fn derivation_label_v1(self) -> &'static str {
        match self {
            Self::NpmToken => "npm-token",
            Self::GitHubToken => "github-token",
            Self::AwsAccessKeyId => "aws-access-key-id",
        }
    }

    fn format_unissued_value_v1(self, material_sha256: &Sha256Digest) -> String {
        let hexadecimal = material_sha256
            .as_str()
            .strip_prefix("sha256:")
            .expect("sha256 digest prefix");
        match self {
            Self::NpmToken => format!("npm_{}", &hexadecimal[..36]),
            Self::GitHubToken => format!("ghp_{}", &hexadecimal[..36]),
            Self::AwsAccessKeyId => format!("AKIA{}", &hexadecimal[..16].to_ascii_uppercase()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxVzPackageGuestEnvironmentCanaryBindingV1 {
    kind: LinuxVzPackageGuestEnvironmentCanaryKindV1,
    value_sha256: Sha256Digest,
}

impl LinuxVzPackageGuestEnvironmentCanaryBindingV1 {
    pub const fn kind(&self) -> LinuxVzPackageGuestEnvironmentCanaryKindV1 {
        self.kind
    }

    pub const fn environment_name(&self) -> &'static str {
        self.kind.environment_name()
    }

    pub fn value_sha256(&self) -> &Sha256Digest {
        &self.value_sha256
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct LinuxVzPackageGuestEnvironmentCanariesV1 {
    derivation_binding_sha256: Sha256Digest,
    bindings: [LinuxVzPackageGuestEnvironmentCanaryBindingV1; 3],
    values: [String; 3],
}

impl fmt::Debug for LinuxVzPackageGuestEnvironmentCanariesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageGuestEnvironmentCanariesV1")
            .field("derivation_binding_sha256", &self.derivation_binding_sha256)
            .field("bindings", &self.bindings)
            .field("raw_values", &"<fake-canary-values-redacted>")
            .finish()
    }
}

impl LinuxVzPackageGuestEnvironmentCanariesV1 {
    pub fn derivation_binding_sha256(&self) -> &Sha256Digest {
        &self.derivation_binding_sha256
    }

    pub fn bindings(&self) -> &[LinuxVzPackageGuestEnvironmentCanaryBindingV1] {
        &self.bindings
    }

    pub(crate) fn apply_to_exact_environment_v1(
        &self,
        environment: &mut BTreeMap<String, String>,
    ) -> Result<(), LinuxVzPackageGuestEnvironmentCanaryErrorV1> {
        if self
            .bindings
            .iter()
            .any(|binding| environment.contains_key(binding.environment_name()))
        {
            return Err(LinuxVzPackageGuestEnvironmentCanaryErrorV1::EnvironmentCollision);
        }
        for (binding, value) in self.bindings.iter().zip(&self.values) {
            environment.insert(binding.environment_name().to_string(), value.clone());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageGuestEnvironmentCanaryErrorV1 {
    InvalidDerivationBinding,
    EnvironmentCollision,
}

impl LinuxVzPackageGuestEnvironmentCanaryErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidDerivationBinding => {
                "linux_vz_package_guest_environment_canary_derivation_binding_invalid"
            }
            Self::EnvironmentCollision => {
                "linux_vz_package_guest_environment_canary_environment_collision"
            }
        }
    }
}

impl fmt::Display for LinuxVzPackageGuestEnvironmentCanaryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageGuestEnvironmentCanaryErrorV1 {}

/// Produces provider-shaped but never provisioned fake credentials for an exact npm run.
///
/// This first slice is deliberately deterministic so both CI profiles can independently derive
/// the same values from authenticated inputs. That also means artifact-aware code could derive or
/// recognize them; a fresh secret-seeded matrix binding remains an explicit anti-evasion follow-up.
pub fn derive_linux_vz_package_guest_environment_canaries_v1(
    derivation_binding_sha256: &Sha256Digest,
) -> Result<LinuxVzPackageGuestEnvironmentCanariesV1, LinuxVzPackageGuestEnvironmentCanaryErrorV1> {
    if derivation_binding_sha256 == &Sha256Digest::from_bytes(&[]) {
        return Err(LinuxVzPackageGuestEnvironmentCanaryErrorV1::InvalidDerivationBinding);
    }

    let values = ENVIRONMENT_CANARY_KINDS_V1.map(|kind| {
        let derivation = format!(
            "{LINUX_VZ_PACKAGE_GUEST_ENVIRONMENT_CANARIES_SCHEMA_V1}\0{}\0{}",
            kind.derivation_label_v1(),
            derivation_binding_sha256.as_str()
        );
        let material_sha256 = Sha256Digest::from_bytes(derivation.as_bytes());
        kind.format_unissued_value_v1(&material_sha256)
    });
    let bindings = std::array::from_fn(|index| LinuxVzPackageGuestEnvironmentCanaryBindingV1 {
        kind: ENVIRONMENT_CANARY_KINDS_V1[index],
        value_sha256: Sha256Digest::from_bytes(values[index].as_bytes()),
    });
    Ok(LinuxVzPackageGuestEnvironmentCanariesV1 {
        derivation_binding_sha256: derivation_binding_sha256.clone(),
        bindings,
        values,
    })
}

/// Derives the one credential-canary binding shared by every profile in an exact-artifact
/// scenario matrix. The complete scenario plan (not a selected template or one execution grant)
/// makes this stable across CI=false/CI=true while still changing with the prepared artifact or
/// matrix definition.
pub fn derive_linux_vz_package_guest_environment_canary_matrix_binding_v1(
    artifact_sha256: &Sha256Digest,
    scenario_plan_sha256: &Sha256Digest,
) -> Result<Sha256Digest, LinuxVzPackageGuestEnvironmentCanaryErrorV1> {
    let empty = Sha256Digest::from_bytes(&[]);
    if artifact_sha256 == &empty || scenario_plan_sha256 == &empty {
        return Err(LinuxVzPackageGuestEnvironmentCanaryErrorV1::InvalidDerivationBinding);
    }
    let binding = format!(
        "{LINUX_VZ_PACKAGE_GUEST_ENVIRONMENT_CANARY_MATRIX_BINDING_SCHEMA_V1}\0{}\0{}",
        artifact_sha256.as_str(),
        scenario_plan_sha256.as_str()
    );
    Ok(Sha256Digest::from_bytes(binding.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    #[test]
    fn environment_canaries_are_stable_matrix_bound_and_debug_redacted() {
        let first = derive_linux_vz_package_guest_environment_canaries_v1(&digest("matrix one"))
            .expect("first canaries");
        let repeated = derive_linux_vz_package_guest_environment_canaries_v1(&digest("matrix one"))
            .expect("repeated canaries");
        let second = derive_linux_vz_package_guest_environment_canaries_v1(&digest("matrix two"))
            .expect("second canaries");

        assert_eq!(first, repeated);
        assert_ne!(first, second);
        assert_eq!(
            first
                .bindings()
                .iter()
                .map(LinuxVzPackageGuestEnvironmentCanaryBindingV1::environment_name)
                .collect::<Vec<_>>(),
            ["NPM_TOKEN", "GITHUB_TOKEN", "AWS_ACCESS_KEY_ID"]
        );
        for binding in first.bindings() {
            assert_ne!(
                binding.value_sha256(),
                second
                    .bindings()
                    .iter()
                    .find(|candidate| candidate.kind() == binding.kind())
                    .expect("same kind")
                    .value_sha256()
            );
        }
        assert_eq!(first.values[0].len(), 40);
        assert!(first.values[0].starts_with("npm_"));
        assert!(first.values[0][4..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(first.values[1].len(), 40);
        assert!(first.values[1].starts_with("ghp_"));
        assert!(first.values[1][4..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(first.values[2].len(), 20);
        assert!(first.values[2].starts_with("AKIA"));
        assert!(first.values[2][4..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase()));
        assert!(first
            .values
            .iter()
            .all(|value| !value.contains("whoathere") && !value.contains("fake")));
        let debug = format!("{first:?}");
        assert!(debug.contains("<fake-canary-values-redacted>"));
        for value in &first.values {
            assert!(!debug.contains(value));
        }
    }

    #[test]
    fn environment_canaries_refuse_to_overwrite_an_existing_key() {
        let canaries = derive_linux_vz_package_guest_environment_canaries_v1(&digest("matrix"))
            .expect("canaries");
        let mut environment = BTreeMap::from([("NPM_TOKEN".to_string(), "existing".to_string())]);
        assert_eq!(
            canaries.apply_to_exact_environment_v1(&mut environment),
            Err(LinuxVzPackageGuestEnvironmentCanaryErrorV1::EnvironmentCollision)
        );
        assert_eq!(environment.len(), 1);
        assert_eq!(environment["NPM_TOKEN"], "existing");
    }

    #[test]
    fn matrix_binding_is_shared_by_profiles_and_changes_with_artifact_or_plan() {
        let artifact = digest("exact artifact");
        let plan = digest("complete CI profile matrix");
        let first =
            derive_linux_vz_package_guest_environment_canary_matrix_binding_v1(&artifact, &plan)
                .expect("matrix binding");
        let repeated =
            derive_linux_vz_package_guest_environment_canary_matrix_binding_v1(&artifact, &plan)
                .expect("same matrix binding");
        assert_eq!(first, repeated);
        assert_ne!(
            first,
            derive_linux_vz_package_guest_environment_canary_matrix_binding_v1(
                &digest("other exact artifact"),
                &plan,
            )
            .expect("artifact-specific matrix binding")
        );
        assert_ne!(
            first,
            derive_linux_vz_package_guest_environment_canary_matrix_binding_v1(
                &artifact,
                &digest("other complete matrix"),
            )
            .expect("plan-specific matrix binding")
        );
    }
}
