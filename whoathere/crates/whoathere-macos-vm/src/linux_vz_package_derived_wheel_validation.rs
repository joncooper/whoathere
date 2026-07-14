// Darwin exposes several stat mode constants narrower than `u32`, while Linux exposes them as
// `u32`; the explicit conversions keep this descriptor code identical on both targets.
#![allow(clippy::useless_conversion)]

use crate::{
    LinuxVzPackageMaterializationPolicyV1, MacosLinuxVzPackageExecutionActionV1,
    MacosLinuxVzPackageExecutionProcessPlanV1, MacosLinuxVzPackageInternalActionV1,
    MaterializedLinuxVzPackageWorkspaceV1, ValidatedLinuxVzPackageDynamicProcessBindingsV1,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use whoathere_artifact::{
    normalize_derived_wheel, ArtifactManifest, NormalizationCompleteness, NormalizationLimits,
    Sha256Digest,
};

pub const LINUX_VZ_PACKAGE_DERIVED_WHEEL_OBSERVATION_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_derived_wheel_observation.v1";
pub const MAX_LINUX_VZ_PACKAGE_DERIVED_WHEEL_OBSERVATION_BYTES_V1: usize = 64 * 1024;

const DERIVED_ABSOLUTE_ROOT_V1: &str = "/run/whoathere/derived";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageDerivedWheelValidationErrorV1 {
    PrivilegeBoundary,
    InvalidProcessPlan,
    WorkspaceInvalid,
    EntrySetInvalid,
    FileInvalid,
    ReadFailed,
    NormalizationFailed,
    SealFailed,
    VerificationFailed,
    Serialization,
    LimitExceeded,
}

impl LinuxVzPackageDerivedWheelValidationErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::PrivilegeBoundary => "linux_vz_package_derived_wheel_privilege_invalid",
            Self::InvalidProcessPlan => "linux_vz_package_derived_wheel_process_plan_invalid",
            Self::WorkspaceInvalid => "linux_vz_package_derived_wheel_workspace_invalid",
            Self::EntrySetInvalid => "linux_vz_package_derived_wheel_entry_set_invalid",
            Self::FileInvalid => "linux_vz_package_derived_wheel_file_invalid",
            Self::ReadFailed => "linux_vz_package_derived_wheel_read_failed",
            Self::NormalizationFailed => "linux_vz_package_derived_wheel_normalization_failed",
            Self::SealFailed => "linux_vz_package_derived_wheel_seal_failed",
            Self::VerificationFailed => "linux_vz_package_derived_wheel_verification_failed",
            Self::Serialization => "linux_vz_package_derived_wheel_serialization_failed",
            Self::LimitExceeded => "linux_vz_package_derived_wheel_limit_exceeded",
        }
    }
}

impl fmt::Display for LinuxVzPackageDerivedWheelValidationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageDerivedWheelValidationErrorV1 {}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DerivedWheelObservationWireV1<'a> {
    schema_version: &'static str,
    process_plan_sha256: &'a Sha256Digest,
    validation_action_index: String,
    absolute_path: &'a str,
    wheel_sha256: &'a Sha256Digest,
    wheel_byte_length: String,
    wheel_device: String,
    wheel_inode: String,
    initial_uid: String,
    initial_gid: String,
    initial_mode: String,
    sealed_uid: String,
    sealed_gid: String,
    sealed_mode: String,
    normalized_manifest_sha256: &'a Sha256Digest,
    normalized_package_name: &'a str,
    normalized_package_version: &'a str,
    normalization_complete: bool,
    directory_root_sealed: bool,
    arbitrary_path_input_present: bool,
    package_execution: bool,
    sync_back: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct LinuxVzPackageDerivedWheelObservationV1 {
    canonical_json: Vec<u8>,
    observation_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    validation_action_index: usize,
    absolute_path: String,
    wheel_sha256: Sha256Digest,
    wheel_byte_length: u64,
    normalized_manifest_sha256: Sha256Digest,
    normalized_package_name: String,
    normalized_package_version: String,
}

impl fmt::Debug for LinuxVzPackageDerivedWheelObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageDerivedWheelObservationV1")
            .field("observation_sha256", &self.observation_sha256)
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field("validation_action_index", &self.validation_action_index)
            .field("absolute_path", &self.absolute_path)
            .field("wheel_sha256", &self.wheel_sha256)
            .field("wheel_byte_length", &self.wheel_byte_length)
            .field(
                "normalized_manifest_sha256",
                &self.normalized_manifest_sha256,
            )
            .finish()
    }
}

impl LinuxVzPackageDerivedWheelObservationV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn observation_sha256(&self) -> &Sha256Digest {
        &self.observation_sha256
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub const fn validation_action_index(&self) -> usize {
        self.validation_action_index
    }

    pub fn absolute_path(&self) -> &str {
        &self.absolute_path
    }

    pub fn wheel_sha256(&self) -> &Sha256Digest {
        &self.wheel_sha256
    }

    pub const fn wheel_byte_length(&self) -> u64 {
        self.wheel_byte_length
    }

    pub fn normalized_manifest_sha256(&self) -> &Sha256Digest {
        &self.normalized_manifest_sha256
    }

    pub fn normalized_package_name(&self) -> &str {
        &self.normalized_package_name
    }

    pub fn normalized_package_version(&self) -> &str {
        &self.normalized_package_version
    }

    pub const fn package_execution_authority_present(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

pub struct ValidatedLinuxVzPackageDerivedWheelV1 {
    process_plan_sha256: Sha256Digest,
    validation_action_index: usize,
    absolute_path: String,
    basename: CString,
    wheel_sha256: Sha256Digest,
    wheel_byte_length: u64,
    wheel_device: u64,
    wheel_inode: u64,
    normalized_manifest: ArtifactManifest,
    initial_uid: u32,
    initial_gid: u32,
    initial_mode: u32,
    supervisor_uid: u32,
    supervisor_gid: u32,
    run_root: File,
    derived_directory: File,
    wheel_file: File,
}

impl fmt::Debug for ValidatedLinuxVzPackageDerivedWheelV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedLinuxVzPackageDerivedWheelV1")
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field("validation_action_index", &self.validation_action_index)
            .field("absolute_path", &self.absolute_path)
            .field("wheel_sha256", &self.wheel_sha256)
            .field("wheel_byte_length", &self.wheel_byte_length)
            .field(
                "normalized_manifest_sha256",
                &self.normalized_manifest.manifest_sha256,
            )
            .field("wheel_bytes", &"<redacted>")
            .finish()
    }
}

impl ValidatedLinuxVzPackageDerivedWheelV1 {
    pub fn process_bindings_v1(&self) -> ValidatedLinuxVzPackageDynamicProcessBindingsV1 {
        ValidatedLinuxVzPackageDynamicProcessBindingsV1::for_derived_wheel_v1(
            self.absolute_path.clone(),
            self.wheel_sha256.clone(),
        )
    }

    pub fn normalized_manifest(&self) -> &ArtifactManifest {
        &self.normalized_manifest
    }

    pub fn verify_prelaunch(
        &mut self,
    ) -> Result<LinuxVzPackageDerivedWheelObservationV1, LinuxVzPackageDerivedWheelValidationErrorV1>
    {
        self.verify_v1()
    }

    pub fn verify_postrun(
        &mut self,
    ) -> Result<LinuxVzPackageDerivedWheelObservationV1, LinuxVzPackageDerivedWheelValidationErrorV1>
    {
        self.verify_v1()
    }

    fn verify_v1(
        &mut self,
    ) -> Result<LinuxVzPackageDerivedWheelObservationV1, LinuxVzPackageDerivedWheelValidationErrorV1>
    {
        verify_run_root_v1(&self.run_root, self.supervisor_uid, self.supervisor_gid)?;
        verify_sealed_derived_directory_v1(
            &self.run_root,
            &self.derived_directory,
            self.supervisor_uid,
            self.supervisor_gid,
        )?;
        if list_directory_names_v1(&self.derived_directory)?
            != [self.basename.to_string_lossy().into_owned()]
        {
            return Err(LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed);
        }
        let reopened = open_file_at_v1(self.derived_directory.as_raw_fd(), &self.basename, false)?;
        let metadata = verify_sealed_file_v1(
            &mut self.wheel_file,
            self.supervisor_uid,
            self.supervisor_gid,
            &self.wheel_sha256,
            self.wheel_byte_length,
        )?;
        let reopened_metadata = reopened
            .metadata()
            .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed)?;
        if metadata.dev() != self.wheel_device
            || metadata.ino() != self.wheel_inode
            || reopened_metadata.dev() != self.wheel_device
            || reopened_metadata.ino() != self.wheel_inode
        {
            return Err(LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed);
        }
        observation_v1(
            &self.process_plan_sha256,
            self.validation_action_index,
            &self.absolute_path,
            &self.wheel_sha256,
            self.wheel_byte_length,
            self.wheel_device,
            self.wheel_inode,
            self.initial_uid,
            self.initial_gid,
            self.initial_mode,
            self.supervisor_uid,
            self.supervisor_gid,
            &self.normalized_manifest,
        )
    }

    #[cfg(test)]
    fn cleanup_for_test_v1(
        &mut self,
        workspace: &mut MaterializedLinuxVzPackageWorkspaceV1,
    ) -> Result<(), LinuxVzPackageDerivedWheelValidationErrorV1> {
        workspace
            .restore_empty_derived_directory_for_test_v1()
            .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid)?;
        if unsafe {
            libc::unlinkat(
                self.derived_directory.as_raw_fd(),
                self.basename.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed);
        }
        self.derived_directory
            .sync_all()
            .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed)
    }
}

pub fn validate_single_linux_vz_package_derived_wheel_v1(
    workspace: &mut MaterializedLinuxVzPackageWorkspaceV1,
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    policy: &LinuxVzPackageMaterializationPolicyV1,
) -> Result<
    (
        ValidatedLinuxVzPackageDerivedWheelV1,
        LinuxVzPackageDerivedWheelObservationV1,
    ),
    LinuxVzPackageDerivedWheelValidationErrorV1,
> {
    policy
        .validate_current_process()
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::PrivilegeBoundary)?;
    if process_plan.package_execution_authority_permitted() || process_plan.sync_back_permitted() {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::InvalidProcessPlan);
    }
    let validation_action_index = exact_validation_action_index_v1(process_plan)?;
    workspace
        .verify_prelaunch()
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid)?;
    let run_root = workspace
        .run_root()
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid)?
        .try_clone()
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid)?;
    let derived_directory = workspace
        .derived_directory_for_validation_v1()
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid)?
        .try_clone()
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid)?;
    verify_package_derived_directory_v1(
        &run_root,
        &derived_directory,
        policy.package_uid(),
        policy.package_gid(),
    )?;

    let names = list_directory_names_v1(&derived_directory)?;
    let [basename] = names.as_slice() else {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::EntrySetInvalid);
    };
    let basename = fixed_wheel_basename_v1(basename)?;
    let mut wheel_file = open_file_at_v1(derived_directory.as_raw_fd(), &basename, true)?;
    let initial_metadata = wheel_file
        .metadata()
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::FileInvalid)?;
    let maximum = NormalizationLimits::default().max_original_bytes;
    if !initial_metadata.file_type().is_file()
        || initial_metadata.uid() != policy.package_uid()
        || initial_metadata.gid() != policy.package_gid()
        || initial_metadata.nlink() != 1
        || initial_metadata.mode() & 0o022 != 0
        || initial_metadata.len() == 0
        || initial_metadata.len() > maximum
    {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::FileInvalid);
    }
    let bytes = read_exact_file_v1(&mut wheel_file, initial_metadata.len())?;
    let wheel_sha256 = Sha256Digest::from_bytes(&bytes);
    let normalized_manifest = normalize_derived_wheel(
        basename
            .to_str()
            .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::FileInvalid)?,
        &bytes,
        NormalizationLimits::default(),
    )
    .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::NormalizationFailed)?
    .into_manifest();
    if normalized_manifest.identity.is_none()
        || normalized_manifest.artifact_sha256 != wheel_sha256
        || normalized_manifest.normalization_completeness != NormalizationCompleteness::Complete
        || !normalized_manifest.issues.is_empty()
        || !normalized_manifest.anomalies.is_empty()
        || !normalized_manifest.excluded_members.is_empty()
        || !normalized_manifest
            .verify_manifest_sha256()
            .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::NormalizationFailed)?
    {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::NormalizationFailed);
    }
    let absolute_path = format!("{DERIVED_ABSOLUTE_ROOT_V1}/{}", basename.to_string_lossy());
    let observation = observation_v1(
        process_plan.process_plan_sha256(),
        validation_action_index,
        &absolute_path,
        &wheel_sha256,
        initial_metadata.len(),
        initial_metadata.dev(),
        initial_metadata.ino(),
        initial_metadata.uid(),
        initial_metadata.gid(),
        initial_metadata.mode() & 0o7777,
        policy.supervisor_uid(),
        policy.supervisor_gid(),
        &normalized_manifest,
    )?;

    let ownership_changed = unsafe {
        libc::fchown(
            wheel_file.as_raw_fd(),
            policy.supervisor_uid(),
            policy.supervisor_gid(),
        )
    } == 0;
    let mode_changed =
        ownership_changed && unsafe { libc::fchmod(wheel_file.as_raw_fd(), 0o444) } == 0;
    let synchronized = mode_changed && wheel_file.sync_all().is_ok();
    if !synchronized {
        let _ = unsafe {
            libc::fchown(
                wheel_file.as_raw_fd(),
                policy.package_uid(),
                policy.package_gid(),
            )
        };
        let original_mode = libc::mode_t::try_from(initial_metadata.mode() & 0o7777)
            .unwrap_or(0o600 as libc::mode_t);
        let _ = unsafe { libc::fchmod(wheel_file.as_raw_fd(), original_mode) };
        let _ = wheel_file.sync_all();
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::SealFailed);
    }
    if workspace
        .seal_derived_directory_after_validation_v1()
        .is_err()
    {
        let _ = unsafe {
            libc::fchown(
                wheel_file.as_raw_fd(),
                policy.package_uid(),
                policy.package_gid(),
            )
        };
        let original_mode = libc::mode_t::try_from(initial_metadata.mode() & 0o7777)
            .unwrap_or(0o600 as libc::mode_t);
        let _ = unsafe { libc::fchmod(wheel_file.as_raw_fd(), original_mode) };
        let _ = wheel_file.sync_all();
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::SealFailed);
    }
    verify_sealed_file_v1(
        &mut wheel_file,
        policy.supervisor_uid(),
        policy.supervisor_gid(),
        &wheel_sha256,
        initial_metadata.len(),
    )?;
    verify_sealed_derived_directory_v1(
        &run_root,
        &derived_directory,
        policy.supervisor_uid(),
        policy.supervisor_gid(),
    )?;

    let validated = ValidatedLinuxVzPackageDerivedWheelV1 {
        process_plan_sha256: process_plan.process_plan_sha256().clone(),
        validation_action_index,
        absolute_path,
        basename,
        wheel_sha256,
        wheel_byte_length: initial_metadata.len(),
        wheel_device: initial_metadata.dev(),
        wheel_inode: initial_metadata.ino(),
        normalized_manifest,
        initial_uid: initial_metadata.uid(),
        initial_gid: initial_metadata.gid(),
        initial_mode: initial_metadata.mode() & 0o7777,
        supervisor_uid: policy.supervisor_uid(),
        supervisor_gid: policy.supervisor_gid(),
        run_root,
        derived_directory,
        wheel_file,
    };
    Ok((validated, observation))
}

fn exact_validation_action_index_v1(
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
) -> Result<usize, LinuxVzPackageDerivedWheelValidationErrorV1> {
    let indices = process_plan
        .actions()
        .iter()
        .enumerate()
        .filter_map(|(index, action)| {
            matches!(
                action,
                MacosLinuxVzPackageExecutionActionV1::Internal {
                    action: MacosLinuxVzPackageInternalActionV1::ValidateSingleDerivedWheel
                }
            )
            .then_some(index)
        })
        .collect::<Vec<_>>();
    let [index] = indices.as_slice() else {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::InvalidProcessPlan);
    };
    Ok(*index)
}

#[allow(clippy::too_many_arguments)]
fn observation_v1(
    process_plan_sha256: &Sha256Digest,
    validation_action_index: usize,
    absolute_path: &str,
    wheel_sha256: &Sha256Digest,
    wheel_byte_length: u64,
    wheel_device: u64,
    wheel_inode: u64,
    initial_uid: u32,
    initial_gid: u32,
    initial_mode: u32,
    sealed_uid: u32,
    sealed_gid: u32,
    normalized_manifest: &ArtifactManifest,
) -> Result<LinuxVzPackageDerivedWheelObservationV1, LinuxVzPackageDerivedWheelValidationErrorV1> {
    let identity = normalized_manifest
        .identity
        .as_ref()
        .ok_or(LinuxVzPackageDerivedWheelValidationErrorV1::NormalizationFailed)?;
    let wire = DerivedWheelObservationWireV1 {
        schema_version: LINUX_VZ_PACKAGE_DERIVED_WHEEL_OBSERVATION_SCHEMA_V1,
        process_plan_sha256,
        validation_action_index: validation_action_index.to_string(),
        absolute_path,
        wheel_sha256,
        wheel_byte_length: wheel_byte_length.to_string(),
        wheel_device: wheel_device.to_string(),
        wheel_inode: wheel_inode.to_string(),
        initial_uid: initial_uid.to_string(),
        initial_gid: initial_gid.to_string(),
        initial_mode: initial_mode.to_string(),
        sealed_uid: sealed_uid.to_string(),
        sealed_gid: sealed_gid.to_string(),
        sealed_mode: "292".to_string(),
        normalized_manifest_sha256: &normalized_manifest.manifest_sha256,
        normalized_package_name: &identity.normalized_name,
        normalized_package_version: &identity.version,
        normalization_complete: true,
        directory_root_sealed: true,
        arbitrary_path_input_present: false,
        package_execution: false,
        sync_back: false,
    };
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::Serialization)?;
    if canonical_json.is_empty()
        || canonical_json.len() > MAX_LINUX_VZ_PACKAGE_DERIVED_WHEEL_OBSERVATION_BYTES_V1
    {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::LimitExceeded);
    }
    Ok(LinuxVzPackageDerivedWheelObservationV1 {
        observation_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        process_plan_sha256: process_plan_sha256.clone(),
        validation_action_index,
        absolute_path: absolute_path.to_string(),
        wheel_sha256: wheel_sha256.clone(),
        wheel_byte_length,
        normalized_manifest_sha256: normalized_manifest.manifest_sha256.clone(),
        normalized_package_name: identity.normalized_name.clone(),
        normalized_package_version: identity.version.clone(),
    })
}

fn verify_run_root_v1(
    run_root: &File,
    supervisor_uid: u32,
    supervisor_gid: u32,
) -> Result<(), LinuxVzPackageDerivedWheelValidationErrorV1> {
    let metadata = run_root
        .metadata()
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != supervisor_uid
        || metadata.gid() != supervisor_gid
        || metadata.mode() & 0o022 != 0
    {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid);
    }
    Ok(())
}

fn verify_package_derived_directory_v1(
    run_root: &File,
    directory: &File,
    package_uid: u32,
    package_gid: u32,
) -> Result<(), LinuxVzPackageDerivedWheelValidationErrorV1> {
    verify_named_directory_v1(run_root, directory, package_uid, package_gid, 0o700)
}

fn verify_sealed_derived_directory_v1(
    run_root: &File,
    directory: &File,
    supervisor_uid: u32,
    supervisor_gid: u32,
) -> Result<(), LinuxVzPackageDerivedWheelValidationErrorV1> {
    verify_named_directory_v1(run_root, directory, supervisor_uid, supervisor_gid, 0o555)
}

fn verify_named_directory_v1(
    run_root: &File,
    directory: &File,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<(), LinuxVzPackageDerivedWheelValidationErrorV1> {
    let name = CString::new("derived").expect("fixed derived name");
    let reopened = open_directory_at_v1(run_root.as_raw_fd(), &name)?;
    let retained_metadata = directory
        .metadata()
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid)?;
    let reopened_metadata = reopened
        .metadata()
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid)?;
    if !retained_metadata.file_type().is_dir()
        || retained_metadata.uid() != expected_uid
        || retained_metadata.gid() != expected_gid
        || retained_metadata.mode() & 0o7777 != expected_mode
        || retained_metadata.dev() != reopened_metadata.dev()
        || retained_metadata.ino() != reopened_metadata.ino()
    {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid);
    }
    Ok(())
}

fn verify_sealed_file_v1(
    file: &mut File,
    supervisor_uid: u32,
    supervisor_gid: u32,
    expected_sha256: &Sha256Digest,
    expected_length: u64,
) -> Result<std::fs::Metadata, LinuxVzPackageDerivedWheelValidationErrorV1> {
    let metadata = file
        .metadata()
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != supervisor_uid
        || metadata.gid() != supervisor_gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o444
        || metadata.len() != expected_length
        || hash_file_v1(file, expected_length)? != *expected_sha256
    {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed);
    }
    Ok(metadata)
}

fn read_exact_file_v1(
    file: &mut File,
    length: u64,
) -> Result<Vec<u8>, LinuxVzPackageDerivedWheelValidationErrorV1> {
    let capacity = usize::try_from(length)
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::LimitExceeded)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::ReadFailed)?;
    let mut bytes = vec![0_u8; capacity];
    file.read_exact(&mut bytes)
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::ReadFailed)?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::ReadFailed)?
        != 0
    {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::ReadFailed);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::ReadFailed)?;
    Ok(bytes)
}

fn hash_file_v1(
    file: &mut File,
    length: u64,
) -> Result<Sha256Digest, LinuxVzPackageDerivedWheelValidationErrorV1> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed)?;
    let mut hasher = Sha256::new();
    let mut remaining = length;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::LimitExceeded)?;
        let count = file
            .read(&mut buffer[..requested])
            .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed)?;
        if count == 0 {
            return Err(LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed);
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed)?
        != 0
    {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed)?;
    let bytes = hasher.finalize();
    Sha256Digest::parse(format!(
        "sha256:{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
    .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::VerificationFailed)
}

fn fixed_wheel_basename_v1(
    value: &str,
) -> Result<CString, LinuxVzPackageDerivedWheelValidationErrorV1> {
    if value.is_empty()
        || value.len() > 255
        || !value.is_ascii()
        || !value.ends_with(".whl")
        || value.starts_with('.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::EntrySetInvalid);
    }
    CString::new(value).map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::EntrySetInvalid)
}

fn open_directory_at_v1(
    parent: RawFd,
    name: &CString,
) -> Result<File, LinuxVzPackageDerivedWheelValidationErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_file_at_v1(
    parent: RawFd,
    name: &CString,
    writable: bool,
) -> Result<File, LinuxVzPackageDerivedWheelValidationErrorV1> {
    let access = if writable {
        libc::O_RDWR
    } else {
        libc::O_RDONLY
    };
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            access | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::FileInvalid);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn list_directory_names_v1(
    directory: &File,
) -> Result<Vec<String>, LinuxVzPackageDerivedWheelValidationErrorV1> {
    let current = CString::new(".").expect("fixed current-directory component");
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            current.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid);
    }
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        unsafe {
            libc::close(descriptor);
        }
        return Err(LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid);
    }
    let mut names = Vec::new();
    loop {
        set_errno_v1(0);
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = errno_v1();
            unsafe {
                libc::closedir(stream);
            }
            if error != 0 {
                return Err(LinuxVzPackageDerivedWheelValidationErrorV1::WorkspaceInvalid);
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let value = std::str::from_utf8(bytes)
            .map_err(|_| LinuxVzPackageDerivedWheelValidationErrorV1::EntrySetInvalid)?;
        names.push(value.to_string());
    }
    names.sort();
    Ok(names)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn errno_v1() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn errno_v1() -> i32 {
    unsafe { *libc::__error() }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_errno_v1(value: i32) {
    unsafe {
        *libc::__errno_location() = value;
    }
}

#[cfg(target_os = "macos")]
fn set_errno_v1(value: i32) {
    unsafe {
        *libc::__error() = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        create_test_linux_vz_package_workspace_at_v1,
        derive_macos_linux_vz_package_execution_process_plan_v1,
        linux_vz_package_execution_program::test_macos_linux_vz_package_execution_program_v1,
        MacosLinuxVzPackageExecutionStageV1, MacosLinuxVzPackageRuntimeExecutablesV1,
    };
    use std::io::{Cursor, Write};
    use std::path::PathBuf;
    use zip::write::SimpleFileOptions;

    fn derived_plan() -> MacosLinuxVzPackageExecutionProcessPlanV1 {
        let program = test_macos_linux_vz_package_execution_program_v1(
            MacosLinuxVzPackageRuntimeExecutablesV1::PythonPip {
                python_version: "3.14.0".to_string(),
                python_executable_sha256: Sha256Digest::from_bytes(b"inert python"),
                pip_version: "25.2".to_string(),
                pip_cli_sha256: Sha256Digest::from_bytes(b"inert pip"),
            },
            "sdist_build_exact",
            vec![
                MacosLinuxVzPackageExecutionStageV1::PythonSafelyExtractExactSdist {
                    input_basename: "package.tar.gz".to_string(),
                    artifact_format: whoathere_artifact::ArtifactFormat::SdistTarGzip,
                    expected_archive_root: "derived_pkg-1.0.0".to_string(),
                },
                MacosLinuxVzPackageExecutionStageV1::PythonValidateSingleDerivedWheel,
            ],
        );
        derive_macos_linux_vz_package_execution_process_plan_v1(&program).expect("process plan")
    }

    fn wheel_bytes() -> Vec<u8> {
        const DIST_INFO: &str = "derived_pkg-1.0.0.dist-info";
        let metadata = b"Metadata-Version: 2.1\nName: derived-pkg\nVersion: 1.0.0\n\n";
        let wheel = b"Wheel-Version: 1.0\nGenerator: whoathere-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n";
        let module = b"VALUE = 'inert-derived-wheel'\n";
        let mut members = vec![
            (format!("{DIST_INFO}/METADATA"), metadata.as_slice()),
            (format!("{DIST_INFO}/WHEEL"), wheel.as_slice()),
            ("derived_pkg/__init__.py".to_string(), module.as_slice()),
        ];
        let record_path = format!("{DIST_INFO}/RECORD");
        let mut record = members
            .iter()
            .map(|(path, bytes)| {
                format!(
                    "{path},sha256={},{}\n",
                    base64_url_no_pad(&hex_bytes(&sha256_hex_v1(bytes))),
                    bytes.len()
                )
            })
            .collect::<String>();
        record.push_str(&format!("{record_path},,\n"));
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (path, bytes) in members.drain(..) {
            writer
                .start_file(path, SimpleFileOptions::default())
                .expect("wheel member");
            writer.write_all(bytes).expect("wheel bytes");
        }
        writer
            .start_file(record_path, SimpleFileOptions::default())
            .expect("record member");
        writer.write_all(record.as_bytes()).expect("record bytes");
        writer.finish().expect("wheel").into_inner()
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn sha256_hex_v1(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn base64_url_no_pad(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let first = chunk[0];
            let second = chunk.get(1).copied().unwrap_or(0);
            let third = chunk.get(2).copied().unwrap_or(0);
            output.push(ALPHABET[(first >> 2) as usize] as char);
            output.push(ALPHABET[(((first & 3) << 4) | (second >> 4)) as usize] as char);
            if chunk.len() > 1 {
                output.push(ALPHABET[(((second & 15) << 2) | (third >> 6)) as usize] as char);
            }
            if chunk.len() > 2 {
                output.push(ALPHABET[(third & 63) as usize] as char);
            }
        }
        output
    }

    fn unique_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "whoathere-derived-wheel-test-{}-{}",
            std::process::id(),
            &sha256_hex_v1(format!("{:?}", std::time::SystemTime::now()).as_bytes())[..16]
        ))
    }

    #[test]
    fn exact_one_derived_wheel_is_normalized_sealed_and_bound() {
        let base = unique_root();
        std::fs::create_dir(&base).expect("test parent");
        let parent = File::open(&base).expect("open parent");
        let policy = LinuxVzPackageMaterializationPolicyV1::for_current_test_user_v1();
        let plan = derived_plan();
        let mut workspace =
            create_test_linux_vz_package_workspace_at_v1(parent, "scenario", &plan, &policy)
                .expect("workspace");
        let path = base.join("scenario/derived/derived_pkg-1.0.0-py3-none-any.whl");
        std::fs::write(&path, wheel_bytes()).expect("derived wheel");

        let (mut validated, observation) =
            validate_single_linux_vz_package_derived_wheel_v1(&mut workspace, &plan, &policy)
                .expect("validate wheel");
        assert_eq!(observation.normalized_package_name(), "derived-pkg");
        assert_eq!(observation.normalized_package_version(), "1.0.0");
        assert_eq!(
            observation.observation_sha256(),
            &Sha256Digest::from_bytes(observation.canonical_json_v1())
        );
        let binding = validated.process_bindings_v1();
        let install_program = test_macos_linux_vz_package_execution_program_v1(
            MacosLinuxVzPackageRuntimeExecutablesV1::PythonPip {
                python_version: "3.14.0".to_string(),
                python_executable_sha256: Sha256Digest::from_bytes(b"inert python"),
                pip_version: "25.2".to_string(),
                pip_cli_sha256: Sha256Digest::from_bytes(b"inert pip"),
            },
            "sdist_install",
            vec![
                MacosLinuxVzPackageExecutionStageV1::PythonSafelyExtractExactSdist {
                    input_basename: "package.tar.gz".to_string(),
                    artifact_format: whoathere_artifact::ArtifactFormat::SdistTarGzip,
                    expected_archive_root: "derived_pkg-1.0.0".to_string(),
                },
                MacosLinuxVzPackageExecutionStageV1::PythonPipInstallDerivedWheel {
                    resolver_policy:
                        crate::MacosLinuxVzPackageDependencyPolicyV1::NoIndexNoDependencies,
                },
            ],
        );
        let install_plan =
            derive_macos_linux_vz_package_execution_process_plan_v1(&install_program).unwrap();
        let action_index = install_plan
            .actions()
            .iter()
            .position(|action| matches!(action, MacosLinuxVzPackageExecutionActionV1::Process { process } if process.stage_name() == "python_pip_install_derived_wheel"))
            .unwrap();
        let contract = crate::derive_linux_vz_package_process_launch_contract_v1(
            &install_plan,
            action_index,
            &binding,
        )
        .expect("launch contract");
        assert_eq!(
            contract.argv().last().map(String::as_str),
            Some("/run/whoathere/derived/derived_pkg-1.0.0-py3-none-any.whl")
        );
        assert!(contract.measured_inputs().iter().any(|input| {
            input.role() == crate::MacosLinuxVzPackageMeasuredProcessInputRoleV1::DerivedWheel
                && input.expected_sha256() == observation.wheel_sha256()
        }));
        assert_eq!(
            validated
                .verify_prelaunch()
                .expect("reverify")
                .observation_sha256(),
            observation.observation_sha256()
        );

        validated
            .cleanup_for_test_v1(&mut workspace)
            .expect("remove wheel");
        drop(validated);
        workspace.cleanup().expect("workspace cleanup");
        std::fs::remove_dir(&base).expect("test parent cleanup");
    }

    #[test]
    fn zero_or_multiple_or_invalid_derived_wheels_fail_closed() {
        for files in [
            Vec::<(&str, Vec<u8>)>::new(),
            vec![("not-a-wheel.txt", b"inert".to_vec())],
            vec![
                ("derived_pkg-1.0.0-py3-none-any.whl", wheel_bytes()),
                ("other_pkg-1.0.0-py3-none-any.whl", wheel_bytes()),
            ],
        ] {
            let base = unique_root();
            std::fs::create_dir(&base).expect("test parent");
            let parent = File::open(&base).expect("open parent");
            let policy = LinuxVzPackageMaterializationPolicyV1::for_current_test_user_v1();
            let plan = derived_plan();
            let mut workspace =
                create_test_linux_vz_package_workspace_at_v1(parent, "scenario", &plan, &policy)
                    .expect("workspace");
            for (name, bytes) in files {
                std::fs::write(base.join("scenario/derived").join(name), bytes)
                    .expect("test member");
            }
            assert!(validate_single_linux_vz_package_derived_wheel_v1(
                &mut workspace,
                &plan,
                &policy
            )
            .is_err());
            for entry in std::fs::read_dir(base.join("scenario/derived")).unwrap() {
                std::fs::remove_file(entry.unwrap().path()).unwrap();
            }
            workspace.cleanup().expect("workspace cleanup");
            std::fs::remove_dir(&base).expect("test parent cleanup");
        }
    }
}
