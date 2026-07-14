// Darwin exposes several stat mode constants narrower than `u32`, while Linux exposes them as
// `u32`; the explicit conversions keep this descriptor code identical on both targets.
#![allow(clippy::useless_conversion)]

use crate::{
    LinuxVzPackageMaterializationPolicyV1, MacosLinuxVzPackageExecutionActionV1,
    MacosLinuxVzPackageExecutionProcessPlanV1, MacosLinuxVzPackageInternalActionV1,
    MaterializedLinuxVzPackageArtifactV1,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use whoathere_artifact::{
    prepare_sdist_extraction_v1, ArtifactFormat, NormalizationLimits,
    PreparedSdistExtractionMemberTypeV1, PreparedSdistExtractionMemberV1,
    PreparedSdistExtractionV1, Sha256Digest,
};

const SOURCE_DIRECTORY_NAME_V1: &str = "source";
const SOURCE_DESTINATION_V1: &str = "/run/whoathere/source";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageSdistMaterializationErrorV1 {
    PrivilegeBoundary,
    UnsafeRunRoot,
    InvalidProcessPlan,
    ArtifactVerificationFailed,
    ExtractionPreparationFailed,
    CreateFailed,
    WriteFailed,
    SyncFailed,
    OwnershipFailed,
    VerificationFailed,
}

impl LinuxVzPackageSdistMaterializationErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::PrivilegeBoundary => "linux_vz_package_sdist_materialization_privilege_invalid",
            Self::UnsafeRunRoot => "linux_vz_package_sdist_materialization_run_root_unsafe",
            Self::InvalidProcessPlan => "linux_vz_package_sdist_materialization_plan_invalid",
            Self::ArtifactVerificationFailed => {
                "linux_vz_package_sdist_materialization_artifact_verification_failed"
            }
            Self::ExtractionPreparationFailed => {
                "linux_vz_package_sdist_materialization_extraction_preparation_failed"
            }
            Self::CreateFailed => "linux_vz_package_sdist_materialization_create_failed",
            Self::WriteFailed => "linux_vz_package_sdist_materialization_write_failed",
            Self::SyncFailed => "linux_vz_package_sdist_materialization_sync_failed",
            Self::OwnershipFailed => "linux_vz_package_sdist_materialization_ownership_failed",
            Self::VerificationFailed => {
                "linux_vz_package_sdist_materialization_verification_failed"
            }
        }
    }
}

impl fmt::Display for LinuxVzPackageSdistMaterializationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageSdistMaterializationErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageSdistMaterializationObservationV1 {
    process_plan_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    extraction_manifest_sha256: Sha256Digest,
    artifact_format: ArtifactFormat,
    canonical_archive_root: String,
    member_count: usize,
    expanded_byte_length: u64,
    package_uid: u32,
    package_gid: u32,
    source_device: u64,
    source_inode: u64,
}

impl LinuxVzPackageSdistMaterializationObservationV1 {
    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn extraction_manifest_sha256(&self) -> &Sha256Digest {
        &self.extraction_manifest_sha256
    }

    pub const fn artifact_format(&self) -> ArtifactFormat {
        self.artifact_format
    }

    pub fn canonical_archive_root(&self) -> &str {
        &self.canonical_archive_root
    }

    pub const fn member_count(&self) -> usize {
        self.member_count
    }

    pub const fn expanded_byte_length(&self) -> u64 {
        self.expanded_byte_length
    }

    pub const fn package_uid(&self) -> u32 {
        self.package_uid
    }

    pub const fn package_gid(&self) -> u32 {
        self.package_gid
    }

    pub const fn source_device(&self) -> u64 {
        self.source_device
    }

    pub const fn source_inode(&self) -> u64 {
        self.source_inode
    }
}

pub struct MaterializedLinuxVzPackageSdistSourceV1 {
    run_root: File,
    source_directory: File,
    source_name: CString,
    prepared: PreparedSdistExtractionV1,
    process_plan_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    package_uid: u32,
    package_gid: u32,
    source_device: u64,
    source_inode: u64,
}

impl fmt::Debug for MaterializedLinuxVzPackageSdistSourceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializedLinuxVzPackageSdistSourceV1")
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field("artifact_sha256", &self.artifact_sha256)
            .field(
                "extraction_manifest_sha256",
                self.prepared.extraction_manifest_sha256(),
            )
            .field("member_count", &self.prepared.members().len())
            .field("source_device", &self.source_device)
            .field("source_inode", &self.source_inode)
            .field("source_bytes", &"<redacted>")
            .field("path", &"<fixed-run-root-source-path-redacted>")
            .finish()
    }
}

impl MaterializedLinuxVzPackageSdistSourceV1 {
    pub fn verify_prelaunch(
        &mut self,
    ) -> Result<
        LinuxVzPackageSdistMaterializationObservationV1,
        LinuxVzPackageSdistMaterializationErrorV1,
    > {
        verify_named_directory_v1(
            &self.run_root,
            &self.source_name,
            &self.source_directory,
            self.package_uid,
            self.package_gid,
            0o700,
            self.source_device,
            self.source_inode,
        )?;
        verify_source_tree_v1(
            &self.source_directory,
            &self.prepared,
            self.package_uid,
            self.package_gid,
        )?;
        Ok(self.observation())
    }

    fn observation(&self) -> LinuxVzPackageSdistMaterializationObservationV1 {
        LinuxVzPackageSdistMaterializationObservationV1 {
            process_plan_sha256: self.process_plan_sha256.clone(),
            artifact_sha256: self.artifact_sha256.clone(),
            extraction_manifest_sha256: self.prepared.extraction_manifest_sha256().clone(),
            artifact_format: self.prepared.artifact_format(),
            canonical_archive_root: self.prepared.canonical_archive_root().to_string(),
            member_count: self.prepared.members().len(),
            expanded_byte_length: self.prepared.expanded_byte_length(),
            package_uid: self.package_uid,
            package_gid: self.package_gid,
            source_device: self.source_device,
            source_inode: self.source_inode,
        }
    }
}

pub fn materialize_linux_vz_package_sdist_source_v1(
    run_root: &File,
    exact_artifact: &mut MaterializedLinuxVzPackageArtifactV1,
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    policy: &LinuxVzPackageMaterializationPolicyV1,
) -> Result<
    (
        MaterializedLinuxVzPackageSdistSourceV1,
        LinuxVzPackageSdistMaterializationObservationV1,
    ),
    LinuxVzPackageSdistMaterializationErrorV1,
> {
    policy
        .validate_current_process()
        .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::PrivilegeBoundary)?;
    validate_run_root_v1(run_root, policy)?;
    let (input_basename, artifact_format, expected_archive_root) =
        exact_sdist_action_v1(process_plan)?;
    let materialized_basename = exact_materialization_basename_v1(process_plan)?;
    if input_basename != materialized_basename {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::InvalidProcessPlan);
    }
    let artifact_bytes = exact_artifact
        .verified_exact_artifact_bytes_for_plan_v1(process_plan)
        .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::ArtifactVerificationFailed)?;
    let prepared = prepare_sdist_extraction_v1(
        &artifact_bytes,
        artifact_format,
        &expected_archive_root,
        NormalizationLimits::default(),
    )
    .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::ExtractionPreparationFailed)?;
    let retained_run_root = run_root
        .try_clone()
        .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::CreateFailed)?;
    let source_name = fixed_component_v1(SOURCE_DIRECTORY_NAME_V1)?;
    create_directory_at_v1(run_root.as_raw_fd(), &source_name, 0o700)?;
    let source_directory = match open_directory_at_v1(run_root.as_raw_fd(), &source_name) {
        Ok(directory) => directory,
        Err(error) => {
            remove_source_root_v1(run_root, &source_name);
            return Err(error);
        }
    };

    let result = (|| {
        verify_directory_descriptor_v1(
            &source_directory,
            policy.supervisor_uid(),
            policy.supervisor_gid(),
            0o700,
        )?;
        materialize_prepared_members_v1(
            &source_directory,
            &prepared,
            policy.supervisor_uid(),
            policy.supervisor_gid(),
        )?;
        verify_source_tree_v1(
            &source_directory,
            &prepared,
            policy.supervisor_uid(),
            policy.supervisor_gid(),
        )?;
        transfer_tree_ownership_v1(
            &source_directory,
            &prepared,
            policy.package_uid(),
            policy.package_gid(),
        )?;
        set_owner_v1(
            &source_directory,
            policy.package_uid(),
            policy.package_gid(),
        )?;
        source_directory
            .sync_all()
            .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::SyncFailed)?;
        let metadata = source_directory
            .metadata()
            .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
        verify_named_directory_v1(
            run_root,
            &source_name,
            &source_directory,
            policy.package_uid(),
            policy.package_gid(),
            0o700,
            metadata.dev(),
            metadata.ino(),
        )?;
        verify_source_tree_v1(
            &source_directory,
            &prepared,
            policy.package_uid(),
            policy.package_gid(),
        )?;
        run_root
            .sync_all()
            .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::SyncFailed)?;
        Ok((metadata.dev(), metadata.ino()))
    })();

    match result {
        Ok((source_device, source_inode)) => {
            let materialized = MaterializedLinuxVzPackageSdistSourceV1 {
                run_root: retained_run_root,
                source_directory,
                source_name,
                prepared,
                process_plan_sha256: process_plan.process_plan_sha256().clone(),
                artifact_sha256: process_plan.artifact_sha256().clone(),
                package_uid: policy.package_uid(),
                package_gid: policy.package_gid(),
                source_device,
                source_inode,
            };
            let observation = materialized.observation();
            Ok((materialized, observation))
        }
        Err(error) => {
            best_effort_remove_prepared_tree_v1(
                run_root,
                &source_directory,
                &source_name,
                &prepared,
            );
            Err(error)
        }
    }
}

fn exact_sdist_action_v1(
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
) -> Result<(String, ArtifactFormat, String), LinuxVzPackageSdistMaterializationErrorV1> {
    let mut actions = process_plan
        .actions()
        .iter()
        .filter_map(|action| match action {
            MacosLinuxVzPackageExecutionActionV1::Internal {
                action:
                    MacosLinuxVzPackageInternalActionV1::SafelyExtractExactSdist {
                        input_basename,
                        artifact_format,
                        expected_archive_root,
                        destination,
                    },
            } => Some((
                input_basename,
                *artifact_format,
                expected_archive_root,
                destination,
            )),
            _ => None,
        });
    let (input_basename, artifact_format, expected_archive_root, destination) = actions
        .next()
        .ok_or(LinuxVzPackageSdistMaterializationErrorV1::InvalidProcessPlan)?;
    if actions.next().is_some()
        || destination != SOURCE_DESTINATION_V1
        || !matches!(
            artifact_format,
            ArtifactFormat::SdistTarGzip | ArtifactFormat::SdistZip
        )
    {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::InvalidProcessPlan);
    }
    Ok((
        input_basename.clone(),
        artifact_format,
        expected_archive_root.clone(),
    ))
}

fn exact_materialization_basename_v1(
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
) -> Result<String, LinuxVzPackageSdistMaterializationErrorV1> {
    let mut actions = process_plan.actions().iter().filter_map(|action| match action {
        MacosLinuxVzPackageExecutionActionV1::Internal {
            action: MacosLinuxVzPackageInternalActionV1::MaterializeExactArtifact {
                input_basename,
            },
        } => Some(input_basename),
        _ => None,
    });
    let basename = actions
        .next()
        .ok_or(LinuxVzPackageSdistMaterializationErrorV1::InvalidProcessPlan)?;
    if actions.next().is_some() {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::InvalidProcessPlan);
    }
    Ok(basename.clone())
}

fn validate_run_root_v1(
    run_root: &File,
    policy: &LinuxVzPackageMaterializationPolicyV1,
) -> Result<(), LinuxVzPackageSdistMaterializationErrorV1> {
    let metadata = run_root
        .metadata()
        .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::UnsafeRunRoot)?;
    let package_can_traverse = if policy.package_uid() == policy.supervisor_uid() {
        metadata.mode() & 0o100 != 0
    } else if policy.package_gid() == metadata.gid() {
        metadata.mode() & 0o010 != 0
    } else {
        metadata.mode() & 0o001 != 0
    };
    if !metadata.file_type().is_dir()
        || metadata.uid() != policy.supervisor_uid()
        || metadata.gid() != policy.supervisor_gid()
        || metadata.mode() & 0o022 != 0
        || !package_can_traverse
    {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::UnsafeRunRoot);
    }
    Ok(())
}

fn materialize_prepared_members_v1(
    source_directory: &File,
    prepared: &PreparedSdistExtractionV1,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), LinuxVzPackageSdistMaterializationErrorV1> {
    for member in prepared.members() {
        let components = relative_components_v1(member.relative_path())?;
        let (parent, name) = open_relative_parent_v1(source_directory, &components)?;
        match member.member_type() {
            PreparedSdistExtractionMemberTypeV1::Directory => {
                create_directory_at_v1(parent.as_raw_fd(), &name, 0o700)?;
                let directory = open_directory_at_v1(parent.as_raw_fd(), &name)?;
                verify_directory_descriptor_v1(&directory, owner_uid, owner_gid, 0o700)?;
                directory
                    .sync_all()
                    .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::SyncFailed)?;
            }
            PreparedSdistExtractionMemberTypeV1::File => {
                let bytes = member
                    .bytes()
                    .ok_or(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
                let mut file = create_file_at_v1(parent.as_raw_fd(), &name, 0o600)?;
                file.write_all(bytes)
                    .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::WriteFailed)?;
                file.sync_all()
                    .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::SyncFailed)?;
                set_mode_v1(&file, member.package_mode())?;
                file.sync_all()
                    .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::SyncFailed)?;
                verify_file_v1(&parent, &name, &mut file, member, owner_uid, owner_gid)?;
            }
        }
        parent
            .sync_all()
            .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::SyncFailed)?;
    }
    source_directory
        .sync_all()
        .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::SyncFailed)
}

fn transfer_tree_ownership_v1(
    source_directory: &File,
    prepared: &PreparedSdistExtractionV1,
    package_uid: u32,
    package_gid: u32,
) -> Result<(), LinuxVzPackageSdistMaterializationErrorV1> {
    for member in prepared
        .members()
        .iter()
        .filter(|member| member.member_type() == PreparedSdistExtractionMemberTypeV1::File)
    {
        let components = relative_components_v1(member.relative_path())?;
        let (parent, name) = open_relative_parent_v1(source_directory, &components)?;
        let file = open_file_at_v1(parent.as_raw_fd(), &name)?;
        set_owner_v1(&file, package_uid, package_gid)?;
        file.sync_all()
            .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::SyncFailed)?;
    }
    let mut directories = prepared
        .members()
        .iter()
        .filter(|member| member.member_type() == PreparedSdistExtractionMemberTypeV1::Directory)
        .collect::<Vec<_>>();
    directories
        .sort_by_key(|member| std::cmp::Reverse(member.relative_path().matches('/').count()));
    for member in directories {
        let components = relative_components_v1(member.relative_path())?;
        let (parent, name) = open_relative_parent_v1(source_directory, &components)?;
        let directory = open_directory_at_v1(parent.as_raw_fd(), &name)?;
        set_owner_v1(&directory, package_uid, package_gid)?;
        directory
            .sync_all()
            .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::SyncFailed)?;
    }
    Ok(())
}

fn verify_source_tree_v1(
    source_directory: &File,
    prepared: &PreparedSdistExtractionV1,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), LinuxVzPackageSdistMaterializationErrorV1> {
    let observed = collect_tree_member_types_v1(source_directory)?;
    let expected = prepared
        .members()
        .iter()
        .map(|member| (member.relative_path().to_string(), member.member_type()))
        .collect::<BTreeMap<_, _>>();
    if observed != expected {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    for member in prepared.members() {
        let components = relative_components_v1(member.relative_path())?;
        let (parent, name) = open_relative_parent_v1(source_directory, &components)?;
        match member.member_type() {
            PreparedSdistExtractionMemberTypeV1::Directory => {
                let directory = open_directory_at_v1(parent.as_raw_fd(), &name)?;
                verify_directory_descriptor_v1(
                    &directory,
                    expected_uid,
                    expected_gid,
                    member.package_mode(),
                )?;
            }
            PreparedSdistExtractionMemberTypeV1::File => {
                let mut file = open_file_at_v1(parent.as_raw_fd(), &name)?;
                verify_file_v1(
                    &parent,
                    &name,
                    &mut file,
                    member,
                    expected_uid,
                    expected_gid,
                )?;
            }
        }
    }
    Ok(())
}

fn relative_components_v1(
    path: &str,
) -> Result<Vec<CString>, LinuxVzPackageSdistMaterializationErrorV1> {
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    let components = path
        .split('/')
        .map(fixed_component_v1)
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() || components.len() > NormalizationLimits::default().max_path_depth {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    Ok(components)
}

fn fixed_component_v1(value: &str) -> Result<CString, LinuxVzPackageSdistMaterializationErrorV1> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.len() > NormalizationLimits::default().max_component_bytes
        || value.contains('/')
        || value.contains('\\')
    {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    CString::new(value).map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)
}

fn open_relative_parent_v1(
    root: &File,
    components: &[CString],
) -> Result<(File, CString), LinuxVzPackageSdistMaterializationErrorV1> {
    let (name, parents) = components
        .split_last()
        .ok_or(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
    let mut parent = root
        .try_clone()
        .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
    for component in parents {
        parent = open_directory_at_v1(parent.as_raw_fd(), component)?;
    }
    Ok((parent, name.clone()))
}

fn create_directory_at_v1(
    parent: RawFd,
    name: &CString,
    mode: u32,
) -> Result<(), LinuxVzPackageSdistMaterializationErrorV1> {
    if unsafe { libc::mkdirat(parent, name.as_ptr(), mode as libc::mode_t) } != 0 {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::CreateFailed);
    }
    Ok(())
}

fn open_directory_at_v1(
    parent: RawFd,
    name: &CString,
) -> Result<File, LinuxVzPackageSdistMaterializationErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn create_file_at_v1(
    parent: RawFd,
    name: &CString,
    mode: u32,
) -> Result<File, LinuxVzPackageSdistMaterializationErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::CreateFailed);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_file_at_v1(
    parent: RawFd,
    name: &CString,
) -> Result<File, LinuxVzPackageSdistMaterializationErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn set_mode_v1(file: &File, mode: u32) -> Result<(), LinuxVzPackageSdistMaterializationErrorV1> {
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    Ok(())
}

fn set_owner_v1(
    file: &File,
    uid: u32,
    gid: u32,
) -> Result<(), LinuxVzPackageSdistMaterializationErrorV1> {
    let metadata = file
        .metadata()
        .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::OwnershipFailed)?;
    if metadata.uid() == uid && metadata.gid() == gid {
        return Ok(());
    }
    if unsafe { libc::fchown(file.as_raw_fd(), uid as libc::uid_t, gid as libc::gid_t) } != 0 {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::OwnershipFailed);
    }
    Ok(())
}

fn verify_directory_descriptor_v1(
    directory: &File,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<(), LinuxVzPackageSdistMaterializationErrorV1> {
    let metadata = directory
        .metadata()
        .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_named_directory_v1(
    parent: &File,
    name: &CString,
    directory: &File,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    expected_device: u64,
    expected_inode: u64,
) -> Result<(), LinuxVzPackageSdistMaterializationErrorV1> {
    verify_directory_descriptor_v1(directory, expected_uid, expected_gid, expected_mode)?;
    let metadata = directory
        .metadata()
        .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
    let raw = stat_at_v1(parent.as_raw_fd(), name)?;
    let raw_mode = raw.st_mode as u32;
    if raw_mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFDIR)
        || metadata.dev() != expected_device
        || metadata.ino() != expected_inode
        || raw.st_dev as u64 != expected_device
        || raw.st_ino as u64 != expected_inode
        || raw.st_uid != expected_uid
        || raw.st_gid != expected_gid
        || raw_mode & 0o7777 != expected_mode
    {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    Ok(())
}

fn verify_file_v1(
    parent: &File,
    name: &CString,
    file: &mut File,
    member: &PreparedSdistExtractionMemberV1,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), LinuxVzPackageSdistMaterializationErrorV1> {
    let expected_digest = member
        .content_sha256()
        .ok_or(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
    let metadata = file
        .metadata()
        .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
    let raw = stat_at_v1(parent.as_raw_fd(), name)?;
    let raw_mode = raw.st_mode as u32;
    if !metadata.file_type().is_file()
        || raw_mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFREG)
        || metadata.dev() != raw.st_dev as u64
        || metadata.ino() != raw.st_ino as u64
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || raw.st_uid != expected_uid
        || raw.st_gid != expected_gid
        || metadata.nlink() != 1
        || raw.st_nlink as u64 != 1
        || metadata.len() != member.byte_length()
        || raw.st_size < 0
        || raw.st_size as u64 != member.byte_length()
        || metadata.mode() & 0o7777 != member.package_mode()
        || raw_mode & 0o7777 != member.package_mode()
    {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    let (digest, length) = hash_file_v1(file)?;
    if &digest != expected_digest || length != member.byte_length() {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    Ok(())
}

fn stat_at_v1(
    parent: RawFd,
    name: &CString,
) -> Result<libc::stat, LinuxVzPackageSdistMaterializationErrorV1> {
    let mut raw = MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            raw.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    Ok(unsafe { raw.assume_init() })
}

fn hash_file_v1(
    file: &mut File,
) -> Result<(Sha256Digest, u64), LinuxVzPackageSdistMaterializationErrorV1> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        length = length
            .checked_add(count as u64)
            .ok_or(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
    let raw: [u8; 32] = hasher.finalize().into();
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in raw {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}")
            .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
    }
    let digest = Sha256Digest::parse(value)
        .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
    Ok((digest, length))
}

struct DirectoryStreamV1(*mut libc::DIR);

impl Drop for DirectoryStreamV1 {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = unsafe { libc::closedir(self.0) };
        }
    }
}

fn collect_tree_member_types_v1(
    source_directory: &File,
) -> Result<
    BTreeMap<String, PreparedSdistExtractionMemberTypeV1>,
    LinuxVzPackageSdistMaterializationErrorV1,
> {
    let mut members = BTreeMap::new();
    collect_directory_members_v1(source_directory, "", 0, &mut members)?;
    Ok(members)
}

fn collect_directory_members_v1(
    directory: &File,
    prefix: &str,
    depth: usize,
    members: &mut BTreeMap<String, PreparedSdistExtractionMemberTypeV1>,
) -> Result<(), LinuxVzPackageSdistMaterializationErrorV1> {
    if depth > NormalizationLimits::default().max_path_depth {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        let _ = unsafe { libc::close(descriptor) };
        return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
    }
    let stream = DirectoryStreamV1(stream);
    loop {
        clear_errno_v1();
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if errno_v1() != 0 {
                return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let name = name
            .to_str()
            .map_err(|_| LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)?;
        let component = fixed_component_v1(name)?;
        let relative_path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        if relative_path.len() > NormalizationLimits::default().max_path_bytes {
            return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
        }
        let raw = stat_at_v1(directory.as_raw_fd(), &component)?;
        let file_type = (raw.st_mode as u32) & u32::from(libc::S_IFMT);
        let member_type = if file_type == u32::from(libc::S_IFDIR) {
            PreparedSdistExtractionMemberTypeV1::Directory
        } else if file_type == u32::from(libc::S_IFREG) {
            PreparedSdistExtractionMemberTypeV1::File
        } else {
            return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
        };
        if members.insert(relative_path.clone(), member_type).is_some() {
            return Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed);
        }
        if member_type == PreparedSdistExtractionMemberTypeV1::Directory {
            let child = open_directory_at_v1(directory.as_raw_fd(), &component)?;
            collect_directory_members_v1(&child, &relative_path, depth + 1, members)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn clear_errno_v1() {
    unsafe { *libc::__error() = 0 };
}

#[cfg(target_os = "macos")]
fn errno_v1() -> i32 {
    unsafe { *libc::__error() }
}

#[cfg(target_os = "linux")]
fn clear_errno_v1() {
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(target_os = "linux")]
fn errno_v1() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn best_effort_remove_prepared_tree_v1(
    run_root: &File,
    source_directory: &File,
    source_name: &CString,
    prepared: &PreparedSdistExtractionV1,
) {
    let _ = unsafe { libc::fchmod(source_directory.as_raw_fd(), 0o700 as libc::mode_t) };
    for member in prepared.members().iter().rev() {
        let Ok(components) = relative_components_v1(member.relative_path()) else {
            continue;
        };
        let Ok((parent, name)) = open_relative_parent_v1(source_directory, &components) else {
            continue;
        };
        let flags = if member.member_type() == PreparedSdistExtractionMemberTypeV1::Directory {
            libc::AT_REMOVEDIR
        } else {
            0
        };
        let _ = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) };
        let _ = parent.sync_all();
    }
    remove_source_root_v1(run_root, source_name);
}

fn remove_source_root_v1(run_root: &File, source_name: &CString) {
    let _ = unsafe {
        libc::unlinkat(
            run_root.as_raw_fd(),
            source_name.as_ptr(),
            libc::AT_REMOVEDIR,
        )
    };
    let _ = run_root.sync_all();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_macos_linux_vz_package_execution_process_plan_v1,
        linux_vz_package_execution_program::test_macos_linux_vz_package_execution_program_for_artifact_v1,
        materialize_linux_vz_package_artifact_v1, MacosLinuxVzPackageExecutionStageV1,
        MacosLinuxVzPackageRuntimeExecutablesV1,
    };
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::fs::{self, DirBuilder, OpenOptions};
    use std::io::Cursor;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn inert_sdist() -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (path, bytes, mode) in [
            (
                "fixture-1.0.0/pyproject.toml",
                b"[build-system]\nrequires=[]\nbuild-backend='fixture'\n".as_slice(),
                0o644,
            ),
            (
                "fixture-1.0.0/src/fixture/__init__.py",
                b"VALUE = 1\n".as_slice(),
                0o644,
            ),
            (
                "fixture-1.0.0/tools/build",
                b"#!/bin/sh\nexit 0\n".as_slice(),
                0o755,
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(bytes.len() as u64);
            header.set_mode(mode);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            archive
                .append_data(&mut header, path, Cursor::new(bytes))
                .expect("append inert member");
        }
        archive
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip")
    }

    fn test_root() -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "whoathere-linux-vz-sdist-materialization-{}-{counter}",
            std::process::id()
        ));
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&path).expect("create test run root");
        path
    }

    fn open_root(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .expect("open run root")
    }

    fn source_file(path: &Path, bytes: &[u8]) -> File {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create source");
        file.write_all(bytes).expect("write source");
        file.sync_all().expect("sync source");
        file.set_permissions(fs::Permissions::from_mode(0o444))
            .expect("seal source");
        file.seek(SeekFrom::Start(0)).expect("rewind source");
        file
    }

    fn sdist_plan(
        bytes: &[u8],
        expected_archive_root: &str,
    ) -> MacosLinuxVzPackageExecutionProcessPlanV1 {
        let program = test_macos_linux_vz_package_execution_program_for_artifact_v1(
            MacosLinuxVzPackageRuntimeExecutablesV1::PythonPip {
                python_version: "3.14.0".to_string(),
                python_executable_sha256: digest("python"),
                pip_version: "25.0".to_string(),
                pip_cli_sha256: digest("pip"),
            },
            "sdist_build_exact",
            vec![
                MacosLinuxVzPackageExecutionStageV1::PythonSafelyExtractExactSdist {
                    input_basename: "package.tar.gz".to_string(),
                    artifact_format: ArtifactFormat::SdistTarGzip,
                    expected_archive_root: expected_archive_root.to_string(),
                },
            ],
            bytes,
        );
        derive_macos_linux_vz_package_execution_process_plan_v1(&program).expect("process plan")
    }

    #[test]
    fn exact_sdist_is_normalized_fd_relatively_then_verified_for_package_user() {
        let bytes = inert_sdist();
        let plan = sdist_plan(&bytes, "fixture-1.0.0");
        let policy = LinuxVzPackageMaterializationPolicyV1::for_current_test_user_v1();
        let root_path = test_root();
        let archive_path = root_path.with_extension("archive");
        let run_root = open_root(&root_path);
        let mut source = source_file(&archive_path, &bytes);
        let (mut exact_artifact, _) =
            materialize_linux_vz_package_artifact_v1(&run_root, &mut source, &plan, &policy)
                .expect("materialize exact archive");

        let (mut materialized, observation) = materialize_linux_vz_package_sdist_source_v1(
            &run_root,
            &mut exact_artifact,
            &plan,
            &policy,
        )
        .expect("materialize normalized source");
        assert_eq!(observation.canonical_archive_root(), "fixture-1.0.0");
        assert_eq!(observation.member_count(), 6);
        assert_eq!(observation.package_uid(), unsafe { libc::geteuid() });
        assert_eq!(
            fs::read(root_path.join("source/src/fixture/__init__.py")).expect("read inert source"),
            b"VALUE = 1\n"
        );
        assert!(!root_path.join("source/fixture-1.0.0").exists());
        assert_eq!(
            fs::symlink_metadata(root_path.join("source/tools/build"))
                .expect("build metadata")
                .mode()
                & 0o7777,
            0o700
        );
        let prelaunch = materialized.verify_prelaunch().expect("prelaunch verify");
        assert_eq!(
            prelaunch.extraction_manifest_sha256(),
            observation.extraction_manifest_sha256()
        );
        assert!(!format!("{materialized:?}").contains("VALUE = 1"));

        drop(materialized);
        exact_artifact.cleanup().expect("cleanup exact artifact");
        drop(exact_artifact);
        drop(source);
        drop(run_root);
        fs::remove_dir_all(root_path.join("source")).expect("remove source tree");
        fs::remove_file(archive_path).expect("remove source archive");
        fs::remove_dir(root_path).expect("remove root");
    }

    #[test]
    fn wrong_root_and_unexpected_post_materialization_member_fail_closed() {
        let bytes = inert_sdist();
        let policy = LinuxVzPackageMaterializationPolicyV1::for_current_test_user_v1();

        let wrong_plan = sdist_plan(&bytes, "other-1.0.0");
        let wrong_root_path = test_root();
        let wrong_archive_path = wrong_root_path.with_extension("archive");
        let wrong_root = open_root(&wrong_root_path);
        let mut wrong_source = source_file(&wrong_archive_path, &bytes);
        let (mut wrong_artifact, _) = materialize_linux_vz_package_artifact_v1(
            &wrong_root,
            &mut wrong_source,
            &wrong_plan,
            &policy,
        )
        .expect("materialize wrong-root exact archive");
        assert!(matches!(
            materialize_linux_vz_package_sdist_source_v1(
                &wrong_root,
                &mut wrong_artifact,
                &wrong_plan,
                &policy,
            ),
            Err(LinuxVzPackageSdistMaterializationErrorV1::ExtractionPreparationFailed)
        ));
        assert!(!wrong_root_path.join("source").exists());
        wrong_artifact.cleanup().expect("cleanup wrong artifact");
        drop(wrong_artifact);
        drop(wrong_source);
        drop(wrong_root);
        fs::remove_file(wrong_archive_path).expect("remove wrong archive");
        fs::remove_dir(wrong_root_path).expect("remove wrong root");

        let plan = sdist_plan(&bytes, "fixture-1.0.0");
        let root_path = test_root();
        let archive_path = root_path.with_extension("archive");
        let run_root = open_root(&root_path);
        let mut source = source_file(&archive_path, &bytes);
        let (mut exact_artifact, _) =
            materialize_linux_vz_package_artifact_v1(&run_root, &mut source, &plan, &policy)
                .expect("materialize exact archive");
        let (mut materialized, _) = materialize_linux_vz_package_sdist_source_v1(
            &run_root,
            &mut exact_artifact,
            &plan,
            &policy,
        )
        .expect("materialize source");
        fs::write(root_path.join("source/unexpected.txt"), b"inert unexpected")
            .expect("write inert unexpected member");
        assert_eq!(
            materialized.verify_prelaunch(),
            Err(LinuxVzPackageSdistMaterializationErrorV1::VerificationFailed)
        );

        drop(materialized);
        exact_artifact.cleanup().expect("cleanup exact artifact");
        drop(exact_artifact);
        drop(source);
        drop(run_root);
        fs::remove_dir_all(root_path.join("source")).expect("remove source tree");
        fs::remove_file(archive_path).expect("remove archive");
        fs::remove_dir(root_path).expect("remove root");
    }
}
