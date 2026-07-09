use crate::archive::{
    read_tar_gzip, read_zip, ArchiveLimits, ArchiveMembers, RawMember, RawMemberType,
};
use crate::{
    ArchiveAnomaly, ArtifactEnvelope, ArtifactFormat, ArtifactManifest, ArtifactManifestInput,
    ArtifactMetadata, DependencyDeclaration, Ecosystem, MemberRecord, MemberType,
    NormalizationCompleteness, NormalizationError, NormalizedArtifact, NormalizedMemberContent,
    NpmMetadata, PackageIdentity, SdistMetadata, Sha256Digest, WheelMetadata,
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Resource ceilings applied before any package metadata is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizationLimits {
    pub max_original_bytes: u64,
    pub max_members: usize,
    pub max_member_bytes: u64,
    pub max_expanded_bytes: u64,
    pub max_compression_ratio: u64,
    pub max_path_bytes: usize,
    pub max_component_bytes: usize,
    pub max_path_depth: usize,
    pub max_metadata_bytes: u64,
    pub max_tar_trailing_bytes: u64,
}

impl Default for NormalizationLimits {
    fn default() -> Self {
        Self {
            max_original_bytes: 64 * 1024 * 1024,
            max_members: 20_000,
            max_member_bytes: 16 * 1024 * 1024,
            max_expanded_bytes: 256 * 1024 * 1024,
            max_compression_ratio: 200,
            max_path_bytes: 1_024,
            max_component_bytes: 255,
            max_path_depth: 32,
            max_metadata_bytes: 2 * 1024 * 1024,
            max_tar_trailing_bytes: 1024 * 1024,
        }
    }
}

impl NormalizationLimits {
    fn archive_limits(self) -> ArchiveLimits {
        ArchiveLimits {
            max_members: self.max_members,
            max_member_bytes: self.max_member_bytes,
            max_expanded_bytes: self.max_expanded_bytes,
            max_compression_ratio: self.max_compression_ratio,
            max_path_bytes: self.max_path_bytes,
            max_component_bytes: self.max_component_bytes,
            max_path_depth: self.max_path_depth,
            max_tar_trailing_bytes: self.max_tar_trailing_bytes,
        }
    }
}

/// Detect the exact supported package form from magic bytes, ecosystem, and filename claim.
pub fn detect_artifact_format(
    ecosystem: Ecosystem,
    original_filename: &str,
    bytes: &[u8],
) -> Result<ArtifactFormat, NormalizationError> {
    let filename = original_filename.to_ascii_lowercase();
    let is_gzip = bytes.starts_with(&[0x1f, 0x8b]);
    let is_zip = bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08");
    match ecosystem {
        Ecosystem::Npm
            if is_gzip && (filename.ends_with(".tgz") || filename.ends_with(".tar.gz")) =>
        {
            Ok(ArtifactFormat::NpmTarGzip)
        }
        Ecosystem::Pypi if is_zip && filename.ends_with(".whl") => Ok(ArtifactFormat::WheelZip),
        Ecosystem::Pypi
            if is_gzip && (filename.ends_with(".tar.gz") || filename.ends_with(".tgz")) =>
        {
            Ok(ArtifactFormat::SdistTarGzip)
        }
        Ecosystem::Pypi if is_zip && filename.ends_with(".zip") => Ok(ArtifactFormat::SdistZip),
        _ => Err(NormalizationError::UnsupportedFormat(format!(
            "ecosystem={ecosystem:?}, filename={original_filename}, magic={}",
            if is_gzip {
                "gzip"
            } else if is_zip {
                "zip"
            } else {
                "unknown"
            }
        ))),
    }
}

/// Normalize exact artifact bytes without extracting or executing any member.
pub fn normalize_artifact(
    envelope: &ArtifactEnvelope,
    original_bytes: &[u8],
    limits: NormalizationLimits,
) -> Result<NormalizedArtifact, NormalizationError> {
    envelope
        .validate()
        .map_err(|error| NormalizationError::Manifest(error.to_string()))?;
    if original_bytes.len() as u64 > limits.max_original_bytes {
        return Err(NormalizationError::OriginalSizeLimit {
            actual: original_bytes.len() as u64,
            limit: limits.max_original_bytes,
        });
    }
    if !envelope.matches_original_bytes(original_bytes) {
        return Err(NormalizationError::ArtifactIdentityMismatch);
    }
    let detected = detect_artifact_format(
        envelope.ecosystem,
        &envelope.original_filename,
        original_bytes,
    )?;
    if !envelope.verify_magic_format(detected) {
        return Err(NormalizationError::FormatMismatch);
    }

    let archive = match detected {
        ArtifactFormat::NpmTarGzip | ArtifactFormat::SdistTarGzip => {
            read_tar_gzip(original_bytes, limits.archive_limits())?
        }
        ArtifactFormat::WheelZip | ArtifactFormat::SdistZip => {
            read_zip(original_bytes, limits.archive_limits())?
        }
        ArtifactFormat::Unknown => {
            return Err(NormalizationError::UnsupportedFormat(
                "unknown archive form".to_string(),
            ));
        }
    };

    match detected {
        ArtifactFormat::NpmTarGzip => normalize_npm(envelope, archive, limits),
        ArtifactFormat::WheelZip => normalize_wheel(envelope, archive, limits),
        ArtifactFormat::SdistTarGzip | ArtifactFormat::SdistZip => {
            normalize_sdist(envelope, archive, detected, limits)
        }
        ArtifactFormat::Unknown => unreachable!("unknown format rejected above"),
    }
}

fn normalize_npm(
    envelope: &ArtifactEnvelope,
    archive: ArchiveMembers,
    limits: NormalizationLimits,
) -> Result<NormalizedArtifact, NormalizationError> {
    let root = one_package_root(&archive.members)?;
    let logical = logical_members(&archive.members, Some(&root), &envelope.original_sha256)?;
    let package_json = required_file(&logical, "package.json")?;
    ensure_metadata_size(package_json, limits.max_metadata_bytes)?;
    let package = parse_strict_json(package_json.bytes)?;
    let object = package.as_object("package.json must be a JSON object")?;
    let display_name = required_json_string(object, "name")?.to_string();
    let version = required_json_string(object, "version")?.to_string();
    let normalized_name = normalize_npm_name(&display_name)?;
    verify_envelope_identity(envelope, &normalized_name, &version)?;

    let mut npm = NpmMetadata {
        package_json_file_id: Some(package_json.record.file_id.clone()),
        ..NpmMetadata::default()
    };
    if let Some(scripts) = object.get("scripts") {
        for (name, command) in scripts.as_object("package.json scripts must be an object")? {
            if is_npm_lifecycle(name) {
                npm.lifecycle_scripts.insert(
                    name.clone(),
                    command
                        .as_string("package.json script command must be a string")?
                        .to_string(),
                );
            }
        }
    }
    if let Some(bin) = object.get("bin") {
        match bin {
            StrictJson::String(target) => {
                let command_name = display_name.rsplit('/').next().unwrap_or(&display_name);
                npm.bin_targets
                    .insert(command_name.to_string(), target.clone());
            }
            StrictJson::Object(entries) => {
                for (name, target) in entries {
                    npm.bin_targets.insert(
                        name.clone(),
                        target
                            .as_string("package.json bin target must be a string")?
                            .to_string(),
                    );
                }
            }
            _ => {
                return Err(NormalizationError::MetadataInvalid(
                    "package.json bin must be a string or object".to_string(),
                ));
            }
        }
    }
    if let Some(exports) = object.get("exports") {
        collect_json_strings(exports, &mut npm.export_targets);
    }
    for group in [
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "devDependencies",
        "bundledDependencies",
        "bundleDependencies",
    ] {
        let Some(value) = object.get(group) else {
            continue;
        };
        match value {
            StrictJson::Object(entries) => {
                for (name, requirement) in entries {
                    npm.dependency_declarations.push(DependencyDeclaration {
                        group: group.to_string(),
                        name: name.clone(),
                        requirement: requirement
                            .as_string("dependency requirement must be a string")?
                            .to_string(),
                    });
                }
            }
            StrictJson::Array(names)
                if matches!(group, "bundledDependencies" | "bundleDependencies") =>
            {
                for name in names {
                    npm.dependency_declarations.push(DependencyDeclaration {
                        group: group.to_string(),
                        name: name
                            .as_string("bundled dependency name must be a string")?
                            .to_string(),
                        requirement: "bundled".to_string(),
                    });
                }
            }
            _ => {
                return Err(NormalizationError::MetadataInvalid(format!(
                    "package.json {group} has the wrong type"
                )));
            }
        }
    }
    npm.requires_offline_closure = npm.dependency_declarations.iter().any(|dependency| {
        matches!(
            dependency.group.as_str(),
            "dependencies" | "optionalDependencies" | "peerDependencies"
        )
    });
    npm.implicit_node_gyp_rebuild = logical_file(&logical, "binding.gyp").is_some()
        && !npm.lifecycle_scripts.contains_key("preinstall")
        && !npm.lifecycle_scripts.contains_key("install");

    let identity = PackageIdentity {
        ecosystem: Ecosystem::Npm,
        display_name,
        normalized_name,
        version,
    };
    let mut input = manifest_input(
        envelope,
        ArtifactFormat::NpmTarGzip,
        root.clone(),
        identity,
        &logical,
    );
    if root != "package" {
        input.anomalies.push(ArchiveAnomaly {
            reason_code: "npm_noncanonical_package_root".to_string(),
            path: Some(root),
        });
    }
    input.metadata.npm = Some(npm);
    let requires_offline_closure = input
        .metadata
        .npm
        .as_ref()
        .is_some_and(|metadata| metadata.requires_offline_closure);
    if envelope.requires_external_dependency_resolution != requires_offline_closure {
        input.issues.push(crate::ManifestIssue {
            reason_code: "envelope_dependency_resolution_requirement_mismatch".to_string(),
            path: Some("package.json".to_string()),
            detail: format!(
                "envelope={} normalized={requires_offline_closure}",
                envelope.requires_external_dependency_resolution
            ),
        });
        input.normalization_completeness = NormalizationCompleteness::Incomplete;
    }
    add_inventory(&logical, &mut input);
    finalize_artifact(input, &logical)
}

fn normalize_wheel(
    envelope: &ArtifactEnvelope,
    archive: ArchiveMembers,
    limits: NormalizationLimits,
) -> Result<NormalizedArtifact, NormalizationError> {
    let logical = logical_members(&archive.members, None, &envelope.original_sha256)?;
    let dist_info_directories = logical
        .iter()
        .filter_map(|member| {
            let first = member.record.normalized_path.split('/').next()?;
            first.ends_with(".dist-info").then(|| first.to_string())
        })
        .collect::<BTreeSet<_>>();
    if dist_info_directories.len() != 1 {
        return Err(NormalizationError::AmbiguousRoot(format!(
            "wheel must contain exactly one .dist-info directory, found {}",
            dist_info_directories.len()
        )));
    }
    let dist_info = dist_info_directories
        .into_iter()
        .next()
        .expect("one dist-info directory");
    let metadata_path = format!("{dist_info}/METADATA");
    let wheel_path = format!("{dist_info}/WHEEL");
    let record_path = format!("{dist_info}/RECORD");
    let metadata_file = required_file(&logical, &metadata_path)?;
    let wheel_file = required_file(&logical, &wheel_path)?;
    let record_file = required_file(&logical, &record_path)?;
    for member in [metadata_file, wheel_file, record_file] {
        ensure_metadata_size(member, limits.max_metadata_bytes)?;
    }

    let metadata_headers = parse_email_headers(metadata_file.bytes)?;
    let display_name = one_header(&metadata_headers, "Name")?.to_string();
    let version = one_header(&metadata_headers, "Version")?.to_string();
    let normalized_name = normalize_pypi_name(&display_name)?;
    verify_envelope_identity(envelope, &normalized_name, &version)?;
    verify_dist_info_identity(&dist_info, &normalized_name, &version)?;

    let wheel_headers = parse_email_headers(wheel_file.bytes)?;
    let wheel_version = one_header(&wheel_headers, "Wheel-Version")?.to_string();
    if wheel_version != "1.0" {
        return Err(NormalizationError::UnsupportedFormat(format!(
            "unsupported Wheel-Version `{wheel_version}`"
        )));
    }
    let root_is_purelib = match one_header(&wheel_headers, "Root-Is-Purelib")?
        .to_ascii_lowercase()
        .as_str()
    {
        "true" => true,
        "false" => false,
        _ => {
            return Err(NormalizationError::MetadataInvalid(
                "WHEEL Root-Is-Purelib must be true or false".to_string(),
            ));
        }
    };
    let tags = wheel_headers.get("tag").cloned().unwrap_or_default();
    if tags.is_empty() {
        return Err(NormalizationError::MetadataInvalid(
            "WHEEL has no Tag field".to_string(),
        ));
    }
    verify_wheel_filename(envelope, &normalized_name, &version, &tags)?;
    validate_wheel_record(&logical, record_file)?;

    let entry_points_path = format!("{dist_info}/entry_points.txt");
    let entry_points = logical_file(&logical, &entry_points_path);
    if let Some(member) = entry_points {
        ensure_metadata_size(member, limits.max_metadata_bytes)?;
    }
    let parsed_entry_points = entry_points
        .map(|member| parse_entry_points(member.bytes))
        .transpose()?
        .unwrap_or_default();
    let console_entry_points = parsed_entry_points
        .get("console_scripts")
        .cloned()
        .unwrap_or_default();

    let pth_file_ids = logical
        .iter()
        .filter(|member| {
            member.record.member_type == MemberType::File
                && member.record.normalized_path.ends_with(".pth")
        })
        .map(|member| member.record.file_id.clone())
        .collect::<Vec<_>>();
    let import_roots = wheel_import_roots(&logical, &dist_info);
    let script_file_ids = logical
        .iter()
        .filter(|member| {
            member.record.member_type == MemberType::File
                && member.record.normalized_path.contains(".data/scripts/")
        })
        .map(|member| member.record.file_id.clone())
        .collect::<Vec<_>>();
    let native_tags = tags
        .iter()
        .filter(|tag| !tag.ends_with("-none-any"))
        .cloned()
        .collect::<Vec<_>>();
    let wheel = WheelMetadata {
        dist_info_directory: Some(dist_info),
        metadata_file_id: Some(metadata_file.record.file_id.clone()),
        wheel_file_id: Some(wheel_file.record.file_id.clone()),
        record_file_id: Some(record_file.record.file_id.clone()),
        entry_points_file_id: entry_points.map(|member| member.record.file_id.clone()),
        wheel_version: Some(wheel_version),
        root_is_purelib: Some(root_is_purelib),
        tags,
        console_entry_points,
        entry_points: parsed_entry_points,
        pth_file_ids,
        script_file_ids,
        import_roots,
        native_tags,
        requires_dist: metadata_headers
            .get("requires-dist")
            .cloned()
            .unwrap_or_default(),
    };
    let requires_external = !wheel.requires_dist.is_empty();
    let identity = PackageIdentity {
        ecosystem: Ecosystem::Pypi,
        display_name,
        normalized_name,
        version,
    };
    let mut input = manifest_input(
        envelope,
        ArtifactFormat::WheelZip,
        ".".to_string(),
        identity,
        &logical,
    );
    input.metadata.wheel = Some(wheel);
    record_dependency_resolution_mismatch(envelope, requires_external, &mut input, &metadata_path);
    add_inventory(&logical, &mut input);
    finalize_artifact(input, &logical)
}

fn normalize_sdist(
    envelope: &ArtifactEnvelope,
    archive: ArchiveMembers,
    format: ArtifactFormat,
    limits: NormalizationLimits,
) -> Result<NormalizedArtifact, NormalizationError> {
    let root = one_package_root(&archive.members)?;
    let logical = logical_members(&archive.members, Some(&root), &envelope.original_sha256)?;
    let pkg_info = required_file(&logical, "PKG-INFO")?;
    ensure_metadata_size(pkg_info, limits.max_metadata_bytes)?;
    let metadata_headers = parse_email_headers(pkg_info.bytes)?;
    let display_name = one_header(&metadata_headers, "Name")?.to_string();
    let version = one_header(&metadata_headers, "Version")?.to_string();
    let normalized_name = normalize_pypi_name(&display_name)?;
    verify_envelope_identity(envelope, &normalized_name, &version)?;
    verify_sdist_root(&root, &normalized_name, &version)?;

    let pyproject = logical_file(&logical, "pyproject.toml");
    let setup_py = logical_file(&logical, "setup.py");
    let setup_cfg = logical_file(&logical, "setup.cfg");
    if pyproject.is_none() && setup_py.is_none() {
        return Err(NormalizationError::MetadataMissing(
            "sdist pyproject.toml or setup.py".to_string(),
        ));
    }
    for member in [pyproject, setup_py, setup_cfg].into_iter().flatten() {
        ensure_metadata_size(member, limits.max_metadata_bytes)?;
    }
    let build_system = pyproject
        .map(|member| parse_build_system(member.bytes))
        .transpose()?
        .unwrap_or_default();
    let package_roots = sdist_package_roots(&logical);
    let sdist = SdistMetadata {
        pkg_info_file_id: Some(pkg_info.record.file_id.clone()),
        pyproject_file_id: pyproject.map(|member| member.record.file_id.clone()),
        setup_py_file_id: setup_py.map(|member| member.record.file_id.clone()),
        setup_cfg_file_id: setup_cfg.map(|member| member.record.file_id.clone()),
        build_backend: build_system.backend,
        build_requires: build_system.requires,
        backend_paths: build_system.backend_paths,
        package_roots,
        requires_dist: metadata_headers
            .get("requires-dist")
            .cloned()
            .unwrap_or_default(),
        dynamic_build_requirements_possible: pyproject.is_some(),
    };
    let requires_external = !sdist.build_requires.is_empty()
        || !sdist.requires_dist.is_empty()
        || sdist.dynamic_build_requirements_possible;
    let identity = PackageIdentity {
        ecosystem: Ecosystem::Pypi,
        display_name,
        normalized_name,
        version,
    };
    let mut input = manifest_input(envelope, format, root, identity, &logical);
    input.metadata.sdist = Some(sdist);
    record_dependency_resolution_mismatch(
        envelope,
        requires_external,
        &mut input,
        "pyproject.toml",
    );
    add_inventory(&logical, &mut input);
    finalize_artifact(input, &logical)
}

#[derive(Debug)]
struct LogicalMember<'a> {
    record: MemberRecord,
    bytes: &'a [u8],
}

fn one_package_root(members: &[RawMember]) -> Result<String, NormalizationError> {
    let roots = members
        .iter()
        .filter_map(|member| member.archive_path.split('/').next())
        .collect::<BTreeSet<_>>();
    if roots.len() != 1 {
        return Err(NormalizationError::AmbiguousRoot(format!(
            "expected one top-level root, found {}",
            roots.len()
        )));
    }
    let root = roots.into_iter().next().expect("one root");
    if !members.iter().any(|member| {
        member.member_type == RawMemberType::File
            && member.archive_path.starts_with(&format!("{root}/"))
    }) {
        return Err(NormalizationError::AmbiguousRoot(
            "package root contains no regular files".to_string(),
        ));
    }
    Ok(root.to_string())
}

fn logical_members<'a>(
    members: &'a [RawMember],
    root: Option<&str>,
    artifact_sha256: &Sha256Digest,
) -> Result<Vec<LogicalMember<'a>>, NormalizationError> {
    let mut logical_paths = BTreeSet::new();
    let mut logical = Vec::with_capacity(members.len());
    for member in members {
        let normalized_path = match root {
            Some(root) if member.archive_path == root => ".".to_string(),
            Some(root) => member
                .archive_path
                .strip_prefix(&format!("{root}/"))
                .ok_or_else(|| {
                    NormalizationError::AmbiguousRoot(format!(
                        "member `{}` is outside root `{root}`",
                        member.archive_path
                    ))
                })?
                .to_string(),
            None => member.archive_path.clone(),
        };
        if !logical_paths.insert(normalized_path.clone()) {
            return Err(NormalizationError::DuplicatePath {
                path: normalized_path,
            });
        }
        let member_type = match member.member_type {
            RawMemberType::File => MemberType::File,
            RawMemberType::Directory => MemberType::Directory,
        };
        logical.push(LogicalMember {
            record: MemberRecord::from_bytes(
                artifact_sha256,
                normalized_path,
                member.original_path.clone(),
                member_type,
                member.mode,
                &member.bytes,
            ),
            bytes: &member.bytes,
        });
    }
    logical.sort_by(|left, right| {
        left.record
            .normalized_path
            .cmp(&right.record.normalized_path)
    });
    Ok(logical)
}

fn required_file<'a>(
    members: &'a [LogicalMember<'a>],
    path: &str,
) -> Result<&'a LogicalMember<'a>, NormalizationError> {
    logical_file(members, path).ok_or_else(|| NormalizationError::MetadataMissing(path.to_string()))
}

fn logical_file<'a>(members: &'a [LogicalMember<'a>], path: &str) -> Option<&'a LogicalMember<'a>> {
    members.iter().find(|member| {
        member.record.normalized_path == path && member.record.member_type == MemberType::File
    })
}

fn ensure_metadata_size(member: &LogicalMember<'_>, limit: u64) -> Result<(), NormalizationError> {
    if member.record.size > limit {
        return Err(NormalizationError::MemberSizeLimit {
            path: member.record.normalized_path.clone(),
            actual: member.record.size,
            limit,
        });
    }
    Ok(())
}

fn manifest_input(
    envelope: &ArtifactEnvelope,
    format: ArtifactFormat,
    canonical_root: String,
    identity: PackageIdentity,
    members: &[LogicalMember<'_>],
) -> ArtifactManifestInput {
    let mut input = ArtifactManifestInput::new(
        envelope.original_sha256.clone(),
        format,
        canonical_root,
        Some(identity),
    );
    input.members = members.iter().map(|member| member.record.clone()).collect();
    input.normalization_completeness = NormalizationCompleteness::Complete;
    input.metadata = ArtifactMetadata::default();
    input
}

fn finalize_artifact(
    input: ArtifactManifestInput,
    members: &[LogicalMember<'_>],
) -> Result<NormalizedArtifact, NormalizationError> {
    let manifest = ArtifactManifest::new(input)
        .map_err(|error| NormalizationError::Manifest(error.to_string()))?;
    let contents = members
        .iter()
        .filter(|member| member.record.member_type == MemberType::File)
        .map(|member| {
            (
                member.record.file_id.clone(),
                NormalizedMemberContent::from_record(&member.record, member.bytes),
            )
        })
        .collect::<BTreeMap<_, _>>();
    NormalizedArtifact::from_parts(manifest, contents)
        .map_err(|error| NormalizationError::Manifest(error.to_string()))
}

fn record_dependency_resolution_mismatch(
    envelope: &ArtifactEnvelope,
    normalized_requirement: bool,
    input: &mut ArtifactManifestInput,
    path: &str,
) {
    if envelope.requires_external_dependency_resolution == normalized_requirement {
        return;
    }
    input.issues.push(crate::ManifestIssue {
        reason_code: "envelope_dependency_resolution_requirement_mismatch".to_string(),
        path: Some(path.to_string()),
        detail: format!(
            "envelope={} normalized={normalized_requirement}",
            envelope.requires_external_dependency_resolution
        ),
    });
    input.normalization_completeness = NormalizationCompleteness::Incomplete;
}

fn verify_envelope_identity(
    envelope: &ArtifactEnvelope,
    normalized_name: &str,
    version: &str,
) -> Result<(), NormalizationError> {
    if version.is_empty()
        || version.trim() != version
        || version.chars().any(|character| character.is_control())
    {
        return Err(NormalizationError::MetadataInvalid(
            "package version is empty or contains unsupported whitespace/control data".to_string(),
        ));
    }
    if let Some(expected) = envelope.package_name.as_deref() {
        let expected = match envelope.ecosystem {
            Ecosystem::Npm => normalize_npm_name(expected)?,
            Ecosystem::Pypi => normalize_pypi_name(expected)?,
        };
        if expected != normalized_name {
            return Err(NormalizationError::IdentityMismatch(format!(
                "envelope name `{expected}` != metadata name `{normalized_name}`"
            )));
        }
    }
    if let Some(expected) = envelope.package_version.as_deref() {
        if expected != version {
            return Err(NormalizationError::IdentityMismatch(format!(
                "envelope version `{expected}` != metadata version `{version}`"
            )));
        }
    }
    Ok(())
}

fn normalize_npm_name(name: &str) -> Result<String, NormalizationError> {
    let components = if let Some(scoped) = name.strip_prefix('@') {
        let parts = scoped.split('/').collect::<Vec<_>>();
        if parts.len() != 2 {
            return Err(NormalizationError::MetadataInvalid(
                "scoped npm package name must contain exactly one scope separator".to_string(),
            ));
        }
        parts
    } else {
        if name.contains('/') {
            return Err(NormalizationError::MetadataInvalid(
                "unscoped npm package name contains a slash".to_string(),
            ));
        }
        vec![name]
    };
    let valid_component = |component: &str| {
        !component.is_empty()
            && !component.starts_with(['.', '_'])
            && component.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.' | b'~')
            })
    };
    if name.is_empty()
        || name.len() > 214
        || name.trim() != name
        || name.chars().any(|character| character.is_control())
        || name.contains('\\')
        || components
            .iter()
            .any(|component| !valid_component(component))
    {
        return Err(NormalizationError::MetadataInvalid(
            "npm package name is invalid".to_string(),
        ));
    }
    Ok(name.to_string())
}

fn normalize_pypi_name(name: &str) -> Result<String, NormalizationError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(NormalizationError::MetadataInvalid(
            "PyPI package name is outside the supported normalized-name grammar".to_string(),
        ));
    }
    let mut output = String::new();
    let mut separator = false;
    for byte in name.bytes() {
        if matches!(byte, b'-' | b'_' | b'.') {
            if !separator {
                output.push('-');
                separator = true;
            }
        } else {
            output.push((byte as char).to_ascii_lowercase());
            separator = false;
        }
    }
    if output.starts_with('-') || output.ends_with('-') {
        return Err(NormalizationError::MetadataInvalid(
            "PyPI package name starts or ends with a separator".to_string(),
        ));
    }
    Ok(output)
}

fn is_npm_lifecycle(name: &str) -> bool {
    matches!(
        name,
        "preinstall"
            | "install"
            | "postinstall"
            | "preprepare"
            | "prepare"
            | "postprepare"
            | "prepack"
            | "postpack"
            | "prepublish"
            | "prepublishOnly"
            | "publish"
            | "postpublish"
            | "preversion"
            | "version"
            | "postversion"
    )
}

fn collect_json_strings(value: &StrictJson, output: &mut Vec<String>) {
    match value {
        StrictJson::String(value) => output.push(value.clone()),
        StrictJson::Array(values) => {
            for value in values {
                collect_json_strings(value, output);
            }
        }
        StrictJson::Object(values) => {
            for value in values.values() {
                collect_json_strings(value, output);
            }
        }
        _ => {}
    }
}

fn add_inventory(members: &[LogicalMember<'_>], input: &mut ArtifactManifestInput) {
    for member in members {
        if member.record.member_type != MemberType::File {
            continue;
        }
        let path = &member.record.normalized_path;
        let executable_mode = member.record.mode.is_some_and(|mode| mode & 0o111 != 0);
        let shebang = member.bytes.starts_with(b"#!");
        if is_executable_text(path)
            || (looks_like_text(member.bytes) && (executable_mode || shebang))
        {
            input
                .executable_text_file_ids
                .push(member.record.file_id.clone());
        }
        if is_native_binary(path) || has_native_magic(member.bytes) {
            input
                .native_binary_file_ids
                .push(member.record.file_id.clone());
        }
    }
}

fn is_executable_text(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".py", ".pyi", ".sh", ".bash", ".zsh",
        ".ps1", ".pth", ".toml", ".cfg", ".json",
    ]
    .iter()
    .any(|extension| lower.ends_with(extension))
        || lower.ends_with("/setup.py")
        || lower == "setup.py"
}

fn is_native_binary(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".node", ".so", ".dylib", ".dll", ".exe", ".wasm", ".pyd"]
        .iter()
        .any(|extension| lower.ends_with(extension))
}

fn looks_like_text(bytes: &[u8]) -> bool {
    !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok()
}

fn has_native_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"MZ")
        || bytes.starts_with(b"\0asm")
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
}

#[derive(Debug, Clone, PartialEq)]
enum StrictJson {
    Null,
    Bool,
    Number,
    String(String),
    Array(Vec<StrictJson>),
    Object(BTreeMap<String, StrictJson>),
}

impl StrictJson {
    fn as_object(
        &self,
        message: &'static str,
    ) -> Result<&BTreeMap<String, StrictJson>, NormalizationError> {
        match self {
            Self::Object(value) => Ok(value),
            _ => Err(NormalizationError::MetadataInvalid(message.to_string())),
        }
    }

    fn as_string(&self, message: &'static str) -> Result<&str, NormalizationError> {
        match self {
            Self::String(value) => Ok(value),
            _ => Err(NormalizationError::MetadataInvalid(message.to_string())),
        }
    }
}

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson::Null)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(StrictJson::Bool)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(StrictJson::Number)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(StrictJson::Number)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(StrictJson::Number)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJson::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJson::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictJson::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key `{key}`"
                )));
            }
            values.insert(key, map.next_value()?);
        }
        Ok(StrictJson::Object(values))
    }
}

fn parse_strict_json(bytes: &[u8]) -> Result<StrictJson, NormalizationError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJson::deserialize(&mut deserializer)
        .map_err(|error| NormalizationError::MetadataInvalid(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| NormalizationError::MetadataInvalid(error.to_string()))?;
    Ok(value)
}

fn required_json_string<'a>(
    object: &'a BTreeMap<String, StrictJson>,
    key: &'static str,
) -> Result<&'a str, NormalizationError> {
    object
        .get(key)
        .ok_or_else(|| NormalizationError::MetadataMissing(key.to_string()))?
        .as_string("required package.json value must be a string")
}

fn parse_email_headers(bytes: &[u8]) -> Result<BTreeMap<String, Vec<String>>, NormalizationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        NormalizationError::MetadataInvalid("metadata headers are not UTF-8".to_string())
    })?;
    let mut headers = BTreeMap::<String, Vec<String>>::new();
    let mut last_key: Option<String> = None;
    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            let key = last_key.as_ref().ok_or_else(|| {
                NormalizationError::MetadataInvalid(
                    "metadata starts with a continuation line".to_string(),
                )
            })?;
            let values = headers.get_mut(key).expect("last header exists");
            let value = values.last_mut().expect("last header value exists");
            value.push(' ');
            value.push_str(line.trim());
            continue;
        }
        let (key, value) = line.split_once(':').ok_or_else(|| {
            NormalizationError::MetadataInvalid(format!("metadata header has no colon: `{line}`"))
        })?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(NormalizationError::MetadataInvalid(format!(
                "invalid metadata header name `{key}`"
            )));
        }
        let key = key.to_ascii_lowercase();
        headers
            .entry(key.clone())
            .or_default()
            .push(value.trim().to_string());
        last_key = Some(key);
    }
    Ok(headers)
}

fn one_header<'a>(
    headers: &'a BTreeMap<String, Vec<String>>,
    name: &'static str,
) -> Result<&'a str, NormalizationError> {
    let values = headers
        .get(&name.to_ascii_lowercase())
        .ok_or_else(|| NormalizationError::MetadataMissing(name.to_string()))?;
    if values.len() != 1 || values[0].is_empty() {
        return Err(NormalizationError::MetadataInvalid(format!(
            "metadata must contain exactly one nonempty {name} header"
        )));
    }
    Ok(&values[0])
}

fn verify_dist_info_identity(
    dist_info: &str,
    normalized_name: &str,
    version: &str,
) -> Result<(), NormalizationError> {
    let stem = dist_info.strip_suffix(".dist-info").ok_or_else(|| {
        NormalizationError::MetadataInvalid("invalid .dist-info directory".to_string())
    })?;
    let (name, directory_version) = stem.rsplit_once('-').ok_or_else(|| {
        NormalizationError::MetadataInvalid(
            ".dist-info directory does not contain name and version".to_string(),
        )
    })?;
    if normalize_pypi_name(name)? != normalized_name || directory_version != version {
        return Err(NormalizationError::IdentityMismatch(format!(
            ".dist-info `{dist_info}` disagrees with METADATA `{normalized_name}=={version}`"
        )));
    }
    Ok(())
}

fn verify_sdist_root(
    root: &str,
    normalized_name: &str,
    version: &str,
) -> Result<(), NormalizationError> {
    let (name, root_version) = root.rsplit_once('-').ok_or_else(|| {
        NormalizationError::IdentityMismatch(
            "sdist root does not contain a name and version".to_string(),
        )
    })?;
    if normalize_pypi_name(name)? != normalized_name || root_version != version {
        return Err(NormalizationError::IdentityMismatch(format!(
            "sdist root `{root}` disagrees with PKG-INFO `{normalized_name}=={version}`"
        )));
    }
    Ok(())
}

fn verify_wheel_filename(
    envelope: &ArtifactEnvelope,
    normalized_name: &str,
    version: &str,
    metadata_tags: &[String],
) -> Result<(), NormalizationError> {
    let stem = envelope
        .original_filename
        .strip_suffix(".whl")
        .ok_or_else(|| NormalizationError::IdentityMismatch("wheel filename suffix".to_string()))?;
    let parts = stem.split('-').collect::<Vec<_>>();
    if parts.len() < 5 {
        return Err(NormalizationError::IdentityMismatch(
            "wheel filename does not contain distribution, version, and three tags".to_string(),
        ));
    }
    if normalize_pypi_name(parts[0])? != normalized_name || parts[1] != version {
        return Err(NormalizationError::IdentityMismatch(format!(
            "wheel filename `{}` disagrees with METADATA `{normalized_name}=={version}`",
            envelope.original_filename
        )));
    }
    let python_tags = parts[parts.len() - 3].split('.').collect::<Vec<_>>();
    let abi_tags = parts[parts.len() - 2].split('.').collect::<Vec<_>>();
    let platform_tags = parts[parts.len() - 1].split('.').collect::<Vec<_>>();
    for python in &python_tags {
        for abi in &abi_tags {
            for platform in &platform_tags {
                let tag = format!("{python}-{abi}-{platform}");
                if !metadata_tags.contains(&tag) {
                    return Err(NormalizationError::IdentityMismatch(format!(
                        "wheel filename tag `{tag}` is missing from WHEEL metadata"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_wheel_record(
    members: &[LogicalMember<'_>],
    record_file: &LogicalMember<'_>,
) -> Result<(), NormalizationError> {
    let text = std::str::from_utf8(record_file.bytes).map_err(|_| {
        NormalizationError::MetadataInvalid("wheel RECORD is not UTF-8".to_string())
    })?;
    let files = members
        .iter()
        .filter(|member| member.record.member_type == MemberType::File)
        .map(|member| (member.record.normalized_path.as_str(), member))
        .collect::<BTreeMap<_, _>>();
    let record_signature_paths = [
        format!("{}.jws", record_file.record.normalized_path),
        format!("{}.p7s", record_file.record.normalized_path),
    ];
    let mut seen = BTreeSet::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            return Err(NormalizationError::MetadataInvalid(
                "wheel RECORD contains an empty row".to_string(),
            ));
        }
        let fields = parse_csv_row(line)?;
        if fields.len() != 3 {
            return Err(NormalizationError::MetadataInvalid(
                "wheel RECORD row must contain exactly three fields".to_string(),
            ));
        }
        let path = fields[0].as_str();
        if record_signature_paths
            .iter()
            .any(|signature| signature == path)
        {
            return Err(NormalizationError::MetadataInvalid(format!(
                "wheel RECORD must not list its signature file `{path}`"
            )));
        }
        if !seen.insert(path.to_string()) {
            return Err(NormalizationError::MetadataInvalid(format!(
                "wheel RECORD repeats `{path}`"
            )));
        }
        let member = files.get(path).ok_or_else(|| {
            NormalizationError::MetadataInvalid(format!(
                "wheel RECORD references unknown file `{path}`"
            ))
        })?;
        if path == record_file.record.normalized_path {
            if !fields[1].is_empty() || !fields[2].is_empty() {
                return Err(NormalizationError::MetadataInvalid(
                    "wheel RECORD row for RECORD must have empty hash and size".to_string(),
                ));
            }
            continue;
        }
        let expected_hash = wheel_record_sha256(&member.record.sha256)?;
        if fields[1] != expected_hash {
            return Err(NormalizationError::MetadataInvalid(format!(
                "wheel RECORD hash mismatch for `{path}`"
            )));
        }
        let size = fields[2].parse::<u64>().map_err(|_| {
            NormalizationError::MetadataInvalid(format!(
                "wheel RECORD size is invalid for `{path}`"
            ))
        })?;
        if size != member.record.size {
            return Err(NormalizationError::MetadataInvalid(format!(
                "wheel RECORD size mismatch for `{path}`"
            )));
        }
    }
    let expected = files
        .keys()
        .copied()
        .filter(|path| {
            !record_signature_paths
                .iter()
                .any(|signature| signature == path)
        })
        .collect::<BTreeSet<_>>();
    let actual = seen.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(NormalizationError::MetadataInvalid(
            "wheel RECORD does not cover every regular file exactly once".to_string(),
        ));
    }
    Ok(())
}

fn parse_csv_row(line: &str) -> Result<Vec<String>, NormalizationError> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut characters = line.chars().peekable();
    let mut quoted = false;
    while let Some(character) = characters.next() {
        if quoted {
            if character == '"' {
                if characters.peek() == Some(&'"') {
                    characters.next();
                    field.push('"');
                } else {
                    quoted = false;
                    if characters.peek().is_some_and(|next| *next != ',') {
                        return Err(NormalizationError::MetadataInvalid(
                            "wheel RECORD has text after a closing quote".to_string(),
                        ));
                    }
                }
            } else {
                field.push(character);
            }
        } else if character == ',' {
            fields.push(std::mem::take(&mut field));
        } else if character == '"' {
            if !field.is_empty() {
                return Err(NormalizationError::MetadataInvalid(
                    "wheel RECORD quote does not begin a field".to_string(),
                ));
            }
            quoted = true;
        } else {
            field.push(character);
        }
    }
    if quoted {
        return Err(NormalizationError::MetadataInvalid(
            "wheel RECORD has an unterminated quote".to_string(),
        ));
    }
    fields.push(field);
    Ok(fields)
}

fn wheel_record_sha256(digest: &Sha256Digest) -> Result<String, NormalizationError> {
    let hex = digest.as_str().strip_prefix("sha256:").ok_or_else(|| {
        NormalizationError::MetadataInvalid("noncanonical member digest".to_string())
    })?;
    let mut bytes = Vec::with_capacity(32);
    for pair in hex.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair).expect("digest hex is ASCII");
        bytes.push(u8::from_str_radix(text, 16).map_err(|_| {
            NormalizationError::MetadataInvalid("invalid member digest hex".to_string())
        })?);
    }
    Ok(format!("sha256={}", base64_url_no_pad(&bytes)))
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        }
    }
    output
}

fn parse_entry_points(
    bytes: &[u8],
) -> Result<BTreeMap<String, BTreeMap<String, String>>, NormalizationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        NormalizationError::MetadataInvalid("entry_points.txt is not UTF-8".to_string())
    })?;
    let mut section = None::<String>;
    let mut sections = BTreeMap::<String, BTreeMap<String, String>>::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].trim().to_ascii_lowercase();
            if name.is_empty() || sections.contains_key(&name) {
                return Err(NormalizationError::MetadataInvalid(
                    "entry_points.txt contains an empty or duplicate section".to_string(),
                ));
            }
            sections.insert(name.clone(), BTreeMap::new());
            section = Some(name);
            continue;
        }
        let section = section.as_ref().ok_or_else(|| {
            NormalizationError::MetadataInvalid(
                "entry_points.txt entry appears before a section".to_string(),
            )
        })?;
        let (name, target) = line.split_once('=').ok_or_else(|| {
            NormalizationError::MetadataInvalid(
                "console entry point has no equals sign".to_string(),
            )
        })?;
        let name = name.trim();
        let target = target.trim();
        let entries = sections
            .get_mut(section)
            .expect("entry-point section exists");
        if name.is_empty()
            || target.is_empty()
            || entries
                .insert(name.to_string(), target.to_string())
                .is_some()
        {
            return Err(NormalizationError::MetadataInvalid(
                "console entry point is empty or duplicated".to_string(),
            ));
        }
    }
    Ok(sections)
}

fn wheel_import_roots(members: &[LogicalMember<'_>], dist_info: &str) -> Vec<String> {
    let mut roots = BTreeSet::new();
    for member in members {
        if member.record.member_type != MemberType::File {
            continue;
        }
        let mut path = member.record.normalized_path.as_str();
        if path.starts_with(dist_info) {
            continue;
        }
        if let Some((prefix, installed_path)) = path.split_once(".data/purelib/") {
            if !prefix.is_empty() {
                path = installed_path;
            }
        } else if let Some((prefix, installed_path)) = path.split_once(".data/platlib/") {
            if !prefix.is_empty() {
                path = installed_path;
            }
        } else if path.contains(".data/") {
            continue;
        }
        if let Some((first, _)) = path.split_once('/') {
            if path.ends_with(".py") || path.ends_with(".pyi") || is_native_binary(path) {
                roots.insert(first.to_string());
            }
        } else if let Some(stem) = path
            .strip_suffix(".py")
            .or_else(|| path.strip_suffix(".pyi"))
        {
            roots.insert(stem.to_string());
        } else if is_native_binary(path) {
            let root = path.split('.').next().unwrap_or(path);
            if !root.is_empty() {
                roots.insert(root.to_string());
            }
        }
    }
    roots.into_iter().collect()
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ParsedBuildSystem {
    backend: Option<String>,
    requires: Vec<String>,
    backend_paths: Vec<String>,
}

fn parse_build_system(bytes: &[u8]) -> Result<ParsedBuildSystem, NormalizationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        NormalizationError::MetadataInvalid("pyproject.toml is not UTF-8".to_string())
    })?;
    let document = text.parse::<toml::Value>().map_err(|error| {
        NormalizationError::MetadataInvalid(format!("invalid pyproject.toml: {error}"))
    })?;
    let Some(build_system) = document.get("build-system") else {
        return Ok(ParsedBuildSystem::default());
    };
    let table = build_system.as_table().ok_or_else(|| {
        NormalizationError::MetadataInvalid("build-system must be a TOML table".to_string())
    })?;
    let requires = required_toml_string_array(table, "requires")?;
    let backend = table
        .get("build-backend")
        .map(|value| {
            let backend = value.as_str().ok_or_else(|| {
                NormalizationError::MetadataInvalid(
                    "build-system.build-backend must be a string".to_string(),
                )
            })?;
            validate_build_backend(backend)?;
            Ok(backend.to_string())
        })
        .transpose()?;
    let backend_paths = table
        .get("backend-path")
        .map(|_| required_toml_string_array(table, "backend-path"))
        .transpose()?
        .unwrap_or_default();
    for path in &backend_paths {
        validate_backend_path(path)?;
    }
    Ok(ParsedBuildSystem {
        backend,
        requires,
        backend_paths,
    })
}

fn required_toml_string_array(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<Vec<String>, NormalizationError> {
    let values = table
        .get(key)
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            NormalizationError::MetadataInvalid(format!(
                "build-system.{key} must be present and contain an array"
            ))
        })?;
    values
        .iter()
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                NormalizationError::MetadataInvalid(format!(
                    "build-system.{key} entries must be strings"
                ))
            })
        })
        .collect()
}

fn validate_build_backend(backend: &str) -> Result<(), NormalizationError> {
    if backend.is_empty()
        || backend.matches(':').count() > 1
        || backend.split(':').any(|component| {
            component.is_empty()
                || component.split('.').any(|part| {
                    part.is_empty()
                        || !part.bytes().enumerate().all(|(index, byte)| {
                            byte == b'_'
                                || byte.is_ascii_alphanumeric()
                                    && (index > 0 || !byte.is_ascii_digit())
                        })
                })
        })
    {
        return Err(NormalizationError::MetadataInvalid(
            "build-system.build-backend is not a supported Python object reference".to_string(),
        ));
    }
    Ok(())
}

fn validate_backend_path(path: &str) -> Result<(), NormalizationError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(NormalizationError::MetadataInvalid(format!(
            "build-system.backend-path is not a safe relative path: `{path}`"
        )));
    }
    Ok(())
}

fn sdist_package_roots(members: &[LogicalMember<'_>]) -> Vec<String> {
    let mut roots = BTreeSet::new();
    for member in members {
        if member.record.member_type != MemberType::File
            || !member.record.normalized_path.ends_with("/__init__.py")
        {
            continue;
        }
        let path = member.record.normalized_path.as_str();
        if let Some(rest) = path.strip_prefix("src/") {
            if let Some((root, _)) = rest.split_once('/') {
                roots.insert(format!("src/{root}"));
            }
        } else if let Some((root, _)) = path.split_once('/') {
            roots.insert(root.to_string());
        }
    }
    roots.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_package_json_rejects_duplicate_keys_at_any_depth() {
        assert!(matches!(
            parse_strict_json(br#"{"name":"first","name":"second"}"#),
            Err(NormalizationError::MetadataInvalid(message))
                if message.contains("duplicate JSON object key")
        ));
        assert!(matches!(
            parse_strict_json(br#"{"scripts":{"install":"one","install":"two"}}"#),
            Err(NormalizationError::MetadataInvalid(message))
                if message.contains("duplicate JSON object key")
        ));
    }

    #[test]
    fn pep517_parser_uses_full_toml_and_captures_backend_path() {
        let build_system = parse_build_system(
            br#"
                [build-system]
                requires = [
                    "setuptools==75.0.0",
                    "wheel==0.44.0",
                ]
                build-backend = "fixture_backend:Backend"
                backend-path = ["build_backend"]
            "#,
        )
        .expect("parse complete PEP 517 table");
        assert_eq!(
            build_system.backend.as_deref(),
            Some("fixture_backend:Backend")
        );
        assert_eq!(
            build_system.requires,
            ["setuptools==75.0.0", "wheel==0.44.0"]
        );
        assert_eq!(build_system.backend_paths, ["build_backend"]);
    }

    #[test]
    fn pep517_parser_rejects_missing_requires_and_escaping_backend_path() {
        assert!(matches!(
            parse_build_system(
                br#"[build-system]
build-backend = "setuptools.build_meta"
"#
            ),
            Err(NormalizationError::MetadataInvalid(_))
        ));
        assert!(matches!(
            parse_build_system(
                br#"[build-system]
requires = []
backend-path = ["../outside"]
"#
            ),
            Err(NormalizationError::MetadataInvalid(_))
        ));
    }

    #[test]
    fn ecosystem_name_normalizers_reject_ambiguous_names() {
        assert!(normalize_npm_name("@scope/name/extra").is_err());
        assert!(normalize_npm_name("MixedCase").is_err());
        assert!(normalize_pypi_name("../escape").is_err());
        assert_eq!(
            normalize_pypi_name("Fixture_Pkg.Name").expect("normalize PyPI name"),
            "fixture-pkg-name"
        );
    }
}
