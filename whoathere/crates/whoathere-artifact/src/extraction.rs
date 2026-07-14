use crate::archive::{read_tar_gzip, read_zip, RawMember, RawMemberType};
use crate::normalize::one_package_root;
use crate::{ArtifactFormat, NormalizationError, NormalizationLimits, Sha256Digest};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const PREPARED_SDIST_EXTRACTION_SCHEMA_V1: &str = "whoathere.prepared_sdist_extraction.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparedSdistExtractionMemberTypeV1 {
    Directory,
    File,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PreparedSdistExtractionMemberV1 {
    relative_path: String,
    member_type: PreparedSdistExtractionMemberTypeV1,
    package_mode: u32,
    content_sha256: Option<Sha256Digest>,
    byte_length: u64,
    bytes: Vec<u8>,
}

impl fmt::Debug for PreparedSdistExtractionMemberV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSdistExtractionMemberV1")
            .field("relative_path", &self.relative_path)
            .field("member_type", &self.member_type)
            .field("package_mode", &format_args!("{:04o}", self.package_mode))
            .field("content_sha256", &self.content_sha256)
            .field("byte_length", &self.byte_length)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl PreparedSdistExtractionMemberV1 {
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    pub const fn member_type(&self) -> PreparedSdistExtractionMemberTypeV1 {
        self.member_type
    }

    pub const fn package_mode(&self) -> u32 {
        self.package_mode
    }

    pub fn content_sha256(&self) -> Option<&Sha256Digest> {
        self.content_sha256.as_ref()
    }

    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        (self.member_type == PreparedSdistExtractionMemberTypeV1::File)
            .then_some(self.bytes.as_slice())
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PreparedSdistExtractionMemberWireV1<'a> {
    Directory {
        relative_path: &'a str,
        package_mode: String,
    },
    File {
        relative_path: &'a str,
        package_mode: String,
        content_sha256: &'a Sha256Digest,
        byte_length: String,
    },
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PreparedSdistExtractionWireV1<'a> {
    schema_version: &'static str,
    artifact_format: ArtifactFormat,
    canonical_archive_root: &'a str,
    expanded_byte_length: String,
    members: Vec<PreparedSdistExtractionMemberWireV1<'a>>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PreparedSdistExtractionV1 {
    artifact_format: ArtifactFormat,
    canonical_archive_root: String,
    expanded_byte_length: u64,
    members: Vec<PreparedSdistExtractionMemberV1>,
    canonical_manifest_json: Vec<u8>,
    extraction_manifest_sha256: Sha256Digest,
}

impl fmt::Debug for PreparedSdistExtractionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSdistExtractionV1")
            .field("artifact_format", &self.artifact_format)
            .field("canonical_archive_root", &self.canonical_archive_root)
            .field("expanded_byte_length", &self.expanded_byte_length)
            .field("member_count", &self.members.len())
            .field(
                "extraction_manifest_sha256",
                &self.extraction_manifest_sha256,
            )
            .field("member_bytes", &"<redacted>")
            .finish()
    }
}

impl PreparedSdistExtractionV1 {
    pub const fn artifact_format(&self) -> ArtifactFormat {
        self.artifact_format
    }

    pub fn canonical_archive_root(&self) -> &str {
        &self.canonical_archive_root
    }

    pub const fn expanded_byte_length(&self) -> u64 {
        self.expanded_byte_length
    }

    pub fn members(&self) -> &[PreparedSdistExtractionMemberV1] {
        &self.members
    }

    pub fn canonical_manifest_json_v1(&self) -> &[u8] {
        &self.canonical_manifest_json
    }

    pub fn extraction_manifest_sha256(&self) -> &Sha256Digest {
        &self.extraction_manifest_sha256
    }
}

pub fn prepare_sdist_extraction_v1(
    exact_artifact_bytes: &[u8],
    artifact_format: ArtifactFormat,
    expected_archive_root: &str,
    limits: NormalizationLimits,
) -> Result<PreparedSdistExtractionV1, NormalizationError> {
    if exact_artifact_bytes.is_empty()
        || exact_artifact_bytes.len() as u64 > limits.max_original_bytes
    {
        return Err(NormalizationError::OriginalSizeLimit {
            actual: exact_artifact_bytes.len() as u64,
            limit: limits.max_original_bytes,
        });
    }
    let archive = match artifact_format {
        ArtifactFormat::SdistTarGzip => {
            read_tar_gzip(exact_artifact_bytes, limits.archive_limits())?
        }
        ArtifactFormat::SdistZip => read_zip(exact_artifact_bytes, limits.archive_limits())?,
        _ => {
            return Err(NormalizationError::UnsupportedFormat(format!(
                "safe sdist extraction does not accept {artifact_format:?}"
            )))
        }
    };
    let actual_root = one_package_root(&archive.members)?;
    if actual_root != expected_archive_root {
        return Err(NormalizationError::AmbiguousRoot(format!(
            "expected `{expected_archive_root}`, observed `{actual_root}`"
        )));
    }

    let expanded_byte_length = archive.expanded_bytes;
    let members = prepared_members_v1(archive.members, &actual_root)?;
    let member_wires = members
        .iter()
        .map(|member| {
            Ok(match member.member_type {
                PreparedSdistExtractionMemberTypeV1::Directory => {
                    PreparedSdistExtractionMemberWireV1::Directory {
                        relative_path: &member.relative_path,
                        package_mode: format!("{:04o}", member.package_mode),
                    }
                }
                PreparedSdistExtractionMemberTypeV1::File => {
                    PreparedSdistExtractionMemberWireV1::File {
                        relative_path: &member.relative_path,
                        package_mode: format!("{:04o}", member.package_mode),
                        content_sha256: member.content_sha256.as_ref().ok_or_else(|| {
                            NormalizationError::Manifest(
                                "prepared extraction file is missing its content digest"
                                    .to_string(),
                            )
                        })?,
                        byte_length: member.byte_length.to_string(),
                    }
                }
            })
        })
        .collect::<Result<Vec<_>, NormalizationError>>()?;
    let canonical_manifest_json =
        serde_json_canonicalizer::to_vec(&PreparedSdistExtractionWireV1 {
            schema_version: PREPARED_SDIST_EXTRACTION_SCHEMA_V1,
            artifact_format,
            canonical_archive_root: &actual_root,
            expanded_byte_length: expanded_byte_length.to_string(),
            members: member_wires,
        })
        .map_err(|error| NormalizationError::Manifest(error.to_string()))?;
    Ok(PreparedSdistExtractionV1 {
        artifact_format,
        canonical_archive_root: actual_root,
        expanded_byte_length,
        members,
        extraction_manifest_sha256: Sha256Digest::from_bytes(&canonical_manifest_json),
        canonical_manifest_json,
    })
}

fn prepared_members_v1(
    raw_members: Vec<RawMember>,
    root: &str,
) -> Result<Vec<PreparedSdistExtractionMemberV1>, NormalizationError> {
    let prefix = format!("{root}/");
    let mut directories = BTreeSet::new();
    let mut files = BTreeMap::<String, (RawMember, u32)>::new();
    for member in raw_members {
        if member.archive_path == root && member.member_type == RawMemberType::Directory {
            continue;
        }
        let relative_path = member.archive_path.strip_prefix(&prefix).ok_or_else(|| {
            NormalizationError::AmbiguousRoot(format!(
                "member `{}` is outside `{root}`",
                member.archive_path
            ))
        })?;
        if relative_path.is_empty() {
            return Err(NormalizationError::InvalidPath {
                path: member.archive_path.clone(),
                reason: "relative extraction path is empty",
            });
        }
        add_parent_directories_v1(relative_path, &mut directories);
        match member.member_type {
            RawMemberType::Directory => {
                directories.insert(relative_path.to_string());
            }
            RawMemberType::File => {
                let package_mode = if member.mode.unwrap_or(0) & 0o111 == 0 {
                    0o600
                } else {
                    0o700
                };
                files.insert(relative_path.to_string(), (member, package_mode));
            }
        }
    }

    let mut combined = BTreeMap::<String, PreparedSdistExtractionMemberV1>::new();
    for directory in directories {
        combined.insert(
            directory.clone(),
            PreparedSdistExtractionMemberV1 {
                relative_path: directory,
                member_type: PreparedSdistExtractionMemberTypeV1::Directory,
                package_mode: 0o700,
                content_sha256: None,
                byte_length: 0,
                bytes: Vec::new(),
            },
        );
    }
    for (relative_path, (member, package_mode)) in files {
        if combined.contains_key(&relative_path) {
            return Err(NormalizationError::PrefixCollision {
                first: relative_path.clone(),
                second: relative_path,
            });
        }
        let byte_length = member.bytes.len() as u64;
        let content_sha256 = Sha256Digest::from_bytes(&member.bytes);
        combined.insert(
            relative_path.clone(),
            PreparedSdistExtractionMemberV1 {
                relative_path,
                member_type: PreparedSdistExtractionMemberTypeV1::File,
                package_mode,
                content_sha256: Some(content_sha256),
                byte_length,
                bytes: member.bytes,
            },
        );
    }
    if combined.is_empty()
        || !combined
            .values()
            .any(|member| member.member_type == PreparedSdistExtractionMemberTypeV1::File)
    {
        return Err(NormalizationError::AmbiguousRoot(
            "sdist extraction has no regular files".to_string(),
        ));
    }
    Ok(combined.into_values().collect())
}

fn add_parent_directories_v1(path: &str, directories: &mut BTreeSet<String>) {
    let mut current = String::new();
    let components = path.split('/').collect::<Vec<_>>();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(component);
        directories.insert(current.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    fn tar_gzip(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (path, bytes, mode) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(bytes.len() as u64);
            header.set_mode(*mode);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            archive
                .append_data(&mut header, *path, Cursor::new(*bytes))
                .expect("append inert member");
        }
        archive
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip")
    }

    fn zip(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (path, bytes, mode) in entries {
            archive
                .start_file(*path, SimpleFileOptions::default().unix_permissions(*mode))
                .expect("start inert member");
            archive.write_all(bytes).expect("write inert member");
        }
        archive.finish().expect("finish zip").into_inner()
    }

    #[test]
    fn exact_nested_sdist_prepares_canonical_relative_members_without_writing() {
        let bytes = tar_gzip(&[
            ("fixture-1.0.0/pyproject.toml", b"[build-system]\n", 0o644),
            (
                "fixture-1.0.0/src/fixture/__init__.py",
                b"VALUE = 1\n",
                0o644,
            ),
            ("fixture-1.0.0/tools/build", b"#!/bin/sh\nexit 0\n", 0o755),
        ]);
        let prepared = prepare_sdist_extraction_v1(
            &bytes,
            ArtifactFormat::SdistTarGzip,
            "fixture-1.0.0",
            NormalizationLimits::default(),
        )
        .expect("prepare inert sdist");
        assert_eq!(prepared.canonical_archive_root(), "fixture-1.0.0");
        assert_eq!(
            prepared
                .members()
                .iter()
                .map(|member| (member.relative_path(), member.member_type()))
                .collect::<Vec<_>>(),
            [
                ("pyproject.toml", PreparedSdistExtractionMemberTypeV1::File),
                ("src", PreparedSdistExtractionMemberTypeV1::Directory),
                (
                    "src/fixture",
                    PreparedSdistExtractionMemberTypeV1::Directory
                ),
                (
                    "src/fixture/__init__.py",
                    PreparedSdistExtractionMemberTypeV1::File
                ),
                ("tools", PreparedSdistExtractionMemberTypeV1::Directory),
                ("tools/build", PreparedSdistExtractionMemberTypeV1::File),
            ]
        );
        let executable = prepared
            .members()
            .iter()
            .find(|member| member.relative_path() == "tools/build")
            .expect("executable member");
        assert_eq!(executable.package_mode(), 0o700);
        assert_eq!(executable.bytes(), Some(b"#!/bin/sh\nexit 0\n".as_slice()));
        assert_eq!(
            prepared.extraction_manifest_sha256(),
            &Sha256Digest::from_bytes(prepared.canonical_manifest_json_v1())
        );
        assert!(!format!("{prepared:?}").contains("VALUE = 1"));
    }

    #[test]
    fn zip_and_tar_reject_wrong_roots_traversal_and_unsupported_forms() {
        let zip_bytes = zip(&[("fixture-1.0.0/setup.py", b"pass\n", 0o644)]);
        assert!(matches!(
            prepare_sdist_extraction_v1(
                &zip_bytes,
                ArtifactFormat::SdistZip,
                "other-1.0.0",
                NormalizationLimits::default(),
            ),
            Err(NormalizationError::AmbiguousRoot(_))
        ));
        let traversal = zip(&[("../escape/setup.py", b"pass\n", 0o644)]);
        assert!(matches!(
            prepare_sdist_extraction_v1(
                &traversal,
                ArtifactFormat::SdistZip,
                "escape",
                NormalizationLimits::default(),
            ),
            Err(NormalizationError::InvalidPath { .. })
        ));
        assert!(matches!(
            prepare_sdist_extraction_v1(
                &zip_bytes,
                ArtifactFormat::WheelZip,
                "fixture-1.0.0",
                NormalizationLimits::default(),
            ),
            Err(NormalizationError::UnsupportedFormat(_))
        ));
    }
}
