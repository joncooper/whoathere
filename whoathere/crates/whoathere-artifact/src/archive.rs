use crate::NormalizationError;
use flate2::read::MultiGzDecoder;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use unicase::UniCase;
use unicode_normalization::UnicodeNormalization;
use zip::{CompressionMethod, ZipArchive};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawMemberType {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawMember {
    pub original_path: String,
    pub archive_path: String,
    pub member_type: RawMemberType,
    pub mode: Option<u32>,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchiveMembers {
    pub members: Vec<RawMember>,
    pub expanded_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArchiveLimits {
    pub max_members: usize,
    pub max_member_bytes: u64,
    pub max_expanded_bytes: u64,
    pub max_compression_ratio: u64,
    pub max_path_bytes: usize,
    pub max_component_bytes: usize,
    pub max_path_depth: usize,
    pub max_tar_trailing_bytes: u64,
}

#[derive(Default)]
struct PathRegistry {
    exact: BTreeMap<String, RawMemberType>,
    nfc: BTreeMap<String, (String, RawMemberType)>,
    folded: BTreeMap<String, (String, RawMemberType)>,
}

impl PathRegistry {
    fn insert(&mut self, path: &str, member_type: RawMemberType) -> Result<(), NormalizationError> {
        if self.exact.contains_key(path) {
            return Err(NormalizationError::DuplicatePath {
                path: path.to_string(),
            });
        }

        let nfc = path.nfc().collect::<String>();
        if let Some((first, _)) = self.nfc.get(&nfc) {
            if first != path {
                return Err(NormalizationError::UnicodeCollision {
                    first: first.clone(),
                    second: path.to_string(),
                });
            }
        }

        let compatibility = path.nfkc().collect::<String>();
        let folded = UniCase::unicode(compatibility.as_str())
            .to_folded_case()
            .nfc()
            .collect::<String>();
        if let Some((first, _)) = self.folded.get(&folded) {
            if first != path {
                return Err(NormalizationError::CaseCollision {
                    first: first.clone(),
                    second: path.to_string(),
                });
            }
        }

        let components = path.split('/').collect::<Vec<_>>();
        check_prefix_namespace(
            path,
            member_type,
            &components,
            &self.exact,
            |value| value.to_string(),
            |value| value,
        )?;
        check_prefix_namespace(
            path,
            member_type,
            &components,
            &self.nfc,
            |value| value.nfc().collect::<String>(),
            |value| &value.1,
        )?;
        check_prefix_namespace(
            path,
            member_type,
            &components,
            &self.folded,
            portable_fold,
            |value| &value.1,
        )?;

        self.nfc.insert(nfc, (path.to_string(), member_type));
        self.folded.insert(folded, (path.to_string(), member_type));
        self.exact.insert(path.to_string(), member_type);
        Ok(())
    }
}

fn portable_fold(value: &str) -> String {
    let compatibility = value.nfkc().collect::<String>();
    UniCase::unicode(compatibility.as_str())
        .to_folded_case()
        .nfc()
        .collect()
}

fn check_prefix_namespace<V>(
    original_path: &str,
    member_type: RawMemberType,
    components: &[&str],
    namespace: &BTreeMap<String, V>,
    key: impl Fn(&str) -> String,
    kind: impl Fn(&V) -> &RawMemberType,
) -> Result<(), NormalizationError> {
    let mut prefix = String::new();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        let prefix_key = key(&prefix);
        if let Some(value) = namespace.get(&prefix_key) {
            if *kind(value) == RawMemberType::File {
                return Err(NormalizationError::PrefixCollision {
                    first: prefix,
                    second: original_path.to_string(),
                });
            }
        }
    }
    if member_type == RawMemberType::File {
        let path_key = key(original_path);
        let descendant_prefix = format!("{path_key}/");
        if let Some((descendant, _)) = namespace
            .range(descendant_prefix.clone()..)
            .next()
            .filter(|(candidate, _)| candidate.starts_with(&descendant_prefix))
        {
            return Err(NormalizationError::PrefixCollision {
                first: original_path.to_string(),
                second: descendant.clone(),
            });
        }
    }
    Ok(())
}

pub(crate) fn read_tar_gzip(
    bytes: &[u8],
    limits: ArchiveLimits,
) -> Result<ArchiveMembers, NormalizationError> {
    preflight_tar_gzip(bytes, limits)?;

    let decoder = MultiGzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut registry = PathRegistry::default();
    let mut members = Vec::new();
    let mut expanded_bytes = 0u64;
    let entries = archive
        .entries()
        .map_err(|error| NormalizationError::Archive(error.to_string()))?;

    for entry in entries {
        let mut entry = entry.map_err(|error| NormalizationError::Archive(error.to_string()))?;
        let entry_type = entry.header().entry_type();
        let member_type = if entry_type.is_file() {
            RawMemberType::File
        } else if entry_type.is_dir() {
            RawMemberType::Directory
        } else {
            let path = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
            return Err(NormalizationError::UnsupportedMemberType {
                path,
                kind: format!("{entry_type:?}"),
            });
        };

        let original_path = std::str::from_utf8(&entry.path_bytes())
            .map_err(|_| NormalizationError::InvalidPath {
                path: "<non-utf8>".to_string(),
                reason: "path is not UTF-8",
            })?
            .to_string();
        let archive_path = validate_portable_path(&original_path, member_type, limits)?;
        registry.insert(&archive_path, member_type)?;
        ensure_member_count(members.len() + 1, limits.max_members)?;

        let declared_size = entry.size();
        ensure_member_size(&archive_path, declared_size, limits.max_member_bytes)?;
        expanded_bytes =
            checked_expanded_total(expanded_bytes, declared_size, limits.max_expanded_bytes)?;
        let mode = entry.header().mode().ok();
        let member_bytes = if member_type == RawMemberType::File {
            read_exact_bounded(
                &mut entry,
                &archive_path,
                declared_size,
                limits.max_member_bytes,
            )?
        } else {
            if declared_size != 0 {
                return Err(NormalizationError::UnsupportedMemberType {
                    path: archive_path,
                    kind: "directory_with_payload".to_string(),
                });
            }
            Vec::new()
        };

        members.push(RawMember {
            original_path,
            archive_path,
            member_type,
            mode,
            bytes: member_bytes,
        });
    }

    ensure_ratio(
        "<tar-gzip-total>",
        expanded_bytes,
        bytes.len() as u64,
        limits.max_compression_ratio,
    )?;
    members.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    Ok(ArchiveMembers {
        members,
        expanded_bytes,
    })
}

fn preflight_tar_gzip(bytes: &[u8], limits: ArchiveLimits) -> Result<(), NormalizationError> {
    let decoder = MultiGzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut raw_count = 0usize;
    let mut raw_total = 0u64;
    let entries = archive
        .entries()
        .map_err(|error| NormalizationError::Archive(error.to_string()))?
        .raw(true);

    for entry in entries {
        let mut entry = entry.map_err(|error| NormalizationError::Archive(error.to_string()))?;
        raw_count += 1;
        ensure_member_count(raw_count, limits.max_members)?;
        let declared_size = entry.size();
        let display_path = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        ensure_member_size(&display_path, declared_size, limits.max_member_bytes)?;
        raw_total = checked_expanded_total(raw_total, declared_size, limits.max_expanded_bytes)?;
        ensure_ratio(
            "<tar-gzip-total>",
            raw_total,
            bytes.len() as u64,
            limits.max_compression_ratio,
        )?;
        let _ = read_exact_bounded(
            &mut entry,
            &display_path,
            declared_size,
            limits.max_member_bytes,
        )?;
    }

    let mut decoder = archive.into_inner();
    let mut trailing = Vec::new();
    decoder
        .by_ref()
        .take(limits.max_tar_trailing_bytes.saturating_add(1))
        .read_to_end(&mut trailing)
        .map_err(|error| NormalizationError::Archive(error.to_string()))?;
    if trailing.len() as u64 > limits.max_tar_trailing_bytes
        || trailing.iter().any(|byte| *byte != 0)
    {
        return Err(NormalizationError::TrailingArchiveData);
    }
    Ok(())
}

pub(crate) fn read_zip(
    bytes: &[u8],
    limits: ArchiveLimits,
) -> Result<ArchiveMembers, NormalizationError> {
    preflight_zip(bytes, limits)?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| NormalizationError::Archive(error.to_string()))?;
    if archive.offset() != 0 {
        return Err(NormalizationError::TrailingArchiveData);
    }
    ensure_member_count(archive.len(), limits.max_members)?;

    let mut registry = PathRegistry::default();
    let mut members = Vec::with_capacity(archive.len());
    let mut expanded_bytes = 0u64;
    let mut compressed_bytes = 0u64;

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| NormalizationError::Archive(error.to_string()))?;
        if entry.encrypted() {
            return Err(NormalizationError::UnsupportedMemberType {
                path: entry.name().to_string(),
                kind: "encrypted_zip_member".to_string(),
            });
        }
        if !matches!(
            entry.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        ) {
            return Err(NormalizationError::UnsupportedMemberType {
                path: entry.name().to_string(),
                kind: format!("compression_{:?}", entry.compression()),
            });
        }

        let original_path = std::str::from_utf8(entry.name_raw())
            .map_err(|_| NormalizationError::InvalidPath {
                path: "<non-utf8>".to_string(),
                reason: "path is not UTF-8",
            })?
            .to_string();
        if entry.enclosed_name().is_none() {
            return Err(NormalizationError::InvalidPath {
                path: original_path,
                reason: "ZIP path is not enclosed",
            });
        }
        let member_type = zip_member_type(&entry, &original_path)?;
        let archive_path = validate_portable_path(&original_path, member_type, limits)?;
        registry.insert(&archive_path, member_type)?;

        let declared_size = entry.size();
        ensure_member_size(&archive_path, declared_size, limits.max_member_bytes)?;
        expanded_bytes =
            checked_expanded_total(expanded_bytes, declared_size, limits.max_expanded_bytes)?;
        compressed_bytes = compressed_bytes
            .checked_add(entry.compressed_size())
            .ok_or(NormalizationError::ExpandedSizeLimit {
                actual: u64::MAX,
                limit: limits.max_expanded_bytes,
            })?;
        ensure_ratio(
            &archive_path,
            declared_size,
            entry.compressed_size(),
            limits.max_compression_ratio,
        )?;

        let mode = entry.unix_mode();
        let ratio_output_limit = entry
            .compressed_size()
            .saturating_mul(limits.max_compression_ratio)
            .min(limits.max_member_bytes);
        let member_bytes =
            read_exact_bounded(&mut entry, &archive_path, declared_size, ratio_output_limit)?;
        if member_type == RawMemberType::Directory && !member_bytes.is_empty() {
            return Err(NormalizationError::UnsupportedMemberType {
                path: archive_path,
                kind: "directory_with_payload".to_string(),
            });
        }
        members.push(RawMember {
            original_path,
            archive_path,
            member_type,
            mode,
            bytes: member_bytes,
        });
    }

    ensure_ratio(
        "<zip-total>",
        expanded_bytes,
        compressed_bytes,
        limits.max_compression_ratio,
    )?;
    members.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    Ok(ArchiveMembers {
        members,
        expanded_bytes,
    })
}

#[derive(Debug)]
struct RawZipEntry<'a> {
    name: &'a [u8],
    flags: u16,
    compression: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
}

fn preflight_zip(bytes: &[u8], limits: ArchiveLimits) -> Result<(), NormalizationError> {
    let eocd_offset = find_eocd(bytes)?;
    let eocd = bytes
        .get(eocd_offset..eocd_offset + 22)
        .ok_or_else(|| NormalizationError::Archive("truncated ZIP EOCD".to_string()))?;
    let disk = read_u16(eocd, 4)?;
    let central_disk = read_u16(eocd, 6)?;
    let disk_entries = read_u16(eocd, 8)?;
    let total_entries = read_u16(eocd, 10)?;
    let central_size = read_u32(eocd, 12)?;
    let central_offset = read_u32(eocd, 16)?;
    if disk != 0 || central_disk != 0 || disk_entries != total_entries {
        return Err(NormalizationError::UnsupportedFormat(
            "multi-disk ZIP archives are unsupported".to_string(),
        ));
    }
    if total_entries == u16::MAX || central_size == u32::MAX || central_offset == u32::MAX {
        return Err(NormalizationError::UnsupportedFormat(
            "ZIP64 archives require an explicit future parser policy".to_string(),
        ));
    }
    ensure_member_count(total_entries as usize, limits.max_members)?;
    let central_end = (central_offset as usize)
        .checked_add(central_size as usize)
        .ok_or_else(|| NormalizationError::Archive("ZIP central directory overflow".to_string()))?;
    if central_end != eocd_offset {
        return Err(NormalizationError::TrailingArchiveData);
    }

    let mut cursor = central_offset as usize;
    let mut seen_names = BTreeMap::<Vec<u8>, ()>::new();
    let mut ranges = Vec::with_capacity(total_entries as usize);
    for _ in 0..total_entries {
        let header = bytes
            .get(cursor..cursor.saturating_add(46))
            .ok_or_else(|| {
                NormalizationError::Archive("truncated ZIP central header".to_string())
            })?;
        if header.get(0..4) != Some(b"PK\x01\x02") {
            return Err(NormalizationError::Archive(
                "invalid ZIP central header signature".to_string(),
            ));
        }
        let name_length = read_u16(header, 28)? as usize;
        let extra_length = read_u16(header, 30)? as usize;
        let comment_length = read_u16(header, 32)? as usize;
        let record_length = 46usize
            .checked_add(name_length)
            .and_then(|value| value.checked_add(extra_length))
            .and_then(|value| value.checked_add(comment_length))
            .ok_or_else(|| {
                NormalizationError::Archive("ZIP central record overflow".to_string())
            })?;
        let record = bytes
            .get(cursor..cursor.saturating_add(record_length))
            .ok_or_else(|| {
                NormalizationError::Archive("truncated ZIP central record".to_string())
            })?;
        let name = &record[46..46 + name_length];
        let entry = RawZipEntry {
            name,
            flags: read_u16(header, 8)?,
            compression: read_u16(header, 10)?,
            crc32: read_u32(header, 16)?,
            compressed_size: read_u32(header, 20)?,
            uncompressed_size: read_u32(header, 24)?,
            local_header_offset: read_u32(header, 42)?,
        };
        if seen_names.insert(name.to_vec(), ()).is_some() {
            return Err(NormalizationError::DuplicatePath {
                path: String::from_utf8_lossy(name).into_owned(),
            });
        }
        if std::str::from_utf8(name).is_err() {
            return Err(NormalizationError::InvalidPath {
                path: "<non-utf8>".to_string(),
                reason: "path is not UTF-8",
            });
        }
        if entry.flags & 0x0001 != 0 {
            return Err(NormalizationError::UnsupportedMemberType {
                path: String::from_utf8_lossy(name).into_owned(),
                kind: "encrypted_zip_member".to_string(),
            });
        }
        if !matches!(entry.compression, 0 | 8) {
            return Err(NormalizationError::UnsupportedMemberType {
                path: String::from_utf8_lossy(name).into_owned(),
                kind: format!("compression_{}", entry.compression),
            });
        }
        if entry.compressed_size == u32::MAX
            || entry.uncompressed_size == u32::MAX
            || entry.local_header_offset == u32::MAX
        {
            return Err(NormalizationError::UnsupportedFormat(
                "ZIP64 member fields require an explicit future parser policy".to_string(),
            ));
        }
        let range = verify_local_zip_header(bytes, &entry, central_offset as usize)?;
        ranges.push(range);
        cursor = cursor.checked_add(record_length).ok_or_else(|| {
            NormalizationError::Archive("ZIP central cursor overflow".to_string())
        })?;
    }
    if cursor != central_end {
        return Err(NormalizationError::Archive(
            "ZIP central directory count or size is inconsistent".to_string(),
        ));
    }
    if total_entries > 0 && ranges.iter().map(|range| range.0).min() != Some(0) {
        return Err(NormalizationError::TrailingArchiveData);
    }
    ranges.sort_unstable_by_key(|range| range.0);
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(NormalizationError::Archive(
                "ZIP member byte ranges overlap".to_string(),
            ));
        }
    }
    Ok(())
}

fn find_eocd(bytes: &[u8]) -> Result<usize, NormalizationError> {
    const EOCD_MIN: usize = 22;
    const MAX_COMMENT: usize = u16::MAX as usize;
    if bytes.len() < EOCD_MIN {
        return Err(NormalizationError::Archive(
            "ZIP is shorter than an EOCD record".to_string(),
        ));
    }
    let start = bytes.len().saturating_sub(EOCD_MIN + MAX_COMMENT);
    for offset in (start..=bytes.len() - EOCD_MIN).rev() {
        if bytes.get(offset..offset + 4) != Some(b"PK\x05\x06") {
            continue;
        }
        let comment_length = read_u16(&bytes[offset..offset + EOCD_MIN], 20)? as usize;
        if offset + EOCD_MIN + comment_length == bytes.len() {
            return Ok(offset);
        }
    }
    Err(NormalizationError::TrailingArchiveData)
}

fn verify_local_zip_header(
    bytes: &[u8],
    central: &RawZipEntry<'_>,
    central_offset: usize,
) -> Result<(usize, usize), NormalizationError> {
    let offset = central.local_header_offset as usize;
    let local = bytes
        .get(offset..offset.saturating_add(30))
        .ok_or_else(|| NormalizationError::Archive("truncated ZIP local header".to_string()))?;
    if local.get(0..4) != Some(b"PK\x03\x04") {
        return Err(NormalizationError::Archive(
            "invalid ZIP local header signature".to_string(),
        ));
    }
    let flags = read_u16(local, 6)?;
    let compression = read_u16(local, 8)?;
    let crc32 = read_u32(local, 14)?;
    let compressed_size = read_u32(local, 18)?;
    let uncompressed_size = read_u32(local, 22)?;
    let name_length = read_u16(local, 26)? as usize;
    let extra_length = read_u16(local, 28)? as usize;
    let name_start = offset
        .checked_add(30)
        .ok_or_else(|| NormalizationError::Archive("ZIP local header overflow".to_string()))?;
    let name_end = name_start
        .checked_add(name_length)
        .ok_or_else(|| NormalizationError::Archive("ZIP local name overflow".to_string()))?;
    let data_start = name_end
        .checked_add(extra_length)
        .ok_or_else(|| NormalizationError::Archive("ZIP local extra overflow".to_string()))?;
    let data_end = data_start
        .checked_add(central.compressed_size as usize)
        .ok_or_else(|| NormalizationError::Archive("ZIP member range overflow".to_string()))?;
    let local_name = bytes
        .get(name_start..name_end)
        .ok_or_else(|| NormalizationError::Archive("truncated ZIP local name".to_string()))?;
    if local_name != central.name
        || flags != central.flags
        || compression != central.compression
        || data_end > central_offset
    {
        return Err(NormalizationError::Archive(
            "ZIP local and central headers disagree".to_string(),
        ));
    }
    let uses_descriptor = flags & 0x0008 != 0;
    let range_end = if uses_descriptor {
        let sizes_are_zero = crc32 == 0 && compressed_size == 0 && uncompressed_size == 0;
        let sizes_match = crc32 == central.crc32
            && compressed_size == central.compressed_size
            && uncompressed_size == central.uncompressed_size;
        if !sizes_are_zero && !sizes_match {
            return Err(NormalizationError::Archive(
                "ZIP data-descriptor local sizes disagree with central header".to_string(),
            ));
        }
        verify_zip_data_descriptor(bytes, data_end, central, central_offset)?
    } else if crc32 != central.crc32
        || compressed_size != central.compressed_size
        || uncompressed_size != central.uncompressed_size
    {
        return Err(NormalizationError::Archive(
            "ZIP local sizes or CRC disagree with central header".to_string(),
        ));
    } else {
        data_end
    };
    Ok((offset, range_end))
}

fn verify_zip_data_descriptor(
    bytes: &[u8],
    offset: usize,
    central: &RawZipEntry<'_>,
    central_offset: usize,
) -> Result<usize, NormalizationError> {
    let signed_matches = bytes
        .get(offset..offset.saturating_add(16))
        .is_some_and(|descriptor| {
            descriptor.get(0..4) == Some(b"PK\x07\x08")
                && u32::from_le_bytes(descriptor[4..8].try_into().expect("four CRC bytes"))
                    == central.crc32
                && u32::from_le_bytes(descriptor[8..12].try_into().expect("four size bytes"))
                    == central.compressed_size
                && u32::from_le_bytes(descriptor[12..16].try_into().expect("four size bytes"))
                    == central.uncompressed_size
        });
    let unsigned_matches = bytes
        .get(offset..offset.saturating_add(12))
        .is_some_and(|descriptor| {
            u32::from_le_bytes(descriptor[0..4].try_into().expect("four CRC bytes"))
                == central.crc32
                && u32::from_le_bytes(descriptor[4..8].try_into().expect("four size bytes"))
                    == central.compressed_size
                && u32::from_le_bytes(descriptor[8..12].try_into().expect("four size bytes"))
                    == central.uncompressed_size
        });
    let end = if signed_matches {
        offset + 16
    } else if unsigned_matches {
        offset + 12
    } else {
        return Err(NormalizationError::Archive(
            "ZIP data descriptor is missing or disagrees with central header".to_string(),
        ));
    };
    if end > central_offset {
        return Err(NormalizationError::Archive(
            "ZIP data descriptor overlaps the central directory".to_string(),
        ));
    }
    Ok(end)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, NormalizationError> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| NormalizationError::Archive("truncated ZIP integer".to_string()))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, NormalizationError> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| NormalizationError::Archive("truncated ZIP integer".to_string()))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn zip_member_type<R: Read>(
    entry: &zip::read::ZipFile<'_, R>,
    path: &str,
) -> Result<RawMemberType, NormalizationError> {
    if entry.is_symlink() {
        return Err(NormalizationError::UnsupportedMemberType {
            path: path.to_string(),
            kind: "symlink".to_string(),
        });
    }
    let name_is_dir = path.ends_with('/');
    if let Some(mode) = entry.unix_mode() {
        let file_type = mode & 0o170000;
        if file_type != 0 && file_type != 0o100000 && file_type != 0o040000 {
            return Err(NormalizationError::UnsupportedMemberType {
                path: path.to_string(),
                kind: format!("unix_mode_{file_type:o}"),
            });
        }
        if file_type == 0o040000 && !name_is_dir {
            return Err(NormalizationError::UnsupportedMemberType {
                path: path.to_string(),
                kind: "directory_mode_without_directory_name".to_string(),
            });
        }
        if file_type == 0o100000 && name_is_dir {
            return Err(NormalizationError::UnsupportedMemberType {
                path: path.to_string(),
                kind: "regular_mode_with_directory_name".to_string(),
            });
        }
    }
    Ok(if name_is_dir {
        RawMemberType::Directory
    } else {
        RawMemberType::File
    })
}

fn validate_portable_path(
    original: &str,
    member_type: RawMemberType,
    limits: ArchiveLimits,
) -> Result<String, NormalizationError> {
    if original.is_empty() {
        return invalid_path(original, "path is empty");
    }
    if original.len() > limits.max_path_bytes {
        return invalid_path(original, "path is too long");
    }
    if original.starts_with('/') || original.starts_with('\\') {
        return invalid_path(original, "path is absolute");
    }
    if original.contains('\\') {
        return invalid_path(original, "backslash path separators are not portable");
    }
    if original
        .chars()
        .any(|character| character == '\0' || character.is_control())
    {
        return invalid_path(original, "path contains NUL or control characters");
    }

    let path = if member_type == RawMemberType::Directory {
        original.strip_suffix('/').unwrap_or(original)
    } else {
        original
    };
    if path.is_empty() {
        return invalid_path(original, "path is the archive root");
    }
    let components = path.split('/').collect::<Vec<_>>();
    if components.len() > limits.max_path_depth {
        return invalid_path(original, "path nesting is too deep");
    }
    for (index, component) in components.iter().enumerate() {
        if component.is_empty() || *component == "." || *component == ".." {
            return invalid_path(original, "path has an empty, dot, or traversal component");
        }
        if component.len() > limits.max_component_bytes {
            return invalid_path(original, "path component is too long");
        }
        if index == 0 && component.as_bytes().get(1) == Some(&b':') {
            return invalid_path(original, "path has a Windows drive prefix");
        }
    }
    Ok(path.to_string())
}

fn invalid_path<T>(path: &str, reason: &'static str) -> Result<T, NormalizationError> {
    Err(NormalizationError::InvalidPath {
        path: path.to_string(),
        reason,
    })
}

fn ensure_member_count(actual: usize, limit: usize) -> Result<(), NormalizationError> {
    if actual > limit {
        return Err(NormalizationError::MemberCountLimit { actual, limit });
    }
    Ok(())
}

fn ensure_member_size(path: &str, actual: u64, limit: u64) -> Result<(), NormalizationError> {
    if actual > limit {
        return Err(NormalizationError::MemberSizeLimit {
            path: path.to_string(),
            actual,
            limit,
        });
    }
    Ok(())
}

fn checked_expanded_total(
    current: u64,
    member: u64,
    limit: u64,
) -> Result<u64, NormalizationError> {
    let actual = current
        .checked_add(member)
        .ok_or(NormalizationError::ExpandedSizeLimit {
            actual: u64::MAX,
            limit,
        })?;
    if actual > limit {
        return Err(NormalizationError::ExpandedSizeLimit { actual, limit });
    }
    Ok(actual)
}

fn ensure_ratio(
    path: &str,
    expanded: u64,
    compressed: u64,
    max_ratio: u64,
) -> Result<(), NormalizationError> {
    if expanded == 0 {
        return Ok(());
    }
    if compressed == 0 || expanded > compressed.saturating_mul(max_ratio) {
        return Err(NormalizationError::CompressionRatioLimit {
            path: path.to_string(),
        });
    }
    Ok(())
}

fn read_exact_bounded(
    reader: &mut impl Read,
    path: &str,
    declared_size: u64,
    limit: u64,
) -> Result<Vec<u8>, NormalizationError> {
    ensure_member_size(path, declared_size, limit)?;
    let capacity =
        usize::try_from(declared_size).map_err(|_| NormalizationError::MemberSizeLimit {
            path: path.to_string(),
            actual: declared_size,
            limit,
        })?;
    let mut bytes = Vec::with_capacity(capacity);
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| NormalizationError::Archive(error.to_string()))?;
    if bytes.len() as u64 != declared_size {
        return Err(NormalizationError::Archive(format!(
            "member `{path}` decoded length {} does not match declared length {declared_size}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn limits() -> ArchiveLimits {
        ArchiveLimits {
            max_members: 16,
            max_member_bytes: 1024,
            max_expanded_bytes: 4096,
            max_compression_ratio: 100,
            max_path_bytes: 256,
            max_component_bytes: 64,
            max_path_depth: 8,
            max_tar_trailing_bytes: 1024,
        }
    }

    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        for (path, bytes) in entries {
            writer
                .start_file(*path, SimpleFileOptions::default())
                .expect("start ZIP member");
            writer.write_all(bytes).expect("write ZIP member");
        }
        writer.finish().expect("finish ZIP").into_inner()
    }

    fn tar_gzip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (path, bytes) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_path(path).expect("set tar path");
                header.set_cksum();
                builder.append(&header, *bytes).expect("append tar member");
            }
            builder.finish().expect("finish tar");
        }
        gzip_bytes(&tar_bytes)
    }

    fn gzip_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).expect("write gzip bytes");
        encoder.finish().expect("finish gzip")
    }

    fn replace_all_same_length(bytes: &mut [u8], from: &[u8], to: &[u8]) -> usize {
        assert_eq!(from.len(), to.len());
        let mut replacements = 0;
        let mut offset = 0;
        while offset + from.len() <= bytes.len() {
            if &bytes[offset..offset + from.len()] == from {
                bytes[offset..offset + to.len()].copy_from_slice(to);
                replacements += 1;
                offset += from.len();
            } else {
                offset += 1;
            }
        }
        replacements
    }

    #[test]
    fn zip_reader_rejects_traversal_and_duplicate_paths() {
        let traversal = zip_with(&[("../escape", b"no")]);
        assert!(matches!(
            read_zip(&traversal, limits()),
            Err(NormalizationError::InvalidPath { .. })
        ));

        let mut duplicate = zip_with(&[("root/a", b"one"), ("root/b", b"two")]);
        assert_eq!(
            replace_all_same_length(&mut duplicate, b"root/b", b"root/a"),
            2
        );
        assert!(matches!(
            read_zip(&duplicate, limits()),
            Err(NormalizationError::DuplicatePath { .. })
        ));
    }

    #[test]
    fn zip_reader_rejects_case_and_unicode_collisions() {
        let case_collision = zip_with(&[("root/File.py", b"one"), ("root/file.py", b"two")]);
        assert!(matches!(
            read_zip(&case_collision, limits()),
            Err(NormalizationError::CaseCollision { .. })
        ));

        let unicode_collision = zip_with(&[
            ("root/caf\u{e9}.py", b"one"),
            ("root/cafe\u{301}.py", b"two"),
        ]);
        assert!(matches!(
            read_zip(&unicode_collision, limits()),
            Err(NormalizationError::UnicodeCollision { .. })
        ));
    }

    #[test]
    fn zip_reader_rejects_folded_prefix_conflicts_in_both_orders() {
        for bytes in [
            zip_with(&[("root/Foo", b"file"), ("root/foo/bar", b"child")]),
            zip_with(&[("root/foo/bar", b"child"), ("root/Foo", b"file")]),
        ] {
            assert!(matches!(
                read_zip(&bytes, limits()),
                Err(NormalizationError::PrefixCollision { .. })
            ));
        }
    }

    #[test]
    fn zip_reader_rejects_appended_bytes_and_local_central_name_mismatch() {
        let mut appended = zip_with(&[("root/a", b"inert")]);
        appended.extend_from_slice(b"not part of the ZIP");
        assert!(matches!(
            read_zip(&appended, limits()),
            Err(NormalizationError::TrailingArchiveData)
        ));

        let mut mismatched = zip_with(&[("root/a", b"inert")]);
        let first = mismatched
            .windows(b"root/a".len())
            .position(|window| window == b"root/a")
            .expect("local filename");
        mismatched[first..first + b"root/a".len()].copy_from_slice(b"evil/a");
        assert!(matches!(
            read_zip(&mismatched, limits()),
            Err(NormalizationError::Archive(_))
        ));
    }

    #[test]
    fn zip_reader_never_writes_members_and_returns_bounded_bytes() {
        let bytes = zip_with(&[("root/a.txt", b"inert")]);
        let archive = read_zip(&bytes, limits()).expect("read ZIP");
        assert_eq!(archive.expanded_bytes, 5);
        assert_eq!(archive.members.len(), 1);
        assert_eq!(archive.members[0].bytes, b"inert");
    }

    #[test]
    fn tar_reader_returns_regular_members_without_extraction() {
        let bytes = tar_gzip_with(&[("package/package.json", br#"{"name":"inert"}"#)]);
        let archive = read_tar_gzip(&bytes, limits()).expect("read tar.gz");
        assert_eq!(archive.members.len(), 1);
        assert_eq!(archive.members[0].archive_path, "package/package.json");
        assert_eq!(archive.members[0].bytes, br#"{"name":"inert"}"#);
    }

    #[test]
    fn tar_reader_rejects_traversal_special_members_and_payload_after_end_marker() {
        let mut raw_traversal = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut raw_traversal);
            let mut header = tar::Header::new_gnu();
            header.set_size(2);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.as_mut_bytes()[..9].copy_from_slice(b"../escape");
            header.set_cksum();
            builder
                .append(&header, &b"no"[..])
                .expect("append traversal");
            builder.finish().expect("finish traversal tar");
        }
        assert!(matches!(
            read_tar_gzip(&gzip_bytes(&raw_traversal), limits()),
            Err(NormalizationError::InvalidPath { .. })
        ));

        let mut raw_link = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut raw_link);
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o777);
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_path("package/link").expect("set link path");
            header.set_link_name("target").expect("set link target");
            header.set_cksum();
            builder
                .append(&header, std::io::empty())
                .expect("append symlink");
            builder.finish().expect("finish link tar");
        }
        assert!(matches!(
            read_tar_gzip(&gzip_bytes(&raw_link), limits()),
            Err(NormalizationError::UnsupportedMemberType { .. })
        ));

        let valid = tar_gzip_with(&[("package/a", b"inert")]);
        let mut decoder = MultiGzDecoder::new(Cursor::new(valid));
        let mut raw = Vec::new();
        decoder.read_to_end(&mut raw).expect("decode test tar");
        raw.extend_from_slice(b"smuggled");
        assert!(matches!(
            read_tar_gzip(&gzip_bytes(&raw), limits()),
            Err(NormalizationError::TrailingArchiveData)
        ));
    }
}
