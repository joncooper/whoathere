#![allow(dead_code)]

use std::fmt;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;
use whoathere_artifact::Sha256Digest;

const BTF_MAGIC_V1: u16 = 0xeb9f;
const BTF_VERSION_V1: u8 = 1;
const BTF_HEADER_BYTES_V1: usize = 24;
const MAX_BTF_BYTES_V1: usize = 8 * 1024 * 1024;
const MAX_BTF_TYPES_V1: usize = 262_144;
const BTF_KIND_INT_V1: u8 = 1;
const BTF_KIND_STRUCT_V1: u8 = 4;
const BTF_INT_SIGNED_V1: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageSensorBtfErrorV1 {
    Empty,
    LimitExceeded,
    InvalidHeader,
    InvalidType,
    InvalidString,
    MissingTaskStruct,
    MissingExitCode,
    DuplicateExitCode,
    IncompatibleExitCode,
    Io,
}

impl LinuxVzPackageSensorBtfErrorV1 {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "linux_vz_package_sensor_btf_empty",
            Self::LimitExceeded => "linux_vz_package_sensor_btf_limit_exceeded",
            Self::InvalidHeader => "linux_vz_package_sensor_btf_header_invalid",
            Self::InvalidType => "linux_vz_package_sensor_btf_type_invalid",
            Self::InvalidString => "linux_vz_package_sensor_btf_string_invalid",
            Self::MissingTaskStruct => "linux_vz_package_sensor_btf_task_struct_missing",
            Self::MissingExitCode => "linux_vz_package_sensor_btf_exit_code_missing",
            Self::DuplicateExitCode => "linux_vz_package_sensor_btf_exit_code_duplicate",
            Self::IncompatibleExitCode => "linux_vz_package_sensor_btf_exit_code_incompatible",
            Self::Io => "linux_vz_package_sensor_btf_io_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageSensorBtfErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageSensorBtfErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageTaskExitCodeLayoutV1 {
    btf_sha256: Sha256Digest,
    byte_offset: u32,
}

impl LinuxVzPackageTaskExitCodeLayoutV1 {
    pub(crate) fn btf_sha256_v1(&self) -> &Sha256Digest {
        &self.btf_sha256
    }

    pub(crate) const fn byte_offset_v1(&self) -> u32 {
        self.byte_offset
    }
}

#[derive(Debug, Clone, Copy)]
struct BtfTypeSummaryV1 {
    kind: u8,
    size_or_type: u32,
    int_data: Option<u32>,
}

pub(crate) fn decode_linux_vz_package_task_exit_code_layout_v1(
    bytes: &[u8],
) -> Result<LinuxVzPackageTaskExitCodeLayoutV1, LinuxVzPackageSensorBtfErrorV1> {
    if bytes.is_empty() {
        return Err(LinuxVzPackageSensorBtfErrorV1::Empty);
    }
    if bytes.len() > MAX_BTF_BYTES_V1 {
        return Err(LinuxVzPackageSensorBtfErrorV1::LimitExceeded);
    }
    if bytes.len() < BTF_HEADER_BYTES_V1
        || read_u16_v1(bytes, 0)? != BTF_MAGIC_V1
        || bytes[2] != BTF_VERSION_V1
        || bytes[3] != 0
    {
        return Err(LinuxVzPackageSensorBtfErrorV1::InvalidHeader);
    }
    let header_length = usize_v1(read_u32_v1(bytes, 4)?)?;
    let type_offset = usize_v1(read_u32_v1(bytes, 8)?)?;
    let type_length = usize_v1(read_u32_v1(bytes, 12)?)?;
    let string_offset = usize_v1(read_u32_v1(bytes, 16)?)?;
    let string_length = usize_v1(read_u32_v1(bytes, 20)?)?;
    let type_start = header_length
        .checked_add(type_offset)
        .ok_or(LinuxVzPackageSensorBtfErrorV1::InvalidHeader)?;
    let type_end = type_start
        .checked_add(type_length)
        .ok_or(LinuxVzPackageSensorBtfErrorV1::InvalidHeader)?;
    let string_start = header_length
        .checked_add(string_offset)
        .ok_or(LinuxVzPackageSensorBtfErrorV1::InvalidHeader)?;
    let string_end = string_start
        .checked_add(string_length)
        .ok_or(LinuxVzPackageSensorBtfErrorV1::InvalidHeader)?;
    if header_length != BTF_HEADER_BYTES_V1
        || type_length == 0
        || string_length == 0
        || type_start != header_length
        || type_end != string_start
        || string_end != bytes.len()
    {
        return Err(LinuxVzPackageSensorBtfErrorV1::InvalidHeader);
    }
    let strings = &bytes[string_start..string_end];
    if strings.first() != Some(&0) {
        return Err(LinuxVzPackageSensorBtfErrorV1::InvalidString);
    }

    let mut cursor = type_start;
    let mut summaries = Vec::new();
    let mut task_struct_seen = false;
    let mut exit_code_member = None;
    while cursor < type_end {
        if summaries.len() >= MAX_BTF_TYPES_V1 || type_end - cursor < 12 {
            return Err(LinuxVzPackageSensorBtfErrorV1::LimitExceeded);
        }
        let name_offset = read_u32_v1(bytes, cursor)?;
        let info = read_u32_v1(bytes, cursor + 4)?;
        let size_or_type = read_u32_v1(bytes, cursor + 8)?;
        let kind = u8::try_from((info >> 24) & 0x1f)
            .map_err(|_| LinuxVzPackageSensorBtfErrorV1::InvalidType)?;
        let kind_flag = info >> 31 != 0;
        let value_count = usize::from((info & 0xffff) as u16);
        let name = string_v1(strings, name_offset)?;
        cursor += 12;
        let extra_length = extra_type_bytes_v1(kind, value_count)?;
        let extra_end = cursor
            .checked_add(extra_length)
            .filter(|end| *end <= type_end)
            .ok_or(LinuxVzPackageSensorBtfErrorV1::InvalidType)?;
        let int_data = if kind == BTF_KIND_INT_V1 {
            if value_count != 0 || extra_length != 4 {
                return Err(LinuxVzPackageSensorBtfErrorV1::InvalidType);
            }
            Some(read_u32_v1(bytes, cursor)?)
        } else {
            None
        };

        validate_nested_names_v1(bytes, cursor, kind, value_count, strings)?;
        if kind == BTF_KIND_STRUCT_V1 && name == b"task_struct" {
            if task_struct_seen {
                return Err(LinuxVzPackageSensorBtfErrorV1::InvalidType);
            }
            task_struct_seen = true;
            if size_or_type == 0 || value_count == 0 {
                return Err(LinuxVzPackageSensorBtfErrorV1::InvalidType);
            }
            for index in 0..value_count {
                let member = cursor + index * 12;
                let member_name = string_v1(strings, read_u32_v1(bytes, member)?)?;
                if member_name != b"exit_code" {
                    continue;
                }
                if exit_code_member.is_some() {
                    return Err(LinuxVzPackageSensorBtfErrorV1::DuplicateExitCode);
                }
                let member_type = read_u32_v1(bytes, member + 4)?;
                let encoded_offset = read_u32_v1(bytes, member + 8)?;
                let (bit_offset, bitfield_size) = if kind_flag {
                    (encoded_offset & 0x00ff_ffff, encoded_offset >> 24)
                } else {
                    (encoded_offset, 0)
                };
                if member_type == 0
                    || bitfield_size != 0
                    || bit_offset % 8 != 0
                    || bit_offset / 8 >= size_or_type
                {
                    return Err(LinuxVzPackageSensorBtfErrorV1::IncompatibleExitCode);
                }
                exit_code_member = Some((member_type, bit_offset / 8));
            }
        }
        summaries.push(BtfTypeSummaryV1 {
            kind,
            size_or_type,
            int_data,
        });
        cursor = extra_end;
    }
    if cursor != type_end || summaries.is_empty() {
        return Err(LinuxVzPackageSensorBtfErrorV1::InvalidType);
    }
    if !task_struct_seen {
        return Err(LinuxVzPackageSensorBtfErrorV1::MissingTaskStruct);
    }
    let (member_type, byte_offset) =
        exit_code_member.ok_or(LinuxVzPackageSensorBtfErrorV1::MissingExitCode)?;
    require_signed_int32_v1(member_type, &summaries)?;
    Ok(LinuxVzPackageTaskExitCodeLayoutV1 {
        btf_sha256: Sha256Digest::from_bytes(bytes),
        byte_offset,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn read_linux_vz_package_task_exit_code_layout_v1(
) -> Result<LinuxVzPackageTaskExitCodeLayoutV1, LinuxVzPackageSensorBtfErrorV1> {
    let mut file =
        File::open("/sys/kernel/btf/vmlinux").map_err(|_| LinuxVzPackageSensorBtfErrorV1::Io)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_BTF_BYTES_V1 as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LinuxVzPackageSensorBtfErrorV1::Io)?;
    decode_linux_vz_package_task_exit_code_layout_v1(&bytes)
}

fn require_signed_int32_v1(
    mut type_id: u32,
    summaries: &[BtfTypeSummaryV1],
) -> Result<(), LinuxVzPackageSensorBtfErrorV1> {
    for _ in 0..32 {
        let index = usize::try_from(type_id)
            .ok()
            .and_then(|value| value.checked_sub(1))
            .filter(|index| *index < summaries.len())
            .ok_or(LinuxVzPackageSensorBtfErrorV1::IncompatibleExitCode)?;
        let summary = summaries[index];
        match summary.kind {
            BTF_KIND_INT_V1 => {
                let data = summary
                    .int_data
                    .ok_or(LinuxVzPackageSensorBtfErrorV1::IncompatibleExitCode)?;
                let encoding = ((data >> 24) & 0x0f) as u8;
                let bit_offset = ((data >> 16) & 0xff) as u8;
                let bit_width = (data & 0xff) as u8;
                if summary.size_or_type != 4
                    || encoding & BTF_INT_SIGNED_V1 == 0
                    || bit_offset != 0
                    || bit_width != 32
                {
                    return Err(LinuxVzPackageSensorBtfErrorV1::IncompatibleExitCode);
                }
                return Ok(());
            }
            8..=11 | 18 => type_id = summary.size_or_type,
            _ => return Err(LinuxVzPackageSensorBtfErrorV1::IncompatibleExitCode),
        }
    }
    Err(LinuxVzPackageSensorBtfErrorV1::IncompatibleExitCode)
}

fn extra_type_bytes_v1(
    kind: u8,
    value_count: usize,
) -> Result<usize, LinuxVzPackageSensorBtfErrorV1> {
    let per_value = match kind {
        0 | 2 | 7..=12 | 16 | 18 => 0,
        1 | 14 | 17 => {
            if value_count != 0 {
                return Err(LinuxVzPackageSensorBtfErrorV1::InvalidType);
            }
            return Ok(4);
        }
        3 => {
            if value_count != 0 {
                return Err(LinuxVzPackageSensorBtfErrorV1::InvalidType);
            }
            return Ok(12);
        }
        4 | 5 | 15 | 19 => 12,
        6 | 13 => 8,
        _ => return Err(LinuxVzPackageSensorBtfErrorV1::InvalidType),
    };
    value_count
        .checked_mul(per_value)
        .ok_or(LinuxVzPackageSensorBtfErrorV1::LimitExceeded)
}

fn validate_nested_names_v1(
    bytes: &[u8],
    cursor: usize,
    kind: u8,
    value_count: usize,
    strings: &[u8],
) -> Result<(), LinuxVzPackageSensorBtfErrorV1> {
    let stride = match kind {
        4 | 5 | 19 => 12,
        6 | 13 => 8,
        _ => return Ok(()),
    };
    for index in 0..value_count {
        string_v1(strings, read_u32_v1(bytes, cursor + index * stride)?)?;
    }
    Ok(())
}

fn string_v1(strings: &[u8], offset: u32) -> Result<&[u8], LinuxVzPackageSensorBtfErrorV1> {
    let offset = usize_v1(offset)?;
    let tail = strings
        .get(offset..)
        .ok_or(LinuxVzPackageSensorBtfErrorV1::InvalidString)?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(LinuxVzPackageSensorBtfErrorV1::InvalidString)?;
    Ok(&tail[..end])
}

fn usize_v1(value: u32) -> Result<usize, LinuxVzPackageSensorBtfErrorV1> {
    usize::try_from(value).map_err(|_| LinuxVzPackageSensorBtfErrorV1::LimitExceeded)
}

fn read_u16_v1(bytes: &[u8], offset: usize) -> Result<u16, LinuxVzPackageSensorBtfErrorV1> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(LinuxVzPackageSensorBtfErrorV1::InvalidHeader)?
        .try_into()
        .map_err(|_| LinuxVzPackageSensorBtfErrorV1::InvalidHeader)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32_v1(bytes: &[u8], offset: usize) -> Result<u32, LinuxVzPackageSensorBtfErrorV1> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(LinuxVzPackageSensorBtfErrorV1::InvalidType)?
        .try_into()
        .map_err(|_| LinuxVzPackageSensorBtfErrorV1::InvalidType)?;
    Ok(u32::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_btf_v1(member_offset_bits: u32, int_data: u32) -> Vec<u8> {
        let strings = b"\0int\0task_struct\0exit_code\0";
        let mut types = Vec::new();
        types.extend_from_slice(&1_u32.to_le_bytes());
        types.extend_from_slice(&(u32::from(BTF_KIND_INT_V1) << 24).to_le_bytes());
        types.extend_from_slice(&4_u32.to_le_bytes());
        types.extend_from_slice(&int_data.to_le_bytes());
        types.extend_from_slice(&5_u32.to_le_bytes());
        types.extend_from_slice(&((u32::from(BTF_KIND_STRUCT_V1) << 24) | 1).to_le_bytes());
        types.extend_from_slice(&1024_u32.to_le_bytes());
        types.extend_from_slice(&17_u32.to_le_bytes());
        types.extend_from_slice(&1_u32.to_le_bytes());
        types.extend_from_slice(&member_offset_bits.to_le_bytes());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&BTF_MAGIC_V1.to_le_bytes());
        bytes.push(BTF_VERSION_V1);
        bytes.push(0);
        bytes.extend_from_slice(&(BTF_HEADER_BYTES_V1 as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&(types.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(types.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&types);
        bytes.extend_from_slice(strings);
        bytes
    }

    #[test]
    fn exact_task_exit_code_layout_is_byte_bound_and_measured() {
        let bytes = exact_btf_v1(320, (u32::from(BTF_INT_SIGNED_V1) << 24) | 32);
        let layout =
            decode_linux_vz_package_task_exit_code_layout_v1(&bytes).expect("exit-code layout");
        assert_eq!(layout.byte_offset_v1(), 40);
        assert_eq!(layout.btf_sha256_v1(), &Sha256Digest::from_bytes(&bytes));
    }

    #[test]
    fn malformed_or_incompatible_task_exit_code_layout_fails_closed() {
        let signed_int32 = (u32::from(BTF_INT_SIGNED_V1) << 24) | 32;
        assert_eq!(
            decode_linux_vz_package_task_exit_code_layout_v1(&[]),
            Err(LinuxVzPackageSensorBtfErrorV1::Empty)
        );
        assert_eq!(
            decode_linux_vz_package_task_exit_code_layout_v1(&exact_btf_v1(321, signed_int32)),
            Err(LinuxVzPackageSensorBtfErrorV1::IncompatibleExitCode)
        );
        assert_eq!(
            decode_linux_vz_package_task_exit_code_layout_v1(&exact_btf_v1(320, 32)),
            Err(LinuxVzPackageSensorBtfErrorV1::IncompatibleExitCode)
        );
        let mut truncated = exact_btf_v1(320, signed_int32);
        truncated.pop();
        assert_eq!(
            decode_linux_vz_package_task_exit_code_layout_v1(&truncated),
            Err(LinuxVzPackageSensorBtfErrorV1::InvalidHeader)
        );
    }
}
