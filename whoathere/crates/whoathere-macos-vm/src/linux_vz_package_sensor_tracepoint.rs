#![allow(dead_code)]

use std::fmt;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;
use whoathere_artifact::Sha256Digest;

const MAX_TRACEPOINT_FORMAT_BYTES_V1: usize = 64 * 1024;
const MAX_TRACEPOINT_RECORD_BYTES_V1: usize = 512;
const MAX_TRACEPOINT_FIELDS_V1: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageTracepointKindV1 {
    SchedProcessFork,
    SchedProcessExec,
    SchedProcessExit,
    RawSyscallsSysEnter,
    RawSyscallsSysExit,
}

impl LinuxVzPackageTracepointKindV1 {
    pub(crate) const fn category_v1(self) -> &'static str {
        match self {
            Self::SchedProcessFork | Self::SchedProcessExec | Self::SchedProcessExit => "sched",
            Self::RawSyscallsSysEnter | Self::RawSyscallsSysExit => "raw_syscalls",
        }
    }

    pub(crate) const fn name_v1(self) -> &'static str {
        match self {
            Self::SchedProcessFork => "sched_process_fork",
            Self::SchedProcessExec => "sched_process_exec",
            Self::SchedProcessExit => "sched_process_exit",
            Self::RawSyscallsSysEnter => "sys_enter",
            Self::RawSyscallsSysExit => "sys_exit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageTracepointErrorV1 {
    Empty,
    LimitExceeded,
    InvalidUtf8,
    InvalidHeader,
    InvalidIdentifier,
    InvalidField,
    DuplicateField,
    OverlappingField,
    MissingField,
    IncompatibleField,
    Io,
}

impl LinuxVzPackageTracepointErrorV1 {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "linux_vz_package_tracepoint_format_empty",
            Self::LimitExceeded => "linux_vz_package_tracepoint_format_limit_exceeded",
            Self::InvalidUtf8 => "linux_vz_package_tracepoint_format_utf8_invalid",
            Self::InvalidHeader => "linux_vz_package_tracepoint_format_header_invalid",
            Self::InvalidIdentifier => "linux_vz_package_tracepoint_identifier_invalid",
            Self::InvalidField => "linux_vz_package_tracepoint_field_invalid",
            Self::DuplicateField => "linux_vz_package_tracepoint_field_duplicate",
            Self::OverlappingField => "linux_vz_package_tracepoint_field_overlap",
            Self::MissingField => "linux_vz_package_tracepoint_field_missing",
            Self::IncompatibleField => "linux_vz_package_tracepoint_field_incompatible",
            Self::Io => "linux_vz_package_tracepoint_format_io_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageTracepointErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageTracepointErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxVzPackageTracepointFieldV1 {
    name: String,
    declaration: String,
    offset: usize,
    size: usize,
    signed: bool,
    data_location: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageTracepointFieldLocationV1 {
    offset: usize,
    size: usize,
    signed: bool,
    data_location: bool,
}

impl LinuxVzPackageTracepointFieldLocationV1 {
    pub(crate) const fn offset_v1(self) -> usize {
        self.offset
    }

    pub(crate) const fn size_v1(self) -> usize {
        self.size
    }

    pub(crate) const fn signed_v1(self) -> bool {
        self.signed
    }

    pub(crate) const fn data_location_v1(self) -> bool {
        self.data_location
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageTracepointLayoutV1 {
    kind: LinuxVzPackageTracepointKindV1,
    tracepoint_id: u32,
    format_sha256: Sha256Digest,
    maximum_record_bytes: usize,
    parent_pid: Option<LinuxVzPackageTracepointFieldLocationV1>,
    child_pid: Option<LinuxVzPackageTracepointFieldLocationV1>,
    filename: Option<LinuxVzPackageTracepointFieldLocationV1>,
    pid: Option<LinuxVzPackageTracepointFieldLocationV1>,
    old_pid: Option<LinuxVzPackageTracepointFieldLocationV1>,
    syscall_id: Option<LinuxVzPackageTracepointFieldLocationV1>,
    syscall_arguments: Option<LinuxVzPackageTracepointFieldLocationV1>,
    syscall_result: Option<LinuxVzPackageTracepointFieldLocationV1>,
}

impl LinuxVzPackageTracepointLayoutV1 {
    pub(crate) const fn kind_v1(&self) -> LinuxVzPackageTracepointKindV1 {
        self.kind
    }

    pub(crate) const fn tracepoint_id_v1(&self) -> u32 {
        self.tracepoint_id
    }

    pub(crate) fn format_sha256_v1(&self) -> &Sha256Digest {
        &self.format_sha256
    }

    pub(crate) const fn maximum_record_bytes_v1(&self) -> usize {
        self.maximum_record_bytes
    }

    pub(crate) const fn parent_pid_v1(&self) -> Option<LinuxVzPackageTracepointFieldLocationV1> {
        self.parent_pid
    }

    pub(crate) const fn child_pid_v1(&self) -> Option<LinuxVzPackageTracepointFieldLocationV1> {
        self.child_pid
    }

    pub(crate) const fn filename_v1(&self) -> Option<LinuxVzPackageTracepointFieldLocationV1> {
        self.filename
    }

    pub(crate) const fn pid_v1(&self) -> Option<LinuxVzPackageTracepointFieldLocationV1> {
        self.pid
    }

    pub(crate) const fn old_pid_v1(&self) -> Option<LinuxVzPackageTracepointFieldLocationV1> {
        self.old_pid
    }

    pub(crate) const fn syscall_id_v1(&self) -> Option<LinuxVzPackageTracepointFieldLocationV1> {
        self.syscall_id
    }

    pub(crate) const fn syscall_arguments_v1(
        &self,
    ) -> Option<LinuxVzPackageTracepointFieldLocationV1> {
        self.syscall_arguments
    }

    pub(crate) const fn syscall_result_v1(
        &self,
    ) -> Option<LinuxVzPackageTracepointFieldLocationV1> {
        self.syscall_result
    }
}

pub(crate) fn decode_linux_vz_package_tracepoint_layout_v1(
    kind: LinuxVzPackageTracepointKindV1,
    bytes: &[u8],
) -> Result<LinuxVzPackageTracepointLayoutV1, LinuxVzPackageTracepointErrorV1> {
    if bytes.is_empty() {
        return Err(LinuxVzPackageTracepointErrorV1::Empty);
    }
    if bytes.len() > MAX_TRACEPOINT_FORMAT_BYTES_V1 {
        return Err(LinuxVzPackageTracepointErrorV1::LimitExceeded);
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| LinuxVzPackageTracepointErrorV1::InvalidUtf8)?;
    if text.contains('\r') || !text.ends_with('\n') {
        return Err(LinuxVzPackageTracepointErrorV1::InvalidHeader);
    }
    let mut observed_name = None;
    let mut tracepoint_id = None;
    let mut format_marker_count = 0_usize;
    let mut print_marker_count = 0_usize;
    let mut fields = Vec::new();
    let mut inside_format = false;
    for line in text.lines() {
        if let Some(name) = line.strip_prefix("name: ") {
            if observed_name.replace(name).is_some() {
                return Err(LinuxVzPackageTracepointErrorV1::InvalidHeader);
            }
            continue;
        }
        if let Some(id) = line.strip_prefix("ID: ") {
            if tracepoint_id.replace(parse_decimal_u32_v1(id)?).is_some() {
                return Err(LinuxVzPackageTracepointErrorV1::InvalidHeader);
            }
            continue;
        }
        if line == "format:" {
            format_marker_count += 1;
            inside_format = true;
            continue;
        }
        if line.starts_with("print fmt:") {
            print_marker_count += 1;
            inside_format = false;
            continue;
        }
        if inside_format && line.trim_start().starts_with("field:") {
            if fields.len() >= MAX_TRACEPOINT_FIELDS_V1 {
                return Err(LinuxVzPackageTracepointErrorV1::LimitExceeded);
            }
            let field = parse_field_v1(line.trim())?;
            if fields
                .iter()
                .any(|existing: &LinuxVzPackageTracepointFieldV1| existing.name == field.name)
            {
                return Err(LinuxVzPackageTracepointErrorV1::DuplicateField);
            }
            fields.push(field);
        }
    }
    if observed_name != Some(kind.name_v1())
        || tracepoint_id.is_none()
        || tracepoint_id == Some(0)
        || format_marker_count != 1
        || print_marker_count != 1
        || fields.is_empty()
    {
        return Err(LinuxVzPackageTracepointErrorV1::InvalidHeader);
    }
    validate_field_ranges_v1(&fields)?;
    require_common_fields_v1(&fields)?;
    let maximum_record_bytes = fields
        .iter()
        .map(|field| field.offset + field.size)
        .max()
        .ok_or(LinuxVzPackageTracepointErrorV1::MissingField)?;
    let mut layout = LinuxVzPackageTracepointLayoutV1 {
        kind,
        tracepoint_id: tracepoint_id.ok_or(LinuxVzPackageTracepointErrorV1::InvalidHeader)?,
        format_sha256: Sha256Digest::from_bytes(bytes),
        maximum_record_bytes,
        parent_pid: None,
        child_pid: None,
        filename: None,
        pid: None,
        old_pid: None,
        syscall_id: None,
        syscall_arguments: None,
        syscall_result: None,
    };
    match kind {
        LinuxVzPackageTracepointKindV1::SchedProcessFork => {
            layout.parent_pid = Some(require_field_v1(&fields, "parent_pid", 4, true, false)?);
            layout.child_pid = Some(require_field_v1(&fields, "child_pid", 4, true, false)?);
        }
        LinuxVzPackageTracepointKindV1::SchedProcessExec => {
            layout.filename = Some(require_field_v1(&fields, "filename", 4, true, true)?);
            layout.pid = Some(require_field_v1(&fields, "pid", 4, true, false)?);
            layout.old_pid = Some(require_field_v1(&fields, "old_pid", 4, true, false)?);
        }
        LinuxVzPackageTracepointKindV1::SchedProcessExit => {
            layout.pid = Some(require_field_v1(&fields, "pid", 4, true, false)?);
        }
        LinuxVzPackageTracepointKindV1::RawSyscallsSysEnter => {
            layout.syscall_id = Some(require_field_v1(&fields, "id", 8, true, false)?);
            layout.syscall_arguments = Some(require_field_v1(&fields, "args", 48, false, false)?);
        }
        LinuxVzPackageTracepointKindV1::RawSyscallsSysExit => {
            layout.syscall_id = Some(require_field_v1(&fields, "id", 8, true, false)?);
            layout.syscall_result = Some(require_field_v1(&fields, "ret", 8, true, false)?);
        }
    }
    for location in [
        layout.parent_pid,
        layout.child_pid,
        layout.filename,
        layout.pid,
        layout.old_pid,
        layout.syscall_id,
        layout.syscall_arguments,
        layout.syscall_result,
    ]
    .into_iter()
    .flatten()
    {
        if location.offset < 8 {
            return Err(LinuxVzPackageTracepointErrorV1::IncompatibleField);
        }
    }
    Ok(layout)
}

#[cfg(target_os = "linux")]
pub(crate) fn read_linux_vz_package_tracepoint_layout_v1(
    kind: LinuxVzPackageTracepointKindV1,
) -> Result<LinuxVzPackageTracepointLayoutV1, LinuxVzPackageTracepointErrorV1> {
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
        return Err(LinuxVzPackageTracepointErrorV1::Io);
    }
    let path = format!(
        "/sys/kernel/tracing/events/{}/{}/format",
        kind.category_v1(),
        kind.name_v1()
    );
    let mut file = File::open(path).map_err(|_| LinuxVzPackageTracepointErrorV1::Io)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_TRACEPOINT_FORMAT_BYTES_V1 as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LinuxVzPackageTracepointErrorV1::Io)?;
    if bytes.len() > MAX_TRACEPOINT_FORMAT_BYTES_V1 {
        return Err(LinuxVzPackageTracepointErrorV1::LimitExceeded);
    }
    decode_linux_vz_package_tracepoint_layout_v1(kind, &bytes)
}

fn parse_field_v1(
    line: &str,
) -> Result<LinuxVzPackageTracepointFieldV1, LinuxVzPackageTracepointErrorV1> {
    let parts = line.split(';').collect::<Vec<_>>();
    if parts.len() != 5 || !parts[4].is_empty() {
        return Err(LinuxVzPackageTracepointErrorV1::InvalidField);
    }
    let declaration = parts[0]
        .strip_prefix("field:")
        .ok_or(LinuxVzPackageTracepointErrorV1::InvalidField)?
        .trim();
    let offset = parse_labeled_usize_v1(parts[1].trim(), "offset:")?;
    let size = parse_labeled_usize_v1(parts[2].trim(), "size:")?;
    let signed = match parts[3].trim().strip_prefix("signed:") {
        Some("0") => false,
        Some("1") => true,
        _ => return Err(LinuxVzPackageTracepointErrorV1::InvalidField),
    };
    if declaration.is_empty() || declaration.contains(['\n', '\r', ';']) || size == 0 {
        return Err(LinuxVzPackageTracepointErrorV1::InvalidField);
    }
    let name_token = declaration
        .split_ascii_whitespace()
        .last()
        .ok_or(LinuxVzPackageTracepointErrorV1::InvalidField)?;
    let name = name_token.split('[').next().unwrap_or_default();
    if !valid_identifier_v1(name) {
        return Err(LinuxVzPackageTracepointErrorV1::InvalidIdentifier);
    }
    Ok(LinuxVzPackageTracepointFieldV1 {
        name: name.to_string(),
        declaration: declaration.to_string(),
        offset,
        size,
        signed,
        data_location: declaration
            .split_ascii_whitespace()
            .any(|token| token == "__data_loc"),
    })
}

fn validate_field_ranges_v1(
    fields: &[LinuxVzPackageTracepointFieldV1],
) -> Result<(), LinuxVzPackageTracepointErrorV1> {
    for (index, field) in fields.iter().enumerate() {
        let end = field
            .offset
            .checked_add(field.size)
            .ok_or(LinuxVzPackageTracepointErrorV1::LimitExceeded)?;
        if end > MAX_TRACEPOINT_RECORD_BYTES_V1 {
            return Err(LinuxVzPackageTracepointErrorV1::LimitExceeded);
        }
        if fields[..index].iter().any(|prior| {
            let prior_end = prior.offset + prior.size;
            field.offset < prior_end && prior.offset < end
        }) {
            return Err(LinuxVzPackageTracepointErrorV1::OverlappingField);
        }
    }
    Ok(())
}

fn require_common_fields_v1(
    fields: &[LinuxVzPackageTracepointFieldV1],
) -> Result<(), LinuxVzPackageTracepointErrorV1> {
    for (name, offset, size, signed) in [
        ("common_type", 0, 2, false),
        ("common_flags", 2, 1, false),
        ("common_preempt_count", 3, 1, false),
        ("common_pid", 4, 4, true),
    ] {
        let field = fields
            .iter()
            .find(|field| field.name == name)
            .ok_or(LinuxVzPackageTracepointErrorV1::MissingField)?;
        if field.offset != offset
            || field.size != size
            || field.signed != signed
            || field.data_location
        {
            return Err(LinuxVzPackageTracepointErrorV1::IncompatibleField);
        }
    }
    Ok(())
}

fn require_field_v1(
    fields: &[LinuxVzPackageTracepointFieldV1],
    name: &str,
    size: usize,
    signed: bool,
    data_location: bool,
) -> Result<LinuxVzPackageTracepointFieldLocationV1, LinuxVzPackageTracepointErrorV1> {
    let field = fields
        .iter()
        .find(|field| field.name == name)
        .ok_or(LinuxVzPackageTracepointErrorV1::MissingField)?;
    if field.size != size || field.signed != signed || field.data_location != data_location {
        return Err(LinuxVzPackageTracepointErrorV1::IncompatibleField);
    }
    Ok(LinuxVzPackageTracepointFieldLocationV1 {
        offset: field.offset,
        size: field.size,
        signed: field.signed,
        data_location: field.data_location,
    })
}

fn parse_labeled_usize_v1(
    value: &str,
    label: &str,
) -> Result<usize, LinuxVzPackageTracepointErrorV1> {
    let value = value
        .strip_prefix(label)
        .ok_or(LinuxVzPackageTracepointErrorV1::InvalidField)?;
    parse_decimal_usize_v1(value)
}

fn parse_decimal_u32_v1(value: &str) -> Result<u32, LinuxVzPackageTracepointErrorV1> {
    if !minimal_decimal_v1(value) {
        return Err(LinuxVzPackageTracepointErrorV1::InvalidHeader);
    }
    value
        .parse()
        .map_err(|_| LinuxVzPackageTracepointErrorV1::InvalidHeader)
}

fn parse_decimal_usize_v1(value: &str) -> Result<usize, LinuxVzPackageTracepointErrorV1> {
    if !minimal_decimal_v1(value) {
        return Err(LinuxVzPackageTracepointErrorV1::InvalidField);
    }
    value
        .parse()
        .map_err(|_| LinuxVzPackageTracepointErrorV1::InvalidField)
}

fn minimal_decimal_v1(value: &str) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_identifier_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMON: &str = "\
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n";

    fn format_v1(name: &str, fields: &str) -> Vec<u8> {
        format!("name: {name}\nID: 220\nformat:\n{COMMON}\n{fields}\nprint fmt: \"closed\"\n")
            .into_bytes()
    }

    #[test]
    fn required_tracepoint_layouts_decode_and_bind_exact_format_hashes() {
        let cases = [
            (
                LinuxVzPackageTracepointKindV1::SchedProcessFork,
                "\tfield:char parent_comm[16]; offset:8; size:16; signed:1;\n\
\tfield:pid_t parent_pid; offset:24; size:4; signed:1;\n\
\tfield:char child_comm[16]; offset:28; size:16; signed:1;\n\
\tfield:pid_t child_pid; offset:44; size:4; signed:1;",
            ),
            (
                LinuxVzPackageTracepointKindV1::SchedProcessExec,
                "\tfield:__data_loc char[] filename; offset:8; size:4; signed:1;\n\
\tfield:pid_t pid; offset:12; size:4; signed:1;\n\
\tfield:pid_t old_pid; offset:16; size:4; signed:1;",
            ),
            (
                LinuxVzPackageTracepointKindV1::SchedProcessExit,
                "\tfield:char comm[16]; offset:8; size:16; signed:1;\n\
\tfield:pid_t pid; offset:24; size:4; signed:1;\n\
\tfield:int prio; offset:28; size:4; signed:1;",
            ),
            (
                LinuxVzPackageTracepointKindV1::RawSyscallsSysEnter,
                "\tfield:long id; offset:8; size:8; signed:1;\n\
\tfield:unsigned long args[6]; offset:16; size:48; signed:0;",
            ),
            (
                LinuxVzPackageTracepointKindV1::RawSyscallsSysExit,
                "\tfield:long id; offset:8; size:8; signed:1;\n\
\tfield:long ret; offset:16; size:8; signed:1;",
            ),
        ];
        for (kind, fields) in cases {
            let bytes = format_v1(kind.name_v1(), fields);
            let layout = decode_linux_vz_package_tracepoint_layout_v1(kind, &bytes)
                .expect("tracepoint layout");
            assert_eq!(layout.kind_v1(), kind);
            assert_eq!(layout.tracepoint_id_v1(), 220);
            assert_eq!(layout.format_sha256_v1(), &Sha256Digest::from_bytes(&bytes));
            assert!(layout.maximum_record_bytes_v1() >= 20);
        }
    }

    #[test]
    fn tracepoint_layout_rejects_wrong_name_missing_and_incompatible_fields() {
        let fields = "\tfield:long id; offset:8; size:8; signed:1;\n\
\tfield:unsigned long args[6]; offset:16; size:48; signed:0;";
        let wrong_name = format_v1("sys_exit", fields);
        assert_eq!(
            decode_linux_vz_package_tracepoint_layout_v1(
                LinuxVzPackageTracepointKindV1::RawSyscallsSysEnter,
                &wrong_name,
            ),
            Err(LinuxVzPackageTracepointErrorV1::InvalidHeader)
        );
        let missing = format_v1("sys_enter", "\tfield:long id; offset:8; size:8; signed:1;");
        assert_eq!(
            decode_linux_vz_package_tracepoint_layout_v1(
                LinuxVzPackageTracepointKindV1::RawSyscallsSysEnter,
                &missing,
            ),
            Err(LinuxVzPackageTracepointErrorV1::MissingField)
        );
        let incompatible = format_v1(
            "sys_enter",
            "\tfield:long id; offset:8; size:4; signed:1;\n\
\tfield:unsigned long args[6]; offset:16; size:48; signed:0;",
        );
        assert_eq!(
            decode_linux_vz_package_tracepoint_layout_v1(
                LinuxVzPackageTracepointKindV1::RawSyscallsSysEnter,
                &incompatible,
            ),
            Err(LinuxVzPackageTracepointErrorV1::IncompatibleField)
        );
    }

    #[test]
    fn tracepoint_layout_rejects_duplicate_overlap_noncanonical_and_limits() {
        let duplicate = format_v1(
            "sched_process_exit",
            "\tfield:pid_t pid; offset:8; size:4; signed:1;\n\
\tfield:pid_t pid; offset:12; size:4; signed:1;",
        );
        assert_eq!(
            decode_linux_vz_package_tracepoint_layout_v1(
                LinuxVzPackageTracepointKindV1::SchedProcessExit,
                &duplicate,
            ),
            Err(LinuxVzPackageTracepointErrorV1::DuplicateField)
        );
        let overlap = format_v1(
            "sched_process_exit",
            "\tfield:pid_t pid; offset:6; size:4; signed:1;",
        );
        assert_eq!(
            decode_linux_vz_package_tracepoint_layout_v1(
                LinuxVzPackageTracepointKindV1::SchedProcessExit,
                &overlap,
            ),
            Err(LinuxVzPackageTracepointErrorV1::OverlappingField)
        );
        let mut no_newline = format_v1(
            "sched_process_exit",
            "\tfield:pid_t pid; offset:8; size:4; signed:1;",
        );
        no_newline.pop();
        assert_eq!(
            decode_linux_vz_package_tracepoint_layout_v1(
                LinuxVzPackageTracepointKindV1::SchedProcessExit,
                &no_newline,
            ),
            Err(LinuxVzPackageTracepointErrorV1::InvalidHeader)
        );
        assert_eq!(
            decode_linux_vz_package_tracepoint_layout_v1(
                LinuxVzPackageTracepointKindV1::SchedProcessExit,
                &vec![b'x'; MAX_TRACEPOINT_FORMAT_BYTES_V1 + 1],
            ),
            Err(LinuxVzPackageTracepointErrorV1::LimitExceeded)
        );
    }
}
